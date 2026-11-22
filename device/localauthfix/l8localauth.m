/*
 * l8localauth.dylib - make passcode confirmations succeed on the SEP-less boot.
 *
 * Every "enter your passcode to confirm" prompt (Trust this computer, install a
 * marketplace / alternative app store, authorise a setting) ends in
 * LocalAuthentication asking the Secure Enclave, via ACM, to verify the
 * passcode. With no SEP, ACM returns -3 before any sheet appears, and the app
 * sees com.apple.LocalAuthentication/-1000, which looks like the user cancelled.
 *
 * This is the general form of the per-marketplace workaround from the lhook
 * branch (marketplace-confirmation.m) and of upstream's lockdownd-only
 * l8pair_auth.m. It hooks LAContext in whatever process loads it and, only for
 * the exact SEP-less ACM failure, reports LAErrorPasscodeNotSet instead. That
 * is truthful on this boot (there is no SEP-backed passcode) and sends the UI
 * down its existing no-passcode branch, so the action proceeds. It is not real
 * passcode authorisation; the no-SEP boot cannot produce that.
 *
 * Hooked, each only if present with the expected arity (selectors from the
 * 23H30 LocalAuthentication):
 *   evaluatePolicy:options:reply:         async policy path (public calls it)
 *   evaluatePolicy:options:error:         synchronous policy path (daemons)
 *   canEvaluatePolicy:error:
 *   evaluateAccessControl:operation:localizedReason:reply:   public, keychain
 *   evaluateAccessControl:operation:options:reply:           private async
 *   evaluateAccessControl:operation:options:error:           private sync
 * A public method that calls a hooked private one is translated once: the
 * translated error no longer matches the SEP-less signature.
 *
 * E07 passcode-set gate (decoded from the 24B119 shared cache; see
 * docs/aks-research/E07-passcode-milestone-recon.md): Settings' passcode pane
 * and every canEvaluatePolicy answer read "passcode is set" from
 * -[LACPasscodeUserHelper isPasscodeSetForUser:error:] via
 * LACManagedConfiguration.isPasscodeSet = keybagState != 1. The keybag-state
 * table can never produce state 1 on this boot, so the belief is always true
 * and the pane demands a passcode that does not exist. The hook answers the
 * same NO with the same error the class itself produces in that case
 * (LACError -5 "Passcode not set."), which routes the whole stack down its
 * real no-passcode branch: the mechanism factory stores the availability
 * error, canEvaluatePolicy stops claiming a passcode, and the pane stops
 * opening the LAPSPasscode sheet that aborts on the SEP-less ACM query.
 *   LACPasscodeUserHelper isPasscodeSetForUser:error:   concrete gate
 *   LACPasscodeHelper       isPasscodeSetForUser:error:   the wrapper above it
 * Both are hooked because the mechanism factory reaches the gate through a
 * dependencies object whose helper class is not named in the callers; either
 * class answering NO settles the question.
 *
 * Device test result (2026-11-05 clean boot): Settings' "Face ID & Passcode"
 * pane still demanded the passcode with zero calls through the LACore gate,
 * so the pane consults the LocalAuthenticationPrivateUI passcode stack
 * instead. That stack's passcode-present source is -hasPasscode on the
 * LAPSPasscode* adapter family; the MCAdapter variant reads the
 * ManagedConfiguration profile connection, a state store that knows nothing
 * about this boot's missing keybag. Hooked here, each forwarding unless the
 * marker is on:
 *   LAPSPasscodePersistenceAdapter hasPasscode   (base forwarder)
 *   LAPSPasscodePersistenceMCAdapter hasPasscode (profile-connection backed)
 *   LAPSCurrentPasscodeService hasPasscode
 *   LAPSPasscodePersistence hasPasscode
 *   LAPSPasscodeChangeSystem{Standard,Verification,Recovery,Stubbed}Adapter,
 *   LAPSPasscodeChangeSystemDispatchDecorator
 * With the marker on the three state-backed providers answer NO; the pure
 * forwarders keep forwarding so the probe log shows which one the pane hits.
 *
 * Built without ARC on purpose: the reply wrappers forward the first block
 * argument untouched, so its exact type (object or BOOL) cannot be
 * mis-retained.
 *
 * Scope and safety:
 *   - Dormant unless the root-owned marker /var/jb/.liter8-localauth exists, so
 *     it is a runtime kill switch (rm it to restore stock behaviour).
 *   - Translates ONLY the exact ACM -3 / LA -1000 signature. Every success,
 *     every other policy outcome and every other error pass through unchanged.
 *   - Changes no executable pages and needs no task port, so it works whether
 *     or not the code-signing-invalid kernel patches are present.
 *   - Does not link LocalAuthentication. The filter reaches every Objective-C
 *     process, but most never use LAContext, so the framework is not pulled
 *     into them. The hook is installed when LAContext appears: immediately if
 *     the host already loaded the framework, otherwise from an objc image-load
 *     callback, which runs after objc has registered the new image's classes.
 *
 * Install it as an ElleKit tweak: l8localauth.dylib and l8localauth.plist in
 * /var/jb/usr/lib/TweakInject. lhook's TweakLoader then loads it into every
 * Objective-C process (the filter is Foundation). It is a method swizzle, so it
 * needs no code-signing patch. Build: device/localauthfix/build.sh.
 *
 * Self-test (no device, no injection):
 *   clang -DLITER8_LOCALAUTH_TEST -framework Foundation \
 *       -framework LocalAuthentication l8localauth.m -o t && ./t
 */

#import <Foundation/Foundation.h>
#import <objc/message.h>
#import <objc/runtime.h>

#import "l8_hooking.h"
#import "l8_acm_core.h"

#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <os/log.h>
#include <stdatomic.h>
#include <sys/stat.h>
#include <string.h>

/* LocalAuthentication's public values, spelled out so nothing links against
 * the framework (LAErrorDomain is a symbol, not a macro). */
static NSString *const kL8LADomain = @"com.apple.LocalAuthentication";
static const NSInteger kL8PasscodeNotSet = -5;
/* ACM's status when there is no credential to verify against, which is what a
 * SEP-less boot produces. Named so the matcher reads as a status comparison
 * rather than a string that happens to appear in the message. */
static const NSInteger kL8ACMNoCredential = -3;

typedef void (^PolicyReply)(id result, NSError *error);
typedef void (^AccessReply)(BOOL success, NSError *error);
typedef void (*EvaluateIMP)(id, SEL, NSInteger, NSDictionary *, PolicyReply);
typedef id (*EvaluateSyncIMP)(id, SEL, NSInteger, NSDictionary *, NSError **);
typedef BOOL (*CanEvaluateIMP)(id, SEL, NSInteger, NSError **);
typedef void (*AccessIMP)(id, SEL, CFTypeRef, NSInteger, NSString *, AccessReply);
typedef void (*AccessOptionsIMP)(id, SEL, CFTypeRef, NSInteger, NSDictionary *, PolicyReply);
typedef id (*AccessSyncIMP)(id, SEL, CFTypeRef, NSInteger, NSDictionary *, NSError **);
typedef BOOL (*PasscodeSetIMP)(id, SEL, unsigned int, id *);
typedef BOOL (*HasPasscodeIMP)(id, SEL);

static EvaluateIMP gOriginalEvaluate;
static EvaluateSyncIMP gOriginalEvaluateSync;
static CanEvaluateIMP gOriginalCanEvaluate;
static AccessIMP gOriginalAccess;
static AccessOptionsIMP gOriginalAccessOptions;
static AccessSyncIMP gOriginalAccessSync;
static PasscodeSetIMP gOriginalUserHelperPasscodeSet;
static PasscodeSetIMP gOriginalHelperPasscodeSet;

/* One original per hooked class; the replacement recovers its own pair from
 * the receiver's class so a single body serves the whole adapter family. */
#define L8_PERSISTENCE_HOOKS \
    HOOK(LAPSPasscodePersistenceAdapter) \
    HOOK(LAPSPasscodePersistenceMCAdapter) \
    HOOK(LAPSCurrentPasscodeService) \
    HOOK(LAPSPasscodePersistence) \
    HOOK(LAPSPasscodeChangeSystemStandardAdapter) \
    HOOK(LAPSPasscodeChangeSystemVerificationAdapter) \
    HOOK(LAPSPasscodeChangeSystemRecoveryAdapter) \
    HOOK(LAPSPasscodeChangeSystemStubbedAdapter) \
    HOOK(LAPSPasscodeChangeSystemDispatchDecorator)

#define HOOK(cls) static HasPasscodeIMP gOriginal_##cls##_hasPasscode;
L8_PERSISTENCE_HOOKS
#undef HOOK

/* passcodeType probe: the pane's row rendering (Turn Passcode Off vs On)
 * stayed passcode-era even with every hasPasscode answering NO, so the rows
 * read passcodeType from some provider this family has not named yet. Each
 * class gets a forwarding probe that logs the answering class and the class
 * of the returned LACPasscode. */
#define HOOK(cls) static id (*gOriginal_##cls##_passcodeType)(id, SEL);
L8_PERSISTENCE_HOOKS
#undef HOOK

static const char *const kHasPasscodeEncodings[] = { "B@:", "c@:" };
static const char *const kPasscodeTypeEncodings[] = { "@@:" };

/* The marker, its owner check and the swizzle plumbing live in l8_hooking.h
 * so the ACM section file compiles the same helpers. kMarker is the name the
 * self-test creates and removes the marker under. */
#ifdef LITER8_LOCALAUTH_TEST
static const char *const kMarker = LITER8_LOCALAUTH_MARKER;
#endif

static BOOL marker_enabled(void) {
    return l8_marker_enabled();
}

/* The SEP-less condition, not a specific prompt: ACM could not verify the
 * credential because there is no SEP to verify it against. Matching the
 * signature rather than a policy number is what makes this general across every
 * passcode prompt, while staying narrow enough to leave real failures alone. */
static BOOL is_sep_less_acm_failure(NSError *error) {
    if (error == nil || error.code != -1000 || ![error.domain isEqualToString:kL8LADomain]) {
        return NO;
    }
    id detail = error.userInfo[NSDebugDescriptionErrorKey];
    if (![detail isKindOfClass:[NSString class]]) return NO;
    NSString *text = (NSString *)detail;
    if (![text containsString:@"ACM verification"]) return NO;
    // "ACM verification of <policy> on ACMContext N failed: -3"
    //
    // Parse the status rather than matching its text: "failed: -3" is a prefix
    // of "failed: -30", so a substring test also claims unrelated ACM failures
    // and rewrites them into the bypass. scanInteger consumes the whole run, so
    // -30 scans as -30 and is rejected by the comparison.
    NSRange marker = [text rangeOfString:@"failed: "];
    if (marker.location == NSNotFound) return NO;
    NSScanner *scanner =
        [NSScanner scannerWithString:[text substringFromIndex:NSMaxRange(marker)]];
    NSInteger status = 0;
    return [scanner scanInteger:&status] && status == kL8ACMNoCredential;
}

static NSError *translated(NSError *error) {
    if (!is_sep_less_acm_failure(error)) return error;
    os_log_error(OS_LOG_DEFAULT,
                 "l8localauth: SEP-less ACM -3 -> passcode-not-set (pid %d)", getpid());
    return [NSError errorWithDomain:kL8LADomain code:kL8PasscodeNotSet userInfo:nil];
}

static void l8_evaluate(id self, SEL sel, NSInteger policy,
                        NSDictionary *options, PolicyReply reply) {
    if (reply == nil || !marker_enabled()) {
        gOriginalEvaluate(self, sel, policy, options, reply);
        return;
    }
    gOriginalEvaluate(self, sel, policy, options, ^(id result, NSError *error) {
        reply(result, result != nil ? error : translated(error));
    });
}

/* The three synchronous wrappers check the marker before calling through, so a
 * disabled shim forwards the caller's own error pointer, NULL included.
 * Substituting &native regardless meant a caller that asked for no error
 * reporting had the original invoked as though it had asked for it, which is a
 * difference the kill switch exists to remove. The async wrappers already
 * short-circuit the same way. The extra lstat is immaterial here: these are
 * user-initiated authentication prompts, not a hot path. */
static id l8_evaluateSync(id self, SEL sel, NSInteger policy,
                          NSDictionary *options, NSError **error) {
    if (!marker_enabled()) return gOriginalEvaluateSync(self, sel, policy, options, error);
    NSError *native = nil;
    id result = gOriginalEvaluateSync(self, sel, policy, options, error ? &native : NULL);
    if (error) *error = result != nil ? native : translated(native);
    return result;
}

static BOOL l8_canEvaluate(id self, SEL sel, NSInteger policy, NSError **error) {
    if (!marker_enabled()) return gOriginalCanEvaluate(self, sel, policy, error);
    NSError *native = nil;
    BOOL ok = gOriginalCanEvaluate(self, sel, policy, error ? &native : NULL);
    if (error) *error = ok ? native : translated(native);
    return ok;
}

static void l8_access(id self, SEL sel, CFTypeRef accessControl, NSInteger operation,
                      NSString *reason, AccessReply reply) {
    if (reply == nil || !marker_enabled()) {
        gOriginalAccess(self, sel, accessControl, operation, reason, reply);
        return;
    }
    gOriginalAccess(self, sel, accessControl, operation, reason, ^(BOOL success, NSError *error) {
        reply(success, success ? error : translated(error));
    });
}

static void l8_accessOptions(id self, SEL sel, CFTypeRef accessControl, NSInteger operation,
                             NSDictionary *options, PolicyReply reply) {
    if (reply == nil || !marker_enabled()) {
        gOriginalAccessOptions(self, sel, accessControl, operation, options, reply);
        return;
    }
    gOriginalAccessOptions(self, sel, accessControl, operation, options, ^(id result, NSError *error) {
        reply(result, result != nil ? error : translated(error));
    });
}

static id l8_accessSync(id self, SEL sel, CFTypeRef accessControl, NSInteger operation,
                        NSDictionary *options, NSError **error) {
    if (!marker_enabled()) {
        return gOriginalAccessSync(self, sel, accessControl, operation, options, error);
    }
    NSError *native = nil;
    id result = gOriginalAccessSync(self, sel, accessControl, operation, options,
                                    error ? &native : NULL);
    if (error) *error = result != nil ? native : translated(native);
    return result;
}

/* The error the class itself reports when the managed configuration says no
 * passcode is set (decompiled 24B119: [LACError errorWithCode:-5
 * debugDescription:"Passcode not set."]). Producing the identical object keeps
 * every downstream consumer on the branch it already has for that case. */
static NSError *passcode_not_set_error(void) {
    Class lacError = NSClassFromString(@"LACError");
    SEL factory = sel_registerName("errorWithCode:debugDescription:");
    if (lacError != Nil && ((BOOL (*)(id, SEL, SEL))objc_msgSend)(
                               (id)lacError, sel_registerName("respondsToSelector:"),
                               factory)) {
        return ((id (*)(id, SEL, NSInteger, NSString *))objc_msgSend)(
            (id)lacError, factory, kL8PasscodeNotSet, @"Passcode not set.");
    }
    return [NSError errorWithDomain:kL8LADomain code:kL8PasscodeNotSet userInfo:nil];
}

/* One body for both hooked classes: NO with the not-set error. The passcode
 * gate is a state question, not a verification, so no original is consulted
 * and there is no failure signature to match - on this boot "no passcode" is
 * simply the truth, and every consumer has an existing no-passcode branch. */
static BOOL l8_passcode_set_replacement(id self, SEL sel, unsigned int userId, id *error,
                                        PasscodeSetIMP original) {
    if (!marker_enabled()) return original(self, sel, userId, error);
    if (l8_passcode_state_on()) {
        os_log_error(OS_LOG_DEFAULT,
                     "l8localauth: isPasscodeSetForUser:%u -> YES (shim store, pid %d)",
                     userId, getpid());
        return YES;
    }
    os_log_error(OS_LOG_DEFAULT, "l8localauth: isPasscodeSetForUser:%u -> NO (pid %d)",
                 userId, getpid());
    if (error != NULL) *error = passcode_not_set_error();
    return NO;
}

static BOOL l8_userHelperPasscodeNotSet(id self, SEL sel, unsigned int userId, id *error) {
    return l8_passcode_set_replacement(self, sel, userId, error, gOriginalUserHelperPasscodeSet);
}

static BOOL l8_helperPasscodeNotSet(id self, SEL sel, unsigned int userId, id *error) {
    return l8_passcode_set_replacement(self, sel, userId, error, gOriginalHelperPasscodeSet);
}

/* ManagedConfiguration answers from its profile store, a persisted state that
 * predates this boot's missing keybag, so it is one of the two providers the
 * override answers NO. CurrentPasscodeService is the other: the change-system
 * adapters all read it. */
static BOOL l8_mcAdapter_hasPasscode(id self, SEL sel) {
    if (!marker_enabled()) return gOriginal_LAPSPasscodePersistenceMCAdapter_hasPasscode(self, sel);
    BOOL forwarded = gOriginal_LAPSPasscodePersistenceMCAdapter_hasPasscode(self, sel);
    BOOL state = l8_passcode_state_on();
    os_log_error(OS_LOG_DEFAULT,
                 "l8localauth: MCAdapter hasPasscode %{public}s -> %{public}s (pid %d)",
                 forwarded ? "YES" : "NO", state ? "YES" : "NO", getpid());
    return state;
}

static BOOL l8_currentPasscodeService_hasPasscode(id self, SEL sel) {
    if (!marker_enabled()) return gOriginal_LAPSCurrentPasscodeService_hasPasscode(self, sel);
    BOOL forwarded = gOriginal_LAPSCurrentPasscodeService_hasPasscode(self, sel);
    BOOL state = l8_passcode_state_on();
    os_log_error(OS_LOG_DEFAULT,
                 "l8localauth: CurrentPasscodeService hasPasscode %{public}s -> %{public}s "
                 "(pid %d)",
                 forwarded ? "YES" : "NO", state ? "YES" : "NO", getpid());
    return state;
}

/* Everything else in the family forwards with a log line, so the probe names
 * the provider the pane actually consults. Dynamic strings are marked public:
 * os_log redacts %@ otherwise, and class names are not sensitive. */
static BOOL l8_persistence_probe(id self, SEL sel, HasPasscodeIMP original) {
    BOOL forwarded = original(self, sel);
    if (marker_enabled()) {
        os_log_error(OS_LOG_DEFAULT,
                     "l8localauth: [%{public}@ hasPasscode] -> %{public}s (probe, pid %d)",
                     NSStringFromClass([self class]), forwarded ? "YES" : "NO", getpid());
    }
    return forwarded;
}

#define HOOK(cls) \
    static BOOL l8_##cls##_hasPasscode(id self, SEL sel) { \
        return l8_persistence_probe(self, sel, gOriginal_##cls##_hasPasscode); \
    }
L8_PERSISTENCE_HOOKS
#undef HOOK

#define HOOK(cls) \
    static id l8_##cls##_passcodeType(id self, SEL sel) { \
        id result = gOriginal_##cls##_passcodeType(self, sel); \
        if (l8_marker_enabled()) { \
            os_log_error(OS_LOG_DEFAULT, \
                         "l8localauth: [%{public}@ passcodeType] -> %{public}@ (probe, pid %d)", \
                         NSStringFromClass([self class]), \
                         result != nil ? NSStringFromClass([result class]) : @"nil", \
                         getpid()); \
        } \
        return result; \
    }
L8_PERSISTENCE_HOOKS
#undef HOOK

/* The DTO provider and the profile connection are the row-source suspects
 * outside the LAPS family: LACDTODeviceInfoProvider backs the DTO policy
 * processor (its class is defined in a binary outside the shared cache, but
 * it registers at runtime wherever its image loads), and MCProfileConnection
 * is the ManagedConfiguration store the MCAdapter wraps. Both are probed
 * forwarding-only: this cycle names what the pane consults. */
static IMP gOriginalDTOHasPasscodeSet;
static IMP gOriginalDTOHasPasscodeSetCurrentUser;
static IMP gOriginalMCIsPasscodeSet;

static BOOL l8_dto_hasPasscodeSetForUser(id self, SEL sel, unsigned int userId) {
    BOOL forwarded = ((BOOL (*)(id, SEL, unsigned int))gOriginalDTOHasPasscodeSet)(
        self, sel, userId);
    if (marker_enabled()) {
        os_log_error(OS_LOG_DEFAULT,
                     "l8localauth: [LACDTODeviceInfoProvider hasPasscodeSetForUser:%u] -> "
                     "%{public}s (probe, pid %d)", userId, forwarded ? "YES" : "NO", getpid());
    }
    return forwarded;
}

static BOOL l8_dto_hasPasscodeSetForCurrentUser(id self, SEL sel) {
    BOOL forwarded = ((BOOL (*)(id, SEL))gOriginalDTOHasPasscodeSetCurrentUser)(self, sel);
    if (marker_enabled()) {
        os_log_error(OS_LOG_DEFAULT,
                     "l8localauth: [LACDTODeviceInfoProvider hasPasscodeSetForCurrentUser] -> "
                     "%{public}s (probe, pid %d)", forwarded ? "YES" : "NO", getpid());
    }
    return forwarded;
}

static BOOL l8_mc_isPasscodeSet(id self, SEL sel) {
    BOOL forwarded = ((BOOL (*)(id, SEL))gOriginalMCIsPasscodeSet)(self, sel);
    if (!marker_enabled()) return forwarded;
    /* The profile connection sits at its fail-closed default on this boot:
     * keybagd never reports passcode state (its own AKS is broken), so
     * managedconfiguration answers YES forever - the day-one belief every
     * consumer (the pane's rows, the MCAdapter, the DTO stack) hangs off.
     * NO is truthful: there is no passcode on this device. */
    BOOL state = l8_passcode_state_on();
    os_log_error(OS_LOG_DEFAULT,
                 "l8localauth: [MCProfileConnection isPasscodeSet] forwarded %{public}s "
                 "-> %{public}s (pid %d)", forwarded ? "YES" : "NO",
                 state ? "YES" : "NO", getpid());
    return state;
}

static IMP gOriginalMCPasscodeConstraints;

/* The new-passcode strength gate: the change system's
 * verifyNewPasscodeMeetsPlatformRequirements forwards the candidate through
 * the MCAdapter to this profile-connection call, whose "current constraints"
 * sit on the same fail-closed daemon state as isPasscodeSet and reject every
 * candidate as easily guessed (measured: 000000 and strong 6-digit codes
 * alike). With the marker on the constraints are answered as met: the shim's
 * own software store has no policy profile to satisfy. */
static BOOL l8_mc_passcodeConstraints(id self, SEL sel, id passcodeContext, id *outError) {
    BOOL forwarded = ((BOOL (*)(id, SEL, id, id *))gOriginalMCPasscodeConstraints)(
        self, sel, passcodeContext, outError);
    if (!marker_enabled()) return forwarded;
    os_log_error(OS_LOG_DEFAULT,
                 "l8localauth: [MCProfileConnection passcodeContext:meetsCurrentConstraints"
                 "OutError:] forwarded %{public}s -> YES (pid %d)",
                 forwarded ? "YES" : "NO", getpid());
    if (outError != NULL) *outError = nil;
    return YES;
}

static IMP gOriginalMCChangePasscode;

/* The change itself: the persistence adapter forwards
 * changePasscode:to:enableRecovery:error: through the MCAdapter to this
 * profile-connection call, which fails on the same fail-closed daemon state
 * (measured: all three credentials stored, constraints passed, then the
 * client cancels its own connection and reports PASSCODE_CHANGE_FAILED).
 * With the marker on the change is answered as done: the credential store
 * already holds the new credential. */
static BOOL l8_mc_changePasscode(id self, SEL sel, id oldContext, id newContext,
                                 BOOL skipRecovery, id *outError) {
    BOOL forwarded = ((BOOL (*)(id, SEL, id, id, BOOL, id *))gOriginalMCChangePasscode)(
        self, sel, oldContext, newContext, skipRecovery, outError);
    if (!marker_enabled()) return forwarded;
    os_log_error(OS_LOG_DEFAULT,
                 "l8localauth: [MCProfileConnection changePasscodeWithOldPasscodeContext:"
                 "newPasscodeContext:skipRecovery:outError:] forwarded %{public}s -> YES "
                 "(pid %d)",
                 forwarded ? "YES" : "NO", getpid());
    if (outError != NULL) *outError = nil;
    return YES;
}

static void l8_dto_install(void);
static void l8_ratchet_install(void);

static void l8_dto_install(void) {
    Class dto = objc_lookUpClass("LACDTODeviceInfoProvider");
    Class mc = objc_lookUpClass("MCProfileConnection");
    int hooked = 0;
    static const char *const uintEncodings[] = {"B@:I", "c@:I", "B@:Q", "c@:Q"};
    static const char *const plainEncodings[] = {"B@:", "c@:"};
    if (dto != Nil) {
        Method m = class_getInstanceMethod(dto, sel_registerName("hasPasscodeSetForUser:"));
        if (l8_swap_any(m, "LACDTODeviceInfoProvider hasPasscodeSetForUser:", 3,
                        uintEncodings, 4, (IMP)l8_dto_hasPasscodeSetForUser,
                        &gOriginalDTOHasPasscodeSet))
            hooked |= 1 << 0;
        m = class_getInstanceMethod(
            dto, sel_registerName("hasPasscodeSetForCurrentUser"));
        if (l8_swap_any(m, "LACDTODeviceInfoProvider hasPasscodeSetForCurrentUser", 2,
                        plainEncodings, 2, (IMP)l8_dto_hasPasscodeSetForCurrentUser,
                        &gOriginalDTOHasPasscodeSetCurrentUser))
            hooked |= 1 << 1;
    }
    if (mc != Nil) {
        Method m = class_getInstanceMethod(mc, sel_registerName("isPasscodeSet"));
        if (l8_swap_any(m, "MCProfileConnection isPasscodeSet", 2, plainEncodings, 2,
                        (IMP)l8_mc_isPasscodeSet, &gOriginalMCIsPasscodeSet))
            hooked |= 1 << 2;
        /* The new-passcode strength gate: BOOL(object, error*). */
        static const char *const constraintEncodings[] = {"B@:@^@", "c@:@^@"};
        m = class_getInstanceMethod(
            mc, sel_registerName("passcodeContext:meetsCurrentConstraintsOutError:"));
        if (l8_swap_any(m, "MCProfileConnection passcodeContext:meetsCurrentConstraints"
                            "OutError:",
                        4, constraintEncodings, 2, (IMP)l8_mc_passcodeConstraints,
                        &gOriginalMCPasscodeConstraints))
            hooked |= 1 << 3;
        static const char *const changeEncodings[] = {"B@:@@c^@", "B@:@@B^@", "c@:@@c^@",
                                                      "c@:@@B^@"};
        m = class_getInstanceMethod(
            mc, sel_registerName("changePasscodeWithOldPasscodeContext:newPasscodeContext:"
                                 "skipRecovery:outError:"));
        if (l8_swap_any(m, "MCProfileConnection changePasscodeWithOldPasscodeContext:"
                           "newPasscodeContext:skipRecovery:outError:",
                        6, changeEncodings, 4, (IMP)l8_mc_changePasscode,
                        &gOriginalMCChangePasscode))
            hooked |= 1 << 4;
    }
    if (hooked) {
        os_log_error(OS_LOG_DEFAULT,
                     "l8localauth: dto/mc probe mask 0x%x in pid %d", hooked, getpid());
    }
    l8_ratchet_install();
}

/* The passcode-change ratchet. The set flow gets as far as LAPasscodeChangeService
 * ('Set Passcode') and then demands prior authentication per the change ratchet,
 * which cannot complete on a boot with no passcode - so the screen never presents.
 * Two levers, both forwarding-first:
 *   1. +[LACACMHelper requirement:uint32Property:] (ACMRequirementGetProperty) - the
 *      ratchet's state source. Without a SEP the property read fails and the
 *      caller treats it as "no proof of recent auth". On failure the shim answers
 *      0 ("requirement satisfied") instead of nil.
 *   2. LARatchetManager reads - probed so the log shows what the flow consults. */
static IMP gOriginalACMRequirement;
static IMP gOriginalRatchetFeatureEnabled;
static IMP gOriginalRatchetFeatureAvailable;
static IMP gOriginalRatchetFeatureSupported;
static IMP gOriginalDTOFeatureEnabled;
static IMP gOriginalDTOFeatureAvailable;
static IMP gOriginalDTOStrictModeEnabled;
static IMP gOriginalDTOArmRequest;

/* The arm request is what kills the set flow: it makes coreauthd fetch the
 * ratchet config-and-status from the SEP interface, whose payload is invalid
 * on a SEP-less boot - a payload anomaly tripwire then deliberately crashes
 * coreauthd (measured: 'Ratchet config-and-status payload anomaly' -> corpse).
 * Completing the request locally with the null ratchet state tells the change
 * flow "no ratchet owed" and the SEP fetch never happens. The completion is a
 * block taking (LACDTORatchetState *, NSError *). */
static void l8_dto_armRequest(id self, SEL sel, id context, id options, id completion) {
    if (!marker_enabled()) {
        ((void (*)(id, SEL, id, id, id))gOriginalDTOArmRequest)(self, sel, context, options,
                                                                 completion);
        return;
    }
    /* (nil, nil): the arm's completion block feeds its first argument through
     * +[LARatchetManager ratchetResultForResult:], which nil-checks and maps
     * nil to a nil result - the authorizer then sees "ratchet produced no
     * result" instead of a daemon round-trip that would crash coreauthd on
     * the SEP payload anomaly. The composite object crashes here: the block
     * expects the XPC reply dictionary shape (objectForKeyedSubscript:). */
    os_log_error(OS_LOG_DEFAULT,
                 "l8localauth: ratchet arm request intercepted -> nil result (pid %d)",
                 getpid());
    if (completion != nil) {
        ((void (^)(id, id))completion)(nil, nil);
    }
}

/* The DTO ratchet manager's feature-disabled family answers NO. SDP cannot
 * exist on a SEP-less boot; NO everywhere means no ratchet for any consumer
 * that consults the manager instead of its own cached verdict. One body
 * serves the three selectors; the original is picked by name so the
 * marker-off forward stays faithful. */
static BOOL l8_dto_ratchet_no(id self, SEL sel) {
    const char *name = sel_getName(sel);
    IMP original = gOriginalDTOFeatureEnabled;
    if (strcmp(name, "isFeatureAvailable") == 0) {
        original = gOriginalDTOFeatureAvailable;
    } else if (strcmp(name, "isFeatureStrictModeEnabled") == 0) {
        original = gOriginalDTOStrictModeEnabled;
    }
    if (!marker_enabled()) return ((BOOL (*)(id, SEL))original)(self, sel);
    os_log_error(OS_LOG_DEFAULT,
                 "l8localauth: [LACDTORatchetManager %{public}s] -> NO (override, pid %d)",
                 name, getpid());
    return NO;
}

static id l8_acm_requirement(id self, SEL sel, void *requirement, unsigned int property) {
    id result = ((id (*)(id, SEL, void *, unsigned int))gOriginalACMRequirement)(
        self, sel, requirement, property);
    if (result == nil && marker_enabled()) {
        os_log_error(OS_LOG_DEFAULT,
                     "l8localauth: ACM requirement property %u failed -> answering 0 "
                     "(pid %d)", property, getpid());
        return @0;
    }
    if (marker_enabled()) {
        os_log_error(OS_LOG_DEFAULT,
                     "l8localauth: ACM requirement property %u -> %@ (probe, pid %d)",
                     property, result, getpid());
    }
    return result;
}

static BOOL l8_ratchet_bool_probe(id self, SEL sel, IMP original, const char *what) {
    BOOL forwarded = ((BOOL (*)(id, SEL))original)(self, sel);
    if (marker_enabled()) {
        os_log_error(OS_LOG_DEFAULT,
                     "l8localauth: [LARatchetManager %{public}s] -> %{public}s (probe, pid %d)",
                     what, forwarded ? "YES" : "NO", getpid());
    }
    return forwarded;
}

static BOOL l8_ratchet_featureEnabled(id self, SEL sel) {
    return l8_ratchet_bool_probe(self, sel, gOriginalRatchetFeatureEnabled, "isFeatureEnabled");
}
static BOOL l8_ratchet_featureAvailable(id self, SEL sel) {
    return l8_ratchet_bool_probe(self, sel, gOriginalRatchetFeatureAvailable,
                                 "isFeatureAvailable");
}
static BOOL l8_ratchet_featureSupported(id self, SEL sel) {
    return l8_ratchet_bool_probe(self, sel, gOriginalRatchetFeatureSupported,
                                 "isFeatureSupported");
}

static void l8_ratchet_install(void) {
    int hooked = 0;
    static const char *const plainEncodings[] = {"B@:", "c@:"};

    /* The ACM requirement read: a class method taking a C requirement pointer
     * and a property index, returning an NSNumber. The encoding embeds the
     * struct spelling, so match on arity plus the return/self prefix and log
     * the full letters when they do not fit. */
    Class acmHelper = objc_lookUpClass("LACACMHelper");
    if (acmHelper != Nil) {
        Method m = class_getClassMethod(
            acmHelper, sel_registerName("requirement:uint32Property:"));
        if (m != NULL && method_getNumberOfArguments(m) == 4) {
            char letters[160];
            l8_encoding_letters(method_getTypeEncoding(m), letters, sizeof letters);
            if (strncmp(letters, "@@:^", 4) == 0) {
                gOriginalACMRequirement = method_getImplementation(m);
                method_setImplementation(m, (IMP)l8_acm_requirement);
                hooked |= 1 << 0;
            } else {
                os_log_error(OS_LOG_DEFAULT,
                             "l8localauth: requirement:uint32Property: encoding "
                             "%{public}s unexpected; not hooked", letters);
            }
        }
    }

    Class ratchet = objc_lookUpClass("LARatchetManager");
    if (ratchet != Nil) {
        struct { const char *sel; IMP *original; IMP replacement; const char *what; int bit; }
        reads[] = {
            {"isFeatureEnabled", &gOriginalRatchetFeatureEnabled,
             (IMP)l8_ratchet_featureEnabled, "isFeatureEnabled", 1},
            {"isFeatureAvailable", &gOriginalRatchetFeatureAvailable,
             (IMP)l8_ratchet_featureAvailable, "isFeatureAvailable", 2},
            {"isFeatureSupported", &gOriginalRatchetFeatureSupported,
             (IMP)l8_ratchet_featureSupported, "isFeatureSupported", 4},
        };
        for (size_t i = 0; i < sizeof reads / sizeof reads[0]; i++) {
            Method m = class_getInstanceMethod(ratchet, sel_registerName(reads[i].sel));
            if (l8_swap_any(m, reads[i].sel, 2, plainEncodings, 2, reads[i].replacement,
                            reads[i].original))
                hooked |= reads[i].bit;
        }
    }

    /* The DTO ratchet manager (LocalAuthenticationCore): an XPC proxy to the
     * daemon's Stolen Device Protection state. The daemon already answers NO
     * on this boot, yet the pane's ratchet verdict came out armed - force the
     * feature-disabled family NO here so every consumer sees one truth, and
     * log where the deciding classes come from (the pane framework is in no
     * cache image and no on-disk binary we can find; the runtime knows). */
    Class dtoRatchet = objc_lookUpClass("LACDTORatchetManager");
    if (dtoRatchet != Nil) {
        struct { const char *sel; IMP *original; int bit; }
        dtoReads[] = {
            {"isFeatureEnabled", &gOriginalDTOFeatureEnabled, 1 << 3},
            {"isFeatureAvailable", &gOriginalDTOFeatureAvailable, 1 << 4},
            {"isFeatureStrictModeEnabled", &gOriginalDTOStrictModeEnabled, 1 << 5},
        };
        for (size_t i = 0; i < sizeof dtoReads / sizeof dtoReads[0]; i++) {
            Method m = class_getInstanceMethod(dtoRatchet, sel_registerName(dtoReads[i].sel));
            if (l8_swap_any(m, dtoReads[i].sel, 2, plainEncodings, 2,
                            (IMP)l8_dto_ratchet_no, dtoReads[i].original))
                hooked |= dtoReads[i].bit;
        }
        /* The arm request: intercepted before the XPC to coreauthd. The
         * completion is a block, so its encoding letter can be '?' or '@';
         * the rest is (context object, options dictionary, completion). */
        Method arm = class_getInstanceMethod(
            dtoRatchet, sel_registerName("performArmRequestWithContext:options:completion:"));
        if (arm != NULL && method_getNumberOfArguments(arm) == 5) {
            char armLetters[160];
            l8_encoding_letters(method_getTypeEncoding(arm), armLetters, sizeof armLetters);
            if (strncmp(armLetters, "v@:@@@", 6) == 0) {
                gOriginalDTOArmRequest = method_getImplementation(arm);
                method_setImplementation(arm, (IMP)l8_dto_armRequest);
                hooked |= 1 << 6;
            } else {
                os_log_error(OS_LOG_DEFAULT,
                             "l8localauth: performArmRequest encoding %{public}s unexpected; "
                             "not hooked", armLetters);
            }
        }
    }
    {
        const char *classes[] = {"FAPasscodeSettingsController", "LAPasscodeChangeService",
                                 "LACDTORatchetManager", "LACDTOPolicyProcessorEmptyPasscode",
                                 "LACDTODeviceInfoProvider"};
        for (size_t i = 0; i < sizeof classes / sizeof classes[0]; i++) {
            Class c = objc_lookUpClass(classes[i]);
            const char *image = c != Nil ? class_getImageName(c) : NULL;
            os_log_error(OS_LOG_DEFAULT,
                         "l8localauth: class %{public}s -> image %{public}s (pid %d)",
                         classes[i], image != NULL ? image : "(not loaded)", getpid());
        }
    }
    if (hooked) {
        os_log_error(OS_LOG_DEFAULT,
                     "l8localauth: ratchet probe mask 0x%x in pid %d", hooked, getpid());
    }
}

/* A method's type encoding with the frame offsets stripped, leaving only the
 * type letters. The offsets are frame-layout detail and say nothing about
 * whether the casts above are valid; the letters are exactly what they depend
 * on, and dropping the numbers keeps the expectation readable. */
static void encoding_letters(const char *encoding, char *out, size_t size) {
    size_t n = 0;
    for (const char *p = encoding; p != NULL && *p != '\0' && n + 1 < size; p++) {
        if (*p < '0' || *p > '9') out[n++] = *p;
    }
    out[n] = '\0';
}

/* Swizzle one method if it exists with the expected argument count and the
 * expected type encoding. The original is published before the replacement is
 * installed, so a thread that enters the hook at once never sees a NULL
 * original. Each hook is independent: a selector missing on some build leaves
 * the others working.
 *
 * Arity alone was not enough. These are mostly private selectors, and a private
 * selector can keep its argument count across builds while changing a return,
 * a scalar or a block ABI. Forwarding such a method through the fixed typedefs
 * above corrupts arguments or kills the host process, and the marker does not
 * prevent it because the swizzle happens either way. An unrecognised encoding
 * now leaves the method alone and says so, which costs that one fallback and
 * keeps the process alive. */
static BOOL swap(Class cls, const char *name, unsigned arguments, const char *types,
                 IMP replacement, IMP *original) {
    Method method = class_getInstanceMethod(cls, sel_registerName(name));
    if (method == NULL || method_getNumberOfArguments(method) != arguments) return NO;
    char letters[160];
    encoding_letters(method_getTypeEncoding(method), letters, sizeof letters);
    if (strcmp(letters, types) != 0) {
        os_log_error(OS_LOG_DEFAULT,
                     "l8localauth: %{public}s encoding is %{public}s, expected %{public}s; "
                     "not hooked", name, letters, types);
        return NO;
    }
    *original = method_getImplementation(method);
    method_setImplementation(method, replacement);
    return YES;
}

/* swap() against a list of acceptable encodings. The passcode-set gate's BOOL
 * return and unsigned argument each have two spellings the runtime uses ('B'
 * vs 'c', 'I' vs 'i' vs 'Q'); they are ABI-identical, but an unknown encoding
 * is still refused rather than forwarded through a guessed cast. */
static BOOL swap_any(Class cls, const char *name, unsigned arguments,
                     const char *const *candidates, unsigned candidate_count,
                     IMP replacement, IMP *original) {
    Method method = class_getInstanceMethod(cls, sel_registerName(name));
    if (method == NULL || method_getNumberOfArguments(method) != arguments) return NO;
    char letters[160];
    encoding_letters(method_getTypeEncoding(method), letters, sizeof letters);
    for (unsigned i = 0; i < candidate_count; i++) {
        if (strcmp(letters, candidates[i]) != 0) continue;
        *original = method_getImplementation(method);
        method_setImplementation(method, replacement);
        return YES;
    }
    os_log_error(OS_LOG_DEFAULT,
                 "l8localauth: %{public}s encoding is %{public}s, expected one of "
                 "%{public}s; not hooked",
                 name, letters, candidates[0]);
    return NO;
}

static atomic_bool gLAFInstalled;
static atomic_bool gHelperInstalled;
static atomic_bool gPersistenceInstalled;

/* BOOL/integer spellings the runtime uses for isPasscodeSetForUser:error:.
 * Read as type letters with offsets stripped; see swap_any. */
static const char *const kPasscodeSetEncodings[] = {
    "B@:I^@", "c@:I^@", "B@:i^@", "c@:i^@", "B@:Q^@", "c@:Q^@",
};

static void install_if_ready(void) {
    /* LocalAuthenticationCore side. LocalAuthenticationCore loads before (and
     * often without) LocalAuthentication, so this is what fires wherever the
     * passcode-pane machinery lives. The one-shot flag is only consumed when
     * at least one of the two classes is present, so an early call cannot burn
     * the attempt before the framework has registered its classes. */
    if (!atomic_load(&gHelperInstalled)) {
        Class userHelper = objc_lookUpClass("LACPasscodeUserHelper");
        Class helper = objc_lookUpClass("LACPasscodeHelper");
        if (userHelper != Nil || helper != Nil) {
            bool expected = false;
            if (atomic_compare_exchange_strong(&gHelperInstalled, &expected, true)) {
                int hooked = 0;
                if (userHelper != Nil)
                    hooked |= swap_any(userHelper, "isPasscodeSetForUser:error:", 4,
                                       kPasscodeSetEncodings, 6, (IMP)l8_userHelperPasscodeNotSet,
                                       (IMP *)&gOriginalUserHelperPasscodeSet)
                              << 0;
                if (helper != Nil)
                    hooked |= swap_any(helper, "isPasscodeSetForUser:error:", 4,
                                       kPasscodeSetEncodings, 6, (IMP)l8_helperPasscodeNotSet,
                                       (IMP *)&gOriginalHelperPasscodeSet)
                              << 1;
                os_log_error(OS_LOG_DEFAULT,
                             "l8localauth: passcode-set gate mask 0x%x in pid %d",
                             hooked, getpid());
            }
        }
    }

    /* LocalAuthenticationPrivateUI side: the passcode pane's persistence
     * family. LocalAuthenticationEmbeddedUI pulls this in for the pane flow,
     * so the flag is consumed only when a member class exists. */
    if (!atomic_load(&gPersistenceInstalled)) {
        bool anyPresent = false;
#define HOOK(cls) anyPresent |= objc_lookUpClass(#cls) != Nil;
        L8_PERSISTENCE_HOOKS
#undef HOOK
        if (anyPresent) {
            bool expected = false;
            if (atomic_compare_exchange_strong(&gPersistenceInstalled, &expected, true)) {
                int hooked = 0;
                int k = 0;
#define HOOK(cls) \
    { \
        Class c = objc_lookUpClass(#cls); \
        if (c != Nil) { \
            IMP replacement = (IMP)l8_##cls##_hasPasscode; \
            if (strcmp(#cls, "LAPSPasscodePersistenceMCAdapter") == 0) \
                replacement = (IMP)l8_mcAdapter_hasPasscode; \
            else if (strcmp(#cls, "LAPSCurrentPasscodeService") == 0) \
                replacement = (IMP)l8_currentPasscodeService_hasPasscode; \
            hooked |= swap_any(c, "hasPasscode", 2, kHasPasscodeEncodings, 2, \
                               replacement, (IMP *)&gOriginal_##cls##_hasPasscode) << k; \
        } \
        k++; \
    }
                L8_PERSISTENCE_HOOKS
#undef HOOK
                int typeHooked = 0;
                int t = 0;
#define HOOK(cls) \
    { \
        Class c = objc_lookUpClass(#cls); \
        if (c != Nil) { \
            Method m = class_getInstanceMethod(c, sel_registerName("passcodeType")); \
            if (l8_swap_any(m, #cls " passcodeType", 2, kPasscodeTypeEncodings, 1, \
                            (IMP)l8_##cls##_passcodeType, \
                            (IMP *)&gOriginal_##cls##_passcodeType)) \
                typeHooked |= 1 << t; \
        } \
        t++; \
    }
                L8_PERSISTENCE_HOOKS
#undef HOOK
                os_log_error(OS_LOG_DEFAULT,
                             "l8localauth: persistence mask 0x%x passcodeType mask 0x%x "
                             "in pid %d", hooked, typeHooked, getpid());
            }
        }
    }

    /* Software credential crypto (l8_acm.m): the LACACMHelper class-method
     * swizzles that answer the SEP-bound ACM encode/decode. */
    l8_acm_install_if_ready();

    /* Daemon-side ACM pool accounting (l8_acmpool.m): the LACACMPoolInfo
     * getter override that keeps the SEP-less pool from evicting the flow's
     * own context mid-operation. */
    l8_acmpool_install_if_ready();

    /* Confirm-compare plaintext hook (l8_passcodematch.m): serves
     * -[LAPSPasscode data] from the entered string instead of the SEP-bound
     * extractable-password decrypt. */
    l8_passcodematch_install_if_ready();

    /* Lock-screen prompt enabler (l8_lockstate.m): the MKBKeyStoreDevice
     * lock-state fabrication that makes SpringBoard's cover sheet show the
     * passcode entry. */
    l8_lockstate_install_if_ready();

    /* Row-source probes: the DTO provider and the profile connection. Their
     * images load with the pane flow, so this runs per install pass. */
    l8_dto_install();

    /* LocalAuthentication side: the six LAContext hooks. */
    if (atomic_load(&gLAFInstalled)) return;
    Class cls = objc_lookUpClass("LAContext");
    if (cls == Nil) return;
    bool expected = false;
    if (!atomic_compare_exchange_strong(&gLAFInstalled, &expected, true)) return;

    /* Encodings read from the live runtime on n104/24B5099f, offsets stripped.
     * CFTypeRef comes back concretely typed as the SecAccessControl struct
     * pointer, and the two reply: variants are indistinguishable by encoding
     * because NSString* and NSDictionary* are both '@'; the selector name is
     * what separates those two, which is why both are still listed. */
    int hooked = 0;
    hooked |= swap(cls, "evaluatePolicy:options:reply:", 5, "v@:q@@?",
                   (IMP)l8_evaluate, (IMP *)&gOriginalEvaluate) << 0;
    hooked |= swap(cls, "evaluatePolicy:options:error:", 5, "@@:q@^@",
                   (IMP)l8_evaluateSync, (IMP *)&gOriginalEvaluateSync) << 1;
    hooked |= swap(cls, "canEvaluatePolicy:error:", 4, "B@:q^@",
                   (IMP)l8_canEvaluate, (IMP *)&gOriginalCanEvaluate) << 2;
    hooked |= swap(cls, "evaluateAccessControl:operation:localizedReason:reply:", 6,
                   "v@:^{__SecAccessControl=}q@@?",
                   (IMP)l8_access, (IMP *)&gOriginalAccess) << 3;
    hooked |= swap(cls, "evaluateAccessControl:operation:options:reply:", 6,
                   "v@:^{__SecAccessControl=}q@@?",
                   (IMP)l8_accessOptions, (IMP *)&gOriginalAccessOptions) << 4;
    hooked |= swap(cls, "evaluateAccessControl:operation:options:error:", 6,
                   "@@:^{__SecAccessControl=}q@^@",
                   (IMP)l8_accessSync, (IMP *)&gOriginalAccessSync) << 5;
    os_log_error(OS_LOG_DEFAULT, "l8localauth: installed in pid %d (hook mask 0x%x of 0x3f)",
                 getpid(), hooked);
}

/* Whether a loaded image is one of the LocalAuthentication family (the
 * passcode gate lives in Core, the pane's persistence family in PrivateUI,
 * which EmbeddedUI pulls in for the pane flow), read from the image's own
 * LC_ID_DYLIB. Pure memory parsing: the objc image-load callback runs with the
 * runtime lock held, so it must not call into the objc runtime (that
 * deadlocks, measured) or dyld. */
static BOOL is_localauth_image(const struct mach_header *header) {
    if (header == NULL || header->magic != MH_MAGIC_64) return NO;
    const struct load_command *command =
        (const struct load_command *)((const char *)header + sizeof(struct mach_header_64));
    for (uint32_t i = 0; i < header->ncmds; i++) {
        if (command->cmd == LC_ID_DYLIB) {
            const struct dylib_command *dylib = (const struct dylib_command *)command;
            const char *name = (const char *)command + dylib->dylib.name.offset;
            return strstr(name, "/LocalAuthentication.framework/") != NULL ||
                   strstr(name, "/LocalAuthenticationCore.framework/") != NULL ||
                   strstr(name, "/LocalAuthenticationPrivateUI.framework/") != NULL ||
                   strstr(name, "/LocalAuthenticationEmbeddedUI.framework/") != NULL;
        }
        command = (const struct load_command *)((const char *)command + command->cmdsize);
    }
    return NO;
}

#ifndef LITER8_LOCALAUTH_TEST
static void deferred_install(void *context) {
    (void)context;
    @autoreleasepool { install_if_ready(); }
}

/* Called for every image already loaded at registration and for each later
 * one, after objc has registered its classes, with the runtime lock held. The
 * swizzle needs that lock, so it is queued and runs as soon as the load ends.
 * A call made in the window between the load and the queued install is not
 * translated; processes that link LocalAuthentication are hooked directly by
 * the constructor and never take this path. */
static void image_loaded(const struct mach_header *header) {
    if (!is_localauth_image(header)) return;
    if (atomic_load(&gLAFInstalled) && atomic_load(&gHelperInstalled) &&
        atomic_load(&gPersistenceInstalled) && l8_acm_installed()) return;
    dispatch_async_f(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), NULL,
                     deferred_install);
}

__attribute__((constructor))
static void install(void) {
    @autoreleasepool {
        /* NSZombie for the over-release hunt: the crash under investigation is
         * a deferred over-release of a freed chunk whose isa is unrecoverable;
         * with zombies on, the second release aborts with the CLASS name in
         * the corpse instead. Constructor-time setenv is the only reliable
         * route: launchctl setenv does not reach SpringBoard-spawned apps and
         * LLDB cannot setenv a hardened target (both measured). */
        setenv("NSZombieEnabled", "1", 1);
        install_if_ready();
        if (!atomic_load(&gLAFInstalled) || !atomic_load(&gHelperInstalled) ||
            !atomic_load(&gPersistenceInstalled) || !l8_acm_installed())
            objc_addLoadImageFunc(image_loaded);
    }
}
#else
#import <LocalAuthentication/LocalAuthentication.h>
#include <stdlib.h>

static const NSInteger kL8UserCancel = -2;

int main(void) {
    @autoreleasepool {
        // The spelled-out values must equal the framework's.
        if (![kL8LADomain isEqualToString:LAErrorDomain]) return 10;
        if (kL8PasscodeNotSet != LAErrorPasscodeNotSet) return 11;
        if (kL8UserCancel != LAErrorUserCancel) return 12;

        NSError *acm = [NSError errorWithDomain:kL8LADomain code:-1000
            userInfo:@{NSDebugDescriptionErrorKey:
                @"ACM verification of Oslo on ACMContext 0 failed: -3"}];
        NSError *cancel = [NSError errorWithDomain:kL8LADomain code:kL8UserCancel userInfo:nil];
        NSError *otherMinus1000 = [NSError errorWithDomain:kL8LADomain code:-1000 userInfo:nil];
        NSError *wrongDomain = [NSError errorWithDomain:@"other" code:-1000
            userInfo:@{NSDebugDescriptionErrorKey: @"ACM verification failed: -3"}];

        if (translated(acm).code != kL8PasscodeNotSet) return 1;
        if (translated(cancel) != cancel) return 2;
        if (translated(otherMinus1000) != otherMinus1000) return 3;
        if (translated(wrongDomain) != wrongDomain) return 4;
        if (translated(nil) != nil) return 5;

        /* "failed: -3" is a prefix of "failed: -30". An unrelated ACM status
         * must keep stock behaviour instead of being rewritten into the bypass. */
        for (NSString *other in @[@"-30", @"-31", @"-399", @"-3000"]) {
            NSError *near = [NSError errorWithDomain:kL8LADomain code:-1000
                userInfo:@{NSDebugDescriptionErrorKey: [NSString stringWithFormat:
                    @"ACM verification of Oslo on ACMContext 0 failed: %@", other]}];
            if (translated(near) != near) return 13;
        }
        /* The real one still matches, with and without trailing text. */
        NSError *trailing = [NSError errorWithDomain:kL8LADomain code:-1000
            userInfo:@{NSDebugDescriptionErrorKey:
                @"ACM verification of Oslo on ACMContext 0 failed: -3 (ignored)"}];
        if (translated(trailing).code != kL8PasscodeNotSet) return 14;
        /* A message with no status at all is not a match. */
        NSError *noStatus = [NSError errorWithDomain:kL8LADomain code:-1000
            userInfo:@{NSDebugDescriptionErrorKey: @"ACM verification of Oslo gave up"}];
        if (translated(noStatus) != noStatus) return 15;
        // Translation is idempotent, so a hooked public method calling a
        // hooked private one cannot translate twice into something else.
        if (translated(translated(acm)).code != kL8PasscodeNotSet) return 6;

        // The image-load callback recognises the framework family by header.
        BOOL found = NO, wrong = NO;
        for (uint32_t i = 0; i < _dyld_image_count(); i++) {
            BOOL match = is_localauth_image(_dyld_get_image_header(i));
            const char *imageName = _dyld_get_image_name(i);
            BOOL named = strstr(imageName, "/LocalAuthentication.framework/") != NULL ||
                         strstr(imageName, "/LocalAuthenticationCore.framework/") != NULL ||
                         strstr(imageName, "/LocalAuthenticationPrivateUI.framework/") != NULL ||
                         strstr(imageName, "/LocalAuthenticationEmbeddedUI.framework/") != NULL;
            found |= match && named;
            wrong |= match != named;
        }
        if (!found || wrong) return 8;

        // The passcode-set gate. The LocalAuthenticationCore classes are
        // usually present on the host too; when they are, the gate must hook
        // and answer NO with the not-set error while the marker is on, and
        // must forward without it. When the host has neither class, the gate
        // is skipped and the device install path still covers it.
        Class userHelper = NSClassFromString(@"LACPasscodeUserHelper");
        Class helper = NSClassFromString(@"LACPasscodeHelper");
        unsigned gateMask = 0;
        if (userHelper != Nil || helper != Nil) {
            install_if_ready();
            gateMask = (gOriginalUserHelperPasscodeSet != NULL ? 1u : 0u) |
                       (gOriginalHelperPasscodeSet != NULL ? 2u : 0u);
            if (!gateMask) return 17;
            Class gateClass = (gateMask & 1u) ? userHelper : helper;
            id instance = ((id (*)(id, SEL))objc_msgSend)(
                (id)gateClass, sel_registerName("new"));
            if (instance == nil) return 19;
            /* The replacement consults the marker at call time; create it at
             * the sandbox path (re-declared as -D flags by build.sh, uid-tuned
             * so the unprivileged test run satisfies the owner check). */
            FILE *markerFile = fopen(kMarker, "w");
            if (markerFile == NULL) return 20;
            fclose(markerFile);
            chmod(kMarker, 0600);
            SEL gate = sel_registerName("isPasscodeSetForUser:error:");
            NSError *gateError = nil;
            BOOL set = ((BOOL (*)(id, SEL, unsigned int, NSError **))objc_msgSend)(
                instance, gate, 501u, &gateError);
            if (set || gateError == nil || gateError.code != kL8PasscodeNotSet) return 18;
            /* Marker off: the original runs. The host's own answer is whatever
             * it is; the assertion is that the forward survives it. */
            remove(kMarker);
            gateError = nil;
            (void)((BOOL (*)(id, SEL, unsigned int, NSError **))objc_msgSend)(
                instance, gate, 501u, &gateError);
        } else {
            printf("note: passcode gate classes absent on this host; gate test skipped\n");
        }

        // The software ACM crypto core: round-trip, seed/context binding,
        // tamper refusal, foreign-blob pass-through.
        uint8_t master[L8_ACM_MASTER_LEN];
        for (int i = 0; i < L8_ACM_MASTER_LEN; i++) master[i] = (uint8_t)(i * 7 + 1);
        const char *seed = "seed-1234";
        const char *ctxBytes = "\x01\x02\x03\x04";
        const char *secret = "the passcode credential bytes";
        uint8_t *blob = NULL;
        size_t blobLen = 0;
        if (l8_acm_core_encode(master, seed, strlen(seed), ctxBytes, 4, secret,
                               strlen(secret), &blob, &blobLen) != 0) return 21;
        if (!l8_acm_core_is_our_blob(blob, blobLen)) return 22;
        uint8_t *plain = NULL;
        size_t plainLen = 0;
        if (l8_acm_core_decode(master, seed, strlen(seed), ctxBytes, 4, blob, blobLen,
                               &plain, &plainLen) != 0) return 23;
        if (plainLen != strlen(secret) || memcmp(plain, secret, (size_t)plainLen) != 0) return 24;
        free(plain);
        plain = NULL;
        blob[blobLen - 1] ^= 0x40; /* flip a MAC byte */
        if (l8_acm_core_decode(master, seed, strlen(seed), ctxBytes, 4, blob, blobLen,
                               &plain, &plainLen) != -3) return 25;
        free(blob);
        blob = NULL;
        if (l8_acm_core_encode(master, seed, strlen(seed), ctxBytes, 4, secret,
                               strlen(secret), &blob, &blobLen) != 0) return 26;
        /* A different seed or a different externalized context must refuse the
         * blob: the tag binds both. */
        if (l8_acm_core_decode(master, "other-seed", 10, ctxBytes, 4, blob, blobLen,
                               &plain, &plainLen) != -3) return 27;
        if (l8_acm_core_decode(master, seed, strlen(seed), "\x09", 1, blob, blobLen,
                               &plain, &plainLen) != -3) return 28;
        free(blob);
        /* Input that is not an L8CM blob is simply not ours. */
        if (l8_acm_core_decode(master, seed, strlen(seed), ctxBytes, 4, "garbage!!", 9,
                               &plain, &plainLen) != -2) return 29;

        // LAContext is linked into this test binary, so the path the
        // constructor takes must find and hook all three.
        install_if_ready();
        if (!gOriginalEvaluate || !gOriginalCanEvaluate || !gOriginalAccess) return 7;
        printf("PASS: SEP-less ACM -3 translated; cancellation, other errors and success "
               "preserved; public LAContext methods hooked (private: sync=%d "
               "access-options=%d access-sync=%d) passcode-gate mask 0x%x "
               "l8acm-core round-trip ok\n",
               gOriginalEvaluateSync != NULL, gOriginalAccessOptions != NULL,
               gOriginalAccessSync != NULL, gateMask);
        return 0;
    }
}
#endif
