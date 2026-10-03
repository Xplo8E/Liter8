/*
 * Narrow LocalAuthentication fallback for lockdownd's Trust flow.
 *
 * The user must still accept lockdownd's Trust notification. Only after that
 * explicit acceptance does lockdownd evaluate private policy 1028
 * (LocationBasedTrustComputer) to request the device passcode. On the
 * SEP-less Liter8 boot profile, ACM returns -3 before presenting that UI.
 *
 * Preserve the real evaluation first. If, and only if, policy 1028 returns the
 * exact observed LocalAuthentication -1000 / ACM -3 failure while the existing
 * pairing-fallback marker is active, report an empty successful result to
 * lockdownd. Every successful evaluation, other policy, and other failure is
 * passed through unchanged.
 */

#import <Foundation/Foundation.h>
#import <objc/runtime.h>

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <syslog.h>

enum { kLocationBasedTrustComputerPolicy = 1028 };

static const char *kPairingFallbackMarker =
    "/private/var/root/Library/Lockdown/.liter8-pairing-fallback";

typedef void (^L8PolicyReply)(id result, NSError *error);
typedef void (*EvaluatePolicyIMP)(id, SEL, NSInteger, NSDictionary *,
                                  L8PolicyReply);

static EvaluatePolicyIMP gOriginalEvaluatePolicy;

static bool pairing_fallback_enabled(void)
{
    struct stat status;
    if (lstat(kPairingFallbackMarker, &status) != 0) {
        return false;
    }
    return S_ISREG(status.st_mode) && status.st_uid == 0 &&
           (status.st_mode & (S_IWGRP | S_IWOTH)) == 0;
}

static bool is_expected_sep_less_failure(NSError *error)
{
    if (error == nil || error.code != -1000 ||
        ![error.domain isEqualToString:@"com.apple.LocalAuthentication"]) {
        return false;
    }

    id debug_value = error.userInfo[@"NSDebugDescription"];
    if (![debug_value isKindOfClass:[NSString class]]) {
        return false;
    }
    NSString *debug_description = (NSString *)debug_value;
    return [debug_description containsString:@"LocationBasedTrustComputer"] &&
           [debug_description containsString:@"failed: -3"];
}

static void l8_evaluatePolicy(id self, SEL command, NSInteger policy,
                              NSDictionary *options, L8PolicyReply reply)
{
    if (policy != kLocationBasedTrustComputerPolicy || reply == nil ||
        !pairing_fallback_enabled()) {
        gOriginalEvaluatePolicy(self, command, policy, options, reply);
        return;
    }

    gOriginalEvaluatePolicy(
        self, command, policy, options, ^(id result, NSError *error) {
            if (result == nil && is_expected_sep_less_failure(error)) {
                syslog(LOG_NOTICE,
                       "l8pair: accepted explicit Trust after expected "
                       "SEP-less policy 1028 failure");
                reply(@{}, nil);
                return;
            }
            reply(result, error);
        });
}

__attribute__((constructor))
static void install_trust_computer_policy_guard(void)
{
    const char *program = getprogname();
    if (program == NULL || strcmp(program, "lockdownd") != 0) {
        return;
    }

    Class context = objc_lookUpClass("LAContext");
    SEL selector = sel_registerName("evaluatePolicy:options:reply:");
    Method method = context != Nil ? class_getInstanceMethod(context, selector)
                                   : NULL;
    if (method == NULL) {
        syslog(LOG_ERR,
               "l8pair: private Trust-computer policy method is unavailable");
        return;
    }

    gOriginalEvaluatePolicy =
        (EvaluatePolicyIMP)method_setImplementation(method,
                                                     (IMP)l8_evaluatePolicy);
    if (gOriginalEvaluatePolicy == NULL) {
        syslog(LOG_ERR,
               "l8pair: could not install Trust-computer policy guard");
        return;
    }
    syslog(LOG_NOTICE,
           "l8pair: installed marker-gated Trust-computer policy guard");
}
