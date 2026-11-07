/*
 * l8_lockstate - the lock-screen passcode-prompt enabler (build 13l).
 *
 * The lock screen's passcode prompt is gated on the keybag lock state, not
 * on the MC/pane layer the settings flows use: SpringBoard consumes
 * -[MKBKeyStoreDevice getDeviceLockStateForUser:extendedState:withLockStateInfo:]
 * (MobileKeyBag, running inside SpringBoard as the keybagd XPC client). The
 * reply block writes exactly one int - the ls value - into the caller's
 * pointer (reply block decoded: ___79-..._block_invoke_0 writes *outState =
 * a2 and the completion flag, nothing else).
 *
 * keybagd is the early-boot tweak-less spawn and its AKS is broken, so the
 * real answer is "no keybag" and the lock screen never prompts. This hook
 * calls the original (the XPC still works - keybagd is alive) and then
 * overwrites *outState with the fabricated locked-with-passcode value when
 * both markers are present:
 *   - the passcode state file (a credential exists in the shim store)
 *   - LITER8_LOCKSTATE_FAKE_MARKER (deploy-time switch: flipping it live
 *     changes the lock screen without rebuilding; remove + reboot to revert)
 *
 * Value choice: ls=2 maps to LACKeyBagState 3 in the E07 ls table (locked
 * flavor); 5 = Unlocked. Build-overridable for value iteration.
 *
 * Boot safety: keybagd's GLOBAL lock state is load-bearing for content
 * protection (E07-E1 wedge), but this fabrication is scoped to the ObjC
 * client method SpringBoard's UI consumes - keybagd itself and the kernel
 * AKS layer stay untouched. If protected-class opens retry-loop at boot,
 * remove the fake marker and reboot (pwnDFU recovery as always).
 */
#import "l8_hooking.h"
#import <os/log.h>
#import <objc/message.h>
#import <objc/runtime.h>
#import <stdatomic.h>

#ifndef LITER8_LOCKSTATE_FAKE_MARKER
#define LITER8_LOCKSTATE_FAKE_MARKER "/var/mobile/Library/l8acm.lockstate-fake"
#endif

#ifndef LITER8_LOCKSTATE_FAKE_VALUE
#define LITER8_LOCKSTATE_FAKE_VALUE 2
#endif

static IMP gOriginalGetDeviceLockState;

static atomic_bool gLockStateInstalled = ATOMIC_VAR_INIT(false);
static atomic_bool gLockStateLogged = ATOMIC_VAR_INIT(false);

BOOL l8_lockstate_installed(void) {
    return atomic_load(&gLockStateInstalled);
}

static BOOL l8_lockstate_fake_enabled(void) {
    struct stat st;
    if (lstat(LITER8_LOCKSTATE_FAKE_MARKER, &st) != 0) return NO;
    return S_ISREG(st.st_mode);
}

/* B@:iB^i family - (int user, BOOL extended, int *outState) -> BOOL. */
static BOOL l8_getDeviceLockState(id self, SEL sel, int user, BOOL extended, int *outState) {
    BOOL ok = ((BOOL (*)(id, SEL, int, BOOL, int *))gOriginalGetDeviceLockState)(
        self, sel, user, extended, outState);
    if (!l8_marker_enabled() || !l8_passcode_state_on() || !l8_lockstate_fake_enabled()) {
        return ok;
    }
    int real = outState ? *outState : -1;
    if (outState) *outState = LITER8_LOCKSTATE_FAKE_VALUE;
    if (!atomic_exchange(&gLockStateLogged, true)) {
        os_log_error(OS_LOG_DEFAULT,
                     "l8lockstate: fabrication active, real=%d -> fake=%d (pid %d)",
                     real, LITER8_LOCKSTATE_FAKE_VALUE, getpid());
    }
    return ok;
}

void l8_lockstate_install_if_ready(void) {
    if (atomic_load(&gLockStateInstalled)) return;
    Class device = objc_lookUpClass("MKBKeyStoreDevice");
    if (device == Nil) {
        /* MobileKeyBag not loaded yet; the image-load callback retries. */
        return;
    }
    atomic_store(&gLockStateInstalled, true);
    static const char *const encodings[] = {
        "B@:iB^i", "c@:iB^i", "B@:iB^I", "c@:iB^I", "B@:i c@:^i",
    };
    Method m = class_getInstanceMethod(
        device, sel_registerName("getDeviceLockStateForUser:extendedState:withLockStateInfo:"));
    int hooked = 0;
    if (l8_swap_any(m, "MKBKeyStoreDevice getDeviceLockStateForUser:extendedState:"
                        "withLockStateInfo:",
                    5, encodings, 5, (IMP)l8_getDeviceLockState,
                    &gOriginalGetDeviceLockState))
        hooked = 1;
    os_log_error(OS_LOG_DEFAULT, "l8lockstate: lock-state hook mask 0x%x in pid %d", hooked,
                 getpid());
}
