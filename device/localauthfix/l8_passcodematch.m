/*
 * l8_passcodematch - the confirm-step plaintext hook (build 13h).
 *
 * The set-passcode confirm compare is client-side: -[LAPSPasscode isEqual:]
 * -> -[passcode] -> -[data] -> -[LACSExtractablePassword data:] -> the
 * LACS C-level ACM decrypt, which fails SEP-less and raises
 * NSInternalInconsistencyException("Failed to extract passcode data")
 * (measured: both Preferences and coreauthd died of the rethrow, corpses
 * Preferences-2026-11-06-205837.000.ips / coreauthd-...-205837.ips).
 *
 * The plaintext only exists at init: -[LAPSPasscode
 * initWithLocalizedPasscode:type:] / initWithPasscode:type: receive the
 * entered string and immediately wrap it into the extractable password.
 * This section records that string on the object (associated reference)
 * and serves -[data] from it, so the confirm compare runs on plaintext
 * equality without touching the SEP-bound crypto.
 *
 * Marker-gated; forwards everything when the marker is off.
 */
#import "l8_hooking.h"
#import <os/log.h>
#import <objc/message.h>
#import <objc/runtime.h>
#import <stdatomic.h>

static char kL8PasscodeStringKey;

static IMP gOriginalInitPasscode;
static IMP gOriginalInitLocalized;
static IMP gOriginalData;

static atomic_bool gMatchInstalled = ATOMIC_VAR_INIT(false);

BOOL l8_passcodematch_installed(void) {
    return atomic_load(&gMatchInstalled);
}

/* @@:@@ - (id)string, (id)type. The original throws when the passcode type
 * rejects the string; only successful objects get the string associated. */
static id l8_passcode_init(id self, SEL sel, id string, id type, IMP original) {
    id result = ((id (*)(id, SEL, id, id))original)(self, sel, string, type);
    if (result != nil && l8_marker_enabled()) {
        objc_setAssociatedObject(result, &kL8PasscodeStringKey, string,
                                 OBJC_ASSOCIATION_RETAIN_NONATOMIC);
    }
    return result;
}

static id l8_passcode_initPasscode(id self, SEL sel, id string, id type) {
    return l8_passcode_init(self, sel, string, type, gOriginalInitPasscode);
}

static id l8_passcode_initLocalized(id self, SEL sel, id string, id type) {
    return l8_passcode_init(self, sel, string, type, gOriginalInitLocalized);
}

/* @@: - the original returns an autoreleased NSData (or empty). */
static id l8_passcode_data(id self, SEL sel) {
    if (l8_marker_enabled()) {
        NSString *string = objc_getAssociatedObject(self, &kL8PasscodeStringKey);
        if (string != nil) {
            NSData *data = [string dataUsingEncoding:NSUTF8StringEncoding];
            if (data != nil) {
                return data; /* factory: autoreleased, matches the original */
            }
        }
    }
    return ((id (*)(id, SEL))gOriginalData)(self, sel);
}

void l8_passcodematch_install_if_ready(void) {
    if (atomic_load(&gMatchInstalled)) return;
    Class cls = objc_lookUpClass("LAPSPasscode");
    if (cls == Nil) {
        /* LocalAuthenticationEmbeddedUI not loaded yet; the image-load
         * callback retries on the next family image. */
        return;
    }
    atomic_store(&gMatchInstalled, true);
    static const char *const initEncodings[] = {"@@:@@", "c@:@@"};
    static const char *const dataEncodings[] = {"@@:", "c@:"};
    int hooked = 0;
    hooked |= l8_swap_any(class_getInstanceMethod(cls, sel_registerName("initWithPasscode:type:")),
                          "LAPSPasscode initWithPasscode:type:", 4, initEncodings, 2,
                          (IMP)l8_passcode_initPasscode, &gOriginalInitPasscode) << 0;
    hooked |= l8_swap_any(class_getInstanceMethod(cls, sel_registerName("initWithLocalizedPasscode:type:")),
                          "LAPSPasscode initWithLocalizedPasscode:type:", 4, initEncodings, 2,
                          (IMP)l8_passcode_initLocalized, &gOriginalInitLocalized) << 1;
    hooked |= l8_swap_any(class_getInstanceMethod(cls, sel_registerName("data")),
                          "LAPSPasscode data", 2, dataEncodings, 2,
                          (IMP)l8_passcode_data, &gOriginalData) << 2;
    os_log_error(OS_LOG_DEFAULT, "l8passcodematch: confirm-compare hook mask 0x%x in pid %d",
                 hooked, getpid());
}
