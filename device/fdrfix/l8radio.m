/*
 * l8radio - force a baseband reset by toggling airplane mode.
 *
 * Testing anything on the baseband bring-up path needs that path to run again.
 * CommCenter only drives the ICE updater (BBUICE16UpdateSource: Loaded PSI2 /
 * EBL / NVM, then the calibration search) while the modem is being brought up,
 * so restarting CommCenter against an already-running modem does not re-run it
 * and a plain `launchctl kickstart` observes nothing.
 *
 * On a tethered Liter8 boot a reboot costs a full DFU cycle, so toggling
 * airplane mode is the cheap way to get the same bring-up: it powers the modem
 * down and back up through the normal supported path.
 *
 * Usage:
 *   l8radio            report the current airplane-mode state
 *   l8radio on|off     set it
 *   l8radio cycle      on, wait, off, which is what forces the reset
 *
 * RadiosPreferences is private, so it is resolved at runtime rather than linked.
 */

#import <Foundation/Foundation.h>

#include <dlfcn.h>
#include <objc/message.h>
#include <objc/runtime.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

/* objc_msgSend is declared variadic, so casting it straight to a concrete
 * signature trips -Wcast-function-type-mismatch. Going through void * is the
 * usual way to express "call it with this ABI" without suppressing warnings
 * wholesale. */
typedef bool (*BoolReturningMessage)(id, SEL);
typedef void (*BoolTakingMessage)(id, SEL, bool);
typedef void (*VoidMessage)(id, SEL);

static const char *kPreferencesFramework =
    "/System/Library/PrivateFrameworks/Preferences.framework/Preferences";

/* Long enough for CommCenter to tear the modem down and publish the change
 * before it is asked to bring it back up. */
static const unsigned kSettleSeconds = 6;

static id make_radios_preferences(void)
{
    if (dlopen(kPreferencesFramework, RTLD_NOW) == NULL) {
        fprintf(stderr, "l8radio: cannot load Preferences.framework: %s\n", dlerror());
        return nil;
    }
    Class radios = objc_lookUpClass("RadiosPreferences");
    if (radios == Nil) {
        fprintf(stderr, "l8radio: RadiosPreferences is unavailable\n");
        return nil;
    }
    id preferences = [[radios alloc] init];
    if (preferences == nil) {
        fprintf(stderr, "l8radio: could not construct RadiosPreferences\n");
    }
    return preferences;
}

static bool read_airplane_mode(id preferences, bool *value)
{
    SEL getter = sel_registerName("airplaneMode");
    if (![preferences respondsToSelector:getter]) {
        fprintf(stderr, "l8radio: -airplaneMode is unavailable\n");
        return false;
    }
    *value = ((BoolReturningMessage)(void *)objc_msgSend)(preferences, getter);
    return true;
}

static bool write_airplane_mode(id preferences, bool value)
{
    SEL setter = sel_registerName("setAirplaneMode:");
    SEL sync = sel_registerName("synchronize");
    if (![preferences respondsToSelector:setter]) {
        fprintf(stderr, "l8radio: -setAirplaneMode: is unavailable\n");
        return false;
    }
    ((BoolTakingMessage)(void *)objc_msgSend)(preferences, setter, value);
    if ([preferences respondsToSelector:sync]) {
        ((VoidMessage)(void *)objc_msgSend)(preferences, sync);
    }

    // The setter is advisory: it writes a preference that CommCenter acts on.
    // Read it back so a silent refusal is reported rather than assumed to work.
    bool observed = false;
    if (!read_airplane_mode(preferences, &observed)) {
        return false;
    }
    if (observed != value) {
        fprintf(stderr, "l8radio: airplane mode did not change, still %s\n",
                observed ? "on" : "off");
        return false;
    }
    printf("l8radio: airplane mode %s\n", value ? "on" : "off");
    return true;
}

int main(int argc, char **argv)
{
    @autoreleasepool {
        id preferences = make_radios_preferences();
        if (preferences == nil) {
            return 1;
        }

        const char *action = argc > 1 ? argv[1] : "";

        if (argc <= 1) {
            bool value = false;
            if (!read_airplane_mode(preferences, &value)) {
                return 1;
            }
            printf("airplane mode: %s\n", value ? "on" : "off");
            return 0;
        }

        if (strcmp(action, "on") == 0) {
            return write_airplane_mode(preferences, true) ? 0 : 1;
        }
        if (strcmp(action, "off") == 0) {
            return write_airplane_mode(preferences, false) ? 0 : 1;
        }
        if (strcmp(action, "cycle") == 0) {
            if (!write_airplane_mode(preferences, true)) {
                return 1;
            }
            sleep(kSettleSeconds);
            if (!write_airplane_mode(preferences, false)) {
                return 1;
            }
            printf("l8radio: cycled, the modem is being brought back up\n");
            return 0;
        }

        fprintf(stderr, "usage: %s [on|off|cycle]\n", argv[0]);
        return 2;
    }
}
