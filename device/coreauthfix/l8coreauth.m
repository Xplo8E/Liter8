/*
 * l8coreauth.dylib - tolerate the empty SEP ratchet state on Liter8 boots.
 *
 * coreauthd receives a zero-length NSData from ACM on the SEP-less boot path.
 * LocalAuthenticationCore then copies the 75-byte status structure at offset
 * 0x100 without checking NSData.length, crashing at NULL + 0x120.  Keep the
 * framework's normal parser and object construction intact: only malformed
 * short inputs are copied into the 331-byte zeroed layout that the parser
 * expects.  Valid SEP state passes through byte-for-byte.
 *
 * The dylib is weak-loaded only by coreauthd.  The process-name check is a
 * second guard against accidental reuse from another executable.
 */

#import <Foundation/Foundation.h>
#import <objc/runtime.h>

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

enum { kRatchetStateBytes = 0x14b };

typedef id (*RatchetStateParserIMP)(id, SEL, NSData *);

static RatchetStateParserIMP gOriginalRatchetStateFromState;

static id l8_ratchetStateFromState(id self, SEL command, NSData *state)
{
    if (state != nil && ![state isKindOfClass:[NSData class]]) {
        return gOriginalRatchetStateFromState(self, command, state);
    }
    NSUInteger length = state.length;
    if (length >= kRatchetStateBytes) {
        return gOriginalRatchetStateFromState(self, command, state);
    }

    NSMutableData *padded = [NSMutableData dataWithLength:kRatchetStateBytes];
    if (padded == nil) {
        return gOriginalRatchetStateFromState(self, command, state);
    }
    if (length != 0) {
        memcpy(padded.mutableBytes, state.bytes, length);
    }
    syslog(LOG_NOTICE,
           "l8coreauth: padded short SEP ratchet state (%lu -> %u bytes)",
           (unsigned long)length, kRatchetStateBytes);
    return gOriginalRatchetStateFromState(self, command, padded);
}

__attribute__((constructor))
static void install_ratchet_state_guard(void)
{
    const char *program = getprogname();
    if (program == NULL || strcmp(program, "coreauthd") != 0) {
        return;
    }

    Class parser = objc_lookUpClass("LACDTORatchetSEPStateParser");
    SEL selector = sel_registerName("ratchetStateFromState:");
    Method method = parser != Nil ? class_getInstanceMethod(parser, selector) : NULL;
    if (method == NULL) {
        syslog(LOG_ERR, "l8coreauth: ratchet parser method is unavailable");
        return;
    }

    gOriginalRatchetStateFromState =
        (RatchetStateParserIMP)method_setImplementation(
            method, (IMP)l8_ratchetStateFromState);
    if (gOriginalRatchetStateFromState == NULL) {
        syslog(LOG_ERR, "l8coreauth: could not install ratchet parser guard");
        return;
    }
    syslog(LOG_NOTICE, "l8coreauth: installed SEP ratchet-state length guard");
}
