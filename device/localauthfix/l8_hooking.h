/*
 * Shared plumbing for the l8localauth swizzle sections: the kill-switch
 * marker, the encoding-letter helper and the guarded swap. Kept as static
 * inline so each section file compiles its own copy and the build stays
 * flat; the helpers are a dozen lines each and unlikely to diverge.
 */
#ifndef L8_HOOKING_H
#define L8_HOOKING_H

#import <Foundation/Foundation.h>
#import <objc/message.h>
#import <objc/runtime.h>
#include <os/log.h>
#include <string.h>
#include <sys/stat.h>

/* l8_acm.m - the software credential crypto section. */
void l8_acm_install_if_ready(void);
BOOL l8_acm_installed(void);

/* l8_acmpool.m - the daemon-side ACM pool accounting override. */
void l8_acmpool_install_if_ready(void);
BOOL l8_acmpool_installed(void);

/* l8_acmdaemon.m - the daemon-side credential read-back server. */
void l8_acmdaemon_install_if_ready(void);
BOOL l8_acmdaemon_installed(void);

/* The passcode-set state file: the daemon blob store (l8_acmdaemon.m, in
 * coreauthd) writes it when a credential is stored; the client-side pane
 * overrides read it so the UI flips to Turn Passcode Off once the shim's
 * software store actually holds a credential. */
#ifndef LITER8_PASSCODE_STATE
#define LITER8_PASSCODE_STATE "/var/mobile/Library/l8acm.passcode-set"
#endif

static inline BOOL l8_passcode_state_on(void) {
    struct stat st;
    if (stat(LITER8_PASSCODE_STATE, &st) != 0) return NO;
    return S_ISREG(st.st_mode) && (st.st_mode & (S_IWGRP | S_IWOTH)) == 0;
}

/* l8_passcodematch.m - the confirm-compare plaintext hook. */
void l8_passcodematch_install_if_ready(void);
BOOL l8_passcodematch_installed(void);

/* l8_lockstate.m - the lock-screen passcode-prompt enabler. */
void l8_lockstate_install_if_ready(void);
BOOL l8_lockstate_installed(void);

#ifndef LITER8_LOCALAUTH_MARKER
#define LITER8_LOCALAUTH_MARKER "/private/var/jb/.liter8-localauth"
#endif
/* The device marker must be root-owned; the host self-test runs unprivileged
 * and re-declares both as -D flags from build.sh. */
#ifndef LITER8_LOCALAUTH_MARKER_UID
#define LITER8_LOCALAUTH_MARKER_UID 0
#endif

static inline BOOL l8_marker_enabled(void) {
    struct stat st;
    if (lstat(LITER8_LOCALAUTH_MARKER, &st) != 0) return NO;
    return S_ISREG(st.st_mode) && st.st_uid == LITER8_LOCALAUTH_MARKER_UID &&
           (st.st_mode & (S_IWGRP | S_IWOTH)) == 0;
}

/* A method's type encoding with the frame offsets stripped, leaving only the
 * type letters. The offsets are frame-layout detail and say nothing about
 * whether a fixed-signature cast is valid; the letters are exactly what the
 * casts depend on. */
static inline void l8_encoding_letters(const char *encoding, char *out, size_t size) {
    size_t n = 0;
    for (const char *p = encoding; p != NULL && *p != '\0' && n + 1 < size; p++) {
        if (*p < '0' || *p > '9') out[n++] = *p;
    }
    out[n] = '\0';
}

/* Swizzle one instance or class method if it exists with the expected
 * argument count and one of the acceptable encodings. The original is
 * published before the replacement is installed, so a thread that enters the
 * hook at once never sees a NULL original. An unrecognised encoding leaves
 * the method alone and says so: forwarding through a guessed cast corrupts
 * arguments or kills the host process, and the marker does not prevent it
 * because the swizzle happens either way. For class methods pass the result
 * of class_getClassMethod (the metaclass-owned Method). */
static inline BOOL l8_swap_any(Method method, const char *name, unsigned arguments,
                               const char *const *candidates, unsigned candidate_count,
                               IMP replacement, IMP *original) {
    if (method == NULL || method_getNumberOfArguments(method) != arguments) return NO;
    char letters[160];
    l8_encoding_letters(method_getTypeEncoding(method), letters, sizeof letters);
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

/* The error shape every failing call in this shim reports: LACError when the
 * class exists (matching what LocalAuthenticationCore itself produces),
 * otherwise an NSError in LAErrorDomain with the same code. */
static inline NSError *l8_make_lac_error(NSInteger code, NSString *debug) {
    Class lacError = NSClassFromString(@"LACError");
    SEL factory = sel_registerName("errorWithCode:debugDescription:");
    if (lacError != Nil && ((BOOL (*)(id, SEL, SEL))objc_msgSend)(
                               (id)lacError, sel_registerName("respondsToSelector:"),
                               factory)) {
        return ((id (*)(id, SEL, NSInteger, NSString *))objc_msgSend)(
            (id)lacError, factory, code, debug);
    }
    return [NSError errorWithDomain:@"com.apple.LocalAuthentication" code:code userInfo:nil];
}

#endif
