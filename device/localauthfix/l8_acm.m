/*
 * l8_acm - the software credential crypto section of l8localauth.
 *
 * The passcode credential crypto funnels through two class methods on
 * LACACMHelper (LocalAuthenticationCore), each a thin two-phase wrapper over
 * the ACM C API (decoded 24B119):
 *   +encodeData:seed:externalizedContext:error:  -> ACMEncryptDataEx
 *   +decodeData:seed:externalizedContext:error:  -> ACMDecryptDataEx
 * Both return status -3 on this boot: the SEP that holds the ACM credential
 * context is absent, and that is the wall every passcode set/change/verify
 * dies against ("Failed to obtain encryption size -3" -> LACError -1001).
 *
 * Context creation itself (ACMContextCreateWithFlags, retried on -29/-5) is
 * local bookkeeping and succeeds without a SEP, so only the crypto needs
 * replacing. These swizzles answer with the software blob from
 * l8_acm_core.c: AES-256-CTR + HMAC-SHA256 over a master key file, binding
 * the caller's seed and externalized context into the tag so a blob cannot
 * be replayed under a different (seed, context) pair.
 *
 * Everything above this layer (LACContextCredentialCoder, LAContext
 * _encodeCredential/_decodeCredential, LACS, LAPSPasscode, Settings' flows)
 * keeps running stock; it only sees a working encoder where ACM stood.
 *
 * Master key: 32 bytes at /var/mobile/Library/l8acm.master (0600, created
 * from SecRandomCopyBytes by the first process that needs it). Settings and
 * SpringBoard run as mobile and can create it; root daemons read it fine.
 * A daemon sandbox that denies the read logs clearly and forwards to the
 * original (which fails -3 as it would have). The usual stance applies:
 * software keys protect nothing against the device operator.
 *
 * Class methods swizzle through class_getClassMethod (the metaclass-owned
 * Method); the helpers take the Method directly so instance and class hooks
 * share one code path.
 */
#import "l8_hooking.h"
#import "l8_acm_core.h"
#import <CommonCrypto/CommonCrypto.h>
#import <Foundation/Foundation.h>
#import <objc/message.h>
#import <objc/runtime.h>
#include <fcntl.h>
#include <os/log.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifndef LITER8_ACM_MASTER
#define LITER8_ACM_MASTER "/var/mobile/Library/l8acm.master"
#endif

static IMP gOriginalEncode;
static IMP gOriginalDecode;
static IMP gOriginalSeedWithReply;
static uint8_t gMasterKey[L8_ACM_MASTER_LEN];
static BOOL gMasterLoaded = NO;
static BOOL l8_acm_load_master(void);

/* The credential-encoding seed comes over a synchronous XPC to coreauthd,
 * which derives it from the SEP-bound ACM context. The reply payload carries
 * a malformed object on this boot and the autorelease pop of the XPC
 * transaction SIGSEGVs the caller (measured: crash right after the encode
 * succeeded). Serving the seed locally keeps the reply pool clean, and a
 * deterministic derivation keeps encode/decode HKDF-consistent. The reply
 * block is ^(NSData *seed, NSError *error). */
static void l8_acm_seedWithReply(id self, SEL sel, id reply) {
    if (!l8_marker_enabled() || !l8_acm_load_master()) {
        ((void (*)(id, SEL, id))gOriginalSeedWithReply)(self, sel, reply);
        return;
    }
    uint8_t seed[32];
    CC_SHA256(gMasterKey, L8_ACM_MASTER_LEN, seed);
    /* Autoreleased factory object, never explicitly released: the ARC machinery
     * across the reply block owns the lifetime, and an explicit release here
     * over-releases once the pool also drains its reference (measured: delayed
     * SIGSEGV in AutoreleasePoolPage::releaseUntil on the freed chunk). */
    id seedData = [NSData dataWithBytes:seed length:sizeof seed];
    memset(seed, 0, sizeof seed);
    os_log_error(OS_LOG_DEFAULT, "l8acm: serving deterministic encoding seed (pid %d)",
                 getpid());
    if (reply != nil) {
        ((void (^)(id, id))reply)(seedData, nil);
    }
}

/* The master key loads once per process. A failed load is remembered as an
 * empty key so every call takes the same forward path instead of retrying
 * the filesystem per credential. */

static BOOL l8_acm_read_random(uint8_t out[L8_ACM_MASTER_LEN]) {
    int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return NO;
    BOOL ok = YES;
    size_t got = 0;
    while (got < L8_ACM_MASTER_LEN) {
        ssize_t n = read(fd, out + got, L8_ACM_MASTER_LEN - got);
        if (n <= 0) {
            ok = NO;
            break;
        }
        got += (size_t)n;
    }
    close(fd);
    return ok;
}

static void l8_acm_load_master_once(void) {
    int fd = open(LITER8_ACM_MASTER, O_RDONLY | O_CLOEXEC);
    if (fd >= 0) {
        ssize_t got = 0;
        while (got < L8_ACM_MASTER_LEN) {
            ssize_t n = read(fd, gMasterKey + got, (size_t)(L8_ACM_MASTER_LEN - got));
            if (n <= 0) break;
            got += n;
        }
        close(fd);
        if (got == L8_ACM_MASTER_LEN) {
            gMasterLoaded = YES;
            return;
        }
        memset(gMasterKey, 0, sizeof gMasterKey);
        os_log_error(OS_LOG_DEFAULT,
                     "l8acm: master key at %{public}s short-read (%zd), forwarding to ACM",
                     LITER8_ACM_MASTER, got);
        return;
    }
    /* Create it: exclusive, private, filled from the system RNG. A racing
     * process loses the O_EXCL race and falls through to a fresh read. */
    fd = open(LITER8_ACM_MASTER, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (fd >= 0) {
        if (l8_acm_read_random(gMasterKey) &&
            write(fd, gMasterKey, L8_ACM_MASTER_LEN) == L8_ACM_MASTER_LEN) {
            gMasterLoaded = YES;
            os_log_error(OS_LOG_DEFAULT, "l8acm: created master key %{public}s",
                         LITER8_ACM_MASTER);
        } else {
            memset(gMasterKey, 0, sizeof gMasterKey);
        }
        close(fd);
        return;
    }
    /* Neither readable nor creatable: sandbox or permissions. Say so once
     * and let every call forward to the original. */
    os_log_error(OS_LOG_DEFAULT,
                 "l8acm: cannot read or create %{public}s (%{public}i), forwarding to ACM",
                 LITER8_ACM_MASTER, errno);
}

static BOOL l8_acm_load_master(void) {
    static pthread_once_t once = PTHREAD_ONCE_INIT;
    pthread_once(&once, l8_acm_load_master_once);
    return gMasterLoaded;
}

/* The inputs and outputs are NSData/LACSecureData-shaped (the stock methods
 * call bytes/length on the inputs and build the output with
 * +[LACSecureData secureDataWithBytes:length:]). Access stays behind
 * objc_msgSend casts: nothing here links LocalAuthenticationCore. */
static BOOL l8_acm_bytes_of(id data, const void **bytes, size_t *len) {
    if (data == nil) {
        *bytes = NULL;
        *len = 0;
        return YES;
    }
    *bytes = ((const void *(*)(id, SEL))objc_msgSend)(data, sel_registerName("bytes"));
    *len = (size_t)((unsigned long (*)(id, SEL))objc_msgSend)(data, sel_registerName("length"));
    return YES;
}

static id l8_acm_secure_data(const void *bytes, size_t len) {
    Class secureData = NSClassFromString(@"LACSecureData");
    if (secureData == Nil) return nil;
    id result = ((id (*)(id, SEL, const void *, unsigned long))objc_msgSend)(
        (id)secureData, sel_registerName("secureDataWithBytes:length:"), bytes,
        (unsigned long)len);
    return result != nil ? [result autorelease] : nil;
}

static id l8_acm_encode(id self, SEL sel, id data, id seed, id ctx, id *error) {
    if (!l8_marker_enabled() || !l8_acm_load_master()) {
        return ((id (*)(id, SEL, id, id, id, id *))gOriginalEncode)(self, sel, data, seed, ctx,
                                                                    error);
    }
    const void *dataBytes, *seedBytes, *ctxBytes;
    size_t dataLen, seedLen, ctxLen;
    l8_acm_bytes_of(data, &dataBytes, &dataLen);
    l8_acm_bytes_of(seed, &seedBytes, &seedLen);
    l8_acm_bytes_of(ctx, &ctxBytes, &ctxLen);

    uint8_t *blob = NULL;
    size_t blobLen = 0;
    int rc = l8_acm_core_encode(gMasterKey, seedBytes, seedLen, ctxBytes, ctxLen, dataBytes,
                                dataLen, &blob, &blobLen);
    if (rc != 0) {
        os_log_error(OS_LOG_DEFAULT, "l8acm: encode failed rc=%d (pid %d)", rc, getpid());
        if (error != NULL) {
            *error = l8_make_lac_error(-1000, @"l8acm: encode failed");
        }
        return nil;
    }
    os_log_error(OS_LOG_DEFAULT, "l8acm: encoded %zu bytes -> %zu-byte blob (pid %d)", dataLen,
                 blobLen, getpid());
    id result = l8_acm_secure_data(blob, blobLen);
    memset(blob, 0, blobLen);
    free(blob);
    return result;
}

static id l8_acm_decode(id self, SEL sel, id blobObj, id seed, id ctx, id *error) {
    /* A blob that is not ours belongs to the real ACM (a pre-Liter8
     * credential, or another process that ran with the marker off): forward
     * and let the original answer. */
    const void *blobBytes;
    size_t blobLen;
    l8_acm_bytes_of(blobObj, &blobBytes, &blobLen);
    if (!l8_marker_enabled() || !l8_acm_core_is_our_blob(blobBytes, blobLen)) {
        return ((id (*)(id, SEL, id, id, id, id *))gOriginalDecode)(self, sel, blobObj, seed, ctx,
                                                                    error);
    }
    if (!l8_acm_load_master()) {
        return ((id (*)(id, SEL, id, id, id, id *))gOriginalDecode)(self, sel, blobObj, seed, ctx,
                                                                    error);
    }
    const void *seedBytes, *ctxBytes;
    size_t seedLen, ctxLen;
    l8_acm_bytes_of(seed, &seedBytes, &seedLen);
    l8_acm_bytes_of(ctx, &ctxBytes, &ctxLen);

    uint8_t *plain = NULL;
    size_t plainLen = 0;
    int rc = l8_acm_core_decode(gMasterKey, seedBytes, seedLen, ctxBytes, ctxLen, blobBytes,
                                blobLen, &plain, &plainLen);
    if (rc == -2) {
        return ((id (*)(id, SEL, id, id, id, id *))gOriginalDecode)(self, sel, blobObj, seed, ctx,
                                                                    error);
    }
    if (rc == -3) {
        /* Mirrors the stock mapping of ACM's "credential not found" status
         * (-7) so callers keep their existing not-found branch. */
        os_log_error(OS_LOG_DEFAULT, "l8acm: decode refused (tag mismatch, pid %d)", getpid());
        if (error != NULL) *error = l8_make_lac_error(-1008, @"Not found.");
        return nil;
    }
    if (rc != 0) {
        os_log_error(OS_LOG_DEFAULT, "l8acm: decode failed rc=%d (pid %d)", rc, getpid());
        if (error != NULL) *error = l8_make_lac_error(-1000, @"l8acm: decode failed");
        return nil;
    }
    os_log_error(OS_LOG_DEFAULT, "l8acm: decoded %zu-byte blob -> %zu bytes (pid %d)", blobLen,
                 plainLen, getpid());
    id result = l8_acm_secure_data(plain, plainLen);
    memset(plain, 0, plainLen);
    free(plain);
    return result;
}

/* Type letters for both methods (offsets stripped), read from the live
 * runtime on 24B119: the return is an object, then self, SEL, data, seed,
 * context (objects) and the error out-pointer. */
static const char *const kAcmEncodings[] = {"@@:@@@^@"};

static atomic_bool gAcmDone = ATOMIC_VAR_INIT(false);

BOOL l8_acm_installed(void) {
    return atomic_load(&gAcmDone);
}

void l8_acm_install_if_ready(void) {
    if (atomic_load(&gAcmDone)) return;
    Class cls = objc_lookUpClass("LACACMHelper");
    if (cls == Nil) {
        /* LocalAuthenticationCore not loaded yet; the image-load callback in
         * l8localauth.m calls again on the next family image. */
        return;
    }
    /* One-shot from here: the attempt is made once the framework's classes
     * exist, matching the other install sections. */
    atomic_store(&gAcmDone, true);
    /* Class methods: class_getClassMethod hands back the metaclass-owned
     * Method, which method_setImplementation accepts directly. */
    SEL encodeSel = sel_registerName("encodeData:seed:externalizedContext:error:");
    SEL decodeSel = sel_registerName("decodeData:seed:externalizedContext:error:");
    int hooked = 0;
    hooked |= l8_swap_any(class_getClassMethod(cls, encodeSel),
                          "+encodeData:seed:externalizedContext:error:", 6,
                          kAcmEncodings, 1, (IMP)l8_acm_encode, &gOriginalEncode)
              << 0;
    hooked |= l8_swap_any(class_getClassMethod(cls, decodeSel),
                          "+decodeData:seed:externalizedContext:error:", 6,
                          kAcmEncodings, 1, (IMP)l8_acm_decode, &gOriginalDecode)
              << 1;
    /* The credential-encoding seed: served locally, never fetched over XPC. */
    Class client = objc_lookUpClass("LAClient");
    if (client != Nil) {
        static const char *const seedEncodings[] = {"v@:@?", "v@:@"};
        Method seedMethod =
            class_getInstanceMethod(client, sel_registerName("credentialEncodingSeedWithReply:"));
        if (l8_swap_any(seedMethod, "credentialEncodingSeedWithReply:", 3, seedEncodings, 2,
                        (IMP)l8_acm_seedWithReply, &gOriginalSeedWithReply))
            hooked |= 1 << 2;
    }
    os_log_error(OS_LOG_DEFAULT, "l8acm: credential crypto mask 0x%x in pid %d", hooked,
                 getpid());
}
