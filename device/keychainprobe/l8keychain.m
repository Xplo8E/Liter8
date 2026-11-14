/*
 * l8keychain.dylib — software keychain class keys for SEP-less Liter8.
 *
 * Without a SEP the device keybag has no per-class keys, so securityd's
 * ks_crypt cannot wrap or unwrap keychain secrets: every SecItemAdd fails
 * with -25291 "No key available for class" and the system keychain is dead.
 * (Verified on the 24B119 E06 boot: ks_crypt -> aks_wrap_key -> status
 * 0xe00002f0 -> -25291.)
 *
 * This interposer gives securityd software-backed wrap/unwrap for the
 * item-secret keyclasses of the DEVICE keybag (handle 0):
 *
 *     6    key_class_ak        device-only item secrets
 *     7    key_class_ck        always-available item secrets (Wi-Fi
 *                              passwords land here - measured)
 *     10   key_class_cku       always-available, this-device-only
 *     39   metadata            the securityd metadata store key
 *
 * The interposition point is the client boundary, not ks_crypt itself:
 * ks_crypt is internal to securityd and unreachable by dyld interposition,
 * while aks_wrap_key / aks_unwrap_key are AppleKeyStore.framework exports
 * securityd imports normally. Intercepting them is the same layer of effect
 * — ks_crypt only maps the client's status to OSStatus/CFError — but it uses
 * the exact dyld __interpose mechanism l8pair/l8wifi/l8coreauth already
 * prove works inside restricted platform binaries on this rig, with no
 * hooking library and no undefined dynamic-lookup imports. (The v1 build's
 * MSHookFunction import required -Wl,-undefined,dynamic_lookup, and the fat
 * arm64+arm64e build carrying that flag killed every TweakInject-loaded
 * process with KERN_CODESIGN_ERROR on 2026-11-04; the same flag in an
 * arm64-only build loaded cleanly, so the poison was the combination — see
 * E04-securityd-classkey-provider.md. v2 removes both variables by following
 * the proven shim recipe exactly.)
 *
 * Blob format (same bytes v1 used, so a master key already minted survives):
 *
 *     offset  size  field
 *     0       4     magic 'L8KC'
 *     4       1     version (1)
 *     5       1     keyclass
 *     6       2     reserved (0)
 *     8       16    CTR nonce
 *     24      n     ciphertext (AES-256-CTR, per-class key)
 *     24+n    32    HMAC-SHA256 (mac key) over bytes [0, 24+n)
 *
 * Keys derive from one 32-byte master (HMAC-SHA256) persisted 0600 at
 * L8KEYCHAIN_MASTER_PATH, minted on first use if provisioning has not already
 * created it. Like the
 * Wi-Fi credential store and the pairing fallback, this protects nothing
 * against the operator of the device: it is an explicit security tradeoff of
 * the experimental SEP-less system, it is gated by an operator-created
 * marker, and it must never be presented as hardware-backed Data Protection.
 *
 * Pass-through contract: any other keyclass, any other keybag handle, any
 * non-L8KC blob, any malformed request, and the whole shim when the marker
 * is absent — all go to the real AppleKeyStore implementation. Removing the
 * marker restores complete stock behavior without re-signing securityd.
 *
 * Caller-visible contracts (verified against the decompiled 24B119 ks_crypt
 * at 0x10000d34c and the AppleKeyStore client disassembly; see
 * E04-securityd-classkey-provider.md):
 *
 *     kern_return_t aks_wrap_key(const void *source, int source_len,
 *                                int keyclass, int keybag, void *out_buf,
 *                                int *dest_len, int *actual_class);
 *     kern_return_t aks_unwrap_key(const void *source, int source_len,
 *                                  int keyclass, int keybag, void *out_buf,
 *                                  int *dest_len);
 *
 * dest_len[0] arrives holding the destination length (the caller sizes it
 * from its CFMutableData) and must leave holding the produced length; both
 * functions return 0 on success, and ks_crypt then grows its destination to
 * dest_len[0] and treats the item as processed. This mirrors what the real
 * client functions relay from the kernel reply.
 */

#include <CommonCrypto/CommonCrypto.h>
#include <mach/kern_return.h>
#include <sys/stat.h>
#include <sys/syslog.h>
#include <fcntl.h>
#include <unistd.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Overridable so the host test can compile this source into a harness that
 * calls the replacements and stub replacees directly, without dyld. */
#ifndef DYLD_INTERPOSE
#define DYLD_INTERPOSE(_replacement, _replacee)                                      \
    __attribute__((used)) static struct {                                            \
        const void *replacement;                                                     \
        const void *replacee;                                                        \
    } _interpose_##_replacee __attribute__((section("__DATA,__interpose"))) = {      \
        (const void *)(unsigned long)&_replacement,                                  \
        (const void *)(unsigned long)&_replacee                                      \
    };
#endif

/* The enable marker. /usr/lib/.liter8-keychain sits beside the dylib on the
 * sealed System volume, written by provisioning, and survives every reboot;
 * the /private/var/root path is the v1 marker deploy.sh created on Data, so
 * a device enabled by hand keeps working across the migration. Both must be
 * root-owned and not group/other writable. */
#ifndef L8KEYCHAIN_MARKER_SYSTEM
#define L8KEYCHAIN_MARKER_SYSTEM "/usr/lib/.liter8-keychain"
#endif
#ifndef L8KEYCHAIN_MARKER_DATA
#define L8KEYCHAIN_MARKER_DATA "/private/var/root/Library/.liter8-keychain"
#endif

/* The master key lives in securityd's own keychain directory on Data:
 * /var/root is outside securityd's sandbox (kernel denies both create and
 * read for securityd there, measured 2026-11-04), while /private/var/Keychains
 * holds keychain-2.db and is the one directory securityd provably may read
 * and write. Provisioning pre-creates the file so the sandboxed mint path
 * is not load-bearing. */
#ifndef L8KEYCHAIN_MASTER_PATH
#define L8KEYCHAIN_MASTER_PATH "/private/var/Keychains/l8keychain.master"
#endif

/* The daemon this shim belongs to. The dylib is weak-loaded into securityd
 * alone, but the check is repeated here so a copy that reaches another
 * process stays inert. */
#ifndef L8KEYCHAIN_TARGET_PROGRAM
#define L8KEYCHAIN_TARGET_PROGRAM "securityd"
#endif

/* The master key must be ours alone: owned by root or by this process, and
 * never group or other accessible. securityd runs as _securityd (uid 64,
 * measured on 24B156), not root, so in practice the master must be owned by that account:
 * a root-owned 0600 master cannot even be opened, and every wrap then falls
 * back to the real AKS path. sshrd_provision.sh creates it with that owner. */
#ifndef L8KEYCHAIN_MARKER_UID
#define L8KEYCHAIN_MARKER_UID 0
#endif

/* The largest item the shim will wrap. The keychain never carries payloads
 * this size, so a request above it is a caller bug, not a secret. */
#ifndef L8KEYCHAIN_MAXIMUM_ITEM_BYTES
#define L8KEYCHAIN_MAXIMUM_ITEM_BYTES (1024 * 1024)
#endif

enum {
    kKeyClassAK = 6,    /* key_class_ak: device-only item secrets */
    kKeyClassCK = 7,    /* key_class_ck: always-available item secrets;
                         * measured on device: wifid's AirPort password add
                         * is an 'oe' of class 7 (2026-11-04 re-join) */
    kKeyClassCKU = 10,  /* key_class_cku: observed failing inserts */
    kKeyClassMeta = 39, /* the securityd metadata store key */
    kKeybagDevice = 0,  /* g_keychain_keybag: the DEVICE keybag handle */
    kBlobHeader = 8,
    kBlobNonce = 16,
    kBlobMac = 32,
};

enum {
    kL8KCVersion = 1,
};

/* A blob that fails authentication is reported the way the real client
 * reports an undecryptable item: 0xe00002fc makes ks_crypt answer -26275
 * "Item can't be decrypted on this device, ever, so drop the item", which
 * is exactly the semantics of a keychain row whose wrapping is broken. */
enum {
    kAKSStatusDrop = 0xE00002FC,
};

#define L8KC_VERSION kL8KCVersion

static const char *const kMarkers[] = {
    L8KEYCHAIN_MARKER_SYSTEM,
    L8KEYCHAIN_MARKER_DATA,
};

static pthread_mutex_t gMasterLock = PTHREAD_MUTEX_INITIALIZER;
static uint8_t gMaster[32];
static bool gHaveMaster;

/* ------------------------------------------------------------------ */
/* Gates                                                               */
/* ------------------------------------------------------------------ */

static bool marker_ok(const char *path)
{
    struct stat st;
    if (lstat(path, &st) != 0)
        return false;
    return S_ISREG(st.st_mode) && st.st_uid == L8KEYCHAIN_MARKER_UID &&
           (st.st_mode & (S_IWGRP | S_IWOTH)) == 0;
}

static bool shim_enabled(void)
{
    for (size_t i = 0; i < sizeof(kMarkers) / sizeof(kMarkers[0]); i++) {
        if (marker_ok(kMarkers[i]))
            return true;
    }
    return false;
}

static bool is_securityd(void)
{
    const char *program = getprogname();
    return program != NULL && strcmp(program, L8KEYCHAIN_TARGET_PROGRAM) == 0;
}

/* One predicate for everything the software path insists on, so the wrap
 * and unwrap replacements cannot drift apart about which requests are
 * theirs. Everything failing it goes to the real implementation.
 *
 * The class set is the item-secret classes only. The device-key classes
 * (8 dk, 11 dku, 12 akpu) and any other bag are deliberately not served:
 * those keys guard system state this shim must not pretend to hold. */
static bool class_is_served(int keyclass)
{
    return keyclass == kKeyClassAK || keyclass == kKeyClassCK ||
           keyclass == kKeyClassCKU || keyclass == kKeyClassMeta;
}

static bool request_is_ours(int keyclass, int keybag, const void *source,
                            int source_len, const void *out_buf,
                            const int *dest_len)
{
    if (!shim_enabled() || !is_securityd())
        return false;
    if (keybag != kKeybagDevice)
        return false;
    if (!class_is_served(keyclass))
        return false;
    if (source == NULL || out_buf == NULL || dest_len == NULL)
        return false;
    if (source_len <= 0 || source_len > L8KEYCHAIN_MAXIMUM_ITEM_BYTES)
        return false;
    return true;
}

/* ------------------------------------------------------------------ */
/* Crypto primitives                                                   */
/* ------------------------------------------------------------------ */

static bool soft_crypt(bool encrypt, const uint8_t key[32],
                       const uint8_t *nonce, const uint8_t *in, size_t len,
                       uint8_t *out)
{
    memset(out, 0, len);
    size_t moved = 0;
    CCCryptorRef cryptor = NULL;
    CCCryptorStatus st = CCCryptorCreateWithMode(
        encrypt ? kCCEncrypt : kCCDecrypt, kCCModeCTR, kCCAlgorithmAES,
        ccNoPadding, nonce, key, kCCKeySizeAES256, NULL, 0, 0, 0, &cryptor);
    if (st != kCCSuccess)
        return false;
    st = CCCryptorUpdate(cryptor, in, len, out, len, &moved);
    CCCryptorRelease(cryptor);
    return st == kCCSuccess && moved == len;
}

/* Two-key-style MAC without a second key file: hash the header+nonce under
 * the mac key, then the ciphertext under the intermediate. Deterministic,
 * and a tampered ciphertext cannot be re-signed without the master. */
static void blob_mac(const uint8_t key[32], const uint8_t *a, size_t alen,
                     const uint8_t *b, size_t blen, uint8_t mac[32])
{
    CCHmac(kCCHmacAlgSHA256, key, 32, a, alen, mac);
    uint8_t second[32];
    CCHmac(kCCHmacAlgSHA256, mac, 32, b, blen, second);
    memcpy(mac, second, 32);
}

/* The lock is held by the caller. */
static bool load_master_locked(void)
{
    if (gHaveMaster)
        return true;
    int fd = open(L8KEYCHAIN_MASTER_PATH, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd >= 0) {
        struct stat st;
        ssize_t got = -1;
        /* A master the shim did not mint — wrong size, shared, or writable
         * by others — is treated as absent rather than trusted: failing to
         * read the key material is recoverable, decrypting under an
         * attacker-chosen one is not. */
        if (fstat(fd, &st) == 0 && S_ISREG(st.st_mode) &&
            (st.st_uid == 0 || st.st_uid == geteuid()) &&
            (st.st_mode & (S_IRWXG | S_IRWXO)) == 0 &&
            st.st_size == (off_t)sizeof(gMaster)) {
            got = read(fd, gMaster, sizeof(gMaster));
        }
        close(fd);
        if (got == (ssize_t)sizeof(gMaster)) {
            gHaveMaster = true;
            return true;
        }
        syslog(LOG_ERR, "l8keychain: existing master key is not trustworthy");
        return false;
    }

    int ur = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (ur < 0)
        return false;
    ssize_t got = read(ur, gMaster, sizeof(gMaster));
    close(ur);
    if (got != (ssize_t)sizeof(gMaster))
        return false;
    fd = open(L8KEYCHAIN_MASTER_PATH,
              O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
              S_IRUSR | S_IWUSR);
    if (fd < 0)
        return false;
    ssize_t put = write(fd, gMaster, sizeof(gMaster));
    if (put == (ssize_t)sizeof(gMaster))
        put = fsync(fd) == 0 ? (ssize_t)sizeof(gMaster) : -1;
    close(fd);
    if (put != (ssize_t)sizeof(gMaster))
        return false;
    gHaveMaster = true;
    syslog(LOG_NOTICE, "l8keychain: minted a new software master key");
    return true;
}

static bool class_key(int keyclass, uint8_t out[32])
{
    pthread_mutex_lock(&gMasterLock);
    bool ok = load_master_locked();
    pthread_mutex_unlock(&gMasterLock);
    if (!ok)
        return false;
    char label[48];
    int n = snprintf(label, sizeof(label), "l8kc-class-%d", keyclass);
    if (n <= 0 || (size_t)n >= sizeof(label))
        return false;
    /* The mac key is a distinct derivation so ciphertext and header never
     * share a key. */
    CCHmac(kCCHmacAlgSHA256, gMaster, sizeof(gMaster), label, (size_t)n, out);
    return true;
}

static void mac_key(uint8_t out[32])
{
    uint8_t master[32];
    pthread_mutex_lock(&gMasterLock);
    (void)load_master_locked();
    memcpy(master, gMaster, sizeof(master));
    pthread_mutex_unlock(&gMasterLock);
    CCHmac(kCCHmacAlgSHA256, master, sizeof(master), "l8kc-mac", 8, out);
}

/* ------------------------------------------------------------------ */
/* Blob helpers                                                        */
/* ------------------------------------------------------------------ */

static size_t blob_length_for(size_t plaintext_len)
{
    return (size_t)kBlobHeader + kBlobNonce + plaintext_len + kBlobMac;
}

static bool blob_parse(const uint8_t *blob, size_t blob_len, int keyclass,
                       const uint8_t **nonce, const uint8_t **ct,
                       size_t *ct_len, const uint8_t **mac)
{
    size_t needed = blob_length_for(0);
    if (blob_len < needed)
        return false;
    if (memcmp(blob, "L8KC", 4) != 0 || blob[4] != L8KC_VERSION)
        return false;
    if (blob[5] != (uint8_t)keyclass)
        return false;
    size_t body = blob_len - kBlobHeader - kBlobNonce - kBlobMac;
    if (body == 0)
        return false;
    *nonce = blob + kBlobHeader;
    *ct = blob + kBlobHeader + kBlobNonce;
    *ct_len = body;
    *mac = blob + kBlobHeader + kBlobNonce + body;
    return true;
}

/* ------------------------------------------------------------------ */
/* Replacements                                                        */
/* ------------------------------------------------------------------ */

extern kern_return_t aks_wrap_key(const void *source, int source_len,
                                  int keyclass, int keybag, void *out_buf,
                                  int *dest_len, int *actual_class);
extern kern_return_t aks_unwrap_key(const void *source, int source_len,
                                    int keyclass, int keybag, void *out_buf,
                                    int *dest_len);

/* The interposer calls the replacee only for requests it declines, and the
 * software path never re-enters AKS, so there is no re-entrancy guard here:
 * unlike l8wifi, nothing inside the software path reaches the replaced
 * entry points. */

static kern_return_t l8_aks_wrap_key(const void *source, int source_len,
                                     int keyclass, int keybag, void *out_buf,
                                     int *dest_len, int *actual_class)
{
    if (!request_is_ours(keyclass, keybag, source, source_len, out_buf,
                         dest_len)) {
        return aks_wrap_key(source, source_len, keyclass, keybag, out_buf,
                            dest_len, actual_class);
    }

    uint8_t key[32];
    uint8_t mk[32];
    if (!class_key(keyclass, key) || (mac_key(mk), false)) {
        syslog(LOG_ERR, "l8keychain: master key unavailable for wrap");
        return aks_wrap_key(source, source_len, keyclass, keybag, out_buf,
                            dest_len, actual_class);
    }

    size_t blob_len = blob_length_for((size_t)source_len);
    /* Capacity gate before the final memcpy: the L8KC envelope is
     * source_len + 56 bytes and the request gate only checked dest_len for
     * non-NULL. A caller that sizes its buffer for the raw source would be
     * overrun here. Pass through so the write fails honestly instead of
     * corrupting the caller. */
    if (*dest_len < (int)blob_len) {
        syslog(LOG_ERR,
               "l8keychain: wrap destination too small for class %d (%d < %zu)",
               keyclass, *dest_len, blob_len);
        return aks_wrap_key(source, source_len, keyclass, keybag, out_buf,
                            dest_len, actual_class);
    }
    uint8_t *blob = malloc(blob_len);
    if (blob == NULL)
        return aks_wrap_key(source, source_len, keyclass, keybag, out_buf,
                            dest_len, actual_class);

    memcpy(blob, "L8KC", 4);
    blob[4] = L8KC_VERSION;
    blob[5] = (uint8_t)keyclass;
    blob[6] = 0;
    blob[7] = 0;
    arc4random_buf(blob + kBlobHeader, kBlobNonce);
    if (!soft_crypt(true, key, blob + kBlobHeader, source,
                    (size_t)source_len, blob + kBlobHeader + kBlobNonce)) {
        free(blob);
        return aks_wrap_key(source, source_len, keyclass, keybag, out_buf,
                            dest_len, actual_class);
    }
    size_t ct_off = kBlobHeader + kBlobNonce;
    blob_mac(mk, blob, ct_off, blob + ct_off, blob_len - ct_off - kBlobMac,
             blob + blob_len - kBlobMac);

    memcpy(out_buf, blob, blob_len);
    free(blob);
    *dest_len = (int)blob_len;
    if (actual_class != NULL)
        *actual_class = keyclass;
    syslog(LOG_NOTICE, "l8keychain: wrapped class %d, %d -> %zu bytes",
           keyclass, source_len, blob_len);
    return 0;
}

static kern_return_t l8_aks_unwrap_key(const void *source, int source_len,
                                       int keyclass, int keybag,
                                       void *out_buf, int *dest_len)
{
    if (!request_is_ours(keyclass, keybag, source, source_len, out_buf,
                         dest_len)) {
        return aks_unwrap_key(source, source_len, keyclass, keybag, out_buf,
                              dest_len);
    }

    const uint8_t *nonce;
    const uint8_t *ct;
    size_t ct_len;
    const uint8_t *mac;
    if (!blob_parse(source, (size_t)source_len, keyclass, &nonce, &ct,
                    &ct_len, &mac)) {
        /* Not one of ours: an AKS blob from a previous life, a zero-filled
         * row, or garbage. The real unwrap owns it and fails it honestly. */
        return aks_unwrap_key(source, source_len, keyclass, keybag, out_buf,
                              dest_len);
    }

    uint8_t mk[32];
    mac_key(mk);
    uint8_t want[32];
    blob_mac(mk, source, kBlobHeader + kBlobNonce, ct, ct_len, want);
    if (memcmp(want, mac, kBlobMac) != 0) {
        syslog(LOG_ERR, "l8keychain: HMAC check failed for class %d",
               keyclass);
        return kAKSStatusDrop;
    }

    if (*dest_len < (int)ct_len) {
        syslog(LOG_ERR,
               "l8keychain: destination too small for class %d (%d < %zu)",
               keyclass, *dest_len, ct_len);
        return kAKSStatusDrop;
    }

    uint8_t key[32];
    if (!class_key(keyclass, key))
        return kAKSStatusDrop;
    if (!soft_crypt(false, key, nonce, ct, ct_len, out_buf))
        return kAKSStatusDrop;
    *dest_len = (int)ct_len;
    syslog(LOG_NOTICE, "l8keychain: unwrapped class %d, %d -> %d bytes",
           keyclass, source_len, *dest_len);
    return 0;
}

__attribute__((constructor)) static void l8keychain_loaded(void)
{
    if (!is_securityd())
        return;
    syslog(LOG_NOTICE, "l8keychain: software class-key shim loaded (%s)",
           shim_enabled() ? "enabled" : "marker absent, dormant");
}

DYLD_INTERPOSE(l8_aks_wrap_key, aks_wrap_key)
DYLD_INTERPOSE(l8_aks_unwrap_key, aks_unwrap_key)
