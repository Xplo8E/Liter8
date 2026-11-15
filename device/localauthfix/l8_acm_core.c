#include "l8_acm_core.h"

#include <CommonCrypto/CommonCrypto.h>
#include <stdlib.h>
#include <string.h>

static void l8_sha256(const void *data, size_t len, uint8_t out[CC_SHA256_DIGEST_LENGTH]) {
    CC_SHA256(data, (CC_LONG)len, out);
}

/* HKDF-SHA256 (RFC 5869) with a single output block of want_len bytes; the
 * two derived keys never need more than one expand round. */
static void l8_hkdf_sha256(const uint8_t master[L8_ACM_MASTER_LEN],
                           const uint8_t salt[CC_SHA256_DIGEST_LENGTH],
                           const char *info, size_t info_len,
                           uint8_t *out, size_t want_len) {
    uint8_t prk[CC_SHA256_DIGEST_LENGTH];
    uint8_t block[CC_SHA256_DIGEST_LENGTH];
    size_t info_full = info_len + 1;
    uint8_t *t_input = malloc(info_full);

    if (t_input == NULL) {
        memset(out, 0, want_len);
        return;
    }
    /* extract: PRK = HMAC-SHA256(salt, IKM) */
    CCHmac(kCCHmacAlgSHA256, salt, CC_SHA256_DIGEST_LENGTH, master, L8_ACM_MASTER_LEN, prk);
    /* expand round 1: T(1) = HMAC(PRK, info || 0x01) */
    memcpy(t_input, info, info_len);
    t_input[info_len] = 0x01;
    CCHmac(kCCHmacAlgSHA256, prk, CC_SHA256_DIGEST_LENGTH, t_input, info_full, block);
    memcpy(out, block, want_len < CC_SHA256_DIGEST_LENGTH ? want_len : CC_SHA256_DIGEST_LENGTH);

    memset(prk, 0, sizeof prk);
    memset(block, 0, sizeof block);
    free(t_input);
}

static void l8_derive_keys(const uint8_t master[L8_ACM_MASTER_LEN],
                           const void *seed, size_t seed_len,
                           const void *ctx, size_t ctx_len,
                           uint8_t key_enc[32], uint8_t key_mac[32]) {
    uint8_t salt[CC_SHA256_DIGEST_LENGTH];
    size_t bound = seed_len + ctx_len;
    uint8_t *bound_buf = malloc(bound ? bound : 1);
    if (bound_buf == NULL) {
        memset(key_enc, 0, 32);
        memset(key_mac, 0, 32);
        return;
    }
    if (seed_len) memcpy(bound_buf, seed, seed_len);
    if (ctx_len) memcpy(bound_buf + seed_len, ctx, ctx_len);
    l8_sha256(bound_buf, bound, salt);
    free(bound_buf);

    l8_hkdf_sha256(master, salt, "l8acm-enc", 9, key_enc, 32);
    l8_hkdf_sha256(master, salt, "l8acm-mac", 9, key_mac, 32);
    memset(salt, 0, sizeof salt);
}

/* MAC input: header || len64(seed) || seed || len64(ctx) || ctx || ct.
 * The length prefixes keep the seed/context binding unambiguous. Built as one
 * concatenated buffer so the one-shot CCHmac covers it. */
static int l8_compute_mac(const uint8_t key_mac[32], const uint8_t *header,
                          size_t header_len, const void *seed, size_t seed_len,
                          const void *ctx, size_t ctx_len, const uint8_t *ct,
                          size_t ct_len, uint8_t mac[L8_ACM_MAC_LEN]) {
    size_t input_len = header_len + 8 + seed_len + 8 + ctx_len + ct_len;
    uint8_t *input = malloc(input_len ? input_len : 1);
    if (input == NULL) return -1;
    size_t at = 0;
    memcpy(input + at, header, header_len);
    at += header_len;
    for (int i = 0; i < 8; i++) input[at + i] = (uint8_t)(seed_len >> (8 * (7 - i)));
    at += 8;
    if (seed_len) memcpy(input + at, seed, seed_len);
    at += seed_len;
    for (int i = 0; i < 8; i++) input[at + i] = (uint8_t)(ctx_len >> (8 * (7 - i)));
    at += 8;
    if (ctx_len) memcpy(input + at, ctx, ctx_len);
    at += ctx_len;
    if (ct_len) memcpy(input + at, ct, ct_len);
    at += ct_len;

    CCHmac(kCCHmacAlgSHA256, key_mac, 32, input, at, mac);
    memset(input, 0, input_len);
    free(input);
    return 0;
}

static int l8_ctr_xor(const uint8_t key[32], const uint8_t nonce[L8_ACM_NONCE_LEN],
                      const uint8_t *in, size_t len, uint8_t *out) {
    CCCryptorRef cryptor = NULL;
    size_t moved = 0;
    if (CCCryptorCreateWithMode(kCCEncrypt, kCCModeCTR, kCCAlgorithmAES, ccNoPadding,
                                nonce, key, 32, NULL, 0, 0, 0,
                                &cryptor) != kCCSuccess) {
        return -1;
    }
    if (len) {
        if (CCCryptorUpdate(cryptor, in, len, out, len, &moved) != kCCSuccess ||
            moved != len) {
            CCCryptorRelease(cryptor);
            return -1;
        }
    }
    CCCryptorRelease(cryptor);
    return 0;
}

int l8_acm_core_is_our_blob(const void *blob, size_t blob_len) {
    return blob != NULL && blob_len >= L8_ACM_HEADER_LEN + L8_ACM_MAC_LEN &&
           memcmp(blob, "L8CM", 4) == 0 && ((const uint8_t *)blob)[4] == 0x01;
}

int l8_acm_core_encode(const uint8_t master[L8_ACM_MASTER_LEN],
                       const void *seed, size_t seed_len,
                       const void *ctx, size_t ctx_len,
                       const void *data, size_t data_len,
                       uint8_t **out, size_t *out_len) {
    uint8_t key_enc[32], key_mac[32];
    size_t blob_len = L8_ACM_HEADER_LEN + data_len + L8_ACM_MAC_LEN;
    uint8_t *blob = malloc(blob_len ? blob_len : 1);
    if (blob == NULL) return -1;

    l8_derive_keys(master, seed, seed_len, ctx, ctx_len, key_enc, key_mac);
    memcpy(blob, "L8CM", 4);
    blob[4] = 0x01;
    memset(blob + 5, 0, 3);
    for (int i = 0; i < L8_ACM_NONCE_LEN; i++) {
        blob[L8_ACM_HEADER_LEN - L8_ACM_NONCE_LEN + i] = (uint8_t)arc4random();
    }
    if (l8_ctr_xor(key_enc, blob + L8_ACM_HEADER_LEN - L8_ACM_NONCE_LEN,
                   data, data_len, blob + L8_ACM_HEADER_LEN) != 0) {
        memset(blob, 0, blob_len);
        free(blob);
        memset(key_enc, 0, sizeof key_enc);
        memset(key_mac, 0, sizeof key_mac);
        return -1;
    }
    int rc = l8_compute_mac(key_mac, blob, L8_ACM_HEADER_LEN, seed, seed_len,
                            ctx, ctx_len, blob + L8_ACM_HEADER_LEN, data_len,
                            blob + L8_ACM_HEADER_LEN + data_len);
    memset(key_enc, 0, sizeof key_enc);
    memset(key_mac, 0, sizeof key_mac);
    if (rc != 0) {
        memset(blob, 0, blob_len);
        free(blob);
        return -1;
    }
    *out = blob;
    *out_len = blob_len;
    return 0;
}

int l8_acm_core_decode(const uint8_t master[L8_ACM_MASTER_LEN],
                       const void *seed, size_t seed_len,
                       const void *ctx, size_t ctx_len,
                       const void *blob, size_t blob_len,
                       uint8_t **out, size_t *out_len) {
    if (!l8_acm_core_is_our_blob(blob, blob_len)) return -2;
    const uint8_t *b = blob;
    size_t ct_len = blob_len - L8_ACM_HEADER_LEN - L8_ACM_MAC_LEN;

    uint8_t key_enc[32], key_mac[32], mac[L8_ACM_MAC_LEN];
    l8_derive_keys(master, seed, seed_len, ctx, ctx_len, key_enc, key_mac);
    int rc = l8_compute_mac(key_mac, b, L8_ACM_HEADER_LEN, seed, seed_len,
                            ctx, ctx_len, b + L8_ACM_HEADER_LEN, ct_len, mac);
    if (rc != 0) {
        memset(key_enc, 0, sizeof key_enc);
        memset(key_mac, 0, sizeof key_mac);
        return -1;
    }
    int ok = 1;
    for (int i = 0; i < L8_ACM_MAC_LEN; i++) {
        ok &= (mac[i] == b[L8_ACM_HEADER_LEN + ct_len + i]);
    }
    memset(key_mac, 0, sizeof key_mac);
    memset(mac, 0, sizeof mac);
    if (!ok) {
        memset(key_enc, 0, sizeof key_enc);
        return -3;
    }

    uint8_t *plain = malloc(ct_len ? ct_len : 1);
    if (plain == NULL) {
        memset(key_enc, 0, sizeof key_enc);
        return -1;
    }
    if (l8_ctr_xor(key_enc, b + L8_ACM_HEADER_LEN - L8_ACM_NONCE_LEN,
                   b + L8_ACM_HEADER_LEN, ct_len, plain) != 0) {
        memset(key_enc, 0, sizeof key_enc);
        memset(plain, 0, ct_len);
        free(plain);
        return -1;
    }
    memset(key_enc, 0, sizeof key_enc);
    *out = plain;
    *out_len = ct_len;
    return 0;
}
