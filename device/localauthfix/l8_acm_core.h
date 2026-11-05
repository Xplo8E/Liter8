/*
 * l8_acm_core - the software credential crypto behind the LACACMHelper
 * encode/decode swizzles.
 *
 * The SEP-less boot cannot answer ACMEncryptDataEx/ACMDecryptDataEx (status
 * -3: no SEP to hold the credential context), so the shim replaces the
 * credential crypto with its own: a length-prefixed, MAC'd, AES-CTR blob that
 * binds the caller's seed and ACM externalized context into the
 * authentication tag, so a blob produced for one (seed, context) pair fails
 * verification when presented under another.
 *
 * Blob format ("L8CM", version 1):
 *   magic[4]  = "L8CM"
 *   ver[1]    = 0x01
 *   flags[3]  = 0
 *   nonce[16] = CTR start counter (random per blob)
 *   ct[.]     = AES-256-CTR(key_enc, nonce, plaintext)
 *   mac[32]   = HMAC-SHA256(key_mac, magic || ver || flags || nonce ||
 *                           len64(seed) || seed || len64(ctx) || ctx || ct)
 *
 * Key separation: HKDF-SHA256 over the 32-byte master key with
 * salt = SHA256(seed || ctx) and two info labels, so the encryption and
 * authentication keys never coincide and neither depends on the master alone.
 */
#ifndef L8_ACM_CORE_H
#define L8_ACM_CORE_H

#include <stddef.h>
#include <stdint.h>

#define L8_ACM_MASTER_LEN 32
#define L8_ACM_NONCE_LEN 16
#define L8_ACM_MAC_LEN 32
#define L8_ACM_HEADER_LEN 24 /* magic(4) + ver(1) + flags(3) + nonce(16) */

/* out receives a malloc'd buffer the caller frees; *out_len is the total
 * blob length. Returns 0 on success, -1 on allocation failure. */
int l8_acm_core_encode(const uint8_t master[L8_ACM_MASTER_LEN],
                       const void *seed, size_t seed_len,
                       const void *ctx, size_t ctx_len,
                       const void *data, size_t data_len,
                       uint8_t **out, size_t *out_len);

/* Authenticates and decrypts a blob produced by l8_acm_core_encode. out
 * receives a malloc'd buffer the caller frees (plaintext, data_len long on
 * success). Returns 0 ok, -1 allocation failure, -2 not our blob (magic or
 * version mismatch), -3 authentication failure. */
int l8_acm_core_decode(const uint8_t master[L8_ACM_MASTER_LEN],
                       const void *seed, size_t seed_len,
                       const void *ctx, size_t ctx_len,
                       const void *blob, size_t blob_len,
                       uint8_t **out, size_t *out_len);

int l8_acm_core_is_our_blob(const void *blob, size_t blob_len);

#endif
