#!/bin/bash
# Host self-test for the l8keychain interposer: blob round-trip through the
# real replacement functions, gate behavior (marker, progname, keybag,
# keyclass), HMAC-failure handling, and the pass-through wiring to stub
# replacees. Everything runs against temporary paths via the compiled-in
# override macros; no device needed. Compile errors are NOT masked: no
# pipelines on the compile command.
set -e
cd "$(dirname "$0")"
OUT="${OUT:-/tmp/l8kc-hosttest}"

cat > .host-test-main.c <<'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* The test defines the "real" replacees so pass-through is observable: any
 * call that reaches here was declined by the shim, and the stub reports it
 * through a flag the assertions check. */
int stub_hits = 0;

int aks_wrap_key(const void *source, int source_len, int keyclass,
                 int keybag, void *out_buf, int *dest_len, int *actual_class)
{
    (void)source; (void)source_len; (void)keyclass; (void)keybag;
    (void)out_buf; (void)dest_len; (void)actual_class;
    stub_hits++;
    return 0xe00002f0; /* what the real one returns with no key available */
}

int aks_unwrap_key(const void *source, int source_len, int keyclass,
                   int keybag, void *out_buf, int *dest_len)
{
    (void)source; (void)source_len; (void)keyclass; (void)keybag;
    (void)out_buf; (void)dest_len;
    stub_hits++;
    return 0xe00002f0;
}

/* The shim's declarations must bind to these stubs. */
#include "l8keychain.m"

static int failures;

static void check(const char *what, int condition)
{
    printf("%-52s %s\n", what, condition ? "ok" : "FAIL");
    if (!condition)
        failures++;
}

int main(void)
{
    const uint8_t secret[40] = "photo library gate would store this much";
    uint8_t out[512];
    int dest_len;
    int actual_class;
    int rc;

    /* Off by default: the marker files do not exist in the sandbox. */
    dest_len = (int)sizeof(out);
    rc = l8_aks_wrap_key(secret, 40, 6, 0, out, &dest_len, &actual_class);
    check("dormant without marker (pass-through)", stub_hits == 1 && rc == 0xe00002f0);

    /* Create the enable marker. */
    FILE *f = fopen(L8KEYCHAIN_MARKER_DATA, "w");
    check("marker creatable", f != NULL);
    if (f) fclose(f);

    stub_hits = 0;
    dest_len = (int)sizeof(out);
    rc = l8_aks_wrap_key(secret, 40, 6, 0, out, &dest_len, &actual_class);
    check("wrap class 6 succeeds", rc == 0);
    check("wrap reports blob length", dest_len == (int)blob_length_for(40));
    check("wrap sets actual_class", actual_class == 6);
    check("wrap carries L8KC magic", dest_len > 24 && memcmp(out, "L8KC", 4) == 0);
    check("wrap carries class byte", out[5] == 6);
    check("wrap is not plaintext", memcmp(out + 24, secret, 8) != 0);

    uint8_t back[512];
    int back_len = (int)sizeof(back);
    rc = l8_aks_unwrap_key(out, dest_len, 6, 0, back, &back_len);
    check("unwrap round-trips", rc == 0 && back_len == 40 && memcmp(back, secret, 40) == 0);

    /* A second wrap of the same plaintext must decrypt to the same bytes
     * under a fresh nonce, and the two blobs must differ. */
    uint8_t out2[512];
    int dest_len2 = (int)sizeof(out2);
    rc = l8_aks_unwrap_key(out, dest_len, 6, 0, back, &back_len);
    rc = l8_aks_wrap_key(secret, 40, 6, 0, out2, &dest_len2, &actual_class);
    check("fresh nonce makes distinct blob", dest_len == dest_len2 && memcmp(out, out2, (size_t)dest_len) != 0);
    check("second blob unwraps too",
          l8_aks_unwrap_key(out2, dest_len2, 6, 0, back, &back_len) == 0 &&
          back_len == 40 && memcmp(back, secret, 40) == 0);

    /* Metadata class shares the mechanism. */
    uint8_t meta[256];
    int meta_len = (int)sizeof(meta);
    rc = l8_aks_wrap_key(secret, 40, 39, 0, meta, &meta_len, &actual_class);
    check("wrap class 39 (metadata) succeeds", rc == 0 && meta_len == (int)blob_length_for(40));
    back_len = (int)sizeof(back);
    rc = l8_aks_unwrap_key(meta, meta_len, 39, 0, back, &back_len);
    check("unwrap class 39 round-trips", rc == 0 && back_len == 40);

    /* Class 7 (ck): the class wifid's AirPort password add actually uses
     * (measured on device 2026-11-04), and class 10 (cku). */
    uint8_t ck[256];
    int ck_len = (int)sizeof(ck);
    rc = l8_aks_wrap_key(secret, 40, 7, 0, ck, &ck_len, &actual_class);
    check("wrap class 7 (ck, Wi-Fi) succeeds", rc == 0 && ck_len == (int)blob_length_for(40));
    back_len = (int)sizeof(back);
    rc = l8_aks_unwrap_key(ck, ck_len, 7, 0, back, &back_len);
    check("unwrap class 7 round-trips", rc == 0 && back_len == 40 && memcmp(back, secret, 40) == 0);
    uint8_t cku[256];
    int cku_len = (int)sizeof(cku);
    rc = l8_aks_wrap_key(secret, 40, 10, 0, cku, &cku_len, &actual_class);
    check("wrap class 10 (cku) succeeds", rc == 0);
    back_len = (int)sizeof(back);
    rc = l8_aks_unwrap_key(cku, cku_len, 10, 0, back, &back_len);
    check("unwrap class 10 round-trips", rc == 0 && back_len == 40);

    /* A class-7 blob does not unwrap as class 6: cross-class stays a
     * pass-through for every served class, not only the old two. */
    stub_hits = 0;
    back_len = (int)sizeof(back);
    rc = l8_aks_unwrap_key(ck, ck_len, 6, 0, back, &back_len);
    check("cross-class 7->6 unwrap passes through", stub_hits == 1 && rc == 0xe00002f0);

    /* Cross-class unwrap is a pass-through: a class-6 blob does not belong
     * to class 39, and the shim must not silently cross-decrypt. */
    stub_hits = 0;
    back_len = (int)sizeof(back);
    rc = l8_aks_unwrap_key(out, dest_len, 39, 0, back, &back_len);
    check("cross-class unwrap passes through", stub_hits == 1 && rc == 0xe00002f0);

    /* A non-device keybag is never ours. */
    stub_hits = 0;
    dest_len = (int)sizeof(out);
    rc = l8_aks_wrap_key(secret, 40, 6, 3, out, &dest_len, &actual_class);
    check("non-device keybag passes through", stub_hits == 1 && rc == 0xe00002f0);

    /* An unknown class is never ours. 8 (dk) is a device-key class the
     * shim deliberately does not serve. */
    stub_hits = 0;
    dest_len = (int)sizeof(out);
    rc = l8_aks_wrap_key(secret, 40, 8, 0, out, &dest_len, &actual_class);
    check("unserved class 8 passes through", stub_hits == 1 && rc == 0xe00002f0);

    /* A blob with a corrupted MAC must fail, not decrypt. Re-wrap a fresh
     * class-6 blob first: the earlier tests reuse out as scratch. */
    dest_len = (int)sizeof(out);
    rc = l8_aks_wrap_key(secret, 40, 6, 0, out, &dest_len, &actual_class);
    check("fresh class-6 wrap for tamper test", rc == 0);
    out[dest_len - 1] ^= 0x40;
    back_len = (int)sizeof(back);
    rc = l8_aks_unwrap_key(out, dest_len, 6, 0, back, &back_len);
    check("tampered blob refuses to decrypt", rc == 0xe00002fc && back_len == (int)sizeof(back));

    /* A non-L8KC blob passes through (an AKS blob from a previous life). */
    stub_hits = 0;
    uint8_t legacy[64];
    memset(legacy, 0xAB, sizeof(legacy));
    back_len = (int)sizeof(back);
    rc = l8_aks_unwrap_key(legacy, (int)sizeof(legacy), 6, 0, back, &back_len);
    check("non-L8KC blob passes through", stub_hits == 1 && rc == 0xe00002f0);

    /* The oversize guard. */
    stub_hits = 0;
    dest_len = (int)sizeof(out);
    rc = l8_aks_wrap_key(out, L8KEYCHAIN_MAXIMUM_ITEM_BYTES + 1, 6, 0, out,
                         &dest_len, &actual_class);
    check("oversize item passes through", stub_hits == 1 && rc == 0xe00002f0);

    /* NULL args are declined, never dereferenced. */
    stub_hits = 0;
    rc = l8_aks_wrap_key(NULL, 40, 6, 0, out, &dest_len, &actual_class);
    check("NULL source declined", stub_hits == 1);

    remove(L8KEYCHAIN_MARKER_DATA);
    remove(L8KEYCHAIN_MASTER_PATH);

    if (failures) {
        printf("\n%d FAILURES\n", failures);
        return 1;
    }
    printf("\nall l8keychain host tests passed\n");
    return 0;
}
EOF

# The harness includes l8keychain.m with the override macros active: sandbox
# paths, host test target name, and interpose-as-nothing (the harness calls
# the replacements directly).
xcrun clang -arch arm64 \
    -D'DYLD_INTERPOSE(r,a)=' \
    "-DL8KEYCHAIN_MARKER_UID=$(id -u)" \
    -DL8KEYCHAIN_TARGET_PROGRAM='"securityd-host-test"' \
    -DL8KEYCHAIN_MARKER_SYSTEM='"/tmp/l8kc-sandbox/marker-system"' \
    -DL8KEYCHAIN_MARKER_DATA='"/tmp/l8kc-sandbox/marker-data"' \
    -DL8KEYCHAIN_MASTER_PATH='"/tmp/l8kc-sandbox/master"' \
    -o "$OUT" .host-test-main.c

mkdir -p /tmp/l8kc-sandbox
# getprogname() in the harness binary is the binary name; the shim checks
# against the overridden target name, so the binary must carry it.
cp "$OUT" "/tmp/l8kc-sandbox/securityd-host-test" 2>/dev/null || true
"/tmp/l8kc-sandbox/securityd-host-test"
rc=$?
rm -f "$OUT" "/tmp/l8kc-sandbox/securityd-host-test" .host-test-main.c
exit $rc
