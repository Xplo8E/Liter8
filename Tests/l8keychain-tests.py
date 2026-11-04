#!/usr/bin/env python3
"""Exercise the software keychain shim's decision contract on macOS.

l8keychain is built for iOS and loaded into securityd on the device, so the
behaviour that matters here is the decision logic: which keychain classes
and keybag handles the shim claims, which calls it leaves to the real
AppleKeyStore client, and what it does while the marker is absent. Those
decisions are compiled from the real source rather than reimplemented, so a
change to l8keychain.m that widens or narrows the contract fails here.

The shim source is included directly so its replacements can be called
without dyld interposition, which does not fire for symbols defined in the
same image. The two aks_* entry points it would call on a device are
defined here as probes, so a pass-through is observable.

The marker, the master-key path and the target program name are compiled in
as overrides, so the test never touches a device path and can present
itself as the shim's host process.
"""
import pathlib
import subprocess
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
SRC = ROOT / "device/keychainprobe"

HARNESS = r"""
#include <CommonCrypto/CommonCrypto.h>
#include <stdio.h>
#include <string.h>

/* The probes stand in for the real AppleKeyStore client. A shim that
 * passes a call through lands here; a shim that claims the call does not. */
int probe_calls = 0;

int aks_wrap_key(const void *source, int source_len, int keyclass,
                 int keybag, void *out_buf, int *dest_len, int *actual_class)
{
    (void)source; (void)source_len; (void)keyclass; (void)keybag;
    (void)out_buf; (void)dest_len; (void)actual_class;
    probe_calls++;
    return 0xe00002f0;
}

int aks_unwrap_key(const void *source, int source_len, int keyclass,
                   int keybag, void *out_buf, int *dest_len)
{
    (void)source; (void)source_len; (void)keyclass; (void)keybag;
    (void)out_buf; (void)dest_len;
    probe_calls++;
    return 0xe00002f0;
}

/* The shim's interpose tuples are not wanted here: its functions are called
 * directly, and the tuples would only rebind the probe. */
#define DYLD_INTERPOSE(_replacement, _replacee)

#include "l8keychain.m"

static int failures = 0;

static void check(const char *what, int condition) {
    printf("%-52s %s\n", what, condition ? "ok" : "FAIL");
    if (!condition) failures++;
}

int main(void) {
    const unsigned char secret[] = "liter8 keychain milestone payload";
    unsigned char out[256];
    int out_len = (int)sizeof(out);
    int actual_class = 0;
    int rc;

    /* Dormant without the marker: everything passes through. */
    rc = l8_aks_wrap_key(secret, 32, 6, 0, out, &out_len, &actual_class);
    check("dormant without marker passes through",
          probe_calls == 1 && (unsigned)rc == 0xe00002f0u);

    FILE *f = fopen(L8KEYCHAIN_MARKER_SYSTEM, "w");
    check("marker creatable", f != NULL);
    if (f) fclose(f);

    /* A world-writable marker must not enable the shim: an unprivileged
     * process could otherwise turn it on. */
    chmod(L8KEYCHAIN_MARKER_SYSTEM, 0666);

    probe_calls = 0;
    rc = l8_aks_wrap_key(secret, 32, 6, 0, out, &out_len, &actual_class);
    check("world-writable marker ignored",
          probe_calls == 1 && (unsigned)rc == 0xe00002f0u);

    /* A directory must not enable the shim either. */
    remove(L8KEYCHAIN_MARKER_SYSTEM);
    mkdir(L8KEYCHAIN_MARKER_SYSTEM, 0777);
    probe_calls = 0;
    rc = l8_aks_wrap_key(secret, 32, 6, 0, out, &out_len, &actual_class);
    check("directory marker ignored", probe_calls == 1 && (unsigned)rc == 0xe00002f0u);
    rmdir(L8KEYCHAIN_MARKER_SYSTEM);

    /* A regular marker owned by this user enables the shim (on the device
     * the requirement is root; the sandbox test runs unprivileged). */
    f = fopen(L8KEYCHAIN_MARKER_SYSTEM, "w");
    if (f) fclose(f);

    rc = l8_aks_wrap_key(secret, 32, 6, 0, out, &out_len, &actual_class);
    check("wrap class 6 succeeds",
          rc == 0 && out_len == (int)blob_length_for(32) && actual_class == 6);
    check("wrap carries L8KC magic", out_len > 24 && memcmp(out, "L8KC", 4) == 0);
    check("wrap class byte", out[5] == 6);

    unsigned char back[256];
    int back_len = (int)sizeof(back);
    rc = l8_aks_unwrap_key(out, out_len, 6, 0, back, &back_len);
    check("unwrap round-trips",
          rc == 0 && back_len == 32 && memcmp(back, secret, 32) == 0);

    /* A second wrap uses a fresh nonce, so blobs differ but both unwrap. */
    unsigned char out2[256];
    int out2_len = (int)sizeof(out2);
    rc = l8_aks_wrap_key(secret, 32, 6, 0, out2, &out2_len, &actual_class);
    check("fresh nonce makes distinct blob",
          out2_len == out_len && memcmp(out, out2, (size_t)out_len) != 0);
    back_len = (int)sizeof(back);
    rc = l8_aks_unwrap_key(out2, out2_len, 6, 0, back, &back_len);
    check("second blob unwraps",
          rc == 0 && back_len == 32 && memcmp(back, secret, 32) == 0);

    /* Tamper the MAC: refuse, do not decrypt. */
    out[out_len - 1] ^= 0x40;
    back_len = (int)sizeof(back);
    rc = l8_aks_unwrap_key(out, out_len, 6, 0, back, &back_len);
    check("tampered blob refuses", (unsigned)rc == (unsigned)kAKSStatusDrop);

    /* Cross-class unwrap passes through: a class-6 blob does not belong to
     * class 39, and the shim must not silently cross-decrypt. */
    probe_calls = 0;
    back_len = (int)sizeof(back);
    rc = l8_aks_unwrap_key(out, out_len, 39, 0, back, &back_len);
    check("cross-class unwrap passes through",
          probe_calls == 1 && (unsigned)rc == 0xe00002f0u);

    /* A foreign keybag handle is never ours. */
    probe_calls = 0;
    out_len = (int)sizeof(out);
    rc = l8_aks_wrap_key(secret, 32, 6, 3, out, &out_len, &actual_class);
    check("foreign keybag passes through",
          probe_calls == 1 && (unsigned)rc == 0xe00002f0u);

    /* An unserved class passes through (8 dk is a device-key class the
     * shim deliberately does not serve). */
    probe_calls = 0;
    out_len = (int)sizeof(out);
    rc = l8_aks_wrap_key(secret, 32, 8, 0, out, &out_len, &actual_class);
    check("unserved class 8 passes through",
          probe_calls == 1 && (unsigned)rc == 0xe00002f0u);

    remove(L8KEYCHAIN_MARKER_SYSTEM);
    remove(L8KEYCHAIN_MASTER_PATH);

    if (failures) {
        printf("\n%d FAILURES\n", failures);
        return 1;
    }
    printf("all l8keychain decision-contract checks passed\n");
    return 0;
}
"""


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="l8-keychain-") as work:
        work = pathlib.Path(work)
        marker = work / "marker"
        master = work / "master.key"

        harness_c = work / "harness.c"
        harness_c.write_text(HARNESS)

        flags = [
            "-Wall", "-Wextra", "-Werror",
            f'-DL8KEYCHAIN_MARKER_SYSTEM="{marker}"',
            # The Data-volume legacy marker is never created in the sandbox,
            # so only the System marker gates the shim in this test.
            '-DL8KEYCHAIN_MARKER_DATA="/nonexistent"',
            # The test binary presents itself as keybagd so the process gate
            # opens.
            '-DL8KEYCHAIN_TARGET_PROGRAM="keybagdtest"',
            # The marker must be root-owned on the device. The test runs as
            # an ordinary user, so the required owner is this user instead.
            "-DL8KEYCHAIN_MARKER_UID=geteuid()",
            "-I", str(SRC),
        ]

        binary = work / "keybagdtest"
        subprocess.run([
            "xcrun", "clang", *flags,
            f'-DL8KEYCHAIN_MASTER_PATH="{master}"',
            str(harness_c),
            "-framework", "CoreFoundation",
            "-o", str(binary),
        ], check=True)

        result = subprocess.run([str(binary)], capture_output=True, text=True)
        if result.returncode != 0:
            raise SystemExit(f"FAIL\n{result.stdout}{result.stderr}")


if __name__ == "__main__":
    main()
