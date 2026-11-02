#!/usr/bin/env python3
"""Exercise the AirPort credential shim's query contract on macOS.

The shim is built for iOS and injected into wifid on the device, so the
behaviour that matters here is the decision logic: which keychain item the
shim claims, which it leaves alone, and what it does while it is disabled.
Those decisions are compiled from the real source rather than reimplemented,
so a change to l8wifi.c that widens or narrows the contract fails here.

The shim source is included directly so its functions can be called without
dyld interposition, which does not fire for a symbol defined in the same
image. The four SecItem entry points it would call on a device are defined
here as a probe, so a pass-through is observable.

The marker path, the store path and the target program name are compiled in
as overrides, so the test never touches a device path and can present itself
as wifid.
"""
import pathlib
import plistlib
import shutil
import subprocess
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
SRC = ROOT / "device/wififix"

HARNESS = r"""
#include <Security/Security.h>
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>

/* The probe stands in for the real keychain. A shim that passes a call
 * through lands here; a shim that claims the call does not. */
int probe_called_count = 0;

OSStatus SecItemCopyMatching(CFDictionaryRef query, CFTypeRef *result) {
    (void)query;
    probe_called_count++;
    if (result) { *result = NULL; }
    return errSecItemNotFound;
}

OSStatus SecItemAdd(CFDictionaryRef attributes, CFTypeRef *result) {
    (void)attributes;
    probe_called_count++;
    if (result) { *result = NULL; }
    return errSecSuccess;
}

OSStatus SecItemUpdate(CFDictionaryRef query, CFDictionaryRef updates) {
    (void)query;
    (void)updates;
    probe_called_count++;
    return errSecSuccess;
}

OSStatus SecItemDelete(CFDictionaryRef query) {
    (void)query;
    probe_called_count++;
    return errSecSuccess;
}

/* The shim's interpose tuples are not wanted here: its functions are called
 * directly, and the tuples would only rebind the probe. */
#define DYLD_INTERPOSE(_replacement, _replacee)

#include "l8wifi.c"

static int failures = 0;

static void fail(const char *message) {
    printf("FAIL: %s\n", message);
    failures++;
}

static CFStringRef cfstr(const char *name) {
    return CFStringCreateWithCString(NULL, name, kCFStringEncodingUTF8);
}

static CFDictionaryRef query_with(const char *svc, const char *acct,
                                  const char *cls, int want_data) {
    const void *keys[4];
    const void *values[4];
    int count = 0;
    if (svc) { keys[count] = kSecAttrService; values[count] = cfstr(svc); count++; }
    if (acct) { keys[count] = kSecAttrAccount; values[count] = cfstr(acct); count++; }
    if (cls) { keys[count] = kSecClass; values[count] = cfstr(cls); count++; }
    if (want_data) { keys[count] = kSecReturnData; values[count] = kCFBooleanTrue; count++; }
    return CFDictionaryCreate(NULL, keys, values, count,
                              &kCFTypeDictionaryKeyCallBacks,
                              &kCFTypeDictionaryValueCallBacks);
}

/* A query that asks for the attributes as well as the data. The keychain
 * answers that shape with a dictionary carrying the password inside it. */
static CFDictionaryRef query_with_attributes(const char *svc, const char *acct,
                                             const char *cls) {
    const void *keys[5];
    const void *values[5];
    int count = 0;
    keys[count] = kSecAttrService; values[count] = cfstr(svc); count++;
    keys[count] = kSecAttrAccount; values[count] = cfstr(acct); count++;
    if (cls) { keys[count] = kSecClass; values[count] = cfstr(cls); count++; }
    keys[count] = kSecReturnAttributes; values[count] = kCFBooleanTrue; count++;
    keys[count] = kSecReturnData; values[count] = kCFBooleanTrue; count++;
    return CFDictionaryCreate(NULL, keys, values, count,
                              &kCFTypeDictionaryKeyCallBacks,
                              &kCFTypeDictionaryValueCallBacks);
}

/* An add carries the same identifying attributes the item has, so the
 * service is present exactly as it is on the device. */
static CFDictionaryRef add_with(const char *acct, const char *password) {
    CFDataRef data = CFDataCreate(NULL, (const UInt8 *)password, (CFIndex)strlen(password));
    const void *keys[3] = {kSecValueData, kSecAttrAccount, kSecAttrService};
    const void *values[3] = {data, cfstr(acct), cfstr("AirPort")};
    return CFDictionaryCreate(NULL, keys, values, 3,
                              &kCFTypeDictionaryKeyCallBacks,
                              &kCFTypeDictionaryValueCallBacks);
}

/* The known-networks sweep: every AirPort record at once, with no account. */
static CFDictionaryRef enumerate_query(void) {
    const void *keys[4];
    const void *values[4];
    int count = 0;
    keys[count] = kSecAttrService; values[count] = cfstr("AirPort"); count++;
    keys[count] = kSecReturnAttributes; values[count] = kCFBooleanTrue; count++;
    keys[count] = kSecMatchLimit; values[count] = kSecMatchLimitAll; count++;
    return CFDictionaryCreate(NULL, keys, values, count,
                              &kCFTypeDictionaryKeyCallBacks,
                              &kCFTypeDictionaryValueCallBacks);
}

/* The same sweep against the system keychain. The constant is private, so it
 * is resolved the same way the shim resolves it. */
static CFTypeRef system_keychain_constant(void) {
    const CFTypeRef *address = (const CFTypeRef *)dlsym(RTLD_DEFAULT, "kSecUseSystemKeychain");
    return address != NULL ? *address : NULL;
}

static CFDictionaryRef enumerate_query_system(void) {
    const void *keys[5];
    const void *values[5];
    int count = 0;
    keys[count] = kSecAttrService; values[count] = cfstr("AirPort"); count++;
    keys[count] = kSecReturnAttributes; values[count] = kCFBooleanTrue; count++;
    keys[count] = kSecMatchLimit; values[count] = kSecMatchLimitAll; count++;
    keys[count] = system_keychain_constant(); values[count] = kCFBooleanTrue; count++;
    return CFDictionaryCreate(NULL, keys, values, count,
                              &kCFTypeDictionaryKeyCallBacks,
                              &kCFTypeDictionaryValueCallBacks);
}

/* An add that names the system keychain. */
static CFDictionaryRef add_with_system(const char *acct, const char *password) {
    CFDataRef data = CFDataCreate(NULL, (const UInt8 *)password, (CFIndex)strlen(password));
    const void *keys[4] = {kSecValueData, kSecAttrAccount, kSecAttrService,
                           system_keychain_constant()};
    const void *values[4] = {data, cfstr(acct), cfstr("AirPort"), kCFBooleanTrue};
    return CFDictionaryCreate(NULL, keys, values, 4,
                              &kCFTypeDictionaryKeyCallBacks,
                              &kCFTypeDictionaryValueCallBacks);
}

int main(int argc, char **argv) {
    const char *mode = argc > 1 ? argv[1] : "check";
    CFTypeRef result = NULL;
    OSStatus status;

    if (strcmp(mode, "check") == 0) {
        /* A different service must pass through to the real keychain. */
        probe_called_count = 0;
        CFDictionaryRef foreign = query_with("SomeOtherService", "acct", "genp", 1);
        status = l8_SecItemCopyMatching(foreign, &result);
        if (status != errSecItemNotFound || probe_called_count != 1) {
            fail("a foreign service must reach the real keychain");
        }

        /* The AirPort service with a different item class must pass through. */
        probe_called_count = 0;
        CFDictionaryRef other_class = query_with("AirPort", "acct", "inet", 1);
        result = NULL;
        l8_SecItemCopyMatching(other_class, &result);
        if (probe_called_count != 1) {
            fail("a non-generic-password AirPort item must not be intercepted");
        }

        /* An add must be stored by the shim and never reach the keychain. */
        probe_called_count = 0;
        CFDictionaryRef add = add_with("acct", "hunter2");
        result = NULL;
        status = l8_SecItemAdd(add, &result);
        if (status != errSecSuccess) {
            fail("adding an AirPort credential must succeed");
        }
        if (probe_called_count != 0) {
            fail("adding an AirPort credential must not reach the real keychain");
        }

        /* An AirPort generic-password item must be claimed by the shim, and
         * answered from its own store rather than the real keychain. */
        probe_called_count = 0;
        CFDictionaryRef ours = query_with_attributes("AirPort", "acct", "genp");
        result = NULL;
        status = l8_SecItemCopyMatching(ours, &result);
        if (probe_called_count != 0) {
            fail("an AirPort generic-password item must not reach the real keychain");
        }
        if (status == errSecItemNotFound) {
            fail("a stored AirPort credential must be returned, not reported missing");
        }
        if (result == NULL) {
            fail("the stored AirPort credential must carry data");
        } else {
            CFDictionaryRef attributes = (CFDictionaryRef)result;
            CFTypeRef data = CFDictionaryGetValue(attributes, kSecValueData);
            if (data == NULL || CFGetTypeID(data) != CFDataGetTypeID()) {
                fail("the returned credential must carry its password data");
            }
            CFTypeRef svc = CFDictionaryGetValue(attributes, kSecAttrService);
            if (svc == NULL || !CFEqual(svc, CFSTR("AirPort"))) {
                fail("the returned credential must report the AirPort service");
            }
            CFTypeRef cls = CFDictionaryGetValue(attributes, kSecClass);
            if (cls == NULL || !CFEqual(cls, kSecClassGenericPassword)) {
                fail("the returned credential must report the generic-password class");
            }
        }

        /* The added credential must read back from the shim's store. */
        CFDictionaryRef read_back = query_with("AirPort", "acct", "genp", 1);
        result = NULL;
        status = l8_SecItemCopyMatching(read_back, &result);
        if (status != errSecSuccess || result == NULL) {
            fail("the added credential must be readable back");
        }
        /* A data-only query answers with the password itself. */
        if (result != NULL && CFGetTypeID(result) != CFDataGetTypeID()) {
            fail("a data-only query must answer with the password data");
        }

        /* An unknown account must not resolve to another account's password. */
        CFDictionaryRef unknown = query_with("AirPort", "third", "genp", 1);
        result = NULL;
        status = l8_SecItemCopyMatching(unknown, &result);
        if (status == errSecSuccess) {
            fail("an unknown AirPort account must not resolve to a credential");
        }

        /* A record in the system keychain is a different record from the same
         * account in the user keychain. */
        CFDictionaryRef system_add = add_with_system("acct", "systempassword");
        result = NULL;
        status = l8_SecItemAdd(system_add, &result);
        if (status != errSecSuccess) {
            fail("adding a system-keychain AirPort credential must succeed");
        }

        /* The user-keychain enumeration must not return the system-keychain
         * record. */
        result = NULL;
        status = l8_SecItemCopyMatching(enumerate_query(), &result);
        if (status == errSecSuccess && result != NULL &&
            CFGetTypeID(result) == CFArrayGetTypeID()) {
            if (CFArrayGetCount((CFArrayRef)result) != 1) {
                fail("a user-keychain enumeration must not return system records");
            }
        }

        /* The system-keychain enumeration must return it. */
        result = NULL;
        status = l8_SecItemCopyMatching(enumerate_query_system(), &result);
        if (status != errSecSuccess || result == NULL ||
            CFGetTypeID(result) != CFArrayGetTypeID() ||
            CFArrayGetCount((CFArrayRef)result) != 1) {
            fail("a system-keychain enumeration must return the system record");
        }

        /* An enumeration must answer with the records of the keychain that was
         * asked for and no others. wifid asks for every AirPort record at once
         * when it lists known networks, and a record's system-keychain
         * selection is part of its identity, so the two must not be mixed. */
        CFDictionaryRef enumerate = enumerate_query();
        result = NULL;
        status = l8_SecItemCopyMatching(enumerate, &result);
        if (status != errSecSuccess || result == NULL) {
            fail("an AirPort enumeration must be answered from the shim's store");
        } else if (CFGetTypeID(result) != CFArrayGetTypeID()) {
            fail("an AirPort enumeration must answer with an array of records");
        } else {
            CFIndex count = CFArrayGetCount((CFArrayRef)result);
            if (count != 1) {
                fail("an AirPort enumeration must return only the records of that keychain");
            }
        }

        /* The stored credential belongs to the AirPort service and to the
         * generic-password class. The same account under another service, or
         * under another class, must not resolve to it. This is what catches
         * a filter that has been widened. */
        probe_called_count = 0;
        CFDictionaryRef wrong_service = query_with("SomeOtherService", "acct", "genp", 1);
        result = NULL;
        status = l8_SecItemCopyMatching(wrong_service, &result);
        if (status == errSecSuccess) {
            fail("a stored credential must not answer for another service");
        }
        if (probe_called_count != 1) {
            fail("another service must be left to the real keychain");
        }

        probe_called_count = 0;
        CFDictionaryRef wrong_class = query_with("AirPort", "acct", "inet", 1);
        result = NULL;
        status = l8_SecItemCopyMatching(wrong_class, &result);
        if (status == errSecSuccess) {
            fail("a stored credential must not answer for another item class");
        }
        if (probe_called_count != 1) {
            fail("another item class must be left to the real keychain");
        }

        /* A delete must remove the record without touching the keychain. */
        probe_called_count = 0;
        CFDictionaryRef delete_query = query_with("AirPort", "acct", "genp", 0);
        status = l8_SecItemDelete(delete_query);
        if (status != errSecSuccess || probe_called_count != 0) {
            fail("deleting an AirPort credential must succeed without the keychain");
        }
        result = NULL;
        status = l8_SecItemCopyMatching(read_back, &result);
        if (status == errSecSuccess) {
            fail("a deleted AirPort credential must be gone");
        }

        /* An update must replace the stored password. */
        const char *replacement = "correcthorse";
        CFDataRef new_password = CFDataCreate(NULL, (const UInt8 *)replacement,
                                              (CFIndex)strlen(replacement));
        const void *update_keys[1] = {kSecValueData};
        const void *update_values[1] = {new_password};
        CFDictionaryRef update = CFDictionaryCreate(NULL, update_keys, update_values, 1,
                                                   &kCFTypeDictionaryKeyCallBacks,
                                                   &kCFTypeDictionaryValueCallBacks);
        CFDictionaryRef update_query = query_with("AirPort", "acct", "genp", 0);
        probe_called_count = 0;
        status = l8_SecItemUpdate(update_query, update);
        if (status != errSecSuccess || probe_called_count != 0) {
            fail("updating an AirPort credential must succeed without the keychain");
        }
        result = NULL;
        status = l8_SecItemCopyMatching(read_back, &result);
        if (status != errSecSuccess) {
            fail("the updated credential must be readable back");
        } else if (result == NULL || CFGetTypeID(result) != CFDataGetTypeID() ||
                   CFDataGetLength((CFDataRef)result) != (CFIndex)strlen(replacement)) {
            fail("the update must replace the stored password");
        }
    } else if (strcmp(mode, "disabled") == 0 || strcmp(mode, "inert") == 0) {
        /* Without the marker, or outside wifid, the shim must be completely
         * inert: every call goes to the real keychain. */
        probe_called_count = 0;
        CFDictionaryRef ours = query_with("AirPort", "acct", "genp", 1);
        CFTypeRef result = NULL;
        OSStatus status = l8_SecItemCopyMatching(ours, &result);
        if (status != errSecItemNotFound || probe_called_count != 1) {
            fail("an inert shim must pass every call through");
        }
        probe_called_count = 0;
        CFDictionaryRef add = add_with("acct", "x");
        CFTypeRef added = NULL;
        l8_SecItemAdd(add, &added);
        if (probe_called_count != 1) {
            fail("an inert shim must not intercept an add");
        }
        probe_called_count = 0;
        CFDictionaryRef update_query = query_with("AirPort", "acct", "genp", 0);
        l8_SecItemUpdate(update_query, add);
        if (probe_called_count != 1) {
            fail("an inert shim must not intercept an update");
        }
        probe_called_count = 0;
        CFDictionaryRef delete_query = query_with("AirPort", "acct", "genp", 0);
        l8_SecItemDelete(delete_query);
        if (probe_called_count != 1) {
            fail("an inert shim must not intercept a delete");
        }
    }

    if (failures == 0) {
        printf("PASS: %s\n", mode);
        return 0;
    }
    printf("FAIL: %d checks failed (%s)\n", failures, mode);
    return 1;
}
"""

with tempfile.TemporaryDirectory(prefix="l8-wifi-") as work:
    work = pathlib.Path(work)
    marker = work / "marker"
    store = work / "store.plist"

    harness_c = work / "harness.c"
    harness_c.write_text(HARNESS)

    flags = [
        "-Wall", "-Wextra", "-Werror",
        f'-DL8WIFI_ENABLE_PATH="{marker}"',
        f'-DL8WIFI_STORE_PATH="{store}"',
        # The test binary presents itself as wifid so the process gate opens.
        '-DL8WIFI_TARGET_PROGRAM="wifitest"',
        # The marker must be root-owned on the device. The test runs as an
        # ordinary user, so the required owner is this user instead.
        "-DL8WIFI_MARKER_UID=geteuid()",
        "-I", str(SRC),
    ]

    binary = work / "wifitest"
    subprocess.run([
        "xcrun", "clang", *flags,
        str(harness_c),
        "-framework", "CoreFoundation", "-framework", "Security",
        "-o", str(binary),
    ], check=True)

    # Without the marker the shim must be inert.
    result = subprocess.run([str(binary), "disabled"], capture_output=True, text=True)
    if result.returncode != 0:
        raise SystemExit(f"FAIL: disabled shim\n{result.stdout}{result.stderr}")

    # A marker that is group or other writable must not enable the shim: an
    # unprivileged process could then turn it on.
    marker.write_text("")
    marker.chmod(0o666)
    result = subprocess.run([str(binary), "check"], capture_output=True, text=True)
    if result.returncode == 0:
        raise SystemExit("FAIL: a world-writable marker must not enable the shim")

    # A marker that is a directory must not enable the shim either.
    marker.unlink()
    marker.mkdir()
    result = subprocess.run([str(binary), "check"], capture_output=True, text=True)
    if result.returncode == 0:
        raise SystemExit("FAIL: a directory marker must not enable the shim")
    marker.rmdir()

    # With the marker present the shim must claim exactly the AirPort
    # generic-password item.
    marker.write_text("")
    marker.chmod(0o600)
    result = subprocess.run([str(binary), "check"], capture_output=True, text=True)
    if result.returncode != 0:
        raise SystemExit(f"FAIL: enabled shim\n{result.stdout}{result.stderr}")

    # The same binary under another name is not wifid, so the shim must stay
    # inert there even with the marker present. The dylib is weak-loaded into
    # wifid alone, but the check is repeated inside the shim so a copy that
    # reaches another process cannot capture keychain traffic.
    other = work / "notwifid"
    shutil.copyfile(binary, other)
    other.chmod(0o755)
    result = subprocess.run([str(other), "inert"], capture_output=True, text=True)
    if result.returncode != 0:
        raise SystemExit(
            f"FAIL: the shim must stay inert outside wifid\n{result.stdout}{result.stderr}"
        )

    # The store must exist, be private, and hold the password.
    if not store.exists():
        raise SystemExit("FAIL: the shim did not create its credential store")
    mode = store.stat().st_mode & 0o777
    if mode != 0o600:
        raise SystemExit(f"FAIL: the credential store mode is {mode:o}, expected 600")
    # The store is a binary property list, so the password is inside it as
    # plist data rather than as plain text.
    document = plistlib.loads(store.read_bytes())
    stored = [entry["data"] for entry in document.values()
              if isinstance(entry, dict) and entry.get("data") is not None]
    if not any(bytes(value) == b"correcthorse" for value in stored):
        raise SystemExit("FAIL: the credential store does not hold the password")

    print("PASS: AirPort-only interception, foreign service and class pass through, "
          "add/copy/update/delete round-trip, marker-gated inertness, 0600 store")
