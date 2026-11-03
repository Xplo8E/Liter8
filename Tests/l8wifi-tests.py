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
#include <pthread.h>
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

/* A query whose account selector is present but is not a string. The real
 * keychain rejects it, and the shim must not treat it as an absent selector,
 * which would make a malformed single-record request into a bulk one. */
static CFDictionaryRef query_with_data_account(const char *svc) {
    CFDataRef account = CFDataCreate(NULL, (const UInt8 *)"not-an-account", 13);
    const void *keys[3];
    const void *values[3];
    int count = 0;
    keys[count] = kSecAttrService; values[count] = cfstr(svc); count++;
    keys[count] = kSecClass; values[count] = cfstr("genp"); count++;
    keys[count] = kSecAttrAccount; values[count] = account; count++;
    return CFDictionaryCreate(NULL, keys, values, count,
                              &kCFTypeDictionaryKeyCallBacks,
                              &kCFTypeDictionaryValueCallBacks);
}

/* An add that names the synchronizable attribute. */
static CFDictionaryRef add_with_sync(const char *acct, const char *password,
                                     int synchronizable) {
    CFDataRef data = CFDataCreate(NULL, (const UInt8 *)password, (CFIndex)strlen(password));
    const void *keys[4] = {kSecValueData, kSecAttrAccount, kSecAttrService,
                           kSecAttrSynchronizable};
    const void *values[4] = {data, cfstr(acct), cfstr("AirPort"),
                             synchronizable ? kCFBooleanTrue : kCFBooleanFalse};
    return CFDictionaryCreate(NULL, keys, values, 4,
                              &kCFTypeDictionaryKeyCallBacks,
                              &kCFTypeDictionaryValueCallBacks);
}

/* An add that names a label. */
static CFDictionaryRef add_with_label(const char *acct, const char *password,
                                      const char *label) {
    CFDataRef data = CFDataCreate(NULL, (const UInt8 *)password, (CFIndex)strlen(password));
    const void *keys[4] = {kSecValueData, kSecAttrAccount, kSecAttrService,
                           kSecAttrLabel};
    const void *values[4] = {data, cfstr(acct), cfstr("AirPort"), cfstr(label)};
    return CFDictionaryCreate(NULL, keys, values, 4,
                              &kCFTypeDictionaryKeyCallBacks,
                              &kCFTypeDictionaryValueCallBacks);
}

/* A query that names a label. */
static CFDictionaryRef query_with_label(const char *svc, const char *acct,
                                        int want_data, const char *label) {
    const void *keys[5];
    const void *values[5];
    int count = 0;
    keys[count] = kSecAttrService; values[count] = cfstr(svc); count++;
    if (acct) { keys[count] = kSecAttrAccount; values[count] = cfstr(acct); count++; }
    keys[count] = kSecClass; values[count] = cfstr("genp"); count++;
    if (want_data) { keys[count] = kSecReturnData; values[count] = kCFBooleanTrue; count++; }
    if (label) { keys[count] = kSecAttrLabel; values[count] = cfstr(label); count++; }
    return CFDictionaryCreate(NULL, keys, values, count,
                              &kCFTypeDictionaryKeyCallBacks,
                              &kCFTypeDictionaryValueCallBacks);
}

/* An update whose query names a label. */
static CFDictionaryRef update_query_with_label(const char *acct, const char *label) {
    const void *keys[4];
    const void *values[4];
    int count = 0;
    keys[count] = kSecAttrService; values[count] = cfstr("AirPort"); count++;
    keys[count] = kSecAttrAccount; values[count] = cfstr(acct); count++;
    keys[count] = kSecClass; values[count] = cfstr("genp"); count++;
    keys[count] = kSecAttrLabel; values[count] = cfstr(label); count++;
    return CFDictionaryCreate(NULL, keys, values, count,
                              &kCFTypeDictionaryKeyCallBacks,
                              &kCFTypeDictionaryValueCallBacks);
}

/* An account-filtered enumeration. The keychain answers a search for every
 * match with an array, even when the selectors leave one record standing. */
static CFDictionaryRef enumerate_account_query(const char *acct) {
    const void *keys[4];
    const void *values[4];
    int count = 0;
    keys[count] = kSecAttrService; values[count] = cfstr("AirPort"); count++;
    keys[count] = kSecAttrAccount; values[count] = cfstr(acct); count++;
    keys[count] = kSecReturnAttributes; values[count] = kCFBooleanTrue; count++;
    keys[count] = kSecMatchLimit; values[count] = kSecMatchLimitAll; count++;
    return CFDictionaryCreate(NULL, keys, values, count,
                              &kCFTypeDictionaryKeyCallBacks,
                              &kCFTypeDictionaryValueCallBacks);
}

/* A delete whose label selector is present but is not a string. */
static CFDictionaryRef delete_with_data_label(void) {
    CFDataRef label = CFDataCreate(NULL, (const UInt8 *)"not-a-label", 10);
    const void *keys[3];
    const void *values[3];
    int count = 0;
    keys[count] = kSecAttrService; values[count] = cfstr("AirPort"); count++;
    keys[count] = kSecClass; values[count] = cfstr("genp"); count++;
    keys[count] = kSecAttrLabel; values[count] = label; count++;
    return CFDictionaryCreate(NULL, keys, values, count,
                              &kCFTypeDictionaryKeyCallBacks,
                              &kCFTypeDictionaryValueCallBacks);
}

/* An update whose attributes name a new account and a new password. */
static CFDictionaryRef update_attributes_with_account(const char *acct,
                                                       const char *password) {
    CFDataRef data = CFDataCreate(NULL, (const UInt8 *)password, (CFIndex)strlen(password));
    const void *keys[2] = {kSecValueData, kSecAttrAccount};
    const void *values[2] = {data, cfstr(acct)};
    return CFDictionaryCreate(NULL, keys, values, 2,
                              &kCFTypeDictionaryKeyCallBacks,
                              &kCFTypeDictionaryValueCallBacks);
}

/* An update with no account at all: a broader search the shim does not
 * implement. */
static CFDictionaryRef update_query_without_account(void) {
    const void *keys[2];
    const void *values[2];
    int count = 0;
    keys[count] = kSecAttrService; values[count] = cfstr("AirPort"); count++;
    keys[count] = kSecClass; values[count] = cfstr("genp"); count++;
    return CFDictionaryCreate(NULL, keys, values, count,
                              &kCFTypeDictionaryKeyCallBacks,
                              &kCFTypeDictionaryValueCallBacks);
}

/* The store file as it is on disk, for checking that a refused write left
 * it alone. */
static uint8_t *read_file(const char *path, size_t *length) {
    FILE *stream = fopen(path, "rb");
    if (stream == NULL) { return NULL; }
    fseek(stream, 0, SEEK_END);
    long size = ftell(stream);
    fseek(stream, 0, SEEK_SET);
    if (size <= 0) { fclose(stream); return NULL; }
    uint8_t *bytes = malloc((size_t)size);
    if (bytes == NULL) { fclose(stream); return NULL; }
    if (fread(bytes, 1, (size_t)size, stream) != (size_t)size) {
        free(bytes);
        fclose(stream);
        return NULL;
    }
    fclose(stream);
    *length = (size_t)size;
    return bytes;
}

/* A query that names the synchronizable attribute. */
static CFDictionaryRef query_with_sync(const char *svc, const char *acct,
                                       const char *cls, int want_data,
                                       int synchronizable) {
    const void *keys[5];
    const void *values[5];
    int count = 0;
    keys[count] = kSecAttrService; values[count] = cfstr(svc); count++;
    keys[count] = kSecAttrAccount; values[count] = cfstr(acct); count++;
    if (cls) { keys[count] = kSecClass; values[count] = cfstr(cls); count++; }
    if (want_data) { keys[count] = kSecReturnData; values[count] = kCFBooleanTrue; count++; }
    keys[count] = kSecAttrSynchronizable;
    values[count] = synchronizable ? kCFBooleanTrue : kCFBooleanFalse;
    count++;
    return CFDictionaryCreate(NULL, keys, values, count,
                              &kCFTypeDictionaryKeyCallBacks,
                              &kCFTypeDictionaryValueCallBacks);
}

/* A delete that names the synchronizable attribute. */
static CFDictionaryRef delete_all_sync_query(int synchronizable) {
    const void *keys[3];
    const void *values[3];
    int count = 0;
    keys[count] = kSecAttrService; values[count] = cfstr("AirPort"); count++;
    keys[count] = kSecClass; values[count] = cfstr("genp"); count++;
    keys[count] = kSecAttrSynchronizable;
    values[count] = synchronizable ? kCFBooleanTrue : kCFBooleanFalse;
    count++;
    return CFDictionaryCreate(NULL, keys, values, count,
                              &kCFTypeDictionaryKeyCallBacks,
                              &kCFTypeDictionaryValueCallBacks);
}

/* A delete with no account: every AirPort record of one keychain. */
static CFDictionaryRef delete_all_query(void) {
    const void *keys[2];
    const void *values[2];
    int count = 0;
    keys[count] = kSecAttrService; values[count] = cfstr("AirPort"); count++;
    keys[count] = kSecClass; values[count] = cfstr("genp"); count++;
    return CFDictionaryCreate(NULL, keys, values, count,
                              &kCFTypeDictionaryKeyCallBacks,
                              &kCFTypeDictionaryValueCallBacks);
}

static CFDictionaryRef delete_all_system_query(void) {
    const void *keys[3];
    const void *values[3];
    int count = 0;
    keys[count] = kSecAttrService; values[count] = cfstr("AirPort"); count++;
    keys[count] = kSecClass; values[count] = cfstr("genp"); count++;
    keys[count] = system_keychain_constant(); values[count] = kCFBooleanTrue; count++;
    return CFDictionaryCreate(NULL, keys, values, count,
                              &kCFTypeDictionaryKeyCallBacks,
                              &kCFTypeDictionaryValueCallBacks);
}

/* The store is read into a buffer whose size the shim chooses. If that
 * buffer lives on the stack, the shim only survives on a host thread with a
 * multi-megabyte stack. wifid reaches the keychain from a GCD worker queue
 * whose stack is 512 KiB, and a 1 MiB automatic array trapped in
 * __chkstk_darwin and killed wifid on every AirPort query, which launchd then
 * restarted into the same trap. The test runs the store path on a thread with
 * the device's stack size so that shape is caught here rather than on the
 * phone. */
#define SMALL_STACK_BYTES (512 * 1024)

static int small_stack_finished = 0;

static void *small_stack_body(void *argument) {
    (void)argument;
    /* A separate account, so this mode does not disturb the store the other
     * modes assert on. */
    CFDictionaryRef add = add_with("smallstack", "hunter2");
    CFTypeRef added = NULL;
    l8_SecItemAdd(add, &added);
    if (added) { CFRelease(added); }
    CFDictionaryRef query = query_with("AirPort", "smallstack", "genp", 1);
    CFTypeRef result = NULL;
    l8_SecItemCopyMatching(query, &result);
    if (result) { CFRelease(result); }
    small_stack_finished = 1;
    return NULL;
}

static void check_small_stack(void) {
    pthread_attr_t attributes;
    pthread_t thread;
    if (pthread_attr_init(&attributes) != 0) {
        fail("could not initialise the thread attributes");
        return;
    }
    if (pthread_attr_setstacksize(&attributes, SMALL_STACK_BYTES) != 0) {
        fail("could not set the thread stack size");
        pthread_attr_destroy(&attributes);
        return;
    }
    if (pthread_create(&thread, &attributes, small_stack_body, NULL) != 0) {
        fail("could not start the small-stack thread");
        pthread_attr_destroy(&attributes);
        return;
    }
    pthread_join(thread, NULL);
    pthread_attr_destroy(&attributes);
    if (!small_stack_finished) {
        fail("the small-stack thread did not finish the store path");
    }
}

int main(int argc, char **argv) {
    const char *mode = argc > 1 ? argv[1] : "check";
    CFTypeRef result = NULL;
    OSStatus status;

    if (strcmp(mode, "smallstack") == 0) {
        check_small_stack();
    } else if (strcmp(mode, "bulkdelete") == 0) {
        /* One credential in each namespace, then a bulk delete of the
         * system-keychain one. The user-keychain credential must survive:
         * a record's system-keychain selection is part of its identity, so
         * clearing one keychain must not clear the other. */
        CFDictionaryRef user_add = add_with("bulkuser", "userpassword");
        CFTypeRef added = NULL;
        l8_SecItemAdd(user_add, &added);
        if (added) { CFRelease(added); }
        CFDictionaryRef system_add = add_with_system("bulksys", "systempassword");
        added = NULL;
        l8_SecItemAdd(system_add, &added);
        if (added) { CFRelease(added); }

        probe_called_count = 0;
        status = l8_SecItemDelete(delete_all_system_query());
        if (status != errSecSuccess || probe_called_count != 0) {
            fail("a bulk delete must succeed without reaching the real keychain");
        }

        /* The system-keychain credential is gone. */
        CFDictionaryRef gone = query_with("AirPort", "bulksys", "genp", 1);
        CFTypeRef result = NULL;
        status = l8_SecItemCopyMatching(gone, &result);
        if (status == errSecSuccess) {
            fail("a bulk delete must remove the system-keychain credential");
        }

        /* The user-keychain credential is untouched. */
        CFDictionaryRef kept = query_with("AirPort", "bulkuser", "genp", 1);
        result = NULL;
        status = l8_SecItemCopyMatching(kept, &result);
        if (status != errSecSuccess || result == NULL) {
            fail("a bulk delete must leave the user-keychain credential alone");
        } else {
            if (CFGetTypeID(result) == CFDataGetTypeID() &&
                CFDataGetLength((CFDataRef)result) != (CFIndex)strlen("userpassword")) {
                fail("the user-keychain credential must keep its password");
            }
            CFRelease(result);
        }

        /* And the other direction: a user-keychain bulk delete clears the
         * user-keychain records. */
        probe_called_count = 0;
        status = l8_SecItemDelete(delete_all_query());
        if (status != errSecSuccess || probe_called_count != 0) {
            fail("a user-keychain bulk delete must succeed without the real keychain");
        }
        result = NULL;
        status = l8_SecItemCopyMatching(kept, &result);
        if (status == errSecSuccess) {
            fail("a user-keychain bulk delete must remove the user-keychain credential");
        }
    } else if (strcmp(mode, "malformed") == 0) {
        /* Two accounts, then a request whose account selector is present but
         * is not a string. The real keychain rejects that request, and the
         * shim must reject it too rather than read it as an absent selector,
         * which would delete every credential in the keychain. */
        CFDictionaryRef first = add_with("malformedone", "firstpassword");
        CFTypeRef added = NULL;
        l8_SecItemAdd(first, &added);
        if (added) { CFRelease(added); }
        CFDictionaryRef second = add_with("malformedtwo", "secondpassword");
        added = NULL;
        l8_SecItemAdd(second, &added);
        if (added) { CFRelease(added); }

        CFDictionaryRef broken = query_with_data_account("AirPort");
        probe_called_count = 0;
        status = l8_SecItemDelete(broken);
        if (probe_called_count != 1) {
            fail("a malformed account selector must reach the real keychain");
        }

        /* Neither stored credential may have changed. */
        CFDictionaryRef one = query_with("AirPort", "malformedone", "genp", 1);
        result = NULL;
        status = l8_SecItemCopyMatching(one, &result);
        if (status != errSecSuccess || result == NULL) {
            fail("a malformed account selector must not delete a stored credential");
        }
        CFDictionaryRef two = query_with("AirPort", "malformedtwo", "genp", 1);
        result = NULL;
        status = l8_SecItemCopyMatching(two, &result);
        if (status != errSecSuccess || result == NULL) {
            fail("a malformed account selector must not delete a stored credential");
        }
    } else if (strcmp(mode, "syncselect") == 0) {
        /* One synchronizable and one nonsynchronizable record in the same
         * keychain. A delete that names the synchronizable attribute must
         * remove only the record it selects, and an update that does not name
         * it must keep the stored value, because the keychain does not let
         * that attribute be updated. */
        CFDictionaryRef sync_add = add_with_sync("syncone", "syncpassword", 1);
        CFTypeRef added = NULL;
        l8_SecItemAdd(sync_add, &added);
        if (added) { CFRelease(added); }
        CFDictionaryRef plain_add = add_with_sync("synctwo", "plainpassword", 0);
        added = NULL;
        l8_SecItemAdd(plain_add, &added);
        if (added) { CFRelease(added); }

        probe_called_count = 0;
        status = l8_SecItemDelete(delete_all_sync_query(1));
        if (status != errSecSuccess || probe_called_count != 0) {
            fail("a synchronizable bulk delete must succeed without the real keychain");
        }

        /* The synchronizable record is gone, the other one is not. */
        CFDictionaryRef gone = query_with("AirPort", "syncone", "genp", 1);
        CFTypeRef result = NULL;
        status = l8_SecItemCopyMatching(gone, &result);
        if (status == errSecSuccess) {
            fail("a synchronizable bulk delete must remove the synchronizable record");
        }
        CFDictionaryRef kept = query_with("AirPort", "synctwo", "genp", 1);
        result = NULL;
        status = l8_SecItemCopyMatching(kept, &result);
        if (status != errSecSuccess || result == NULL) {
            fail("a synchronizable bulk delete must leave the other record alone");
        }

        /* An update that does not name the synchronizable attribute must not
         * change it, so the record stays reachable through a query that names
         * it, and stays unreachable through one that names the other value. */
        const char *replacement = "changedpassword";
        CFDataRef new_password = CFDataCreate(NULL, (const UInt8 *)replacement,
                                              (CFIndex)strlen(replacement));
        const void *update_keys[1] = {kSecValueData};
        const void *update_values[1] = {new_password};
        CFDictionaryRef update = CFDictionaryCreate(NULL, update_keys, update_values, 1,
                                                   &kCFTypeDictionaryKeyCallBacks,
                                                   &kCFTypeDictionaryValueCallBacks);
        CFDictionaryRef update_query = query_with("AirPort", "synctwo", "genp", 0);
        status = l8_SecItemUpdate(update_query, update);
        if (status != errSecSuccess) {
            fail("updating a record must succeed");
        }
        CFDictionaryRef still_plain =
            query_with_sync("AirPort", "synctwo", "genp", 1, 0);
        result = NULL;
        status = l8_SecItemCopyMatching(still_plain, &result);
        if (status != errSecSuccess || result == NULL) {
            fail("an update must not clear the stored synchronizable attribute");
        } else {
            if (CFGetTypeID(result) == CFDataGetTypeID() &&
                CFDataGetLength((CFDataRef)result) != (CFIndex)strlen(replacement)) {
                fail("the update must replace the stored password");
            }
            CFRelease(result);
        }
        CFDictionaryRef would_be_sync =
            query_with_sync("AirPort", "synctwo", "genp", 1, 1);
        result = NULL;
        status = l8_SecItemCopyMatching(would_be_sync, &result);
        if (status == errSecSuccess) {
            fail("the record must not answer a query naming the other value");
        }
    } else if (strcmp(mode, "unreadable") == 0) {
        /* A store that exists but cannot be read must not be replaced by the
         * next write, or every saved password goes with it. Making it
         * group and other readable is enough: the shim refuses to read a
         * store that is not private. */
        CFDictionaryRef first = add_with("unreadone", "firstpassword");
        CFTypeRef added = NULL;
        status = l8_SecItemAdd(first, &added);
        if (added) { CFRelease(added); }
        if (status != errSecSuccess) {
            fail("the first credential must be stored");
        }

        size_t before_length = 0;
        uint8_t *before = read_file(kStorePath, &before_length);
        if (before == NULL) {
            fail("could not read the store before the failed write");
        }

        if (chmod(kStorePath, 0644) != 0) {
            fail("could not change the store mode");
        }

        CFDictionaryRef second = add_with("unreadtwo", "secondpassword");
        added = NULL;
        status = l8_SecItemAdd(second, &added);
        if (added) { CFRelease(added); }
        if (status == errSecSuccess) {
            fail("an unreadable store must not be overwritten");
        }

        size_t after_length = 0;
        uint8_t *after = read_file(kStorePath, &after_length);
        if (after == NULL) {
            fail("the store disappeared during the refused write");
        } else {
            if (after_length != before_length ||
                memcmp(after, before, before_length) != 0) {
                fail("a refused write must leave the store exactly as it was");
            }
            free(after);
        }
        free(before);

        /* Restoring the mode makes the store usable again. */
        if (chmod(kStorePath, 0600) != 0) {
            fail("could not restore the store mode");
        }
        CFDictionaryRef third = add_with("unreadthree", "thirdpassword");
        added = NULL;
        status = l8_SecItemAdd(third, &added);
        if (added) { CFRelease(added); }
        if (status != errSecSuccess) {
            fail("a readable store must accept a credential again");
        }
    } else if (strcmp(mode, "label") == 0) {
        /* A query can match on the label, so a delete restricted to one
         * label must not take the records it excludes, and a copy must not
         * answer with a record whose label does not match. */
        CFDictionaryRef labelled = add_with_label("labelled", "labelledpassword", "Work");
        CFTypeRef added = NULL;
        status = l8_SecItemAdd(labelled, &added);
        if (added) { CFRelease(added); }
        CFDictionaryRef plain = add_with_label("plain", "plainpassword", "Home");
        added = NULL;
        status = l8_SecItemAdd(plain, &added);
        if (added) { CFRelease(added); }

        /* An account-less delete naming a label must remove only that
         * label's records. */
        CFDictionaryRef delete_labelled = query_with_label("AirPort", NULL, 0, "Work");
        probe_called_count = 0;
        status = l8_SecItemDelete(delete_labelled);
        if (status != errSecSuccess || probe_called_count != 0) {
            fail("a labelled bulk delete must succeed without the real keychain");
        }

        CFDictionaryRef gone = query_with_label("AirPort", "labelled", 1, NULL);
        CFTypeRef result = NULL;
        status = l8_SecItemCopyMatching(gone, &result);
        if (status == errSecSuccess) {
            fail("a labelled bulk delete must remove the labelled record");
        }
        CFDictionaryRef kept = query_with_label("AirPort", "plain", 1, NULL);
        result = NULL;
        status = l8_SecItemCopyMatching(kept, &result);
        if (status != errSecSuccess || result == NULL) {
            fail("a labelled bulk delete must leave the other record alone");
        }

        /* A copy that names a label must not answer with a record whose
         * label is a different one. */
        CFDictionaryRef wrong_label = query_with_label("AirPort", "plain", 1, "Work");
        result = NULL;
        status = l8_SecItemCopyMatching(wrong_label, &result);
        if (status == errSecSuccess) {
            fail("a copy naming a label must not answer with another label's record");
        }

        /* A search for every match is answered with an array, even when the
         * account leaves one record standing. */
        CFDictionaryRef enumeration = enumerate_account_query("plain");
        result = NULL;
        status = l8_SecItemCopyMatching(enumeration, &result);
        if (status != errSecSuccess || result == NULL) {
            fail("an account-filtered enumeration must be answered");
        } else if (CFGetTypeID(result) != CFArrayGetTypeID()) {
            fail("an account-filtered enumeration must answer with an array");
        } else if (CFArrayGetCount((CFArrayRef)result) != 1) {
            fail("an account-filtered enumeration must hold the one record");
        }
    } else if (strcmp(mode, "updatelabel") == 0) {
        /* An update whose query names a label that does not match the record
         * is not a match: it must not rewrite the password and it must not
         * relabel the record. */
        CFDictionaryRef labelled = add_with_label("updatelabel", "originalpassword", "Home");
        CFTypeRef added = NULL;
        status = l8_SecItemAdd(labelled, &added);
        if (added) { CFRelease(added); }

        const char *replacement = "replacementpassword";
        CFDataRef new_password = CFDataCreate(NULL, (const UInt8 *)replacement,
                                              (CFIndex)strlen(replacement));
        const void *update_keys[1] = {kSecValueData};
        const void *update_values[1] = {new_password};
        CFDictionaryRef update = CFDictionaryCreate(NULL, update_keys, update_values, 1,
                                                   &kCFTypeDictionaryKeyCallBacks,
                                                   &kCFTypeDictionaryValueCallBacks);
        CFDictionaryRef update_query = update_query_with_label("updatelabel", "Work");
        probe_called_count = 0;
        status = l8_SecItemUpdate(update_query, update);
        if (probe_called_count != 1) {
            fail("an update naming a label that does not match must go to the real keychain");
        }

        /* The password and the label are both unchanged. */
        CFDictionaryRef read = query_with_label("AirPort", "updatelabel", 1, NULL);
        CFTypeRef result = NULL;
        status = l8_SecItemCopyMatching(read, &result);
        if (status != errSecSuccess || result == NULL) {
            fail("the record must still be readable");
        } else {
            if (CFGetTypeID(result) == CFDataGetTypeID() &&
                CFDataGetLength((CFDataRef)result) !=
                    (CFIndex)strlen("originalpassword")) {
                fail("a nonmatching update must not rewrite the password");
            }
            CFRelease(result);
        }
        CFDictionaryRef by_label = query_with_label("AirPort", "updatelabel", 1, "Home");
        result = NULL;
        status = l8_SecItemCopyMatching(by_label, &result);
        if (status != errSecSuccess || result == NULL) {
            fail("a nonmatching update must not relabel the record");
        }
    } else if (strcmp(mode, "addresult") == 0) {
        /* The caller asks for a shape of result, so it gets that shape. A
         * caller that asked for the attributes cannot use a CFData. */
        const void *keys[5];
        const void *values[5];
        int count = 0;
        keys[count] = kSecAttrService; values[count] = cfstr("AirPort"); count++;
        keys[count] = kSecAttrAccount; values[count] = cfstr("shape"); count++;
        keys[count] = kSecValueData; values[count] = CFDataCreate(NULL, (const UInt8 *)"secret", 6); count++;
        keys[count] = kSecReturnAttributes; values[count] = kCFBooleanTrue; count++;
        CFDictionaryRef attributes = CFDictionaryCreate(NULL, keys, values, count,
                                                        &kCFTypeDictionaryKeyCallBacks,
                                                        &kCFTypeDictionaryValueCallBacks);
        CFTypeRef result = NULL;
        status = l8_SecItemAdd(attributes, &result);
        if (status != errSecSuccess) {
            fail("the add must succeed");
        }
        if (result == NULL || CFGetTypeID(result) != CFDictionaryGetTypeID()) {
            fail("an add that asks for the attributes must answer with a dictionary");
        } else {
            CFTypeRef account = CFDictionaryGetValue((CFDictionaryRef)result, kSecAttrAccount);
            if (account == NULL || !CFEqual(account, cfstr("shape"))) {
                fail("the returned attributes must carry the account");
            }
            if (CFDictionaryGetValue((CFDictionaryRef)result, kSecValueData) != NULL) {
                fail("the returned attributes must not carry the password unasked");
            }
            CFRelease(result);
        }
    } else if (strcmp(mode, "oversize") == 0) {
        /* A write that would produce a store the reader rejects must be
         * refused, and the readable store must be left alone. */
        int stored = 0;
        OSStatus last = errSecSuccess;
        for (int index = 0; index < 400; index++) {
            char account[32];
            snprintf(account, sizeof(account), "over%03d", index);
            CFDictionaryRef add = add_with(account, "paddingpassword");
            CFTypeRef result = NULL;
            last = l8_SecItemAdd(add, &result);
            if (result) { CFRelease(result); }
            if (last != errSecSuccess) { break; }
            stored++;
        }
        if (last == errSecSuccess) {
            fail("a write past the store limit must be refused");
        }
        if (stored < 1) {
            fail("the credentials written before the limit must exist");
        }
        /* The credentials written before the refused one must still be
         * readable: the store was not replaced by one holding only the last
         * credential. */
        CFDictionaryRef first = query_with("AirPort", "over000", "genp", 1);
        CFTypeRef result = NULL;
        status = l8_SecItemCopyMatching(first, &result);
        if (status != errSecSuccess || result == NULL) {
            fail("a refused write must leave the earlier credentials readable");
        }
    } else if (strcmp(mode, "malformedlabel") == 0) {
        /* A label selector that is present but is not a string is a malformed
         * request. It must not read as an absent label, which would turn it
         * into a delete of everything in the keychain. */
        CFDictionaryRef first = add_with_label("malformedone", "firstpassword", "Home");
        CFTypeRef added = NULL;
        l8_SecItemAdd(first, &added);
        if (added) { CFRelease(added); }
        CFDictionaryRef second = add_with_label("malformedtwo", "secondpassword", "Work");
        added = NULL;
        l8_SecItemAdd(second, &added);
        if (added) { CFRelease(added); }

        probe_called_count = 0;
        status = l8_SecItemDelete(delete_with_data_label());
        if (probe_called_count != 1) {
            fail("a malformed label selector must reach the real keychain");
        }

        /* Neither stored credential may have changed. */
        CFDictionaryRef one = query_with_label("AirPort", "malformedone", 1, NULL);
        CFTypeRef result = NULL;
        status = l8_SecItemCopyMatching(one, &result);
        if (status != errSecSuccess || result == NULL) {
            fail("a malformed label selector must not delete a stored credential");
        }
        CFDictionaryRef two = query_with_label("AirPort", "malformedtwo", 1, NULL);
        result = NULL;
        status = l8_SecItemCopyMatching(two, &result);
        if (status != errSecSuccess || result == NULL) {
            fail("a malformed label selector must not delete a stored credential");
        }
    } else if (strcmp(mode, "rename") == 0) {
        /* An update can change the account. The keychain replaces the item
         * when it does: the old account no longer finds it and the new one
         * does. */
        CFDictionaryRef first = add_with("renameold", "originalpassword");
        CFTypeRef added = NULL;
        status = l8_SecItemAdd(first, &added);
        if (added) { CFRelease(added); }

        const char *replacement = "renamedpassword";
        CFDictionaryRef update =
            update_attributes_with_account("renamenew", replacement);
        CFDictionaryRef update_query = query_with("AirPort", "renameold", "genp", 0);
        status = l8_SecItemUpdate(update_query, update);
        if (status != errSecSuccess) {
            fail("renaming an account must succeed");
        }

        /* Only the new account finds it, with the new password. */
        CFDictionaryRef renamed = query_with("AirPort", "renamenew", "genp", 1);
        CFTypeRef result = NULL;
        status = l8_SecItemCopyMatching(renamed, &result);
        if (status != errSecSuccess || result == NULL) {
            fail("the renamed account must hold the new password");
        } else {
            if (CFGetTypeID(result) == CFDataGetTypeID() &&
                CFDataGetLength((CFDataRef)result) !=
                    (CFIndex)strlen("renamedpassword")) {
                fail("the renamed account must hold the new password");
            }
            CFRelease(result);
        }
        CFDictionaryRef old = query_with("AirPort", "renameold", "genp", 1);
        result = NULL;
        status = l8_SecItemCopyMatching(old, &result);
        if (status == errSecSuccess) {
            fail("the old account must no longer hold the credential");
        }

        /* An update with no account is a broader search the shim does not
         * implement, so it goes to the real keychain. */
        probe_called_count = 0;
        status = l8_SecItemUpdate(update_query_without_account(), update);
        if (probe_called_count != 1) {
            fail("an account-less update must go to the real keychain");
        }
        if (status != errSecSuccess) {
            fail("an account-less update must keep the real keychain's answer");
        }
    } else if (strcmp(mode, "check") == 0) {
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
        f'-DL8WIFI_STORE_PATH="{store}"',
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

    # The store path must not need more stack than a device worker thread
    # has. A shim that keeps the store buffer on the stack dies here by
    # signal rather than by a failed check, so the signal is read separately.
    result = subprocess.run([str(binary), "smallstack"], capture_output=True, text=True)
    if result.returncode < 0:
        raise SystemExit(
            "FAIL: the shim overflowed a device-sized thread stack "
            f"(killed by signal {-result.returncode})"
        )
    if result.returncode != 0:
        raise SystemExit(f"FAIL: small-stack shim\n{result.stdout}{result.stderr}")

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

    # A bulk delete must clear one keychain and not the other. Run last, so
    # it cannot disturb the store the checks above read.
    result = subprocess.run([str(binary), "bulkdelete"], capture_output=True, text=True)
    if result.returncode != 0:
        raise SystemExit(f"FAIL: bulk delete\n{result.stdout}{result.stderr}")

    # A malformed account selector must be rejected, not turned into a bulk
    # request. Run after the bulk delete, which empties the store.
    result = subprocess.run([str(binary), "malformed"], capture_output=True, text=True)
    if result.returncode != 0:
        raise SystemExit(f"FAIL: malformed selector\n{result.stdout}{result.stderr}")

    # The synchronizable attribute is part of the selection, so a delete that
    # names it must not take the records it excludes.
    result = subprocess.run([str(binary), "syncselect"], capture_output=True, text=True)
    if result.returncode != 0:
        raise SystemExit(f"FAIL: synchronizable selection\n{result.stdout}{result.stderr}")

    # An unreadable store must not be replaced by the next write.
    result = subprocess.run([str(binary), "unreadable"], capture_output=True, text=True)
    if result.returncode != 0:
        raise SystemExit(f"FAIL: unreadable store\n{result.stdout}{result.stderr}")

    # A label narrows a match, and the add's result has the shape asked for.
    result = subprocess.run([str(binary), "label"], capture_output=True, text=True)
    if result.returncode != 0:
        raise SystemExit(f"FAIL: label selection\n{result.stdout}{result.stderr}")
    result = subprocess.run([str(binary), "addresult"], capture_output=True, text=True)
    if result.returncode != 0:
        raise SystemExit(f"FAIL: add result shape\n{result.stdout}{result.stderr}")
    result = subprocess.run([str(binary), "updatelabel"], capture_output=True, text=True)
    if result.returncode != 0:
        raise SystemExit(f"FAIL: update label\n{result.stdout}{result.stderr}")
    result = subprocess.run([str(binary), "malformedlabel"], capture_output=True, text=True)
    if result.returncode != 0:
        raise SystemExit(f"FAIL: malformed label\n{result.stdout}{result.stderr}")
    result = subprocess.run([str(binary), "rename"], capture_output=True, text=True)
    if result.returncode != 0:
        raise SystemExit(f"FAIL: account rename\n{result.stdout}{result.stderr}")

    # The store limit is read from the same constant the write path uses, so
    # a second build with a small limit reaches it without writing a
    # megabyte. It has to keep the process name, because the shim only acts
    # inside wifid.
    small = work / "small"
    small.mkdir()
    small_store = small / "store.plist"
    small_binary = small / "wifitest"
    subprocess.run([
        "xcrun", "clang", *flags,
        "-DL8WIFI_MAXIMUM_STORE_BYTES=4096",
        f'-DL8WIFI_STORE_PATH="{small_store}"',
        str(harness_c),
        "-framework", "CoreFoundation", "-framework", "Security",
        "-o", str(small_binary),
    ], check=True)
    result = subprocess.run([str(small_binary), "oversize"], capture_output=True, text=True)
    if result.returncode != 0:
        raise SystemExit(f"FAIL: store limit\n{result.stdout}{result.stderr}")

    print("PASS: AirPort-only interception, foreign service and class pass through, "
          "add/copy/update/delete round-trip, marker-gated inertness, 0600 store, "
          "store path fits a device-sized thread stack, a bulk delete clears one "
          "keychain only, a malformed account selector is rejected, the "
          "synchronizable attribute and the label are part of the selection, an "
          "unreadable store is not overwritten, an add answers with the shape "
          "asked for")
