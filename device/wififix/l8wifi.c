/*
 * l8wifi.dylib - narrow AirPort credential store for SEP-less Liter8.
 *
 * The no-content-protection profile leaves the system keychain unable to
 * retain the generic-password records that carry a Wi-Fi network password.
 * wifid can therefore read and write the item but the device forgets it on
 * the next boot, so a password-protected network has to be typed again.
 *
 * This interposer is intentionally dormant unless an operator-created marker
 * exists on the System volume. When active, it handles exactly one class of
 * keychain item:
 *
 *   service       AirPort
 *   item class    kSecClassGenericPassword
 *
 * Everything else goes to the original implementation, including every other
 * service, every other item class, and any item whose account is absent when
 * the caller wanted a single record rather than an enumeration. Removing the
 * marker restores complete pass-through behavior even though wifid still
 * weak-loads this dylib.
 *
 * The store is a binary property list on the Data volume holding the same
 * bytes the keychain would have held. It is protected only by Unix mode
 * 0600, not by SEP or keychain encryption: this is an explicit security
 * tradeoff of the experimental SEP-less system, and it is the same tradeoff
 * the pairing fallback already makes for the lockdownd RSA key.
 *
 * Design notes that matter for review:
 *
 *   - The shim interposes the four public SecItem entry points only. The
 *     private WiFiSecurity* helpers wifid also resolves are not touched.
 *   - The two known wifid builds (22H374 and an iOS 27 build) both import
 *     kSecUseSystemKeychain, so a record's system-keychain selection is part
 *     of its identity and is kept in the store key.
 *   - Calls to a replacee originating in the interposer image resolve to the
 *     real implementation, the same dyld interpose pattern l8pair uses. The
 *     re-entrancy guard below is belt and braces for that.
 */

#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <syslog.h>
#include <unistd.h>

/* Overridable so a test can compile this source into a harness that calls
 * the hooks directly, without dyld interposition. */
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

/* On the System volume beside the dylib, like the other Liter8 shims. The
 * System volume is sealed at boot, so the marker is written during
 * provisioning and survives every reboot. */
#ifndef L8WIFI_ENABLE_PATH
#define L8WIFI_ENABLE_PATH "/usr/lib/.liter8-wifi-credentials"
#endif

/* On the Data volume, because the System volume is read-only once the device
 * has booted and wifid has to write here at runtime. */
#ifndef L8WIFI_STORE_PATH
#define L8WIFI_STORE_PATH \
    "/private/var/preferences/SystemConfiguration/com.liter8.wifi-passwords.plist"
#endif

/* The daemon this shim belongs to. The dylib is weak-loaded into wifid alone,
 * but the check is repeated here so a copy that reaches another process
 * stays inert. */
#ifndef L8WIFI_TARGET_PROGRAM
#define L8WIFI_TARGET_PROGRAM "wifid"
#endif

/* The marker must be owned by root, so an unprivileged process cannot
 * enable the shim and start capturing keychain traffic. Compiled in as an
 * override so a test can exercise the logic without root. */
#ifndef L8WIFI_MARKER_UID
#define L8WIFI_MARKER_UID 0
#endif

static const char *kEnablePath = L8WIFI_ENABLE_PATH;
static const char *kStorePath = L8WIFI_STORE_PATH;

enum { kMaximumStoreBytes = 1024 * 1024 };

static pthread_mutex_t gStoreLock = PTHREAD_MUTEX_INITIALIZER;
static __thread bool gInsideHook;

static bool fallback_enabled(void)
{
    struct stat status;
    if (lstat(kEnablePath, &status) != 0) {
        return false;
    }
    return S_ISREG(status.st_mode) && status.st_uid == L8WIFI_MARKER_UID &&
           (status.st_mode & (S_IWGRP | S_IWOTH)) == 0;
}

static bool is_wifid(void)
{
    const char *program = getprogname();
    return program != NULL && strcmp(program, L8WIFI_TARGET_PROGRAM) == 0;
}

static CFTypeRef private_security_constant(const char *name)
{
    const CFTypeRef *address = (const CFTypeRef *)dlsym(RTLD_DEFAULT, name);
    return address != NULL ? *address : NULL;
}

static bool dictionary_value_equals(CFDictionaryRef dictionary,
                                    CFTypeRef key,
                                    CFTypeRef expected)
{
    if (dictionary == NULL || key == NULL || expected == NULL) {
        return false;
    }
    CFTypeRef value = CFDictionaryGetValue(dictionary, key);
    return value != NULL && CFEqual(value, expected);
}

static bool dictionary_bool(CFDictionaryRef dictionary, CFTypeRef key)
{
    return dictionary_value_equals(dictionary, key, kCFBooleanTrue);
}

/* The AirPort generic-password item, and nothing else. A query without an
 * item class is accepted because the callers that enumerate known networks
 * omit it; a query for any other class is not ours. */
static bool is_airport_password_query(CFDictionaryRef query)
{
    if (query == NULL || CFGetTypeID(query) != CFDictionaryGetTypeID()) {
        return false;
    }
    if (!dictionary_value_equals(query, kSecAttrService, CFSTR("AirPort"))) {
        return false;
    }
    CFTypeRef item_class = CFDictionaryGetValue(query, kSecClass);
    return item_class == NULL ||
           dictionary_value_equals(query, kSecClass, kSecClassGenericPassword);
}

static CFStringRef query_account(CFDictionaryRef query)
{
    CFTypeRef value = query == NULL ? NULL : CFDictionaryGetValue(query, kSecAttrAccount);
    return value != NULL && CFGetTypeID(value) == CFStringGetTypeID()
               ? (CFStringRef)value
               : NULL;
}

/* Whether the caller asked for the system keychain rather than a per-user
 * one. wifid imports kSecUseSystemKeychain on every known build, and the
 * two are different records, so the answer is part of the store key. */
static bool query_system_keychain(CFDictionaryRef query)
{
    CFTypeRef constant = private_security_constant("kSecUseSystemKeychain");
    if (constant == NULL) {
        return false;
    }
    return dictionary_value_equals(query, constant, kCFBooleanTrue);
}

/* The separator keeps an account and a system flag from colliding in one
 * flat key space. */
static CFStringRef store_key(CFStringRef account, bool system)
{
    return CFStringCreateWithFormat(kCFAllocatorDefault, NULL, CFSTR("%@\x1f%d"),
                                    account, system ? 1 : 0);
}

static CFDataRef read_store_bytes(void)
{
    int descriptor = open(kStorePath, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (descriptor < 0) {
        return NULL;
    }

    struct stat status;
    /* The store must be ours alone: owned by root, which is what wifid runs
     * as on the device, or by this process, and never group or other
     * accessible. */
    if (fstat(descriptor, &status) != 0 || !S_ISREG(status.st_mode) ||
        (status.st_uid != 0 && status.st_uid != geteuid()) ||
        (status.st_mode & (S_IRWXG | S_IRWXO)) != 0 ||
        status.st_size <= 0 || status.st_size > kMaximumStoreBytes) {
        close(descriptor);
        return NULL;
    }

    uint8_t bytes[kMaximumStoreBytes];
    size_t total = 0;
    while (total < (size_t)status.st_size) {
        ssize_t amount = read(descriptor, bytes + total,
                              (size_t)status.st_size - total);
        if (amount <= 0) {
            close(descriptor);
            return NULL;
        }
        total += (size_t)amount;
    }
    close(descriptor);
    return CFDataCreate(kCFAllocatorDefault, bytes, (CFIndex)total);
}

static CFMutableDictionaryRef load_store(void)
{
    CFDataRef bytes = read_store_bytes();
    if (bytes == NULL) {
        return CFDictionaryCreateMutable(kCFAllocatorDefault, 0,
                                         &kCFTypeDictionaryKeyCallBacks,
                                         &kCFTypeDictionaryValueCallBacks);
    }

    CFErrorRef error = NULL;
    CFPropertyListRef property_list = CFPropertyListCreateWithData(
        kCFAllocatorDefault, bytes, kCFPropertyListMutableContainersAndLeaves,
        NULL, &error);
    CFRelease(bytes);
    if (error != NULL) {
        CFRelease(error);
    }

    if (property_list == NULL ||
        CFGetTypeID(property_list) != CFDictionaryGetTypeID()) {
        if (property_list != NULL) {
            CFRelease(property_list);
        }
        syslog(LOG_ERR, "l8wifi: credential store is invalid");
        return NULL;
    }
    return (CFMutableDictionaryRef)property_list;
}

static bool write_all(int descriptor, const uint8_t *bytes, size_t length)
{
    size_t total = 0;
    while (total < length) {
        ssize_t amount = write(descriptor, bytes + total, length - total);
        if (amount <= 0) {
            return false;
        }
        total += (size_t)amount;
    }
    return true;
}

/* The write is atomic: a reader never sees a half-written store, and a
 * crash mid-write leaves the previous store intact. */
static bool write_store(CFDictionaryRef store)
{
    CFErrorRef error = NULL;
    CFDataRef bytes = CFPropertyListCreateData(
        kCFAllocatorDefault, store, kCFPropertyListBinaryFormat_v1_0, 0, &error);
    if (error != NULL) {
        CFRelease(error);
    }
    if (bytes == NULL) {
        return false;
    }

    char temporary[PATH_MAX];
    if (snprintf(temporary, sizeof(temporary), "%s.tmp.%d", kStorePath,
                 getpid()) <= 0) {
        CFRelease(bytes);
        return false;
    }

    unlink(temporary);
    int descriptor = open(temporary,
                          O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
                          S_IRUSR | S_IWUSR);
    bool success = descriptor >= 0 &&
                   write_all(descriptor, CFDataGetBytePtr(bytes),
                             (size_t)CFDataGetLength(bytes)) &&
                   fsync(descriptor) == 0;
    if (descriptor >= 0) {
        close(descriptor);
    }
    if (success) {
        success = chmod(temporary, S_IRUSR | S_IWUSR) == 0 &&
                  rename(temporary, kStorePath) == 0;
    }
    if (!success) {
        unlink(temporary);
    }
    CFRelease(bytes);
    return success;
}

static CFMutableDictionaryRef new_entry(CFStringRef account, CFDataRef data,
                                        bool synchronizable, bool system)
{
    CFMutableDictionaryRef entry = CFDictionaryCreateMutable(
        kCFAllocatorDefault, 0, &kCFTypeDictionaryKeyCallBacks,
        &kCFTypeDictionaryValueCallBacks);
    if (entry == NULL) {
        return NULL;
    }
    CFDateRef now = CFDateCreate(kCFAllocatorDefault, CFAbsoluteTimeGetCurrent());
    CFDictionarySetValue(entry, CFSTR("account"), account);
    CFDictionarySetValue(entry, CFSTR("data"), data);
    CFDictionarySetValue(entry, CFSTR("synchronizable"),
                         synchronizable ? kCFBooleanTrue : kCFBooleanFalse);
    CFDictionarySetValue(entry, CFSTR("system"),
                         system ? kCFBooleanTrue : kCFBooleanFalse);
    if (now != NULL) {
        CFDictionarySetValue(entry, CFSTR("modified"), now);
        CFRelease(now);
    }
    return entry;
}

static CFDictionaryRef find_entry(CFDictionaryRef store, CFStringRef key)
{
    if (store == NULL || key == NULL) {
        return NULL;
    }
    CFTypeRef value = CFDictionaryGetValue(store, key);
    return value != NULL && CFGetTypeID(value) == CFDictionaryGetTypeID()
               ? (CFDictionaryRef)value
               : NULL;
}

/* The attributes a caller is allowed to see for one stored record. The
 * password itself is included only when it asked for the data. */
static CFMutableDictionaryRef result_attributes(CFDictionaryRef entry,
                                                bool wants_data)
{
    CFMutableDictionaryRef result = CFDictionaryCreateMutable(
        kCFAllocatorDefault, 0, &kCFTypeDictionaryKeyCallBacks,
        &kCFTypeDictionaryValueCallBacks);
    if (result == NULL) {
        return NULL;
    }
    CFTypeRef account = CFDictionaryGetValue(entry, CFSTR("account"));
    CFTypeRef data = CFDictionaryGetValue(entry, CFSTR("data"));
    CFTypeRef synchronizable = CFDictionaryGetValue(entry, CFSTR("synchronizable"));
    CFTypeRef modified = CFDictionaryGetValue(entry, CFSTR("modified"));
    CFDictionarySetValue(result, kSecClass, kSecClassGenericPassword);
    CFDictionarySetValue(result, kSecAttrService, CFSTR("AirPort"));
    if (account != NULL) {
        CFDictionarySetValue(result, kSecAttrAccount, account);
    }
    if (synchronizable != NULL) {
        CFDictionarySetValue(result, kSecAttrSynchronizable, synchronizable);
    }
    if (modified != NULL) {
        CFDictionarySetValue(result, kSecAttrModificationDate, modified);
    }
    if (wants_data && data != NULL) {
        CFDictionarySetValue(result, kSecValueData, data);
    }
    return result;
}

/* Store one AirPort credential. The account and the password are both
 * required: a record without a password has nothing to keep. */
static OSStatus store_credential(CFDictionaryRef query, CFDataRef data,
                                 bool synchronizable)
{
    CFStringRef account = query_account(query);
    if (account == NULL || data == NULL) {
        return errSecParam;
    }
    bool system = query_system_keychain(query);

    pthread_mutex_lock(&gStoreLock);
    CFMutableDictionaryRef store = load_store();
    CFStringRef key = store_key(account, system);
    OSStatus status = errSecNotAvailable;
    if (store != NULL && key != NULL) {
        CFMutableDictionaryRef entry =
            new_entry(account, data, synchronizable, system);
        if (entry != NULL) {
            CFDictionarySetValue(store, key, entry);
            status = write_store(store) ? errSecSuccess : errSecNotAvailable;
            CFRelease(entry);
        }
    }
    if (key != NULL) {
        CFRelease(key);
    }
    if (store != NULL) {
        CFRelease(store);
    }
    pthread_mutex_unlock(&gStoreLock);

    if (status == errSecSuccess) {
        syslog(LOG_NOTICE, "l8wifi: stored one AirPort credential");
    } else {
        syslog(LOG_ERR, "l8wifi: could not store the AirPort credential");
    }
    return status;
}

static OSStatus l8_SecItemCopyMatching(CFDictionaryRef query, CFTypeRef *result)
{
    if (gInsideHook || !fallback_enabled() || !is_wifid() ||
        !is_airport_password_query(query)) {
        return SecItemCopyMatching(query, result);
    }
    if (result != NULL) {
        *result = NULL;
    }

    bool wants_data = dictionary_bool(query, kSecReturnData);
    bool wants_attributes = dictionary_bool(query, kSecReturnAttributes);
    bool enumerates = dictionary_value_equals(query, kSecMatchLimit,
                                              kSecMatchLimitAll);
    CFStringRef account = query_account(query);
    bool system = query_system_keychain(query);

    gInsideHook = true;
    pthread_mutex_lock(&gStoreLock);
    CFMutableDictionaryRef store = load_store();
    CFTypeRef produced = NULL;
    if (store != NULL && account != NULL) {
        CFStringRef key = store_key(account, system);
        CFDictionaryRef entry = find_entry(store, key);
        if (entry != NULL) {
            if (wants_attributes) {
                produced = result_attributes(entry, wants_data);
            } else if (wants_data) {
                CFTypeRef data = CFDictionaryGetValue(entry, CFSTR("data"));
                if (data != NULL && CFGetTypeID(data) == CFDataGetTypeID()) {
                    produced = CFRetain(data);
                }
            }
        }
        if (key != NULL) {
            CFRelease(key);
        }
    } else if (store != NULL && account == NULL && wants_attributes && enumerates) {
        /* The known-networks sweep asks for every AirPort record at once. */
        CFIndex count = CFDictionaryGetCount(store);
        const void **values = count ? calloc((size_t)count, sizeof(*values)) : NULL;
        CFMutableArrayRef array = CFArrayCreateMutable(kCFAllocatorDefault, 0,
                                                        &kCFTypeArrayCallBacks);
        if (values != NULL && array != NULL) {
            CFDictionaryGetKeysAndValues(store, NULL, values);
            for (CFIndex index = 0; index < count; index++) {
                if (CFGetTypeID(values[index]) != CFDictionaryGetTypeID()) {
                    continue;
                }
                if (system && !dictionary_bool((CFDictionaryRef)values[index],
                                              CFSTR("system"))) {
                    continue;
                }
                CFDictionaryRef attributes =
                    result_attributes((CFDictionaryRef)values[index], wants_data);
                if (attributes != NULL) {
                    CFArrayAppendValue(array, attributes);
                    CFRelease(attributes);
                }
            }
            if (CFArrayGetCount(array) != 0) {
                produced = array;
            } else {
                CFRelease(array);
            }
        } else if (array != NULL) {
            CFRelease(array);
        }
        free(values);
    }
    if (store != NULL) {
        CFRelease(store);
    }
    pthread_mutex_unlock(&gStoreLock);
    gInsideHook = false;

    if (produced == NULL) {
        return SecItemCopyMatching(query, result);
    }
    if (result != NULL) {
        *result = produced;
    } else {
        CFRelease(produced);
    }
    return errSecSuccess;
}

static OSStatus l8_SecItemAdd(CFDictionaryRef attributes, CFTypeRef *result)
{
    if (gInsideHook || !fallback_enabled() || !is_wifid() ||
        !is_airport_password_query(attributes)) {
        return SecItemAdd(attributes, result);
    }
    if (result != NULL) {
        *result = NULL;
    }

    CFTypeRef data = CFDictionaryGetValue(attributes, kSecValueData);
    if (data == NULL || CFGetTypeID(data) != CFDataGetTypeID()) {
        return SecItemAdd(attributes, result);
    }

    gInsideHook = true;
    OSStatus status = store_credential(attributes, (CFDataRef)data,
                                        dictionary_bool(attributes,
                                                       kSecAttrSynchronizable));
    gInsideHook = false;
    if (status != errSecSuccess) {
        return status;
    }
    if (result != NULL) {
        *result = CFRetain(data);
    }
    return errSecSuccess;
}

static OSStatus l8_SecItemUpdate(CFDictionaryRef query,
                                 CFDictionaryRef attributes_to_update)
{
    if (gInsideHook || !fallback_enabled() || !is_wifid() ||
        !is_airport_password_query(query)) {
        return SecItemUpdate(query, attributes_to_update);
    }

    CFTypeRef data = attributes_to_update == NULL
                         ? NULL
                         : CFDictionaryGetValue(attributes_to_update, kSecValueData);
    if (data == NULL || CFGetTypeID(data) != CFDataGetTypeID()) {
        return SecItemUpdate(query, attributes_to_update);
    }

    gInsideHook = true;
    OSStatus status = store_credential(query, (CFDataRef)data,
                                        dictionary_bool(query,
                                                       kSecAttrSynchronizable));
    gInsideHook = false;
    return status;
}

static OSStatus l8_SecItemDelete(CFDictionaryRef query)
{
    if (gInsideHook || !fallback_enabled() || !is_wifid() ||
        !is_airport_password_query(query)) {
        return SecItemDelete(query);
    }

    CFStringRef account = query_account(query);
    bool system = query_system_keychain(query);

    gInsideHook = true;
    pthread_mutex_lock(&gStoreLock);
    CFMutableDictionaryRef store = load_store();
    bool removed = false;
    bool written = false;
    if (store != NULL) {
        if (account != NULL) {
            CFStringRef key = store_key(account, system);
            if (key != NULL && CFDictionaryContainsKey(store, key)) {
                CFDictionaryRemoveValue(store, key);
                removed = true;
                written = write_store(store);
            }
            if (key != NULL) {
                CFRelease(key);
            }
        } else {
            removed = CFDictionaryGetCount(store) != 0;
            CFDictionaryRemoveAllValues(store);
            written = !removed || write_store(store);
        }
    }
    if (store != NULL) {
        CFRelease(store);
    }
    pthread_mutex_unlock(&gStoreLock);
    gInsideHook = false;

    if (!removed) {
        return SecItemDelete(query);
    }
    if (!written) {
        syslog(LOG_ERR, "l8wifi: could not rewrite the credential store");
        return errSecNotAvailable;
    }
    syslog(LOG_NOTICE, "l8wifi: removed an AirPort credential");
    return errSecSuccess;
}

__attribute__((constructor)) static void l8wifi_loaded(void)
{
    if (!is_wifid()) {
        return;
    }
    syslog(LOG_NOTICE, "l8wifi: AirPort credential shim loaded");
}

DYLD_INTERPOSE(l8_SecItemCopyMatching, SecItemCopyMatching)
DYLD_INTERPOSE(l8_SecItemAdd, SecItemAdd)
DYLD_INTERPOSE(l8_SecItemUpdate, SecItemUpdate)
DYLD_INTERPOSE(l8_SecItemDelete, SecItemDelete)
