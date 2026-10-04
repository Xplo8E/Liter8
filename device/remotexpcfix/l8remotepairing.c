/*
 * l8remotepairing.dylib - narrow RemoteXPC keybag-state repair for Liter8.
 *
 * remotepairingdeviced already has a no-keybag path after the user accepts its
 * visible Trust dialog. On the SEP-less boot, MKBGetDeviceLockState(NULL)
 * returns 0 because the extended state buffer remains zero-filled, even though
 * the scalar MobileKeyBag probes report an unlocked, unprotected device.
 *
 * This interposer exposes the daemon's existing state-3 branch only when all
 * of the measured Liter8 conditions match. It also preserves the daemon's two
 * system-keychain item families in its own preference domain when securityd
 * accepts an add but cannot read it back on the SEP-less boot. Every other
 * call and process sees the original MobileKeyBag and Security behavior.
 * Removing the root-owned marker from SSHRD restores complete pass-through
 * behavior while the weak load remains.
 */

#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <dlfcn.h>
#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <syslog.h>
#include <unistd.h>

#define DYLD_INTERPOSE(_replacement, _replacee)                                  \
    __attribute__((used)) static struct {                                        \
        const void *replacement;                                                 \
        const void *replacee;                                                    \
    } _interpose_##_replacee __attribute__((section("__DATA,__interpose"))) = {  \
        (const void *)(unsigned long)&_replacement,                              \
        (const void *)(unsigned long)&_replacee                                  \
    };

extern int32_t MKBGetDeviceLockState(CFDictionaryRef options);
extern int MKBDeviceFormattedForContentProtection(void);
extern int MKBDeviceUnlockedSinceBoot(void);

static const char *kEnablePath =
    "/usr/lib/.liter8-remotepairing-fallback";
static atomic_flag gLoggedGuardState = ATOMIC_FLAG_INIT;
static pthread_mutex_t gStoreLock = PTHREAD_MUTEX_INITIALIZER;
static __thread bool gInsideSecurityHook;

static CFStringRef const kPreferencesDomain = CFSTR("com.apple.remotepairing");
static CFStringRef const kStoreKey =
    CFSTR("Liter8RemotePairingKeychainItems");
static CFStringRef const kRemotePairingAccessGroup =
    CFSTR("com.apple.RemotePairing");
static CFStringRef const kIdentityDescriptor =
    CFSTR("Remote Pairing Identity");
static CFStringRef const kPeerDescriptor =
    CFSTR("Remote Pairing Paired Peer");

enum {
    kMaximumFallbackItems = 64,
    kMaximumFallbackItemBytes = 128 * 1024,
};

static int fallback_marker_status(void)
{
    struct stat status;
    if (lstat(kEnablePath, &status) != 0) {
        return -errno;
    }
    return S_ISREG(status.st_mode) && status.st_uid == 0 &&
                   (status.st_mode & (S_IWGRP | S_IWOTH)) == 0
               ? 1
               : 0;
}

static bool is_remotepairingdeviced(void)
{
    const char *program = getprogname();
    return program != NULL && strcmp(program, "remotepairingdeviced") == 0;
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

static bool dictionary_has_descriptor(CFDictionaryRef dictionary,
                                      CFStringRef descriptor)
{
    return dictionary_value_equals(dictionary, kSecAttrService, descriptor) ||
           dictionary_value_equals(dictionary, kSecAttrDescription,
                                   descriptor) ||
           dictionary_value_equals(dictionary, kSecAttrLabel, descriptor);
}

static bool is_remote_pairing_dictionary(CFDictionaryRef dictionary)
{
    CFTypeRef system_keychain = private_security_constant("kSecUseSystemKeychain");
    if (dictionary == NULL ||
        CFGetTypeID(dictionary) != CFDictionaryGetTypeID() ||
        !dictionary_value_equals(dictionary, kSecClass,
                                 kSecClassGenericPassword) ||
        !dictionary_value_equals(dictionary, kSecAttrAccessGroup,
                                 kRemotePairingAccessGroup) ||
        !dictionary_value_equals(dictionary, system_keychain, kCFBooleanTrue)) {
        return false;
    }
    return dictionary_has_descriptor(dictionary, kIdentityDescriptor) ||
           dictionary_has_descriptor(dictionary, kPeerDescriptor);
}

static bool item_data_is_bounded(CFDictionaryRef item)
{
    CFTypeRef data = CFDictionaryGetValue(item, kSecValueData);
    return data == NULL ||
           (CFGetTypeID(data) == CFDataGetTypeID() &&
            CFDataGetLength((CFDataRef)data) <= kMaximumFallbackItemBytes);
}

static CFMutableArrayRef copy_stored_items(void)
{
    CFMutableArrayRef output = CFArrayCreateMutable(
        kCFAllocatorDefault, 0, &kCFTypeArrayCallBacks);
    if (output == NULL) {
        return NULL;
    }

    CFTypeRef stored = CFPreferencesCopyAppValue(kStoreKey, kPreferencesDomain);
    if (stored == NULL) {
        return output;
    }
    if (CFGetTypeID(stored) != CFArrayGetTypeID() ||
        CFArrayGetCount((CFArrayRef)stored) > kMaximumFallbackItems) {
        CFRelease(stored);
        return output;
    }

    CFIndex count = CFArrayGetCount((CFArrayRef)stored);
    for (CFIndex index = 0; index < count; index++) {
        CFTypeRef value = CFArrayGetValueAtIndex((CFArrayRef)stored, index);
        if (value != NULL && CFGetTypeID(value) == CFDictionaryGetTypeID() &&
            is_remote_pairing_dictionary((CFDictionaryRef)value) &&
            item_data_is_bounded((CFDictionaryRef)value)) {
            CFArrayAppendValue(output, value);
        }
    }
    CFRelease(stored);
    return output;
}

static bool save_stored_items(CFArrayRef items)
{
    if (items == NULL || CFArrayGetCount(items) > kMaximumFallbackItems) {
        return false;
    }
    CFPreferencesSetAppValue(kStoreKey, items, kPreferencesDomain);
    return CFPreferencesAppSynchronize(kPreferencesDomain);
}

static void remove_query_only_keys(CFMutableDictionaryRef dictionary)
{
    CFDictionaryRemoveValue(dictionary, kSecReturnAttributes);
    CFDictionaryRemoveValue(dictionary, kSecReturnData);
    CFDictionaryRemoveValue(dictionary, kSecReturnRef);
    CFDictionaryRemoveValue(dictionary, kSecMatchLimit);
}

static CFMutableDictionaryRef copy_normalized_item(CFDictionaryRef attributes)
{
    CFMutableDictionaryRef item = CFDictionaryCreateMutableCopy(
        kCFAllocatorDefault, 0, attributes);
    if (item == NULL) {
        return NULL;
    }
    remove_query_only_keys(item);

    CFDateRef now = CFDateCreate(kCFAllocatorDefault,
                                 CFAbsoluteTimeGetCurrent());
    if (now != NULL) {
        if (!CFDictionaryContainsKey(item, kSecAttrCreationDate)) {
            CFDictionarySetValue(item, kSecAttrCreationDate, now);
        }
        CFDictionarySetValue(item, kSecAttrModificationDate, now);
        CFRelease(now);
    }
    return item;
}

static bool item_matches_query(CFDictionaryRef item, CFDictionaryRef query)
{
    const CFTypeRef keys[] = {
        kSecClass,
        kSecAttrAccessGroup,
        kSecAttrAccount,
        kSecAttrService,
        kSecAttrDescription,
        kSecAttrLabel,
    };
    for (size_t index = 0; index < sizeof(keys) / sizeof(keys[0]); index++) {
        CFTypeRef expected = CFDictionaryGetValue(query, keys[index]);
        if (expected != NULL &&
            !dictionary_value_equals(item, keys[index], expected)) {
            return false;
        }
    }

    CFTypeRef system_keychain = private_security_constant("kSecUseSystemKeychain");
    CFTypeRef expected_system = system_keychain != NULL
                                    ? CFDictionaryGetValue(query, system_keychain)
                                    : NULL;
    return expected_system == NULL ||
           dictionary_value_equals(item, system_keychain, expected_system);
}

static bool query_requests(CFDictionaryRef query, CFTypeRef key)
{
    return dictionary_value_equals(query, key, kCFBooleanTrue);
}

static CFTypeRef copy_query_result(CFDictionaryRef item,
                                   bool return_attributes,
                                   bool return_data)
{
    if (!return_attributes && return_data) {
        CFTypeRef data = CFDictionaryGetValue(item, kSecValueData);
        return data != NULL ? CFRetain(data) : NULL;
    }

    CFMutableDictionaryRef result = CFDictionaryCreateMutableCopy(
        kCFAllocatorDefault, 0, item);
    if (result == NULL) {
        return NULL;
    }
    CFTypeRef system_keychain = private_security_constant("kSecUseSystemKeychain");
    if (system_keychain != NULL) {
        CFDictionaryRemoveValue(result, system_keychain);
    }
    if (!return_data) {
        CFDictionaryRemoveValue(result, kSecValueData);
    }
    return result;
}

static OSStatus copy_from_fallback(CFDictionaryRef query, CFTypeRef *result)
{
    bool return_attributes = query_requests(query, kSecReturnAttributes);
    bool return_data = query_requests(query, kSecReturnData);
    bool match_all = dictionary_value_equals(query, kSecMatchLimit,
                                              kSecMatchLimitAll);

    CFMutableArrayRef items = copy_stored_items();
    if (items == NULL) {
        return errSecAllocate;
    }
    CFMutableArrayRef matches = CFArrayCreateMutable(
        kCFAllocatorDefault, 0, &kCFTypeArrayCallBacks);
    if (matches == NULL) {
        CFRelease(items);
        return errSecAllocate;
    }

    CFIndex count = CFArrayGetCount(items);
    for (CFIndex index = 0; index < count; index++) {
        CFDictionaryRef item =
            (CFDictionaryRef)CFArrayGetValueAtIndex(items, index);
        if (!item_matches_query(item, query)) {
            continue;
        }
        CFTypeRef value = copy_query_result(item, return_attributes,
                                            return_data);
        if (value != NULL) {
            CFArrayAppendValue(matches, value);
            CFRelease(value);
        }
        if (!match_all) {
            break;
        }
    }
    CFRelease(items);

    if (CFArrayGetCount(matches) == 0) {
        CFRelease(matches);
        return errSecItemNotFound;
    }
    if (result != NULL) {
        if (match_all) {
            *result = matches;
        } else {
            *result = CFRetain(CFArrayGetValueAtIndex(matches, 0));
            CFRelease(matches);
        }
    } else {
        CFRelease(matches);
    }
    return errSecSuccess;
}

static bool store_fallback_item(CFDictionaryRef attributes)
{
    CFMutableDictionaryRef item = copy_normalized_item(attributes);
    if (item == NULL || !item_data_is_bounded(item)) {
        if (item != NULL) {
            CFRelease(item);
        }
        return false;
    }

    CFMutableArrayRef items = copy_stored_items();
    if (items == NULL) {
        CFRelease(item);
        return false;
    }
    for (CFIndex index = CFArrayGetCount(items); index > 0; index--) {
        CFDictionaryRef existing =
            (CFDictionaryRef)CFArrayGetValueAtIndex(items, index - 1);
        if (item_matches_query(existing, item)) {
            CFArrayRemoveValueAtIndex(items, index - 1);
        }
    }
    bool success = CFArrayGetCount(items) < kMaximumFallbackItems;
    if (success) {
        CFArrayAppendValue(items, item);
        success = save_stored_items(items);
    }
    CFRelease(items);
    CFRelease(item);
    return success;
}

static CFIndex update_fallback_items(CFDictionaryRef query,
                                     CFDictionaryRef attributes)
{
    CFMutableArrayRef items = copy_stored_items();
    if (items == NULL) {
        return 0;
    }
    CFIndex updated = 0;
    CFIndex count = CFArrayGetCount(items);
    for (CFIndex index = 0; index < count; index++) {
        CFDictionaryRef existing =
            (CFDictionaryRef)CFArrayGetValueAtIndex(items, index);
        if (!item_matches_query(existing, query)) {
            continue;
        }
        CFMutableDictionaryRef replacement = CFDictionaryCreateMutableCopy(
            kCFAllocatorDefault, 0, existing);
        if (replacement == NULL) {
            continue;
        }
        CFIndex attribute_count = CFDictionaryGetCount(attributes);
        const void **keys = calloc((size_t)attribute_count, sizeof(*keys));
        const void **values = calloc((size_t)attribute_count, sizeof(*values));
        if (keys != NULL && values != NULL) {
            CFDictionaryGetKeysAndValues(attributes, keys, values);
            for (CFIndex attribute = 0; attribute < attribute_count;
                 attribute++) {
                CFDictionarySetValue(replacement, keys[attribute],
                                     values[attribute]);
            }
            remove_query_only_keys(replacement);
            CFDateRef now = CFDateCreate(kCFAllocatorDefault,
                                         CFAbsoluteTimeGetCurrent());
            if (now != NULL) {
                CFDictionarySetValue(replacement, kSecAttrModificationDate, now);
                CFRelease(now);
            }
            if (item_data_is_bounded(replacement)) {
                CFArraySetValueAtIndex(items, index, replacement);
                updated++;
            }
        }
        free(keys);
        free(values);
        CFRelease(replacement);
    }
    bool saved = updated != 0 && save_stored_items(items);
    CFRelease(items);
    return saved ? updated : 0;
}

static CFIndex delete_fallback_items(CFDictionaryRef query)
{
    CFMutableArrayRef items = copy_stored_items();
    if (items == NULL) {
        return 0;
    }
    CFIndex deleted = 0;
    for (CFIndex index = CFArrayGetCount(items); index > 0; index--) {
        CFDictionaryRef item =
            (CFDictionaryRef)CFArrayGetValueAtIndex(items, index - 1);
        if (item_matches_query(item, query)) {
            CFArrayRemoveValueAtIndex(items, index - 1);
            deleted++;
        }
    }
    bool saved = deleted != 0 && save_stored_items(items);
    CFRelease(items);
    return saved ? deleted : 0;
}

static bool security_fallback_applies(CFDictionaryRef dictionary)
{
    return !gInsideSecurityHook && is_remotepairingdeviced() &&
           fallback_marker_status() == 1 &&
           is_remote_pairing_dictionary(dictionary);
}

static OSStatus l8_SecItemCopyMatching(CFDictionaryRef query, CFTypeRef *result)
{
    if (!security_fallback_applies(query)) {
        return SecItemCopyMatching(query, result);
    }

    gInsideSecurityHook = true;
    OSStatus status = SecItemCopyMatching(query, result);
    if (status == errSecItemNotFound || status == errSecInteractionNotAllowed) {
        pthread_mutex_lock(&gStoreLock);
        status = copy_from_fallback(query, result);
        pthread_mutex_unlock(&gStoreLock);
        if (status == errSecSuccess) {
            syslog(LOG_NOTICE,
                   "l8remotepairing: restored RemotePairing keychain item");
        }
    }
    gInsideSecurityHook = false;
    return status;
}

static OSStatus l8_SecItemAdd(CFDictionaryRef attributes, CFTypeRef *result)
{
    if (!security_fallback_applies(attributes)) {
        return SecItemAdd(attributes, result);
    }

    gInsideSecurityHook = true;
    OSStatus status = SecItemAdd(attributes, result);
    pthread_mutex_lock(&gStoreLock);
    bool stored = store_fallback_item(attributes);
    pthread_mutex_unlock(&gStoreLock);
    gInsideSecurityHook = false;
    if (stored) {
        syslog(LOG_NOTICE,
               "l8remotepairing: persisted RemotePairing keychain item");
        return errSecSuccess;
    }
    return status;
}

static OSStatus l8_SecItemUpdate(CFDictionaryRef query,
                                 CFDictionaryRef attributes_to_update)
{
    if (!security_fallback_applies(query)) {
        return SecItemUpdate(query, attributes_to_update);
    }

    gInsideSecurityHook = true;
    OSStatus status = SecItemUpdate(query, attributes_to_update);
    pthread_mutex_lock(&gStoreLock);
    CFIndex updated = update_fallback_items(query, attributes_to_update);
    pthread_mutex_unlock(&gStoreLock);
    gInsideSecurityHook = false;
    if (updated != 0) {
        syslog(LOG_NOTICE,
               "l8remotepairing: updated RemotePairing keychain item");
        return errSecSuccess;
    }
    return status;
}

static OSStatus l8_SecItemDelete(CFDictionaryRef query)
{
    if (!security_fallback_applies(query)) {
        return SecItemDelete(query);
    }

    gInsideSecurityHook = true;
    OSStatus status = SecItemDelete(query);
    pthread_mutex_lock(&gStoreLock);
    CFIndex deleted = delete_fallback_items(query);
    pthread_mutex_unlock(&gStoreLock);
    gInsideSecurityHook = false;
    if (deleted != 0) {
        syslog(LOG_NOTICE,
               "l8remotepairing: deleted RemotePairing keychain item");
        return errSecSuccess;
    }
    return status;
}

/* References originating in the interposer image resolve to the original
 * MobileKeyBag implementations, matching the proven l8pair interpose model. */
static int32_t l8_MKBGetDeviceLockState(CFDictionaryRef options)
{
    int32_t state = MKBGetDeviceLockState(options);
    if (!is_remotepairingdeviced()) {
        return state;
    }

    int marker = fallback_marker_status();
    int formatted = -1;
    int unlocked = -1;
    if (marker == 1 && options == NULL && state == 0) {
        formatted = MKBDeviceFormattedForContentProtection();
        unlocked = MKBDeviceUnlockedSinceBoot();
    }

    if (!atomic_flag_test_and_set_explicit(&gLoggedGuardState,
                                            memory_order_relaxed)) {
        syslog(LOG_NOTICE,
               "l8remotepairing: guard state=%d null_options=%d marker=%d "
               "formatted=%d unlocked=%d",
               state, options == NULL, marker, formatted, unlocked);
    }

    if (marker != 1 || options != NULL || state != 0 || formatted != 0 ||
        unlocked != 1) {
        return state;
    }

    syslog(LOG_NOTICE,
           "l8remotepairing: reporting disabled keybag state after explicit Trust");
    return 3;
}

DYLD_INTERPOSE(l8_MKBGetDeviceLockState, MKBGetDeviceLockState)
DYLD_INTERPOSE(l8_SecItemCopyMatching, SecItemCopyMatching)
DYLD_INTERPOSE(l8_SecItemAdd, SecItemAdd)
DYLD_INTERPOSE(l8_SecItemUpdate, SecItemUpdate)
DYLD_INTERPOSE(l8_SecItemDelete, SecItemDelete)
