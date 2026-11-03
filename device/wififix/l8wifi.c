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
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
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

/* The largest store the shim will read. A write that would produce a larger
 * one is refused, so the store never becomes unreadable. Overridable so a
 * test can reach the limit without writing a megabyte. */
#ifndef L8WIFI_MAXIMUM_STORE_BYTES
#define L8WIFI_MAXIMUM_STORE_BYTES (1024 * 1024)
#endif

enum { kMaximumStoreBytes = L8WIFI_MAXIMUM_STORE_BYTES };

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

/* An attribute the shim cannot act on faithfully is a request the caller got
 * wrong. The real keychain rejects it, and so does the shim: passing it
 * through keeps the stock behaviour and stops a malformed attribute from
 * being read as an absent one, which would turn a single wrong call into a
 * bulk one.
 *
 * A query is a set of attributes and an update names the attributes it
 * replaces, so the same check covers both. */
static bool attributes_malformed(CFDictionaryRef attributes)
{
    if (attributes == NULL) {
        return false;
    }
    if (CFGetTypeID(attributes) != CFDictionaryGetTypeID()) {
        return true;
    }
    CFTypeRef account = CFDictionaryGetValue(attributes, kSecAttrAccount);
    if (account != NULL && CFGetTypeID(account) != CFStringGetTypeID()) {
        return true;
    }
    CFTypeRef synchronizable =
        CFDictionaryGetValue(attributes, kSecAttrSynchronizable);
    if (synchronizable != NULL &&
        CFGetTypeID(synchronizable) != CFBooleanGetTypeID()) {
        return true;
    }
    /* A label that is present but is not a string reads as an absent label
     * everywhere else, which would turn a malformed request into a bulk one. */
    CFTypeRef label = CFDictionaryGetValue(attributes, kSecAttrLabel);
    return label != NULL && CFGetTypeID(label) != CFStringGetTypeID();
}

/* The synchronizable attribute is part of how the keychain matches a record.
 * A query without the attribute matches every record; a query that carries
 * it matches only the records with that value. */
static bool query_accepts_synchronizable(CFDictionaryRef query,
                                          bool synchronizable)
{
    CFTypeRef value =
        query == NULL ? NULL : CFDictionaryGetValue(query, kSecAttrSynchronizable);
    if (value == NULL) {
        return true;
    }
    return CFEqual(value, synchronizable ? kCFBooleanTrue : kCFBooleanFalse);
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
 * flat key space.
 *
 * The key is the record's identity, and it matches the keychain's own. For
 * a generic password the primary key is the account and the service, so one
 * keychain holds one record for an account, and the synchronizable
 * attribute is a property of that record rather than part of its identity.
 * The system-keychain selection is the other half, because the system
 * keychain and a per-user one are different keychains with their own
 * records.
 *
 * A second add for an account therefore replaces the record, where the
 * keychain would answer errSecDuplicateItem. That divergence is deliberate:
 * this store lives on the Data volume and survives a reboot, while the
 * keychain it stands in for does not, so refusing the add would make
 * wifid's re-add after a reboot fail in a way it never sees against the
 * real keychain. Replacing the record keeps the newest password, which is
 * what the caller asked for. */
static CFStringRef store_key(CFStringRef account, bool system)
{
    return CFStringCreateWithFormat(kCFAllocatorDefault, NULL, CFSTR("%@\x1f%d"),
                                    account, system ? 1 : 0);
}

/* Why the store could not be read. The difference is the whole point: an
 * absent store is an empty store, but an unreadable one is a store that
 * exists and holds every saved password. Reading it as empty would let the
 * next write replace it and lose all of them. */
enum {
    kStoreReadable = 0,
    kStoreAbsent,
    kStoreUnreadable,
};

static int read_store_bytes(CFDataRef *bytes_out)
{
    int descriptor = open(kStorePath, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (descriptor < 0) {
        return errno == ENOENT ? kStoreAbsent : kStoreUnreadable;
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
        return kStoreUnreadable;
    }

    /* The buffer is heap, not stack. wifid reaches the keychain from a GCD
     * worker queue whose stack is a fraction of kMaximumStoreBytes, and a
     * 1 MiB automatic array overflowed it: the first AirPort query trapped
     * in __chkstk_darwin and killed wifid, which launchd then restarted into
     * the same trap. A stack limit that only the host's 8 MiB main thread
     * could absorb is a limit the device never has. */
    uint8_t *bytes = malloc((size_t)status.st_size);
    if (bytes == NULL) {
        close(descriptor);
        return kStoreUnreadable;
    }
    size_t total = 0;
    while (total < (size_t)status.st_size) {
        ssize_t amount = read(descriptor, bytes + total,
                              (size_t)status.st_size - total);
        if (amount <= 0) {
            free(bytes);
            close(descriptor);
            return kStoreUnreadable;
        }
        total += (size_t)amount;
    }
    close(descriptor);
    CFDataRef data = CFDataCreate(kCFAllocatorDefault, bytes, (CFIndex)total);
    free(bytes);
    if (data == NULL) {
        return kStoreUnreadable;
    }
    *bytes_out = data;
    return kStoreReadable;
}

static CFMutableDictionaryRef load_store(void)
{
    CFDataRef bytes = NULL;
    int state = read_store_bytes(&bytes);
    if (state == kStoreAbsent) {
        /* There is no store yet, so an empty one is the right answer. */
        return CFDictionaryCreateMutable(kCFAllocatorDefault, 0,
                                         &kCFTypeDictionaryKeyCallBacks,
                                         &kCFTypeDictionaryValueCallBacks);
    }
    if (state != kStoreReadable) {
        /* The store exists and cannot be read. Treating it as empty would
         * let the next write replace it and lose every saved password, so
         * the failure is propagated and nothing is written. */
        syslog(LOG_ERR, "l8wifi: the credential store could not be read");
        return NULL;
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
    /* The reader rejects a store above kMaximumStoreBytes, so a write that
     * would produce one must be refused. Publishing it would make every
     * saved password unreadable, and the store could not be shrunk again
     * because loading it fails first. */
    if ((size_t)CFDataGetLength(bytes) > kMaximumStoreBytes) {
        syslog(LOG_ERR, "l8wifi: the credential store would exceed its limit");
        CFRelease(bytes);
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
                                        bool synchronizable, bool system,
                                        CFStringRef label)
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
    if (label != NULL) {
        CFDictionarySetValue(entry, CFSTR("label"), label);
    }
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
    CFTypeRef label = CFDictionaryGetValue(entry, CFSTR("label"));
    CFDictionarySetValue(result, kSecClass, kSecClassGenericPassword);
    CFDictionarySetValue(result, kSecAttrService, CFSTR("AirPort"));
    if (account != NULL) {
        CFDictionarySetValue(result, kSecAttrAccount, account);
    }
    if (label != NULL) {
        CFDictionarySetValue(result, kSecAttrLabel, label);
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

/* The label the caller gave the record. A query can match on it, so it is
 * kept rather than dropped. */
static CFStringRef query_label(CFDictionaryRef attributes)
{
    if (attributes == NULL) {
        return NULL;
    }
    CFTypeRef value = CFDictionaryGetValue(attributes, kSecAttrLabel);
    return value != NULL && CFGetTypeID(value) == CFStringGetTypeID()
               ? (CFStringRef)value
               : NULL;
}

/* Whether the query's label selects the record with this label. A query
 * without a label matches every record; a query with one matches only the
 * record that carries it. */
static bool query_accepts_label(CFDictionaryRef query, CFTypeRef stored_label)
{
    CFStringRef wanted = query_label(query);
    if (wanted == NULL) {
        return true;
    }
    return stored_label != NULL &&
           CFGetTypeID(stored_label) == CFStringGetTypeID() &&
           CFEqual(stored_label, wanted);
}

/* The replacement account or label an update names. An absent value means
 * the caller did not change that attribute. The caller has already refused a
 * malformed attribute, so the value here is a string. */
static CFStringRef replacement_string(CFDictionaryRef attributes, CFStringRef key)
{
    if (attributes == NULL) {
        return NULL;
    }
    CFTypeRef value = CFDictionaryGetValue(attributes, key);
    if (value == NULL || CFGetTypeID(value) != CFStringGetTypeID()) {
        return NULL;
    }
    return (CFStringRef)value;
}

/* Store one AirPort credential. The account and the password are both
 * required: a record without a password has nothing to keep.
 *
 * The account and the label are the ones the record ends up with. A null
 * account keeps the queried one, and a null label keeps the stored one. */
static OSStatus store_credential(CFDictionaryRef query, CFDataRef data,
                                 bool synchronizable, CFStringRef target_account,
                                 CFStringRef target_label,
                                 CFDictionaryRef *entry_out)
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
        /* The label, like the synchronizable attribute, is kept unless the
         * caller names a new one. */
        CFDictionaryRef existing = find_entry(store, key);
        CFStringRef label = target_label;
        if (label == NULL && existing != NULL) {
            CFTypeRef stored = CFDictionaryGetValue(existing, CFSTR("label"));
            if (stored != NULL && CFGetTypeID(stored) == CFStringGetTypeID()) {
                label = (CFStringRef)stored;
            }
        }
        /* The account can be changed by an update, and the keychain replaces
         * the item when it does: the old record goes and a new one appears
         * under the new account. */
        CFStringRef new_account = target_account != NULL ? target_account : account;
        CFStringRef new_key = store_key(new_account, system);
        if (new_key != NULL) {
            bool rename = !CFEqual(new_key, key);
            /* A rename onto an account that already holds a credential would
             * destroy that credential. The keychain refuses the change, and
             * so does the store. */
            if (rename && find_entry(store, new_key) != NULL) {
                status = errSecDuplicateItem;
            } else {
                /* The new record is built before the old one goes, so that a
                 * label inherited from it outlives the removal. */
                CFMutableDictionaryRef entry =
                    new_entry(new_account, data, synchronizable, system, label);
                if (entry != NULL) {
                    if (rename) {
                        CFDictionaryRemoveValue(store, key);
                    }
                    CFDictionarySetValue(store, new_key, entry);
                    status = write_store(store) ? errSecSuccess : errSecNotAvailable;
                    if (status == errSecSuccess && entry_out != NULL) {
                        *entry_out = (CFDictionaryRef)CFRetain(entry);
                    }
                    CFRelease(entry);
                }
            }
            CFRelease(new_key);
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

/* The stored records a query selects: the ones of the keychain that was
 * asked for whose synchronizable value, label and account the query
 * accepts. The read and the delete paths share it so that they cannot
 * drift apart and start disagreeing about which records a query names. */
static CFArrayRef matching_entries(CFDictionaryRef store, CFDictionaryRef query,
                                   bool system, CFStringRef account)
{
    CFMutableArrayRef matched = CFArrayCreateMutable(
        kCFAllocatorDefault, 0, &kCFTypeArrayCallBacks);
    if (matched == NULL) {
        return NULL;
    }
    CFIndex count = CFDictionaryGetCount(store);
    const void **values = count ? calloc((size_t)count, sizeof(*values)) : NULL;
    if (values == NULL) {
        CFRelease(matched);
        return NULL;
    }
    CFDictionaryGetKeysAndValues(store, NULL, values);
    for (CFIndex index = 0; index < count; index++) {
        if (CFGetTypeID(values[index]) != CFDictionaryGetTypeID()) {
            continue;
        }
        CFDictionaryRef entry = (CFDictionaryRef)values[index];
        /* The system-keychain selection is part of a record's identity, so a
         * query answers with the records of the keychain that was asked for
         * and no others. */
        if (dictionary_bool(entry, CFSTR("system")) != system) {
            continue;
        }
        /* And so is the synchronizable attribute. */
        if (!query_accepts_synchronizable(
                query, dictionary_bool(entry, CFSTR("synchronizable")))) {
            continue;
        }
        /* And the label, which a query can match on too. */
        if (!query_accepts_label(query, CFDictionaryGetValue(entry, CFSTR("label")))) {
            continue;
        }
        /* And the account, when the query names one. */
        if (account != NULL) {
            CFTypeRef stored = CFDictionaryGetValue(entry, CFSTR("account"));
            if (stored == NULL || !CFEqual(stored, account)) {
                continue;
            }
        }
        CFArrayAppendValue(matched, entry);
    }
    free(values);
    return matched;
}

static OSStatus l8_SecItemCopyMatching(CFDictionaryRef query, CFTypeRef *result)
{
    if (gInsideHook || !fallback_enabled() || !is_wifid() ||
        !is_airport_password_query(query) || attributes_malformed(query)) {
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
    if (store != NULL && enumerates && wants_attributes) {
        /* A query that asks for every match is answered with an array, even
         * when the selectors leave one record standing: the keychain returns
         * an array for kSecMatchLimitAll, and a caller that consumes the
         * result as an array cannot use a bare dictionary. */
        CFArrayRef matched = matching_entries(store, query, system, account);
        CFMutableArrayRef array = CFArrayCreateMutable(kCFAllocatorDefault, 0,
                                                        &kCFTypeArrayCallBacks);
        if (matched != NULL && array != NULL) {
            CFIndex count = CFArrayGetCount(matched);
            for (CFIndex index = 0; index < count; index++) {
                CFDictionaryRef attributes = result_attributes(
                    (CFDictionaryRef)CFArrayGetValueAtIndex(matched, index),
                    wants_data);
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
        if (matched != NULL) {
            CFRelease(matched);
        }
    } else if (store != NULL && account != NULL && !enumerates) {
        CFStringRef key = store_key(account, system);
        CFDictionaryRef entry = find_entry(store, key);
        /* The synchronizable attribute is part of how a record matches, so a
         * query that excludes the stored record does not get it. */
        if (entry != NULL &&
            query_accepts_synchronizable(
                query, dictionary_bool(entry, CFSTR("synchronizable"))) &&
            query_accepts_label(query, CFDictionaryGetValue(entry, CFSTR("label")))) {
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
        !is_airport_password_query(attributes) || attributes_malformed(attributes)) {
        return SecItemAdd(attributes, result);
    }
    if (result != NULL) {
        *result = NULL;
    }

    CFTypeRef data = CFDictionaryGetValue(attributes, kSecValueData);
    if (data == NULL || CFGetTypeID(data) != CFDataGetTypeID()) {
        return SecItemAdd(attributes, result);
    }

    /* The caller asked for a particular shape of result, so it gets that
     * shape rather than the password as data. A caller that asked for the
     * attributes cannot use a CFData. */
    bool wants_data = dictionary_bool(attributes, kSecReturnData);
    bool wants_attributes = dictionary_bool(attributes, kSecReturnAttributes);
    CFDictionaryRef entry = NULL;
    gInsideHook = true;
    OSStatus status = store_credential(attributes, (CFDataRef)data,
                                       dictionary_bool(attributes,
                                                      kSecAttrSynchronizable),
                                       NULL, query_label(attributes), &entry);
    gInsideHook = false;
    if (status != errSecSuccess) {
        if (entry != NULL) {
            CFRelease(entry);
        }
        return status;
    }
    if (result != NULL) {
        if (wants_attributes) {
            *result = result_attributes(entry, wants_data);
        } else if (wants_data) {
            *result = CFRetain(data);
        }
    }
    if (entry != NULL) {
        CFRelease(entry);
    }
    return errSecSuccess;
}

/* The stored record for this query's account and keychain, and whether there
 * is one. The synchronizable attribute and the label are both part of how
 * the keychain matches a record, so the match is decided here, while the
 * store is still alive. */
static bool stored_record(CFDictionaryRef query, bool *synchronizable,
                           bool *matches)
{
    CFStringRef account = query_account(query);
    if (account == NULL) {
        return false;
    }
    pthread_mutex_lock(&gStoreLock);
    CFMutableDictionaryRef store = load_store();
    bool found = false;
    bool accepted = false;
    if (store != NULL) {
        CFStringRef key = store_key(account, query_system_keychain(query));
        if (key != NULL) {
            CFDictionaryRef entry = find_entry(store, key);
            if (entry != NULL) {
                *synchronizable = dictionary_bool(entry, CFSTR("synchronizable"));
                accepted = query_accepts_synchronizable(query, *synchronizable) &&
                           query_accepts_label(
                               query, CFDictionaryGetValue(entry, CFSTR("label")));
                found = true;
            }
            CFRelease(key);
        }
        CFRelease(store);
    }
    pthread_mutex_unlock(&gStoreLock);
    if (matches != NULL) {
        *matches = accepted;
    }
    return found;
}

static OSStatus l8_SecItemUpdate(CFDictionaryRef query,
                                 CFDictionaryRef attributes_to_update)
{
    if (gInsideHook || !fallback_enabled() || !is_wifid() ||
        !is_airport_password_query(query) || attributes_malformed(query) ||
        attributes_malformed(attributes_to_update)) {
        return SecItemUpdate(query, attributes_to_update);
    }

    CFTypeRef data = attributes_to_update == NULL
                         ? NULL
                         : CFDictionaryGetValue(attributes_to_update, kSecValueData);
    if (data == NULL || CFGetTypeID(data) != CFDataGetTypeID()) {
        return SecItemUpdate(query, attributes_to_update);
    }

    /* An update with no account is a broader search. The shim only
     * implements single-account updates, so the real keychain owns it. */
    if (query_account(query) == NULL) {
        return SecItemUpdate(query, attributes_to_update);
    }

    /* The synchronizable attribute and the label are part of how a record
     * matches. An update that does not name a new synchronizable value
     * keeps the stored one, and an update whose query excludes the stored
     * record is not a match at all, so the real keychain owns it. */
    bool stored = false;
    bool synchronizable = false;
    bool matches = false;
    if (stored_record(query, &synchronizable, &matches)) {
        stored = true;
        if (!matches) {
            return SecItemUpdate(query, attributes_to_update);
        }
    }
    CFTypeRef requested = attributes_to_update == NULL
                              ? NULL
                              : CFDictionaryGetValue(attributes_to_update,
                                                     kSecAttrSynchronizable);
    if (requested != NULL) {
        synchronizable = dictionary_bool(attributes_to_update,
                                         kSecAttrSynchronizable);
    } else if (!stored) {
        synchronizable = false;
    }

    /* The account and the label can be changed by an update. The keychain
     * replaces the item when the account changes, so the old record goes and
     * the new one appears under the new account. */
    CFStringRef target_account = replacement_string(attributes_to_update,
                                                    kSecAttrAccount);
    CFStringRef target_label = replacement_string(attributes_to_update,
                                                   kSecAttrLabel);

    gInsideHook = true;
    OSStatus status = store_credential(query, (CFDataRef)data, synchronizable,
                                       target_account, target_label, NULL);
    gInsideHook = false;
    return status;
}

static OSStatus l8_SecItemDelete(CFDictionaryRef query)
{
    if (gInsideHook || !fallback_enabled() || !is_wifid() ||
        !is_airport_password_query(query) || attributes_malformed(query)) {
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
            CFDictionaryRef entry = key != NULL ? find_entry(store, key) : NULL;
            /* A delete that excludes the stored record does not match it. */
            if (entry != NULL &&
                query_accepts_synchronizable(
                    query, dictionary_bool(entry, CFSTR("synchronizable"))) &&
                query_accepts_label(query, CFDictionaryGetValue(entry, CFSTR("label")))) {
                CFDictionaryRemoveValue(store, key);
                removed = true;
                written = write_store(store);
            }
            if (key != NULL) {
                CFRelease(key);
            }
        } else {
            /* A delete without an account removes every AirPort record of the
             * keychain that was asked for, and no others. The system-keychain
             * selection is part of a record's identity, so a bulk delete that
             * ignored it would take the other keychain's records with it. */
            CFArrayRef matched = matching_entries(store, query, system, NULL);
            if (matched != NULL) {
                CFIndex count = CFArrayGetCount(matched);
                for (CFIndex index = 0; index < count; index++) {
                    CFDictionaryRef entry =
                        (CFDictionaryRef)CFArrayGetValueAtIndex(matched, index);
                    CFTypeRef stored = CFDictionaryGetValue(entry, CFSTR("account"));
                    if (stored == NULL) {
                        continue;
                    }
                    CFStringRef key = store_key((CFStringRef)stored, system);
                    if (key != NULL) {
                        CFDictionaryRemoveValue(store, key);
                        CFRelease(key);
                        removed = true;
                    }
                }
                CFRelease(matched);
            }
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
