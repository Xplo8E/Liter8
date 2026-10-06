/*
 * l8pair.dylib - narrow lockdownd pairing-key fallback for SEP-less Liter8.
 *
 * The no-content-protection profile can create an RSA key, but securityd cannot
 * reload the system-keychain metadata key. lockdownd consequently loses the
 * pairing identity between SecItemAdd and its next SecItemCopyMatching call and
 * answers DevicePublicKey with MissingValue.
 *
 * This interposer is intentionally dormant unless an operator-created marker
 * exists on Data. When active, it handles exactly one system-keychain identity:
 *
 *   access group  lockdown-identities
 *   label         com.apple.lockdown.pairingkeypair
 *
 * Every other Security.framework request goes to the original implementation.
 * Removing the marker from SSHRD restores complete pass-through behavior even
 * though lockdownd still weak-loads this dylib.
 */

#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <syslog.h>
#include <unistd.h>

#define DYLD_INTERPOSE(_replacement, _replacee)                                      \
    __attribute__((used)) static struct {                                            \
        const void *replacement;                                                     \
        const void *replacee;                                                        \
    } _interpose_##_replacee __attribute__((section("__DATA,__interpose"))) = {      \
        (const void *)(unsigned long)&_replacement,                                  \
        (const void *)(unsigned long)&_replacee                                      \
    };

static const char *kEnablePath =
    "/private/var/root/Library/Lockdown/.liter8-pairing-fallback";
static const char *kKeyPath =
    "/private/var/root/Library/Lockdown/liter8_pairing_key.der";
enum { kMaximumKeyBytes = 16 * 1024 };

static pthread_mutex_t gFileLock = PTHREAD_MUTEX_INITIALIZER;
static __thread bool gInsideHook;

static bool fallback_enabled(void)
{
    struct stat status;
    if (lstat(kEnablePath, &status) != 0) {
        return false;
    }
    return S_ISREG(status.st_mode) && status.st_uid == 0 &&
           (status.st_mode & (S_IWGRP | S_IWOTH)) == 0;
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

static bool is_pairing_identity_dictionary(CFDictionaryRef dictionary)
{
    CFTypeRef system_keychain = private_security_constant("kSecUseSystemKeychain");
    return dictionary != NULL &&
           CFGetTypeID(dictionary) == CFDictionaryGetTypeID() &&
           dictionary_value_equals(dictionary, kSecAttrAccessGroup,
                                   CFSTR("lockdown-identities")) &&
           dictionary_value_equals(dictionary, kSecAttrLabel,
                                   CFSTR("com.apple.lockdown.pairingkeypair")) &&
           dictionary_value_equals(dictionary, system_keychain, kCFBooleanTrue);
}

static CFDataRef read_key_data(void)
{
    int descriptor = open(kKeyPath, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (descriptor < 0) {
        return NULL;
    }

    struct stat status;
    if (fstat(descriptor, &status) != 0 || !S_ISREG(status.st_mode) ||
        status.st_uid != 0 || (status.st_mode & (S_IRWXG | S_IRWXO)) != 0 ||
        status.st_size <= 0 || (size_t)status.st_size > kMaximumKeyBytes) {
        close(descriptor);
        return NULL;
    }

    uint8_t bytes[kMaximumKeyBytes];
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

static SecKeyRef load_private_key(void)
{
    CFDataRef data = read_key_data();
    if (data == NULL) {
        return NULL;
    }

    const void *keys[] = {kSecAttrKeyType, kSecAttrKeyClass};
    const void *values[] = {kSecAttrKeyTypeRSA, kSecAttrKeyClassPrivate};
    CFDictionaryRef attributes = CFDictionaryCreate(
        kCFAllocatorDefault, keys, values, 2,
        &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFErrorRef error = NULL;
    SecKeyRef key = SecKeyCreateWithData(data, attributes, &error);
    if (error != NULL) {
        CFRelease(error);
    }
    CFRelease(attributes);
    CFRelease(data);
    return key;
}

static CFDataRef copy_private_key_data(SecKeyRef key)
{
    CFErrorRef error = NULL;
    CFDataRef data = SecKeyCopyExternalRepresentation(key, &error);
    if (error != NULL) {
        CFRelease(error);
    }
    if (data != NULL) {
        return data;
    }

    /* lockdownd uses this private accessor too. It is only a compatibility
     * fallback for key implementations that reject the public exporter. */
    typedef CFDictionaryRef (*CopyAttributesFunction)(SecKeyRef);
    CopyAttributesFunction copy_attributes =
        (CopyAttributesFunction)dlsym(RTLD_DEFAULT,
                                      "SecKeyCopyAttributeDictionary");
    if (copy_attributes == NULL) {
        return NULL;
    }
    CFDictionaryRef attributes = copy_attributes(key);
    if (attributes == NULL) {
        return NULL;
    }
    CFTypeRef value = CFDictionaryGetValue(attributes, kSecValueData);
    if (value != NULL && CFGetTypeID(value) == CFDataGetTypeID()) {
        data = CFRetain(value);
    }
    CFRelease(attributes);
    return data;
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

static bool store_private_key(SecKeyRef key)
{
    CFDataRef data = copy_private_key_data(key);
    if (data == NULL || CFDataGetLength(data) <= 0 ||
        (size_t)CFDataGetLength(data) > kMaximumKeyBytes) {
        if (data != NULL) {
            CFRelease(data);
        }
        return false;
    }

    char temporary[512];
    int written = snprintf(temporary, sizeof(temporary), "%s.tmp.%d",
                           kKeyPath, getpid());
    if (written <= 0 || (size_t)written >= sizeof(temporary)) {
        CFRelease(data);
        return false;
    }

    unlink(temporary);
    int descriptor = open(temporary,
                          O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
                          S_IRUSR | S_IWUSR);
    bool success = descriptor >= 0 &&
                   write_all(descriptor, CFDataGetBytePtr(data),
                             (size_t)CFDataGetLength(data)) &&
                   fsync(descriptor) == 0;
    if (descriptor >= 0) {
        close(descriptor);
    }
    if (success) {
        success = chmod(temporary, S_IRUSR | S_IWUSR) == 0 &&
                  rename(temporary, kKeyPath) == 0;
    }
    if (!success) {
        unlink(temporary);
    }
    CFRelease(data);
    return success;
}

/* Calls to a replacee originating in the interposer image resolve to the real
 * implementation. This is the same dyld interpose pattern used by lhook's
 * measured posix_spawn path; resolving with RTLD_NEXT would be load-order
 * dependent because l8pair is appended after lockdownd's other dependencies. */

static OSStatus l8_SecItemCopyMatching(CFDictionaryRef query, CFTypeRef *result)
{
    if (gInsideHook || !fallback_enabled() ||
        !is_pairing_identity_dictionary(query) ||
        !dictionary_value_equals(query, kSecClass, kSecClassKey)) {
        return SecItemCopyMatching(query, result);
    }

    gInsideHook = true;
    pthread_mutex_lock(&gFileLock);
    SecKeyRef key = load_private_key();
    pthread_mutex_unlock(&gFileLock);
    gInsideHook = false;
    if (key == NULL) {
        return SecItemCopyMatching(query, result);
    }

    if (dictionary_value_equals(query, kSecReturnRef, kCFBooleanTrue) &&
        result != NULL) {
        *result = key;
    } else {
        CFRelease(key);
        if (result != NULL) {
            *result = NULL;
        }
    }
    syslog(LOG_NOTICE, "l8pair: matched persistent lockdownd pairing key");
    return errSecSuccess;
}

static OSStatus l8_SecItemAdd(CFDictionaryRef attributes, CFTypeRef *result)
{
    if (gInsideHook || !fallback_enabled() ||
        !is_pairing_identity_dictionary(attributes)) {
        return SecItemAdd(attributes, result);
    }

    /* lockdownd's add dictionary omits kSecClass. kSecValueRef carries the
     * SecKey type; reject an explicit non-key class if a future build adds it. */
    CFTypeRef item_class = CFDictionaryGetValue(attributes, kSecClass);
    if (item_class != NULL && !CFEqual(item_class, kSecClassKey)) {
        return SecItemAdd(attributes, result);
    }

    CFTypeRef value = CFDictionaryGetValue(attributes, kSecValueRef);
    if (value == NULL || CFGetTypeID(value) != SecKeyGetTypeID()) {
        return SecItemAdd(attributes, result);
    }

    gInsideHook = true;
    pthread_mutex_lock(&gFileLock);
    bool stored = store_private_key((SecKeyRef)value);
    pthread_mutex_unlock(&gFileLock);
    gInsideHook = false;
    if (!stored) {
        syslog(LOG_ERR, "l8pair: failed to persist lockdownd pairing key");
        return errSecIO;
    }

    if (result != NULL) {
        *result = CFRetain(value);
    }
    syslog(LOG_NOTICE, "l8pair: persisted lockdownd pairing key");
    return errSecSuccess;
}

static OSStatus l8_SecItemDelete(CFDictionaryRef query)
{
    if (gInsideHook || !fallback_enabled() ||
        !is_pairing_identity_dictionary(query) ||
        !dictionary_value_equals(query, kSecClass, kSecClassKey)) {
        return SecItemDelete(query);
    }

    gInsideHook = true;
    pthread_mutex_lock(&gFileLock);
    int status = unlink(kKeyPath);
    int saved_errno = errno;
    pthread_mutex_unlock(&gFileLock);
    gInsideHook = false;
    if (status == 0) {
        syslog(LOG_NOTICE, "l8pair: deleted persistent lockdownd pairing key");
        return errSecSuccess;
    }
    if (saved_errno == ENOENT) {
        syslog(LOG_NOTICE, "l8pair: persistent lockdownd pairing key absent");
        return errSecItemNotFound;
    }
    return errSecIO;
}

#if defined(L8PAIR_ADD_ONLY)
/* Live-validation build: the normal artifact always uses all three hooks. */
DYLD_INTERPOSE(l8_SecItemAdd, SecItemAdd)
#else
DYLD_INTERPOSE(l8_SecItemCopyMatching, SecItemCopyMatching)
DYLD_INTERPOSE(l8_SecItemAdd, SecItemAdd)
DYLD_INTERPOSE(l8_SecItemDelete, SecItemDelete)
#endif
