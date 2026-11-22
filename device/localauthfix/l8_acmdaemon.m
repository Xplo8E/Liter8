/*
 * l8_acmdaemon - the daemon-side credential read-back server (build 13g).
 *
 * The set-passcode flow's verify phase asks the daemon to read the
 * just-stored credential back: LAContext credentialOfType:-9 ->
 * -[ContextPluginACM credentialOfType:originator:reply:] -> ACM C calls
 * through the kernel user client, whose SEP-bound decrypt fails SEP-less
 * (measured: "returned (null) when attempting to decode credential" ->
 * PASSCODE_CHANGE_FAILED_TITLE). The kernel store itself is a plain
 * key-value store - SetData stored our blob verbatim and GetData returns it
 * verbatim - so the blob is intact; only the daemon's decrypt step dies.
 *
 * This section swizzles the two ObjC entry points around that C path:
 *  - setCredential:type:options:originator:reply: keeps a copy of the blob
 *    bytes it receives (keyed by credential type);
 *  - credentialOfType:originator:reply: serves the stored blob back as a
 *    LACSecureData without touching the kernel or the C crypto.
 * The client then decodes the blob through its own hooked LACACMHelper
 * decode (l8_acm.m, with the master-only retry) - the full path stays in
 * shim-controlled software.
 *
 * Everything forwards untouched when the marker is off.
 */
#import "l8_hooking.h"
#import <os/log.h>
#import <objc/message.h>
#import <objc/runtime.h>
#import <pthread.h>
#import <stdatomic.h>
#import <fcntl.h>
#import <unistd.h>

#define L8_ACMD_MAX_BLOB 1024
#define L8_ACMD_TYPES 4

static pthread_mutex_t gStoreLock = PTHREAD_MUTEX_INITIALIZER;
static struct {
    int live;
    long type;
    uint8_t bytes[L8_ACMD_MAX_BLOB];
    size_t len;
} gStored[L8_ACMD_TYPES];

static IMP gOriginalDaemonSetCredential;
static IMP gOriginalDaemonCredentialOfType;

static atomic_bool gDaemonInstalled = ATOMIC_VAR_INIT(false);

BOOL l8_acmdaemon_installed(void) {
    return atomic_load(&gDaemonInstalled);
}

#ifndef LITER8_PASSCODE_STATE
#define LITER8_PASSCODE_STATE "/var/mobile/Library/l8acm.passcode-set"
#endif

static void l8_acmdaemon_mark_state(void) {
    int fd = open(LITER8_PASSCODE_STATE, O_WRONLY | O_CREAT | O_CLOEXEC, 0600);
    if (fd >= 0) close(fd);
}

static void l8_acmdaemon_store(long type, const void *bytes, size_t len) {
    if (bytes == NULL || len == 0 || len > L8_ACMD_MAX_BLOB) return;
    l8_acmdaemon_mark_state();
    pthread_mutex_lock(&gStoreLock);
    for (int i = 0; i < L8_ACMD_TYPES; i++) {
        if (gStored[i].live && gStored[i].type == type) {
            memcpy(gStored[i].bytes, bytes, len);
            gStored[i].len = len;
            pthread_mutex_unlock(&gStoreLock);
            return;
        }
    }
    for (int i = 0; i < L8_ACMD_TYPES; i++) {
        if (!gStored[i].live) {
            gStored[i].live = 1;
            gStored[i].type = type;
            memcpy(gStored[i].bytes, bytes, len);
            gStored[i].len = len;
            break;
        }
    }
    pthread_mutex_unlock(&gStoreLock);
}

static BOOL l8_acmdaemon_fetch(long type, uint8_t *out, size_t *outLen) {
    pthread_mutex_lock(&gStoreLock);
    for (int i = 0; i < L8_ACMD_TYPES; i++) {
        if (gStored[i].live && gStored[i].type == type) {
            memcpy(out, gStored[i].bytes, gStored[i].len);
            *outLen = gStored[i].len;
            pthread_mutex_unlock(&gStoreLock);
            return YES;
        }
    }
    pthread_mutex_unlock(&gStoreLock);
    return NO;
}

/* Same byte accessors as the client section: the credential data object is
 * the LACSecureData-shaped externalization, bytes + length by msgSend. */
static const void *l8_acmdaemon_bytes_of(id data, size_t *len) {
    if (data == nil) {
        *len = 0;
        return NULL;
    }
    const void *bytes = ((const void *(*)(id, SEL))objc_msgSend)(
        data, sel_registerName("bytes"));
    *len = (size_t)((unsigned long (*)(id, SEL))objc_msgSend)(data,
                                                              sel_registerName("length"));
    return bytes;
}

static id l8_acmdaemon_secure_data(const void *bytes, size_t len) {
    Class secureData = NSClassFromString(@"LACSecureData");
    if (secureData == Nil) return nil;
    /* Class factory: already autoreleased, never release again (the
     * double-autorelease was the client-side stale-pool bug). */
    return ((id (*)(id, SEL, const void *, unsigned long))objc_msgSend)(
        (id)secureData, sel_registerName("secureDataWithBytes:length:"), bytes,
        (unsigned long)len);
}

/* v56@0:8@16q24@32@40@?48 */
static void l8_daemon_setCredential(id self, SEL sel, id data, long type, id options,
                                    id originator, id reply) {
    size_t len = 0;
    const void *bytes = l8_acmdaemon_bytes_of(data, &len);
    if (l8_marker_enabled() && bytes != NULL && len > 0) {
        l8_acmdaemon_store(type, bytes, len);
        os_log_error(OS_LOG_DEFAULT,
                     "l8acmdaemon: stored %zu-byte blob for type %{public}ld (pid %d)", len,
                     type, getpid());
    }
    ((void (*)(id, SEL, id, long, id, id, id))gOriginalDaemonSetCredential)(
        self, sel, data, type, options, originator, reply);
}

/* v40@0:8q16@24@?32 */
static void l8_daemon_credentialOfType(id self, SEL sel, long type, id originator,
                                       id reply) {
    if (l8_marker_enabled()) {
        uint8_t blob[L8_ACMD_MAX_BLOB];
        size_t len = 0;
        if (reply != nil && l8_acmdaemon_fetch(type, blob, &len)) {
            id data = l8_acmdaemon_secure_data(blob, len);
            if (data != nil) {
                os_log_error(OS_LOG_DEFAULT,
                             "l8acmdaemon: serving %zu-byte blob for type %{public}ld "
                             "(pid %d)",
                             len, type, getpid());
                ((void (^)(id, id))reply)(data, nil);
                return;
            }
        }
        os_log_error(OS_LOG_DEFAULT,
                     "l8acmdaemon: no stored blob for type %{public}ld, forwarding (pid %d)",
                     type, getpid());
    }
    ((void (*)(id, SEL, long, id, id))gOriginalDaemonCredentialOfType)(self, sel, type,
                                                                       originator, reply);
}

void l8_acmdaemon_install_if_ready(void) {
    if (atomic_load(&gDaemonInstalled)) return;
    Class plugin = objc_lookUpClass("ContextPluginACM");
    if (plugin == Nil) {
        /* ModuleACM.bundle not loaded yet in this process (only coreauthd
         * loads it); the next install pass retries - the pool override and
         * the constraints hook both fire mid-flow and re-enter here. */
        return;
    }
    atomic_store(&gDaemonInstalled, true);
    static const char *const setEncodings[] = {"v@:@q@@@?"};
    static const char *const ofTypeEncodings[] = {"v@:q@@?"};
    int hooked = 0;
    hooked |= l8_swap_any(
        class_getInstanceMethod(plugin, sel_registerName("setCredential:type:options:"
                                                         "originator:reply:")),
        "ContextPluginACM setCredential:type:options:originator:reply:", 7,
        setEncodings, 1, (IMP)l8_daemon_setCredential,
        &gOriginalDaemonSetCredential) << 0;
    hooked |= l8_swap_any(class_getInstanceMethod(plugin,
                                                  sel_registerName("credentialOfType:"
                                                                   "originator:reply:")),
                          "ContextPluginACM credentialOfType:originator:reply:", 5,
                          ofTypeEncodings, 1, (IMP)l8_daemon_credentialOfType,
                          &gOriginalDaemonCredentialOfType) << 1;
    os_log_error(OS_LOG_DEFAULT, "l8acmdaemon: daemon blob store mask 0x%x in pid %d",
                 hooked, getpid());
}
