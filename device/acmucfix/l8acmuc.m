/*
 * l8acmuc - IOKit user-client interposer for the ACM credential store.
 *
 * The SEP-less boot routes every ACM call through one IOKit user client:
 *
 *   IOServiceGetMatchingService(0, IOServiceMatching("AppleCredentialManager"))
 *   IOServiceOpen(svc, task, 0, &conn)                 -> AppleCredentialManagerUserClient
 *   IOConnectCallStructMethod(conn, 0, blob, len, out, &outLen)
 *
 * with the ACM command number riding in the 8-byte blob header, NOT in the
 * IOConnect selector (research/aks-e07/ACM-IOKIT-TRANSPORT-DECODE.md):
 *
 *   struct { uint32 magic = 0x53435244; uint8 cmd; uint8 b5; uint8 b6; uint8 ver = 2; }
 *
 * Every ACM function the client libraries export (46 of them across the
 * context / data-store / credential / verify / SEP / kernel families) funnels
 * through selector 0, so the whole surface is served by intercepting three
 * IOKit framework exports with dyld __DATA,__interpose:
 *
 *   IOServiceMatching                 tag the ACM match dictionary
 *   IOServiceGetMatchingService       hand back a synthetic service, no kernel
 *   IOServiceOpen                     synthetic service -> synthetic connect
 *   IOObjectRelease                   swallow the synthetic service
 *   IOConnectCallStructMethod         serve selector 0 from the software store
 *
 * Everything else forwards untouched: the interposers are one pointer
 * comparison on the hot path, so unrelated user clients (graphics, baseband,
 * every other IOKit consumer in the process) never notice the shim.
 *
 * The daemon-side ACM context store in coreauthd (which poisons Preferences'
 * pool with SEP-bound garbage, the E07 wall) links the same client library,
 * so one dylib loaded into coreauthd replaces the kernel store there too.
 *
 * Marker-gated like l8localauth: /private/var/jb/.liter8-localauth, root
 * 0600. Marker off = pure forward, zero behaviour change.
 *
 * Build 1: serves context lifecycle (create/delete/getinfo/ping) and
 * contains (honest empty store); every other command logs its cmd byte and
 * payload and returns -5, a well-formed failure from our own code instead of
 * the SEP-bound reply the kernel produces. The log names the next payloads
 * to decode.
 */
#include <CoreFoundation/CoreFoundation.h>
#include <mach/mach.h>
#include <os/log.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>

#ifndef LITER8_ACMUC_MARKER
#define LITER8_ACMUC_MARKER "/private/var/jb/.liter8-localauth"
#endif
#ifndef LITER8_ACMUC_MARKER_UID
#define LITER8_ACMUC_MARKER_UID 0
#endif

/* ------------------------------------------------------------------ */
/* IOKit client API. The iPhoneOS SDK ships no IOKit link surface for
 * these, so the prototypes are local and the symbols resolve at load. */
typedef mach_port_t io_object_t;
typedef io_object_t io_service_t;
typedef io_object_t io_connect_t;
typedef uint32_t IOReturn;

extern io_service_t IOServiceGetMatchingService(mach_port_t, void *) __attribute__((weak_import));
extern void *IOServiceMatching(const char *) __attribute__((weak_import));
extern IOReturn IOServiceOpen(io_service_t, task_port_t, uint32_t, io_connect_t *) __attribute__((weak_import));
extern IOReturn IOObjectRelease(io_object_t) __attribute__((weak_import));
extern IOReturn IOConnectCallStructMethod(mach_port_t, uint32_t, const void *, size_t,
                                          void *, size_t *) __attribute__((weak_import));

/* The originals, captured through dyld's interpose rebinding: the "original"
 * pointer in the __interpose tuple is the real implementation, and our
 * replacement calls it explicitly for everything it does not own. */
IOReturn l8_acmuc_IOServiceOpen(io_service_t, task_port_t, uint32_t, io_connect_t *);
void *l8_acmuc_IOServiceMatching(const char *);
io_service_t l8_acmuc_IOServiceGetMatchingService(mach_port_t, void *);
IOReturn l8_acmuc_IOObjectRelease(io_object_t);
IOReturn l8_acmuc_IOConnectCallStructMethod(mach_port_t, uint32_t, const void *, size_t,
                                            void *, size_t *);

__attribute__((used, section("__DATA,__interpose")))
static struct { void *replacement; void *original; } l8_acmuc_interpose[] = {
    { (void *)l8_acmuc_IOServiceOpen,              (void *)IOServiceOpen },
    { (void *)l8_acmuc_IOServiceMatching,          (void *)IOServiceMatching },
    { (void *)l8_acmuc_IOServiceGetMatchingService,(void *)IOServiceGetMatchingService },
    { (void *)l8_acmuc_IOObjectRelease,            (void *)IOObjectRelease },
    { (void *)l8_acmuc_IOConnectCallStructMethod,  (void *)IOConnectCallStructMethod },
};

/* ------------------------------------------------------------------ */
/* Marker with a 5 s TTL cache: IOConnectCallStructMethod runs thousands of
 * times a second in some daemons and stat() on every call is not acceptable
 * on the forward path. */
static atomic_int g_marker_cached;
static atomic_long g_marker_checked_at;
static atomic_int g_marker_state;

static int l8_acmuc_marker_now(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    long now = tv.tv_sec;
    int cached = atomic_load(&g_marker_cached);
    long at = atomic_load(&g_marker_checked_at);
    if (cached && now - at < 5) return atomic_load(&g_marker_state);

    struct stat st;
    int enabled = 0;
    if (lstat(LITER8_ACMUC_MARKER, &st) == 0 && S_ISREG(st.st_mode) &&
        st.st_uid == LITER8_ACMUC_MARKER_UID &&
        (st.st_mode & (S_IWGRP | S_IWOTH)) == 0) {
        enabled = 1;
    }
    atomic_store(&g_marker_state, enabled);
    atomic_store(&g_marker_checked_at, now);
    atomic_store(&g_marker_cached, 1);
    return enabled;
}

/* ------------------------------------------------------------------ */
/* Synthetic handles: addresses of our own bytes, unique and never equal to
 * a real mach port or io_service_t. */
static char l8_svc_tag;
static char l8_conn_tag;
#define L8_ACM_SVC   ((io_service_t)(uintptr_t)&l8_svc_tag)
#define L8_ACM_CONN  ((io_connect_t)(uintptr_t)&l8_conn_tag)

/* ------------------------------------------------------------------ */
/* Wire structures (all decoded, ACM-IOKIT-TRANSPORT-DECODE.md). */

#define L8_ACM_CMD_MAGIC 0x53435244u

typedef struct {
    uint32_t magic;
    uint8_t cmd;
    uint8_t b5;
    uint8_t b6;
    uint8_t version;
} l8_acm_cmd_hdr;

/* ACM status codes the client library maps to LACError (-3 = the SEP-less
 * wall code, -7 = not found, -5 = parameter). */
#define L8_ACM_OK            0
#define L8_ACM_ERR_PARAM     (-5)
#define L8_ACM_ERR_NOTFOUND  (-7)
#define L8_ACM_ERR_CTX       (-3)

/* Command bytes. */
#define L8_ACM_CMD_CONTEXT_DELETE        0x02
#define L8_ACM_CMD_VERIFY_POLICY_EX      0x03
#define L8_ACM_CMD_CONTAINS_CRED_TYPE    0x04
#define L8_ACM_CMD_ADD_CREDENTIAL        0x05
#define L8_ACM_CMD_REMOVE_CREDS_SCOPE    0x09
#define L8_ACM_CMD_CONTAINS_PASSPHRASE   0x0D
#define L8_ACM_CMD_REMOVE_PASSPHRASE     0x10
#define L8_ACM_CMD_GET_EXTERNAL_FORM     0x13
#define L8_ACM_CMD_ENV_GET               0x19
#define L8_ACM_CMD_KERNEL_CONTROL        0x1A
#define L8_ACM_CMD_PING_2                0x1D
#define L8_ACM_CMD_CONTEXT_CREATE        0x24
#define L8_ACM_CMD_TRM_LOAD              0x26
#define L8_ACM_CMD_TRM_SAVE              0x27
#define L8_ACM_CMD_CONTEXT_SETDATA       0x28
#define L8_ACM_CMD_CONTEXT_GETDATA       0x29
#define L8_ACM_CMD_TRM_SAVE_ALT          0x2B
#define L8_ACM_CMD_ENV_SET               0x2C
#define L8_ACM_CMD_CONTEXT_GETINFO       0x2E
#define L8_ACM_CMD_PING_1                0x2F
#define L8_ACM_CMD_CONTEXT_LOAD_IMAGE    0x30
#define L8_ACM_CMD_CONTEXT_UNLOAD_IMAGE  0x31
#define L8_ACM_CMD_GET_UNLOCK_SECRET     0x32
#define L8_ACM_CMD_SEP_CONTROL           0x33
#define L8_ACM_CMD_CONTEXT_CREATE_FLAGS  0x34
#define L8_ACM_CMD_CONTEXT_COPYDATA      0x35

static const char *l8_acm_cmd_name(uint8_t cmd) {
    switch (cmd) {
    case L8_ACM_CMD_CONTEXT_CREATE:       return "ACMContextCreate";
    case L8_ACM_CMD_CONTEXT_CREATE_FLAGS: return "ACMContextCreateWithFlags";
    case L8_ACM_CMD_CONTEXT_DELETE:       return "ACMContextDelete";
    case L8_ACM_CMD_CONTEXT_GETINFO:      return "ACMContextGetInfo";
    case L8_ACM_CMD_CONTEXT_SETDATA:      return "ACMContextSetData";
    case L8_ACM_CMD_CONTEXT_GETDATA:      return "ACMContextGetData";
    case L8_ACM_CMD_CONTEXT_COPYDATA:     return "ACMContextCopyData";
    case L8_ACM_CMD_CONTAINS_CRED_TYPE:   return "ACMContextContainsCredentialTypeEx";
    case L8_ACM_CMD_ADD_CREDENTIAL:       return "ACMContextAddCredentialWithScope";
    case L8_ACM_CMD_VERIFY_POLICY_EX:     return "ACMContextVerifyPolicyEx";
    case L8_ACM_CMD_GET_EXTERNAL_FORM:    return "ACMContextGetExternalForm";
    case L8_ACM_CMD_CONTEXT_LOAD_IMAGE:   return "ACMContextLoadFromImage";
    case L8_ACM_CMD_CONTEXT_UNLOAD_IMAGE: return "ACMContextUnloadToImage";
    case L8_ACM_CMD_GET_UNLOCK_SECRET:    return "ACMSecContextGetUnlockSecret";
    case L8_ACM_CMD_SEP_CONTROL:          return "ACMSEPControl";
    case L8_ACM_CMD_KERNEL_CONTROL:       return "ACMKernelControl";
    case L8_ACM_CMD_ENV_GET:              return "ACMGetEnvironmentVariable";
    case L8_ACM_CMD_ENV_SET:              return "ACMSetEnvironmentVariable";
    case L8_ACM_CMD_TRM_LOAD:             return "ACMTRMLoadState";
    case L8_ACM_CMD_TRM_SAVE:             return "ACMTRMSaveState";
    case L8_ACM_CMD_TRM_SAVE_ALT:         return "ACMTRMSaveState(alt)";
    case L8_ACM_CMD_PING_1:               return "ACMPing(0x2f)";
    case L8_ACM_CMD_PING_2:               return "ACMPing(0x1d)";
    case L8_ACM_CMD_REMOVE_CREDS_SCOPE:   return "ACMContextRemoveCredentialsByTypeAndScope";
    case L8_ACM_CMD_REMOVE_PASSPHRASE:    return "ACMContextRemovePassphraseCredentialsByPurposeAndScope";
    case L8_ACM_CMD_CONTAINS_PASSPHRASE:  return "ACMContextContainsPassphraseCredentialWithPurpose";
    default:                              return "unknown";
    }
}

/* ------------------------------------------------------------------ */
/* Software ACM context store. Build 1: lifecycle only. */

#define L8_ACM_MAX_CONTEXTS 16
#define L8_ACM_HANDLE_MAGIC 0x4C38434D5543ULL /* "L8CMUC" */

typedef struct {
    int live;
    uint64_t id;
} l8_acm_ctx;

static l8_acm_ctx g_ctxs[L8_ACM_MAX_CONTEXTS];
static uint64_t g_ctx_next_id = 0x1000;
static pthread_mutex_t g_store_lock = PTHREAD_MUTEX_INITIALIZER;

static void l8_acm_log_cmd(const char *fn, uint8_t cmd, const void *payload, size_t len) {
    char hex[65];
    size_t n = len < 32 ? len : 32;
    static const char digits[] = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {
        hex[i * 2] = digits[((const uint8_t *)payload)[i] >> 4];
        hex[i * 2 + 1] = digits[((const uint8_t *)payload)[i] & 0xF];
    }
    hex[n * 2] = '\0';
    os_log(OS_LOG_DEFAULT,
           "l8acmuc: %{public}s cmd=0x%{public}x len=%{public}zu payload[:32]=%{public}s",
           fn, cmd, len, hex);
}

/* The create reply the client checks for: 0x15 bytes (LibCall_ACMContextCreate
 * compares the returned outLen against 0x15, then copies the first 16 into
 * the 20-byte handle and zeroes the tracking word). */
#define L8_ACM_CREATE_REPLY_LEN 0x15

static IOReturn l8_acmuc_dispatch(const void *input, size_t inLen,
                                  void *out, size_t *outLen) {
    if (inLen < sizeof(l8_acm_cmd_hdr) || input == NULL) return L8_ACM_ERR_PARAM;

    const l8_acm_cmd_hdr *hdr = (const l8_acm_cmd_hdr *)input;
    if (hdr->magic != L8_ACM_CMD_MAGIC) return L8_ACM_ERR_PARAM;
    if (hdr->version != 2) {
        os_log(OS_LOG_DEFAULT, "l8acmuc: unknown blob version %{public}u", hdr->version);
        return L8_ACM_ERR_PARAM;
    }

    const uint8_t *payload = (const uint8_t *)input + sizeof(l8_acm_cmd_hdr);
    size_t payloadLen = inLen - sizeof(l8_acm_cmd_hdr);
    size_t replyLen = 0;

    switch (hdr->cmd) {
    case L8_ACM_CMD_CONTEXT_CREATE:
    case L8_ACM_CMD_CONTEXT_CREATE_FLAGS: {
        pthread_mutex_lock(&g_store_lock);
        uint64_t id = 0;
        for (int i = 0; i < L8_ACM_MAX_CONTEXTS; i++) {
            if (!g_ctxs[i].live) {
                g_ctxs[i].live = 1;
                g_ctxs[i].id = ++g_ctx_next_id;
                id = g_ctxs[i].id;
                break;
            }
        }
        pthread_mutex_unlock(&g_store_lock);
        if (id == 0) return L8_ACM_ERR_CTX;
        os_log(OS_LOG_DEFAULT, "l8acmuc: context created id=%{public}llx flags=%{public}x",
               id, hdr->b6);
        uint8_t reply[L8_ACM_CREATE_REPLY_LEN];
        memset(reply, 0, sizeof reply);
        uint64_t m = L8_ACM_HANDLE_MAGIC;
        memcpy(reply, &m, sizeof m);
        memcpy(reply + 8, &id, sizeof id);
        replyLen = sizeof reply;
        if (out != NULL && outLen != NULL && *outLen >= replyLen) {
            memcpy(out, reply, replyLen);
            *outLen = replyLen;
            return L8_ACM_OK;
        }
        return L8_ACM_ERR_PARAM;
    }

    case L8_ACM_CMD_CONTEXT_DELETE: {
        if (payloadLen < 16) return L8_ACM_ERR_PARAM;
        uint64_t id;
        memcpy(&id, payload + 8, sizeof id);
        pthread_mutex_lock(&g_store_lock);
        for (int i = 0; i < L8_ACM_MAX_CONTEXTS; i++) {
            if (g_ctxs[i].live && g_ctxs[i].id == id) {
                g_ctxs[i].live = 0;
                break;
            }
        }
        pthread_mutex_unlock(&g_store_lock);
        os_log(OS_LOG_DEFAULT, "l8acmuc: context deleted id=%{public}llx", id);
        if (outLen != NULL) *outLen = 0;
        return L8_ACM_OK;
    }

    case L8_ACM_CMD_PING_1:
    case L8_ACM_CMD_PING_2:
        if (outLen != NULL) *outLen = 0;
        return L8_ACM_OK;

    case L8_ACM_CMD_CONTAINS_CRED_TYPE: {
        /* Empty store: no credential of any type. The client maps a zero
         * reply u32 to -7 (not found), which is the truthful answer here. */
        if (out != NULL && outLen != NULL && *outLen >= 4) {
            uint32_t zero = 0;
            memcpy(out, &zero, sizeof zero);
            *outLen = 4;
            return L8_ACM_OK;
        }
        return L8_ACM_ERR_PARAM;
    }

    case L8_ACM_CMD_CONTEXT_GETINFO:
    case L8_ACM_CMD_CONTEXT_SETDATA:
    case L8_ACM_CMD_CONTEXT_GETDATA:
    case L8_ACM_CMD_CONTEXT_COPYDATA:
    case L8_ACM_CMD_ADD_CREDENTIAL:
    case L8_ACM_CMD_VERIFY_POLICY_EX:
    case L8_ACM_CMD_GET_EXTERNAL_FORM:
    case L8_ACM_CMD_CONTEXT_LOAD_IMAGE:
    case L8_ACM_CMD_CONTEXT_UNLOAD_IMAGE:
    case L8_ACM_CMD_GET_UNLOCK_SECRET:
    case L8_ACM_CMD_SEP_CONTROL:
    case L8_ACM_CMD_KERNEL_CONTROL:
    case L8_ACM_CMD_ENV_GET:
    case L8_ACM_CMD_ENV_SET:
    case L8_ACM_CMD_TRM_LOAD:
    case L8_ACM_CMD_TRM_SAVE:
    case L8_ACM_CMD_TRM_SAVE_ALT:
    case L8_ACM_CMD_REMOVE_CREDS_SCOPE:
    case L8_ACM_CMD_REMOVE_PASSPHRASE:
    case L8_ACM_CMD_CONTAINS_PASSPHRASE:
        l8_acm_log_cmd(l8_acm_cmd_name(hdr->cmd), hdr->cmd, payload, payloadLen);
        if (outLen != NULL) *outLen = 0;
        return L8_ACM_ERR_PARAM;

    default:
        l8_acm_log_cmd("unknown-cmd", hdr->cmd, payload, payloadLen);
        if (outLen != NULL) *outLen = 0;
        return L8_ACM_ERR_PARAM;
    }
}

/* ------------------------------------------------------------------ */
/* Interposed implementations. */

void *l8_acmuc_IOServiceMatching(const char *name) {
    void *dict = IOServiceMatching(name);
    if (l8_acmuc_marker_now() && dict != NULL && name != NULL &&
        strcmp(name, "AppleCredentialManager") == 0) {
        CFRetain(dict); /* balance the consume in our GetMatchingService path */
    }
    return dict;
}

io_service_t l8_acmuc_IOServiceGetMatchingService(mach_port_t port, void *matching) {
    if (l8_acmuc_marker_now() && matching != NULL &&
        CFGetTypeID(matching) == CFDictionaryGetTypeID()) {
        /* Distinguish by creation: the ACM match dict is the only one we
         * retain an extra +1 on, so refcount == 2 marks it. Cheap and safe:
         * a non-ACM dict never gets the extra retain and forwards. */
        if (CFGetRetainCount((CFTypeRef)matching) == 2) {
            CFTypeRef ours = (CFTypeRef)matching;
            /* Consume both the caller's reference and our marker retain. */
            CFRelease(ours);
            CFRelease(ours);
            os_log(OS_LOG_DEFAULT, "l8acmuc: ACM service match intercepted");
            return L8_ACM_SVC;
        }
    }
    return IOServiceGetMatchingService(port, matching);
}

IOReturn l8_acmuc_IOServiceOpen(io_service_t service, task_port_t task, uint32_t type,
                                io_connect_t *connect) {
    if (service == L8_ACM_SVC && l8_acmuc_marker_now()) {
        if (connect == NULL) return L8_ACM_ERR_PARAM;
        *connect = L8_ACM_CONN;
        os_log(OS_LOG_DEFAULT,
               "l8acmuc: ACM user client opened (type=%{public}u) -> emulated", type);
        return L8_ACM_OK;
    }
    return IOServiceOpen(service, task, type, connect);
}

IOReturn l8_acmuc_IOObjectRelease(io_object_t object) {
    if (object == L8_ACM_SVC) return L8_ACM_OK;
    return IOObjectRelease(object);
}

IOReturn l8_acmuc_IOConnectCallStructMethod(mach_port_t connection, uint32_t selector,
                                            const void *inputStruct, size_t inputStructCnt,
                                            void *outputStruct, size_t *outputStructCnt) {
    if (connection == (mach_port_t)L8_ACM_CONN && l8_acmuc_marker_now()) {
        if (selector != 0) {
            os_log(OS_LOG_DEFAULT, "l8acmuc: unexpected selector %{public}u", selector);
            return L8_ACM_ERR_PARAM;
        }
        IOReturn kr = l8_acmuc_dispatch(inputStruct, inputStructCnt,
                                        outputStruct, outputStructCnt);
        if (kr != L8_ACM_OK) {
            const l8_acm_cmd_hdr *hdr = (const l8_acm_cmd_hdr *)inputStruct;
            if (inputStruct != NULL && inputStructCnt >= sizeof(l8_acm_cmd_hdr) &&
                hdr->magic == L8_ACM_CMD_MAGIC) {
                os_log(OS_LOG_DEFAULT,
                       "l8acmuc: %{public}s cmd=0x%{public}x -> %{public}d",
                       l8_acm_cmd_name(hdr->cmd), hdr->cmd, kr);
            }
        }
        return kr;
    }
    return IOConnectCallStructMethod(connection, selector, inputStruct, inputStructCnt,
                                     outputStruct, outputStructCnt);
}

/* ------------------------------------------------------------------ */
/* Constructor: the install line is the load-verification anchor (the
 * interposers themselves stay silent until ACM traffic arrives). */

__attribute__((constructor))
static void l8_acmuc_ctor(void) {
    os_log(OS_LOG_DEFAULT, "l8acmuc: ACM user client interposer loaded (marker %{public}s)",
           l8_acmuc_marker_now() ? "on" : "off");
}

/* ------------------------------------------------------------------ */
/* Host self-test: the dispatch against fabricated client blobs, no IOKit
 * involved (the interposers stay dormant without a marker). */

#ifdef LITER8_ACMUC_TEST

static int l8_acmuc_test(void) {
    int failures = 0;
    uint8_t blob[128];
    uint8_t out[256];
    size_t outLen;

#define CHECK(cond, name)                                                   \
    do {                                                                    \
        if (cond) printf("[+] %s\n", name);                                 \
        else { printf("[!] %s\n", name); failures++; }                      \
    } while (0)

    /* create */
    l8_acm_cmd_hdr *h = (l8_acm_cmd_hdr *)blob;
    h->magic = L8_ACM_CMD_MAGIC; h->cmd = L8_ACM_CMD_CONTEXT_CREATE;
    h->b5 = 0; h->b6 = 0; h->version = 2;
    outLen = sizeof out;
    IOReturn kr = l8_acmuc_dispatch(blob, sizeof(l8_acm_cmd_hdr), out, &outLen);
    CHECK(kr == L8_ACM_OK, "create returns 0");
    CHECK(outLen == L8_ACM_CREATE_REPLY_LEN, "create reply is 0x15 bytes");
    uint64_t m, id;
    memcpy(&m, out, 8);
    memcpy(&id, out + 8, 8);
    CHECK(m == L8_ACM_HANDLE_MAGIC, "create reply carries handle magic");
    CHECK(id >= 0x1000, "create reply carries context id");

    /* create with flags */
    h->cmd = L8_ACM_CMD_CONTEXT_CREATE_FLAGS; h->b6 = 1;
    outLen = sizeof out;
    kr = l8_acmuc_dispatch(blob, sizeof(l8_acm_cmd_hdr), out, &outLen);
    CHECK(kr == L8_ACM_OK && outLen == L8_ACM_CREATE_REPLY_LEN, "create-with-flags ok");

    /* delete of the first context */
    uint8_t delblob[8 + 16];
    l8_acm_cmd_hdr *dh = (l8_acm_cmd_hdr *)delblob;
    dh->magic = L8_ACM_CMD_MAGIC; dh->cmd = L8_ACM_CMD_CONTEXT_DELETE;
    dh->b5 = 0; dh->b6 = 0; dh->version = 2;
    memcpy(delblob + 8, out, 16);
    outLen = 0;
    kr = l8_acmuc_dispatch(delblob, sizeof delblob, NULL, &outLen);
    CHECK(kr == L8_ACM_OK, "delete returns 0");

    /* contains on the empty store */
    uint8_t cblob[8 + 16];
    l8_acm_cmd_hdr *ch = (l8_acm_cmd_hdr *)cblob;
    ch->magic = L8_ACM_CMD_MAGIC; ch->cmd = L8_ACM_CMD_CONTAINS_CRED_TYPE;
    ch->b5 = 0; ch->b6 = 0; ch->version = 2;
    memset(cblob + 8, 0xAA, 16);
    outLen = sizeof out;
    kr = l8_acmuc_dispatch(cblob, sizeof cblob, out, &outLen);
    CHECK(kr == L8_ACM_OK && outLen == 4, "contains replies 4 bytes");
    uint32_t present;
    memcpy(&present, out, 4);
    CHECK(present == 0, "contains is false on the empty store");

    /* unknown payload family logs and fails cleanly */
    h->cmd = L8_ACM_CMD_CONTEXT_SETDATA;
    memset(blob + 8, 0x11, 40);
    outLen = sizeof out;
    kr = l8_acmuc_dispatch(blob, 8 + 40, out, &outLen);
    CHECK(kr == L8_ACM_ERR_PARAM, "setdata returns -5 with zero reply");
    CHECK(outLen == 0, "setdata reply length is 0");

    /* bad magic / version / short blob */
    h->magic = 0xDEADBEEF; h->cmd = L8_ACM_CMD_CONTEXT_CREATE;
    kr = l8_acmuc_dispatch(blob, sizeof(l8_acm_cmd_hdr), out, &outLen);
    CHECK(kr == L8_ACM_ERR_PARAM, "bad magic refused");
    h->magic = L8_ACM_CMD_MAGIC; h->version = 1;
    kr = l8_acmuc_dispatch(blob, sizeof(l8_acm_cmd_hdr), out, &outLen);
    CHECK(kr == L8_ACM_ERR_PARAM, "bad version refused");
    kr = l8_acmuc_dispatch(blob, 4, out, &outLen);
    CHECK(kr == L8_ACM_ERR_PARAM, "short blob refused");

    /* context pool exhaustion returns -3 after 16 live contexts */
    h->version = 2;
    for (int i = 0; i < 16; i++) {
        h->cmd = L8_ACM_CMD_CONTEXT_CREATE;
        outLen = sizeof out;
        l8_acmuc_dispatch(blob, sizeof(l8_acm_cmd_hdr), out, &outLen);
    }
    outLen = sizeof out;
    kr = l8_acmuc_dispatch(blob, sizeof(l8_acm_cmd_hdr), out, &outLen);
    if (kr != L8_ACM_ERR_CTX) printf("[!] exhaustion kr=%d\n", kr);
    CHECK(kr == L8_ACM_ERR_CTX, "17th create refused with -3");

    printf(failures == 0 ? "PASS: l8acmuc dispatch contract\n"
                         : "FAIL: %d dispatch failures\n", failures);
    return failures;
}

int main(void) { return l8_acmuc_test(); }

#endif /* LITER8_ACMUC_TEST */
