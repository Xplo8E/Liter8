/*
 * l8ari - trace ARI traffic between CommCenter and the Intel baseband.
 *
 * Why this exists
 * ---------------
 * Cellular data on this CFW fails with the control plane entirely healthy. The
 * PDN activates, the network returns an address and DNS, iOS installs an
 * unscoped default route, and the IOReport counters on the Converged IPC rings
 * show the baseband dequeueing and completing every uplink packet it is given.
 * It then never leaves RRC idle, so nothing reaches the air and nothing comes
 * back. The failure is therefore inside the modem, and the only remaining way
 * to see the modem's own side of it is the ARI message stream.
 *
 * Why not the obvious routes
 * --------------------------
 * Frida is deliberately not used here.
 *
 * Syslog is not enough on 24B5099f. All ARI logging comes from six format
 * strings in libARIServer.dylib, and they only record indications being
 * forwarded to XPC clients: message id, client, transport and size, never a
 * payload and never an AP-to-baseband request. Raising com.apple.telephony.bb
 * to Debug and restarting logd changes nothing, because there is nothing more
 * to emit. Across a whole probe the only message that appears is the periodic
 * radio-signal indication.
 *
 * Inline hooking is not available either. As the comment in build.sh records,
 * vm_protect on CommCenter's __DATA_CONST returns KERN_PROTECTION_FAILURE once
 * dyld has applied fixups, and the device boots SPTM, so the process cannot
 * grant itself write. Nothing in-process can patch code or pointers.
 *
 * What this does instead
 * ----------------------
 * libARI.dylib exports a logging-configuration entry point:
 *
 *   Ari::LogConfig(unsigned int level,
 *                  void (*text)(unsigned int, const char *),
 *                  void (*data)(int, std::string, unsigned int,
 *                               const void *, unsigned int));
 *
 * That is a *call*, not a memory write, so it sidesteps the SPTM restriction
 * completely, and its second callback receives raw message buffers with their
 * direction, name and id. Installing our own callbacks gives a full trace.
 *
 * The callback takes std::string by value, so this file is C++ compiled
 * against the same libc++ as the caller rather than C guessing at the string
 * ABI.
 *
 * Operational shape
 * -----------------
 * The dylib lives on the sealed system volume and can only be replaced from
 * SSHRD, which costs a DFU cycle per iteration, so everything that might need
 * changing lives in a config file on the Data volume instead:
 *
 *   /var/root/.l8ari            marker and config. Absent means fully inert.
 *   /var/root/l8ari.log         output, truncated at start, size capped.
 *
 * Config keys, one per line, all optional:
 *
 *   level=<n>        verbosity passed to Ari::LogConfig, default 7
 *   bytes=<n>        payload bytes to hex dump per message, default 64, max 512
 *   maxmb=<n>        stop writing after this many MB, default 32
 *   delay=<n>        seconds to wait before installing, default 15
 *   text=0|1         include the text callback as well, default 1
 *
 * The delay matters: CommCenter configures ARI logging during its own startup,
 * so installing from a library constructor would simply be overwritten. We let
 * it finish and install afterwards.
 *
 * Safety
 * ------
 * Breaking CommCenter breaks telephony on the device, so every failure path
 * here is "do nothing". No exceptions escape, no allocation happens on the
 * logging path beyond a stack buffer, and the whole thing is inert unless the
 * marker file exists.
 */

#include <dispatch/dispatch.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <sys/stat.h>
#include <unistd.h>

namespace {

/* CommCenter runs as _wireless under a sandbox, so the marker and log cannot
 * live wherever is convenient for the operator. The first attempt used
 * /var/root and produced exactly one line of evidence:
 *
 *   Sandbox: CommCenter(538) deny(1) file-read-metadata /private/var/root/.l8ari
 *
 * POSIX permissions were not the problem; the sandbox profile was. Rather than
 * hardcode one replacement and risk another DFU cycle to correct it, try a list
 * and use the first directory whose marker can actually be read. The first
 * entry is CommCenter's own preferences directory, which it demonstrably writes
 * to at runtime, so it is the one that should always work. */
constexpr const char *kDirs[] = {
    "/var/wireless/Library/Preferences",
    "/var/wireless/Library/Caches",
    "/var/wireless",
    "/var/mobile/Library/Preferences",
    "/tmp",
    "/var/root",
};

char g_marker[256];
char g_log_path[256];

struct Config {
    unsigned level = 7;
    unsigned bytes = 64;
    unsigned maxmb = 32;
    unsigned delay = 15;
    bool text = true;
};

Config g_cfg;
int g_fd = -1;
pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
size_t g_written = 0;

/* Single writer for both callbacks. Bounded so a runaway trace cannot fill the
 * Data volume and take the device down with it. */
void emit(const char *buf, size_t len) {
    pthread_mutex_lock(&g_lock);
    if (g_fd >= 0 && g_written + len <= (size_t)g_cfg.maxmb * 1024 * 1024) {
        ssize_t n = write(g_fd, buf, len);
        if (n > 0)
            g_written += (size_t)n;
    }
    pthread_mutex_unlock(&g_lock);
}

void emitf(const char *fmt, ...) {
    char line[1024];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(line, sizeof(line), fmt, ap);
    va_end(ap);
    if (n > 0)
        emit(line, (size_t)n < sizeof(line) ? (size_t)n : sizeof(line) - 1);
}

void hexdump(const void *data, unsigned len) {
    if (!data || len == 0)
        return;
    unsigned show = len < g_cfg.bytes ? len : g_cfg.bytes;
    const unsigned char *p = static_cast<const unsigned char *>(data);

    char line[8 + 512 * 3];
    size_t o = 0;
    o += (size_t)snprintf(line + o, sizeof(line) - o, "    ");
    for (unsigned i = 0; i < show && o + 4 < sizeof(line); i++)
        o += (size_t)snprintf(line + o, sizeof(line) - o, "%02x ", p[i]);
    if (show < len && o + 16 < sizeof(line))
        o += (size_t)snprintf(line + o, sizeof(line) - o, "... (%u total)", len);
    if (o + 2 < sizeof(line))
        o += (size_t)snprintf(line + o, sizeof(line) - o, "\n");
    emit(line, o);
}

/* Matches Ari::LogConfig's second callback exactly, including std::string by
 * value. Direction is the ARI library's own notion; both values are recorded
 * rather than guessed at. */
void data_cb(int dir, std::string name, unsigned int msgId, const void *buf, unsigned int len) {
    emitf("[%d] %-40s id=0x%08x len=%u\n", dir, name.c_str(), msgId, len);
    hexdump(buf, len);
}

void text_cb(unsigned int level, const char *msg) {
    emitf("(text l=%u) %s\n", level, msg ? msg : "(null)");
}

/* Pick the first candidate directory whose marker is readable. Readable, not
 * merely present: the sandbox denies metadata reads outright, so stat() is the
 * honest test of whether this directory is usable at all. */
bool locate_marker() {
    for (size_t i = 0; i < sizeof(kDirs) / sizeof(kDirs[0]); i++) {
        struct stat st;
        snprintf(g_marker, sizeof(g_marker), "%s/.l8ari", kDirs[i]);
        if (stat(g_marker, &st) != 0)
            continue;
        snprintf(g_log_path, sizeof(g_log_path), "%s/l8ari.log", kDirs[i]);
        return true;
    }
    g_marker[0] = g_log_path[0] = '\0';
    return false;
}

bool read_config() {
    if (!locate_marker())
        return false; /* no readable marker anywhere: stay inert */

    FILE *f = fopen(g_marker, "r");
    if (!f)
        return true; /* marker exists but unreadable: run with defaults */

    char line[128];
    while (fgets(line, sizeof(line), f)) {
        unsigned v = 0;
        if (sscanf(line, "level=%u", &v) == 1)
            g_cfg.level = v;
        else if (sscanf(line, "bytes=%u", &v) == 1)
            g_cfg.bytes = v > 512 ? 512 : v;
        else if (sscanf(line, "maxmb=%u", &v) == 1)
            g_cfg.maxmb = v;
        else if (sscanf(line, "delay=%u", &v) == 1)
            g_cfg.delay = v;
        else if (sscanf(line, "text=%u", &v) == 1)
            g_cfg.text = v != 0;
    }
    fclose(f);
    return true;
}

typedef void (*text_cb_t)(unsigned int, const char *);
typedef void (*data_cb_t)(int, std::string, unsigned int, const void *, unsigned int);
typedef void (*log_config_t)(unsigned int, text_cb_t, data_cb_t);

void install() {
    /* libARI is already in the process; CommCenter links it directly. Looking
     * it up by name rather than dlopening a path keeps this working if the
     * library ever moves inside the shared cache. */
    log_config_t cfgfn = (log_config_t)dlsym(
        RTLD_DEFAULT,
        "_ZN3Ari9LogConfigEjPFvjPKcEPFviNSt3__112basic_stringIcNS4_11char_traitsIcEENS4_9allocatorIcEEEEjPKvjE");
    if (!cfgfn) {
        emitf("[!] Ari::LogConfig not found, nothing installed\n");
        return;
    }

    emitf("[*] installing ARI trace: level=%u bytes=%u maxmb=%u text=%d\n", g_cfg.level,
          g_cfg.bytes, g_cfg.maxmb, (int)g_cfg.text);
    cfgfn(g_cfg.level, g_cfg.text ? text_cb : nullptr, data_cb);
    emitf("[*] installed\n");
}

__attribute__((constructor)) void l8ari_init() {
    if (!read_config())
        return;

    g_fd = open(g_log_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (g_fd < 0) {
        /* The marker was readable but the log is not writable. Say so through
         * os_log, since the file this would normally report into is the thing
         * that just failed. */
        fprintf(stderr, "l8ari: cannot open %s: %s\n", g_log_path, strerror(errno));
        return;
    }

    emitf("[*] l8ari loaded in pid %d, marker %s, installing in %us\n", getpid(), g_marker,
          g_cfg.delay);

    /* CommCenter sets up ARI logging during its own startup. Installing from a
     * constructor would be overwritten by that, so wait for it to settle. */
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)g_cfg.delay * NSEC_PER_SEC),
                   dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
                     install();
                   });
}

} // namespace
