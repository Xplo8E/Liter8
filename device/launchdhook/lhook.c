/*
 * lhook.dylib - the PID 1 bootstrap for system-wide injection.
 *
 * Loaded by dyld as an ordinary weak dependency of /sbin/launchd, not through
 * DYLD_INSERT_LIBRARIES. launchd strips DYLD_* from job environments and ignores it for
 * itself, but it cannot strip its own load commands. See LAUNCHD-PID1-HOOK.md.
 *
 * Two jobs:
 *   1. Prove it loaded, by writing a marker naming its own pid.
 *   2. Interpose posix_spawn and posix_spawnp so every process launchd starts inherits
 *      the injection, and so does everything they start.
 *
 * WHY THE INTERPOSE LIVES HERE AND NOT IN THE PAYLOAD.
 * dyld resolves DYLD_INTERPOSE through __DATA,__interpose when an image is loaded, and it
 * does not retroactively rebind images that are already bound. A dylib dlopen'd later
 * therefore cannot interpose launchd's already-resolved posix_spawn calls. Only an image
 * present at launch can, and the load command is what makes this one present at launch.
 * This is also why ElleKit's own pspawn.dylib cannot be reused: it has no __interpose
 * section and hooks posix_spawn at runtime instead, which needs writable __TEXT and dies
 * with CODESIGNING / Invalid Page here.
 *
 * WHY THE POLICY LIVES IN THE PAYLOAD.
 * This file is on the sealed System volume. Changing it costs a DFU trip, so it must be
 * the part that never needs to change. Anything likely to be iterated on belongs in
 * kPayload, which is on the Data volume and can be replaced over SSH.
 *
 * SAFETY. This code runs inside PID 1 and on every spawn on the system. A mistake here is
 * not a crashed process, it is a device that does not boot. Four guards:
 *
 *   1. Nothing happens unless kEnableFile exists. It lives on /var/jb, which is NOT
 *      mounted while launchd is starting, so early boot is untouched for free and
 *      injection only begins once the system is up. Deleting the file over SSH, or from
 *      the ramdisk, disables everything.
 *   2. A denylist of processes that must never be touched.
 *   3. A missing payload means passthrough, rather than handing dyld a path that does not
 *      resolve, which would make every spawn on the system fail.
 *   4. Tracing is off unless kDebugFile exists. An fopen on every spawn out of launchd is
 *      both a performance problem and a way to deadlock early boot.
 *
 * Guard order matters: the enable file is checked first, so removing it disables
 * everything below with no further reasoning required.
 */

#include <fcntl.h>
#include <pthread.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define DYLD_INTERPOSE(_replacement, _replacee)                                        \
    __attribute__((used)) static struct {                                              \
        const void *replacement;                                                       \
        const void *replacee;                                                          \
    } _interpose_##_replacee __attribute__((section("__DATA,__interpose"))) = {        \
        (const void *)(unsigned long)&_replacement,                                    \
        (const void *)(unsigned long)&_replacee                                        \
    };

/* On the System volume, so it resolves before the Data volume is mounted.
 *
 * Overridable at build time only so the interpose logic can be exercised from /var/jb on
 * a running device. Testing this code by deploying it to PID 1 first would mean a DFU
 * trip per iteration, and the whole point of the guards is that they are verified before
 * they ever run in launchd. The production build takes the default. */
#ifndef LHOOK_SELF_PATH
#define LHOOK_SELF_PATH "/usr/lib/lhook.dylib"
#endif
static const char *kSelf       = LHOOK_SELF_PATH;

/* Optional diagnostic payloads, injected in this order if present.
 *
 * The System copy costs a DFU trip to change; the Data copy can be iterated over SSH.
 * Production tweak loading does not require either one: kPayload_C below is ElleKit's
 * loader. Keeping these optional paths preserves the probes used to validate propagation
 * without making a fresh install depend on them.
 *
 * Overridable at build time for the same reason LHOOK_SELF_PATH is: the two-payload path
 * cannot otherwise be exercised until after deployment, because /usr/lib is read-only at
 * runtime and the second candidate does not exist yet. Testing it only on PID 1 would
 * mean discovering a bug there. The production build takes the defaults. */
#ifndef LHOOK_PAYLOAD_A
#define LHOOK_PAYLOAD_A "/usr/lib/systemhook.dylib"
#endif
#ifndef LHOOK_PAYLOAD_B
#define LHOOK_PAYLOAD_B "/var/jb/usr/lib/systemhook.dylib"
#endif

/* ElleKit's tweak loader, a symlink to usr/lib/ellekit/libinjector.dylib. It scans
 * /var/jb/usr/lib/TweakInject (which Library/MobileSubstrate/DynamicLibraries symlinks
 * to), matches each tweak's Filter/Bundles against the host, and dlopens what applies.
 *
 * Inserted by dyld rather than dlopen'ed by systemhook, because that is how ElleKit
 * expects to arrive and it lets dyld order the initializers. Loading ElleKit by hand from
 * a constructor is what killed SpringBoard during testing; inserted directly it returns 0
 * and the host survives, which is measured, not assumed.
 *
 * Listed last so the tweak loader runs after either optional diagnostic payload. The
 * path was confirmed mapped in Preferences on this build; do not infer a process-wide
 * sandbox rule from one target. */
#ifndef LHOOK_PAYLOAD_C
#define LHOOK_PAYLOAD_C "/var/jb/usr/lib/TweakLoader.dylib"
#endif

static const char *kPayloads[] = {
    LHOOK_PAYLOAD_A,
    LHOOK_PAYLOAD_B,
    LHOOK_PAYLOAD_C,
    NULL
};
static const char *kEnableFile = "/var/jb/.lhook_enabled";
static const char *kDebugFile  = "/var/jb/.lhook_debug";
static const char *kLogFile    = "/var/jb/tmp/lhook.log";

/* The tunable denylist, on the Data volume so it can be edited over SSH. This exists
 * because the first version compiled the list into this dylib, which lives on the sealed
 * System volume, making a one-word policy change cost a DFU trip. */
static const char *kDenyFile   = "/var/jb/etc/lhook.deny";

static const char *kMarkerPaths[] = {
    "/var/jb/tmp/lhook.log",
    "/var/tmp/lhook.log",
    "/tmp/lhook.log",
};
static const int kMarkerPathCount = 3;

/* The Data volume appears well within a minute of PID 1 starting, and a thread that
 * lives forever inside launchd is not something to leave behind. */
static const int kMaxAttempts = 120;
static const unsigned kRetryMicroseconds = 500000;

/* Compiled in and NOT overridable. Injecting any of these does not produce a crashed
 * process, it produces a device that does not come back, or one that cannot be reached
 * to fix it. dropbear and sshd are here for that second reason: they are the only way in.
 *
 * Nothing tunable belongs in this list. If an entry here turns out to be wrong it costs a
 * DFU trip to change, which is exactly the problem kDenyFile exists to solve. */
static const char *kHardDeny[] = {
    "launchd", "amfid", "trustd", "securityd", "configd",
    "notifyd", "logd", "opendirectoryd", "keybagd", "watchdogd",
    "dropbear", "sshd",
    NULL
};

/* Used only when kDenyFile is absent. Deliberately conservative: it keeps xpcproxy denied,
 * which is the behaviour that has already been booted and observed to be stable. Creating
 * the file is what opts into anything more adventurous. */
static const char *kDefaultDeny[] = {
    "xpcproxy", "diskarbitrationd", "syslogd", "usbmuxd",
    "mobile_obliterator", "restored_external", "aslmanager",
    NULL
};

static int file_exists(const char *path) {
    struct stat st;
    return stat(path, &st) == 0;
}

/* Guard #3. With no payload present there is nothing to inject, and injecting kSelf alone
 * would spread the interposer with no effect. */
static int any_payload_exists(void) {
    for (int i = 0; kPayloads[i]; i++)
        if (file_exists(kPayloads[i])) return 1;
    return 0;
}

static int name_in(const char **list, const char *name) {
    for (int i = 0; list[i]; i++)
        if (strcmp(name, list[i]) == 0) return 1;
    return 0;
}

/* Read the tunable denylist and test one name against it.
 *
 * The file is re-read per spawn rather than cached. That is deliberate: a cache needs
 * invalidation and a lock, launchd is multithreaded, and a locking bug in the spawn path
 * of PID 1 is far more expensive than a few microseconds of file read. It is also only
 * ever reached once injection is enabled, which cannot happen before /var/jb is mounted,
 * so it never runs during early boot.
 *
 * Format: one process name per line. Blank lines and lines starting with # are ignored,
 * so the file can document itself.
 *
 * Returns 1 deny, 0 allow, -1 if the file is absent and the caller should use the default.
 */
static int denied_by_file(const char *name) {
    FILE *file = fopen(kDenyFile, "r");
    if (!file) return -1;

    char line[256];
    int result = 0;
    int continuation = 0;
    while (fgets(line, sizeof line, file)) {
        /* A line longer than the buffer comes back in fragments, and fgets gives no
         * indication that it did. Without tracking that, the tail of a long comment
         * would be treated as a line of its own: a comment ending in a process name
         * would silently deny that process. Skip fragments that continue a previous
         * incomplete line. */
        size_t length = strlen(line);
        int incomplete = (length > 0 && line[length - 1] != '\n');
        int is_continuation = continuation;
        continuation = incomplete;
        if (is_continuation) continue;

        char *start = line;
        while (*start == ' ' || *start == '\t') start++;
        if (*start == '#' || *start == '\n' || *start == '\r' || *start == '\0') continue;

        char *end = start + strlen(start);
        while (end > start && (end[-1] == '\n' || end[-1] == '\r' ||
                               end[-1] == ' '  || end[-1] == '\t')) end--;
        *end = '\0';

        if (strcmp(start, name) == 0) { result = 1; break; }
    }
    fclose(file);
    return result;
}

static int denied(const char *path) {
    if (!path) return 1;
    const char *base = strrchr(path, '/');
    base = base ? base + 1 : path;

    /* Checked first and unconditionally, so no edit to the file can reach these. */
    if (name_in(kHardDeny, base)) return 1;

    int from_file = denied_by_file(base);
    if (from_file >= 0) return from_file;
    return name_in(kDefaultDeny, base);
}

/* Off unless kDebugFile exists. Checked per call rather than cached so it can be turned
 * on over SSH without a reboot, which matters because a reboot here is a DFU trip. */
static void trace(const char *fmt, const char *arg) {
    if (!file_exists(kDebugFile)) return;
    FILE *log = fopen(kLogFile, "a");
    if (!log) return;
    fprintf(log, fmt, arg);
    fclose(log);
}

/* ---------------------------------------------------------------- proof of load */

static int append_pid(char *out, int at, int value) {
    char digits[16];
    int n = 0;
    if (value == 0) digits[n++] = '0';
    while (value > 0 && n < (int)sizeof(digits)) {
        digits[n++] = (char)('0' + (value % 10));
        value /= 10;
    }
    while (n > 0) out[at++] = digits[--n];
    return at;
}

static int build_message(char *out, int cap) {
    static const char prefix[] = "[lhook] loaded into pid ";
    int at = 0;
    for (const char *p = prefix; *p && at < cap - 24; p++) out[at++] = *p;
    at = append_pid(out, at, (int)getpid());
    out[at++] = '\n';
    return at;
}

static void write_console(const char *message, int length) {
    int fd = open("/dev/console", O_WRONLY | O_NONBLOCK);
    if (fd < 0) return;
    (void)write(fd, message, (size_t)length);
    close(fd);
}

static int write_to(const char *path, const char *message, int length) {
    int fd = open(path, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd < 0) return 0;
    (void)write(fd, message, (size_t)length);
    close(fd);
    return 1;
}

/* TMPDIR is the only path an app-sandboxed process can write. Every fixed path in
 * kMarkerPaths is outside the container and is refused regardless of file mode, which is
 * why injection into Safari and Geekbench looked like a total failure: the variable was
 * delivered correctly and there was simply nowhere to say so.
 *
 * Tried FIRST, and the shared path is still attempted afterwards, so a daemon keeps
 * logging where the daemon log has always been while an app finally gets a voice. */
static int try_write_marker(const char *message, int length) {
    int wrote = 0;

    const char *tmpdir = getenv("TMPDIR");
    if (tmpdir && *tmpdir) {
        char local[1024];
        size_t n = strlen(tmpdir);
        if (n + sizeof("/lhook.log") < sizeof local) {
            memcpy(local, tmpdir, n);
            memcpy(local + n, "/lhook.log", sizeof("/lhook.log"));
            wrote |= write_to(local, message, length);
        }
    }

    for (int i = 0; i < kMarkerPathCount; i++)
        if (write_to(kMarkerPaths[i], message, length)) { wrote = 1; break; }

    return wrote;
}

/* Only reached when nothing was writable at constructor time, which is the PID 1 case:
 * the Data volume is not mounted yet. Ordinary processes never get here. */
static void *marker_thread(void *unused) {
    (void)unused;
    char message[64];
    int length = build_message(message, (int)sizeof(message));

    for (int attempt = 0; attempt < kMaxAttempts; attempt++) {
        if (try_write_marker(message, length)) return NULL;
        usleep(kRetryMicroseconds);
    }
    return NULL;
}

/* ------------------------------------------------------------ spawn interposition */

/* Build a copy of envp with our libraries added to DYLD_INSERT_LIBRARIES.
 *
 * An existing value is appended to rather than replaced, because something else may
 * already be injecting and clobbering it would silently break that. Returns NULL when
 * nothing needs changing, and the caller then uses the original envp untouched.
 */
static const char kInsertKey[] = "DYLD_INSERT_LIBRARIES=";
#define INSERT_KEY_LEN (sizeof(kInsertKey) - 1)

static char **envp_with_insert(char *const envp[], char **allocated) {
    int n = 0;
    while (envp && envp[n]) n++;

    /* getenv semantics: the first entry wins, so that is the one whose value is carried
     * forward. Later duplicates are dropped rather than passed through, otherwise the
     * child could still see a stale value depending on how it reads the environment. */
    /* Only inject payloads that exist. Handing dyld a path that does not resolve is the
     * one mistake here that breaks every spawn on the system. Built before the duplicate
     * check because that check tests for these exact paths. */
    char payloads[512];
    size_t at = 0;
    for (int i = 0; kPayloads[i]; i++) {
        if (!file_exists(kPayloads[i])) continue;
        size_t len = strlen(kPayloads[i]);
        if (at + len + 2 >= sizeof payloads) break;
        if (at) payloads[at++] = ':';
        memcpy(payloads + at, kPayloads[i], len);
        at += len;
    }
    payloads[at] = '\0';
    if (at == 0) return NULL;

    const char *existing = NULL;
    for (int i = 0; i < n; i++) {
        if (strncmp(envp[i], kInsertKey, INSERT_KEY_LEN) != 0) continue;
        if (!existing) existing = envp[i] + INSERT_KEY_LEN;
        /* Already carrying the payloads, so appending again would grow the variable
         * without bound down a deep process tree. Returning NULL here means "no change
         * needed", and the child still inherits the caller's environment, which already
         * contains everything.
         *
         * The test must be the PAYLOADS, not kSelf. A process that was itself injected
         * has kSelf in its environment by definition, so using kSelf as the sentinel
         * makes every injected process refuse to inject its own children, which silently
         * stops propagation one level down. Measured, not theorised. */
        if (strstr(envp[i] + INSERT_KEY_LEN, payloads)) return NULL;
    }

    /* Insert this dylib as well as the payloads. Without lhook itself the child has no
     * interposer, so propagation would stop one level down and only launchd's direct
     * children would ever be injected. */
    char *value = NULL;
    if (existing) {
        if (asprintf(&value, "%s%s:%s:%s", kInsertKey, existing, kSelf, payloads) < 0)
            return NULL;
    } else {
        if (asprintf(&value, "%s%s:%s", kInsertKey, kSelf, payloads) < 0)
            return NULL;
    }

    char **out = calloc(n + 2, sizeof(char *));
    if (!out) { free(value); return NULL; }

    int j = 0;
    for (int i = 0; i < n; i++) {
        if (strncmp(envp[i], kInsertKey, INSERT_KEY_LEN) == 0) continue;
        out[j++] = envp[i];
    }
    out[j++] = value;
    out[j] = NULL;

    /* Hand the caller the exact pointer we allocated. Finding it again by prefix search
     * is wrong: every other entry belongs to the caller, and a duplicate key in their
     * environment would make the search free their memory instead of ours. */
    *allocated = value;
    return out;
}

static int spawn_common(int (*real)(pid_t *, const char *,
                                    const posix_spawn_file_actions_t *,
                                    const posix_spawnattr_t *, char *const *, char *const *),
                        pid_t *pid, const char *path,
                        const posix_spawn_file_actions_t *actions,
                        const posix_spawnattr_t *attr,
                        char *const argv[], char *const envp[]) {
    if (!file_exists(kEnableFile) || denied(path) || !any_payload_exists())
        return real(pid, path, actions, attr, argv, envp);

    trace("[lhook] injecting %s\n", path ? path : "(null)");

    char *allocated = NULL;
    char **newenv = envp_with_insert(envp, &allocated);
    if (!newenv) return real(pid, path, actions, attr, argv, envp);

    int rc = real(pid, path, actions, attr, argv, newenv);

    /* Free exactly what we allocated. Every other entry in newenv belongs to the caller
     * and must not be touched. */
    free(allocated);
    free(newenv);
    return rc;
}

static int my_posix_spawn(pid_t *pid, const char *path,
                          const posix_spawn_file_actions_t *actions,
                          const posix_spawnattr_t *attr,
                          char *const argv[], char *const envp[]) {
    return spawn_common(posix_spawn, pid, path, actions, attr, argv, envp);
}

static int my_posix_spawnp(pid_t *pid, const char *path,
                           const posix_spawn_file_actions_t *actions,
                           const posix_spawnattr_t *attr,
                           char *const argv[], char *const envp[]) {
    return spawn_common(posix_spawnp, pid, path, actions, attr, argv, envp);
}

DYLD_INTERPOSE(my_posix_spawn,  posix_spawn)
DYLD_INTERPOSE(my_posix_spawnp, posix_spawnp)

__attribute__((constructor))
static void lhook_init(void) {
    char message[64];
    int length = build_message(message, (int)sizeof(message));
    write_console(message, length);

    /* Synchronously first, so a short-lived process still leaves proof it ran. A detached
     * thread loses that race: the process exits before it is scheduled. */
    if (try_write_marker(message, length)) return;

    pthread_t thread;
    pthread_attr_t attr;
    if (pthread_attr_init(&attr) != 0) return;
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    (void)pthread_create(&thread, &attr, marker_thread, NULL);
    pthread_attr_destroy(&attr);
}
