/*
 * lhook.c - minimal PID 1 router for Liter8 + ElleKit.
 *
 * Loaded as a weak dependency of /sbin/launchd at /usr/lib/lhook.
 *
 * IMPORTANT DESIGN RULE:
 *   lhook itself NEVER propagates into children.
 *
 * Instead:
 *
 *   launchd -> xpcproxy
 *       inject ElleKit pspawn.dylib only
 *
 *   xpcproxy -> final app/daemon
 *       ElleKit pspawn performs its normal routing:
 *       libinjector/TweakLoader + sandbox extension + tweak Filter matching
 *
 *   launchd -> direct target (SpringBoard and similar)
 *       inject TweakLoader directly
 *
 * This mirrors ElleKit's intended architecture while keeping the one thing
 * Liter8 needs in PID 1 (a dyld __interpose present before launchd main()).
 *
 * Nothing is active until /var/jb/.lhook_enabled exists.
 */

#include <fcntl.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <unistd.h>

#define DYLD_INTERPOSE(_replacement, _replacee)                                      \
    __attribute__((used)) static struct {                                            \
        const void *replacement;                                                     \
        const void *replacee;                                                        \
    } _interpose_##_replacee __attribute__((section("__DATA,__interpose"))) = {      \
        (const void *)(unsigned long)&_replacement,                                  \
        (const void *)(unsigned long)&_replacee                                      \
    };

static const char *kEnableFile = "/var/jb/.lhook_enabled";
static const char *kDebugFile  = "/var/jb/.lhook_debug";
static const char *kLogFile    = "/var/jb/tmp/lhook.log";
static const char *kDenyFile   = "/var/jb/etc/lhook.deny";

static const char *kTweakLoader = "/var/jb/usr/lib/TweakLoader.dylib";
static const char *kSystemHook  = "/usr/lib/systemhook.dylib";

/* ElleKit rootless packages normally install here. Keep a rootful fallback so
 * the router also survives mixed/bootstrap experiments. */
static const char *kPspawnRootless = "/var/jb/usr/lib/ellekit/pspawn.dylib";
static const char *kPspawnRootful  = "/usr/lib/ellekit/pspawn.dylib";

static const char kInsertKey[] = "DYLD_INSERT_LIBRARIES=";
#define INSERT_KEY_LEN (sizeof(kInsertKey) - 1)

static int file_exists(const char *path) {
    struct stat st;
    return path && stat(path, &st) == 0;
}

static const char *last_component(const char *path) {
    if (!path) return "";
    const char *slash = strrchr(path, '/');
    return slash ? slash + 1 : path;
}

static int contains_ci(const char *haystack, const char *needle) {
    if (!haystack || !needle) return 0;

    size_t nlen = strlen(needle);
    if (!nlen) return 1;

    for (const char *p = haystack; *p; p++)
        if (strncasecmp(p, needle, nlen) == 0)
            return 1;

    return 0;
}

static int name_in(const char *const *list, const char *name) {
    for (int i = 0; list[i]; i++)
        if (strcmp(list[i], name) == 0)
            return 1;
    return 0;
}

/* Keep the same spirit as ElleKit's own spawn blacklist, plus recovery/trust
 * processes that must stay clean so a bad tweak cannot remove our way back in. */
static const char *const kHardDeny[] = {
    "launchd",
    "amfid",
    "trustd",
    "securityd",
    "configd",
    "notifyd",
    "logd",
    "opendirectoryd",
    "keybagd",
    "watchdogd",
    "watchdog",
    "mobile_assertion_agent",
    "mobile.usermanagerd",
    "dropbear",
    "sshd",
    "jailbreakd",
    "loader",
    "GSSCred",
    "sh",
    "bash",
    "zsh",
    NULL
};

static int denied_by_file(const char *name) {
    FILE *f = fopen(kDenyFile, "r");
    if (!f) return 0;

    char line[256];
    int result = 0;

    while (fgets(line, sizeof(line), f)) {
        char *start = line;
        while (*start == ' ' || *start == '\t') start++;

        if (*start == '#' || *start == '\n' ||
            *start == '\r' || *start == '\0')
            continue;

        char *end = start + strlen(start);
        while (end > start &&
               (end[-1] == '\n' || end[-1] == '\r' ||
                end[-1] == ' ' || end[-1] == '\t'))
            end--;
        *end = '\0';

        if (strcmp(start, name) == 0) {
            result = 1;
            break;
        }
    }

    fclose(f);
    return result;
}

static int denied(const char *path) {
    const char *name = last_component(path);

    if (name_in(kHardDeny, name)) return 1;
    if (denied_by_file(name)) return 1;

    /* These mirror ElleKit's broad helper exclusions. Safari itself does not
     * match "webkit"; its WebContent/Networking/GPU helpers do. */
    if (contains_ci(path, "webkit")) return 1;
    if (contains_ci(path, "blastdoor")) return 1;

    return 0;
}

static void trace(const char *kind, const char *path) {
    if (!file_exists(kDebugFile)) return;

    FILE *f = fopen(kLogFile, "a");
    if (!f) return;

    fprintf(f, "[lhook] %s -> %s\n",
            kind ? kind : "?",
            path ? path : "(null)");
    fclose(f);
}

static const char *pspawn_path(void) {
    if (file_exists(kPspawnRootless)) return kPspawnRootless;
    if (file_exists(kPspawnRootful)) return kPspawnRootful;
    return NULL;
}

static int value_has_path(const char *value, const char *path) {
    if (!value || !path) return 0;

    size_t plen = strlen(path);
    const char *p = value;

    while ((p = strstr(p, path)) != NULL) {
        int left_ok = (p == value || p[-1] == ':');
        int right_ok = (p[plen] == '\0' || p[plen] == ':');
        if (left_ok && right_ok) return 1;
        p += plen;
    }

    return 0;
}

static int append_path(char **value, const char *path) {
    if (!path || !file_exists(path)) return 1;
    if (*value && value_has_path(*value, path)) return 1;

    char *next = NULL;

    if (*value && **value) {
        if (asprintf(&next, "%s:%s", *value, path) < 0)
            next = NULL;
    } else {
        if (asprintf(&next, "%s", path) < 0)
            next = NULL;
    }

    if (!next) return 0;

    free(*value);
    *value = next;
    return 1;
}

/* Build a fresh child environment. Existing third-party DYLD entries are
 * preserved; this router only adds the one payload required for this edge. */
static char **env_with_payloads(char *const envp[],
                                const char *primary,
                                const char *secondary,
                                char **owned_entry) {
    if (!envp) return NULL;

    size_t count = 0;
    while (envp[count]) count++;

    const char *existing = NULL;
    for (size_t i = 0; i < count; i++) {
        if (strncmp(envp[i], kInsertKey, INSERT_KEY_LEN) == 0) {
            existing = envp[i] + INSERT_KEY_LEN;
            break;
        }
    }

    char *value = strdup(existing ? existing : "");
    if (!value) return NULL;

    if (!append_path(&value, primary) ||
        !append_path(&value, secondary)) {
        free(value);
        return NULL;
    }

    if (!*value) {
        free(value);
        return NULL;
    }

    char *entry = NULL;
    if (asprintf(&entry, "%s%s", kInsertKey, value) < 0)
        entry = NULL;
    free(value);

    if (!entry) return NULL;

    char **out = calloc(count + 2, sizeof(char *));
    if (!out) {
        free(entry);
        return NULL;
    }

    size_t j = 0;
    for (size_t i = 0; i < count; i++) {
        if (strncmp(envp[i], kInsertKey, INSERT_KEY_LEN) == 0)
            continue;
        out[j++] = envp[i];
    }

    out[j++] = entry;
    out[j] = NULL;

    *owned_entry = entry;
    return out;
}

static int spawn_common(int (*real)(pid_t *, const char *,
                                    const posix_spawn_file_actions_t *,
                                    const posix_spawnattr_t *,
                                    char *const [], char *const []),
                        pid_t *pid,
                        const char *path,
                        const posix_spawn_file_actions_t *actions,
                        const posix_spawnattr_t *attr,
                        char *const argv[],
                        char *const envp[]) {
    if (!file_exists(kEnableFile))
        return real(pid, path, actions, attr, argv, envp);

    const char *name = last_component(path);

    /* xpcproxy is the only propagation hop. Give it ElleKit's own pspawn,
     * not libinjector and not lhook itself. */
    if (strcmp(name, "xpcproxy") == 0) {
        const char *pspawn = pspawn_path();

        if (!pspawn) {
            trace("xpcproxy skipped (pspawn missing)", path);
            return real(pid, path, actions, attr, argv, envp);
        }

        trace("pspawn", path);

        char *owned = NULL;
        char **newenv = env_with_payloads(envp, pspawn, NULL, &owned);
        if (!newenv)
            return real(pid, path, actions, attr, argv, envp);

        int rc = real(pid, path, actions, attr, argv, newenv);
        free(owned);
        free(newenv);
        return rc;
    }

    if (denied(path)) {
        trace("clean", path);
        return real(pid, path, actions, attr, argv, envp);
    }

    /* A few launchd jobs (notably SpringBoard) are direct children and never
     * pass through xpcproxy. They still need the final ElleKit loader. */
    if (!file_exists(kTweakLoader)) {
        trace("direct skipped (TweakLoader missing)", path);
        return real(pid, path, actions, attr, argv, envp);
    }

    const char *secondary =
        strcmp(name, "iconservicesagent") == 0 ? kSystemHook : NULL;

    trace("TweakLoader", path);

    char *owned = NULL;
    char **newenv = env_with_payloads(envp,
                                      kTweakLoader,
                                      secondary,
                                      &owned);
    if (!newenv)
        return real(pid, path, actions, attr, argv, envp);

    int rc = real(pid, path, actions, attr, argv, newenv);
    free(owned);
    free(newenv);
    return rc;
}

static int my_posix_spawn(pid_t *pid,
                          const char *path,
                          const posix_spawn_file_actions_t *actions,
                          const posix_spawnattr_t *attr,
                          char *const argv[],
                          char *const envp[]) {
    return spawn_common(posix_spawn, pid, path,
                        actions, attr, argv, envp);
}

static int my_posix_spawnp(pid_t *pid,
                           const char *path,
                           const posix_spawn_file_actions_t *actions,
                           const posix_spawnattr_t *attr,
                           char *const argv[],
                           char *const envp[]) {
    return spawn_common(posix_spawnp, pid, path,
                        actions, attr, argv, envp);
}

DYLD_INTERPOSE(my_posix_spawn,  posix_spawn)
DYLD_INTERPOSE(my_posix_spawnp, posix_spawnp)

__attribute__((constructor))
static void lhook_init(void) {
    if (getpid() != 1) return;

    int fd = open("/dev/console", O_WRONLY | O_NONBLOCK);
    if (fd >= 0) {
        static const char msg[] =
            "[lhook] PID1 router loaded (ElleKit pspawn mode)\n";
        (void)write(fd, msg, sizeof(msg) - 1);
        close(fd);
    }
}
