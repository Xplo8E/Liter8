// pfwatch - ensure each new PosterBoard PID receives the asserted runtime repair.
// Compile the verified probe as an internal entry point so there is only one repair path.

#define main pfruntimeprobe_entry
#include "pfruntimeprobe.m"
#undef main

#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/file.h>
#include <sys/param.h>
#include <unistd.h>

#define PROC_ALL_PIDS 1
extern int proc_listpids(uint32_t type, uint32_t typeinfo, void *buffer,
                         int buffersize);
extern int proc_pidpath(int pid, void *buffer, uint32_t buffersize);

static const char *kWatchTarget = "/Applications/PosterBoard.app/PosterBoard";
// com.jbboot can run before SpringBoard creates ~/Library/SpringBoard on a
// freshly restored phone. /var/mobile already exists because launchd opens the
// job's stdout there, while /var/tmp is an early-boot, world-writable location.
// Using only existing parents prevents the watcher from exiting cleanly before
// it ever observes PosterBoard.
static const char *kWatchLog = "/private/var/mobile/pfwatch.log";
static const char *kWatchLock = "/private/var/tmp/liter8-pfwatch.lock";

static pid_t posterboard_pid(void) {
    static pid_t highest_seen = 0;
    pid_t pids[4096] = {0};
    int bytes = proc_listpids(PROC_ALL_PIDS, 0, pids, sizeof(pids));
    if (bytes <= 0) return 0;

    pid_t found = 0;
    pid_t new_highest = highest_seen;
    int count = bytes / (int)sizeof(pid_t);
    for (int i = 0; i < count; i++) {
        if (pids[i] <= 1) continue;
        if (pids[i] > new_highest) new_highest = pids[i];
        if (highest_seen != 0 && pids[i] <= highest_seen) continue;
        char path[MAXPATHLEN] = {0};
        if (proc_pidpath(pids[i], path, sizeof(path)) > 0 &&
            strcmp(path, kWatchTarget) == 0) {
            found = pids[i];
            break;
        }
    }
    highest_seen = new_highest;
    return found;
}

static int ensure_repaired(pid_t pid) {
    char pid_string[24];
    snprintf(pid_string, sizeof(pid_string), "%d", pid);
    char *argv[] = {"pfwatch-probe", pid_string, "--ensure", NULL};

    int output = open(kWatchLog, O_WRONLY | O_CREAT | O_APPEND, 0644);
    int saved_stdout = dup(STDOUT_FILENO);
    int saved_stderr = dup(STDERR_FILENO);
    if (output >= 0) {
        dup2(output, STDOUT_FILENO);
        dup2(output, STDERR_FILENO);
        close(output);
    }

    int result = pfruntimeprobe_entry(3, argv);
    fflush(NULL);
    if (saved_stdout >= 0) {
        dup2(saved_stdout, STDOUT_FILENO);
        close(saved_stdout);
    }
    if (saved_stderr >= 0) {
        dup2(saved_stderr, STDERR_FILENO);
        close(saved_stderr);
    }
    return result;
}

static void watch_log(pid_t target, int result) {
    FILE *log = fopen(kWatchLog, "a");
    if (!log) return;
    fprintf(log, "[pfwatch] target %d ensure exit %d\n", target, result);
    fclose(log);
}

int main(void) {
    int lock = open(kWatchLock, O_WRONLY | O_CREAT, 0644);
    if (lock < 0 || flock(lock, LOCK_EX | LOCK_NB) != 0) return 0;

    FILE *log = fopen(kWatchLog, "a");
    if (log) {
        fprintf(log, "[pfwatch] pid %d started\n", getpid());
        fclose(log);
    }

    pid_t target = 0;
    BOOL repaired = NO;
    unsigned failures = 0;
    for (;;) {
        if (target > 1 && kill(target, 0) != 0) {
            target = 0;
            repaired = NO;
            failures = 0;
        }
        if (target == 0) target = posterboard_pid();
        if (target > 1 && !repaired) {
            int result = ensure_repaired(target);
            watch_log(target, result);
            repaired = result == 0;
            failures = repaired ? 0 : failures + 1;
        }
        usleep(repaired ? 100000 : (failures < 50 ? 10000 : 500000));
    }
}
