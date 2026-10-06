#include <errno.h>
#include <fcntl.h>
#include <spawn.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/file.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;

static const char *kReadyPlist =
    "/System/Developer/Library/LaunchDaemons/com.apple.coredevice.dtdeviceinfod.plist";
static const char *kBootstrapCommand =
    "exec /var/jb/usr/bin/launchctl bootstrap system "
    "/System/Developer/Library/LaunchDaemons";
static const char *kRegistrationCheck =
    "/var/jb/usr/bin/launchctl print "
    "system/com.apple.coredevice.dtdeviceinfod >/dev/null 2>&1";
static const char *kLogPath = "/private/var/mobile/ddiwatch.log";
static const char *kLockPath = "/private/var/tmp/liter8-ddiwatch.lock";

static void write_log(const char *message, int status) {
    FILE *log = fopen(kLogPath, "a");
    if (!log) return;
    if (status >= 0) {
        fprintf(log, "[ddiwatch] %s: %d\n", message, status);
    } else {
        fprintf(log, "[ddiwatch] %s\n", message);
    }
    fclose(log);
}

static int run_shell(const char *command, bool capture_output) {
    posix_spawn_file_actions_t actions;
    if (posix_spawn_file_actions_init(&actions) != 0) return 125;

    if (capture_output) {
        int flags = O_WRONLY | O_CREAT | O_APPEND;
        if (posix_spawn_file_actions_addopen(
                &actions, STDOUT_FILENO, kLogPath, flags, 0644) != 0 ||
            posix_spawn_file_actions_addopen(
                &actions, STDERR_FILENO, kLogPath, flags, 0644) != 0) {
            posix_spawn_file_actions_destroy(&actions);
            return 125;
        }
    }

    char *const arguments[] = {
        "/bin/sh",
        "-c",
        (char *)command,
        NULL,
    };
    pid_t child = 0;
    int result = posix_spawn(
        &child, "/bin/sh", &actions, NULL, arguments, environ
    );
    posix_spawn_file_actions_destroy(&actions);
    if (result != 0) return result;

    int status = 0;
    while (waitpid(child, &status, 0) < 0) {
        if (errno != EINTR) return errno;
    }
    if (WIFEXITED(status)) return WEXITSTATUS(status);
    if (WIFSIGNALED(status)) return 128 + WTERMSIG(status);
    return 125;
}

static bool services_registered(void) {
    return run_shell(kRegistrationCheck, false) == 0;
}

int main(void) {
    int lock = open(kLockPath, O_WRONLY | O_CREAT, 0644);
    if (lock < 0 || flock(lock, LOCK_EX | LOCK_NB) != 0) return 0;

    write_log("started", -1);
    bool image_ready = false;
    bool registered = false;
    unsigned retry_ticks = 0;

    for (;;) {
        bool ready = access(kReadyPlist, R_OK) == 0;
        if (!ready) {
            if (image_ready) write_log("DeveloperDiskImage unavailable", -1);
            image_ready = false;
            registered = false;
            retry_ticks = 0;
            usleep(250000);
            continue;
        }

        if (!image_ready) {
            image_ready = true;
            write_log("DeveloperDiskImage launch daemons ready", -1);
        }

        if (!registered && retry_ticks == 0) {
            if (services_registered()) {
                registered = true;
                write_log("services already registered", -1);
            } else {
                int result = run_shell(kBootstrapCommand, true);
                write_log("bootstrap exit", result);
                registered = result == 0 || services_registered();
                if (registered) {
                    write_log("services registered", -1);
                } else {
                    // Five seconds at the 250 ms loop interval.  A mount may
                    // become visible just before all image contents are ready.
                    retry_ticks = 20;
                }
            }
        }

        if (retry_ticks > 0) retry_ticks--;
        usleep(250000);
    }
}
