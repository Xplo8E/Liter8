/*
 * Minimal slot-A payload for rootless application icons.
 *
 * iconservicesagent cannot read /var/jb, so registered bundles there render a white
 * placeholder. The per-boot helper writes a read-extension token to a System-readable
 * mailbox. This constructor consumes it only in iconservicesagent and verifies the grant
 * by opening /private/var/jb. Every other process returns after one name comparison.
 */

#include <dlfcn.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

extern int proc_pidpath(int pid, void *buffer, unsigned int buffersize);

#define PATH_MAX_LOCAL 4096
#define TOKEN_MAX      8192

static const char *kTarget   = "iconservicesagent";
static const char *kMailbox  = "/private/var/tmp/sbext.token";
static const char *kVerify   = "/private/var/jb";
static const char *kResult   = "/private/var/tmp/sbext.iconservicesagent.result";

typedef int64_t (*consume_t)(const char *token);

static void report(const char *message) {
    int fd = open(kResult, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW, 0644);
    if (fd < 0) return;
    dprintf(fd, "pid %d %s\n", getpid(), message);
    close(fd);
}

static ssize_t read_token(char *buffer, size_t size) {
    int fd = open(kMailbox, O_RDONLY | O_NOFOLLOW);
    if (fd < 0) return -1;
    ssize_t got = read(fd, buffer, size - 1);
    close(fd);
    if (got <= 0) return got;

    while (got > 0 && (buffer[got - 1] == '\n' || buffer[got - 1] == '\r')) got--;
    buffer[got] = '\0';
    return got;
}

__attribute__((constructor))
static void systemhook_icon_init(void) {
    char path[PATH_MAX_LOCAL] = {0};
    if (proc_pidpath(getpid(), path, sizeof path) <= 0) return;
    const char *name = strrchr(path, '/');
    name = name ? name + 1 : path;
    if (strcmp(name, kTarget) != 0) return;

    char token[TOKEN_MAX];
    ssize_t length = read_token(token, sizeof token);
    if (length <= 0 || !strchr(token, ';')) {
        report("no usable read token");
        return;
    }

    consume_t consume = (consume_t)dlsym(RTLD_DEFAULT, "sandbox_extension_consume");
    if (!consume) {
        report("sandbox_extension_consume unavailable");
        return;
    }
    if (consume(token) < 0) {
        report("read token rejected");
        return;
    }

    int fd = open(kVerify, O_RDONLY);
    if (fd < 0) {
        report("token consumed but /var/jb is still denied");
        return;
    }
    close(fd);
    report("consume OK, /var/jb verified readable");
}
