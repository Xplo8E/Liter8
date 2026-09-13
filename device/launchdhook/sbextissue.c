/* Refresh the bearer read-extension consumed by systemhook_icon.dylib. */

#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static const char *kClass   = "com.apple.app-sandbox.read";
static const char *kPath    = "/private/var/jb";
static const char *kMailbox = "/private/var/tmp/sbext.token";

typedef char *(*issue_file_t)(const char *extension_class, const char *path,
                              uint32_t flags);

static int write_all(int fd, const char *buffer, size_t size) {
    while (size) {
        ssize_t written = write(fd, buffer, size);
        if (written < 0 && errno == EINTR) continue;
        if (written <= 0) return -1;
        buffer += written;
        size -= (size_t)written;
    }
    return 0;
}

int main(void) {
    issue_file_t issue = (issue_file_t)dlsym(RTLD_DEFAULT,
                                              "sandbox_extension_issue_file");
    if (!issue) {
        unlink(kMailbox);
        fprintf(stderr, "sandbox_extension_issue_file unavailable\n");
        return 1;
    }

    char *token = issue(kClass, kPath, 0);
    if (!token || !strchr(token, ';')) {
        unlink(kMailbox);
        fprintf(stderr, "could not issue %s for %s\n", kClass, kPath);
        return 1;
    }

    int fd = open(kMailbox, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW, 0644);
    if (fd < 0) {
        fprintf(stderr, "open %s: %s\n", kMailbox, strerror(errno));
        return 1;
    }
    if (fchown(fd, 0, 0) != 0 || fchmod(fd, 0644) != 0 ||
        write_all(fd, token, strlen(token)) != 0 || fsync(fd) != 0) {
        int saved = errno;
        close(fd);
        unlink(kMailbox);
        fprintf(stderr, "write %s: %s\n", kMailbox, strerror(saved));
        return 1;
    }
    close(fd);
    puts("sandbox read token refreshed");
    return 0;
}
