// personaalloc - can we create persona 99 at runtime?
//
// The persona table on this device is completely empty (0 personas across
// ids 0..120), which is why posix_spawn(persona 99) returns ESRCH rather than
// EPERM: the kernel finds nothing to adopt. Personas are normally created
// during a normal first boot, which this device has never completed.
//
// If kpersona_alloc works, Sileo's spawnAsRoot starts working with no kernel
// patch and no reboot. If it is gated, we learn that cheaply.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <dlfcn.h>
#include <sys/types.h>

struct kpersona_info {
    unsigned int persona_info_version;
    uid_t        persona_id;
    int          persona_type;
    gid_t        persona_gid;
    unsigned int persona_ngroups;
    gid_t        persona_groups[16];
    uid_t        persona_gmuid;
    char         persona_name[257];
};

typedef int (*alloc_t)(struct kpersona_info *, uid_t *);
typedef int (*info_t)(uid_t, struct kpersona_info *);

// persona_type values from XNU bsd/sys/persona.h
#define PERSONA_GUEST   1
#define PERSONA_MANAGED 2
#define PERSONA_PRIV    3
#define PERSONA_SYSTEM  4

static const char *tname(int t) {
    switch (t) { case 1: return "GUEST"; case 2: return "MANAGED";
                 case 3: return "PRIV";  case 4: return "SYSTEM"; default: return "?"; }
}

int main(void) {
    alloc_t kalloc = (alloc_t)dlsym(RTLD_DEFAULT, "kpersona_alloc");
    info_t  kinfo  = (info_t) dlsym(RTLD_DEFAULT, "kpersona_info");
    printf("uid=%d euid=%d  kpersona_alloc=%p\n\n", getuid(), geteuid(), (void *)kalloc);
    if (!kalloc) { printf("kpersona_alloc unavailable\n"); return 1; }

    // Try each type; we do not know which the kernel will accept here.
    int types[] = { PERSONA_PRIV, PERSONA_SYSTEM, PERSONA_MANAGED, PERSONA_GUEST };
    for (unsigned i = 0; i < sizeof(types)/sizeof(types[0]); i++) {
        struct kpersona_info info;
        memset(&info, 0, sizeof(info));
        info.persona_info_version = 1;
        info.persona_id   = 99;      // the id Sileo asks for
        info.persona_type = types[i];
        info.persona_gid  = 0;
        strlcpy(info.persona_name, "sileo", sizeof(info.persona_name));

        uid_t out = 0;
        errno = 0;
        int rc = kalloc(&info, &out);
        printf("  alloc type=%-8s rc=%d errno=%d (%s) -> id=%u\n",
               tname(types[i]), rc, errno, rc ? strerror(errno) : "OK", out);
        if (rc == 0) break;
    }

    printf("\n=== persona 99 present now? ===\n");
    if (kinfo) {
        struct kpersona_info c; memset(&c, 0, sizeof(c)); c.persona_info_version = 1;
        int rc = kinfo(99, &c);
        if (rc == 0) printf("  YES: id=%u type=%s name=%s\n",
                            c.persona_id, tname(c.persona_type), c.persona_name);
        else printf("  NO: rc=%d errno=%d (%s)\n", rc, errno, strerror(errno));
    }
    return 0;
}
