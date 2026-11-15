/*
 * l8_acmpool - the daemon-side ACM pool override behind build 13.
 *
 * coreauthd's ACM module (ModuleACM.bundle) tracks one ContextPluginACM per
 * client context in a bounded pool. The pool's size comes from the SEP-backed
 * kernel user client via -[LACACMPoolsInfo _update] (LACACMPoolInfo is built
 * with initWithSize:used: from the ACM answer). SEP-less, the answer is size
 * 0, so every -[ModuleACM trackPlugin:processId:proxy:context:
 * invalidationBlock:] sees used >= size and runs the hoard eviction: it picks
 * the oldest context of the process holding the most, logs "Will invalidate
 * ... which is the oldest context created by ...", and fires the tracked
 * record's invalidationBlock. That block tears down the flow's own context
 * mid-operation (measured: it landed 13 ms before the flow's successful
 * setCredential), and the client process then over-releases in its next
 * update-cycle autorelease pool pop (three identical crashes, boots 20-21).
 *
 * The override pins the pool accounting to a healthy size: the four scalar
 * LACACMPoolInfo getters (size, free, freeForLA, reservedForLA) answer 64
 * while the marker is on, so used >= size is unreachable and neither the
 * eviction nor the non-disposable "no free slots" failure path can fire. The
 * used getter stays truthful. Everything forwards untouched when the marker
 * is off.
 *
 * Swizzle point chosen over the alternatives: ModuleACM itself is on the
 * sealed system volume (binary patching needs an SSHRD cycle), and the
 * eviction is a C-internal call chain inside it (not interposable); the
 * LACACMPoolInfo getters are ObjC methods in LocalAuthenticationCore, which
 * this shim already hooks in every LA-family process including coreauthd.
 */
#import "l8_hooking.h"
#import <os/log.h>
#import <objc/message.h>
#import <objc/runtime.h>
#import <stdatomic.h>

/* 64 slots: the set-passcode flow creates at most a handful of contexts;
 * stock SEP-backed pools are smaller than this but never evict mid-flow. */
static const unsigned long long kL8PoolSize = 64;

static IMP gOriginalPoolSize;
static IMP gOriginalPoolFree;
static IMP gOriginalPoolFreeForLA;
static IMP gOriginalPoolReservedForLA;

static atomic_bool gPoolInstalled = ATOMIC_VAR_INIT(false);
static atomic_bool gPoolLogged = ATOMIC_VAR_INIT(false);

BOOL l8_acmpool_installed(void) {
    return atomic_load(&gPoolInstalled);
}

/* One replacement per getter: same call shape (self, SEL), same integer
 * return. Marker on -> the pinned size; marker off -> forward through that
 * getter's own original, never another getter's. */
static unsigned long long l8_pool_answer_or_forward(id self, SEL sel, IMP original) {
    if (l8_marker_enabled()) {
        if (!atomic_exchange(&gPoolLogged, true)) {
            os_log_error(OS_LOG_DEFAULT,
                         "l8acmpool: pool accounting override active, size=%llu (pid %d)",
                         kL8PoolSize, getpid());
        }
        /* ModuleACM (and with it ContextPluginACM) is present by the time
         * pool queries run - the right moment to retry the daemon blob-store
         * swizzle in coreauthd. Cheap Nil lookup everywhere else. */
        l8_acmdaemon_install_if_ready();
        return kL8PoolSize;
    }
    return ((unsigned long long (*)(id, SEL))original)(self, sel);
}

static unsigned long long l8_pool_size_override(id self, SEL sel) {
    return l8_pool_answer_or_forward(self, sel, gOriginalPoolSize);
}

static unsigned long long l8_pool_free_override(id self, SEL sel) {
    return l8_pool_answer_or_forward(self, sel, gOriginalPoolFree);
}

static unsigned long long l8_pool_free_for_la_override(id self, SEL sel) {
    return l8_pool_answer_or_forward(self, sel, gOriginalPoolFreeForLA);
}

static unsigned long long l8_pool_reserved_for_la_override(id self, SEL sel) {
    return l8_pool_answer_or_forward(self, sel, gOriginalPoolReservedForLA);
}

void l8_acmpool_install_if_ready(void) {
    if (atomic_load(&gPoolInstalled)) return;
    Class cls = objc_lookUpClass("LACACMPoolInfo");
    if (cls == Nil) {
        /* LocalAuthenticationCore not loaded yet; the image-load callback
         * retries on the next family image, like the other sections. */
        return;
    }
    atomic_store(&gPoolInstalled, true);

    /* The getters return an unsigned 64-bit size ("Q@:") in the headers this
     * was decoded from; accept the signed spelling too. Two implicit
     * arguments, no explicit ones. */
    static const char *const kCandidates[] = {"Q@:", "q@:"};
    struct {
        const char *name;
        IMP *original;
        unsigned bit;
    } hooks[] = {
        {"size", &gOriginalPoolSize, 1 << 0},
        {"free", &gOriginalPoolFree, 1 << 1},
        {"freeForLA", &gOriginalPoolFreeForLA, 1 << 2},
        {"reservedForLA", &gOriginalPoolReservedForLA, 1 << 3},
    };
    int mask = 0;
    static const IMP replacements[] = {
        (IMP)l8_pool_size_override, (IMP)l8_pool_free_override,
        (IMP)l8_pool_free_for_la_override, (IMP)l8_pool_reserved_for_la_override,
    };
    for (unsigned i = 0; i < sizeof hooks / sizeof hooks[0]; i++) {
        SEL sel = sel_registerName(hooks[i].name);
        mask |= l8_swap_any(class_getInstanceMethod(cls, sel), hooks[i].name, 2,
                            kCandidates, 2, (IMP)replacements[i],
                            hooks[i].original) << hooks[i].bit;
    }
    os_log_error(OS_LOG_DEFAULT, "l8acmpool: pool override mask 0x%x in pid %d",
                 mask, getpid());
}
