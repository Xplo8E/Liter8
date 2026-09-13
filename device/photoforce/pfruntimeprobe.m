// Probe and asserted runtime repair for PosterFoundation's cached PosterBoard contract.
//
// Read-only is the default. --apply is gated by a same-process mutation self-test and an
// exact target pre-image. It loads the same shared-cache image locally to recover the live
// cache slide, then reads the cached singleton and its object bytes through the task port.

#import <Foundation/Foundation.h>

#include <dlfcn.h>
#include <mach/mach.h>
#include <malloc/malloc.h>
#include <objc/runtime.h>
#include <ptrauth.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern kern_return_t mach_vm_read_overwrite(vm_map_t, mach_vm_address_t, mach_vm_size_t,
                                             mach_vm_address_t, mach_vm_size_t *);
extern kern_return_t mach_vm_write(vm_map_t, mach_vm_address_t, vm_offset_t,
                                   mach_msg_type_number_t);

static const uintptr_t kPFFunctionPreferred = 0x1c6205facULL;
static const uintptr_t kPFOncePreferred     = 0x1e5c26ae0ULL;
static const uintptr_t kPFObjectPreferred   = 0x1e5c26ae8ULL;
static const char *kPFPath =
    "/System/Library/PrivateFrameworks/PosterFoundation.framework/PosterFoundation";

typedef NSDictionary *(*PFValuesFn)(void);

static kern_return_t read_remote(task_t task, mach_vm_address_t address,
                                 void *output, size_t size) {
    mach_vm_size_t copied = 0;
    kern_return_t kr = mach_vm_read_overwrite(task, address, size,
                                               (mach_vm_address_t)output, &copied);
    if (kr == KERN_SUCCESS && copied != size) return KERN_FAILURE;
    return kr;
}

static void dump_words(const char *label, const void *bytes, size_t size) {
    const uint64_t *words = bytes;
    printf("%s (%zu bytes):\n", label, size);
    for (size_t i = 0; i < size / sizeof(*words); i++) {
        printf("  +0x%02zx  0x%016llx\n", i * sizeof(*words), words[i]);
    }
}

static int run_local_mutation_selftest(void) {
    id keys[2] = { NSURLIsReadableKey, NSURLFileProtectionKey };
    id values[2] = { [NSNumber numberWithBool:YES], NSURLFileProtectionNone };
    NSDictionary *test = [[NSDictionary alloc] initWithObjects:values forKeys:keys count:2];
    uint64_t *words = (__bridge void *)test;

    printf("local mutation self-test: class=%s size=%zu\n",
           object_getClassName(test), malloc_size((__bridge const void *)test));
    if (malloc_size((__bridge const void *)test) != 0x40 ||
        words[1] != 0x0400000000000002ULL ||
        words[2] != (uintptr_t)NSURLFileProtectionKey ||
        words[3] != (uintptr_t)NSURLFileProtectionNone ||
        words[4] != 0 || words[5] != 0 ||
        words[6] != (uintptr_t)NSURLIsReadableKey ||
        words[7] != (uintptr_t)[NSNumber numberWithBool:YES]) {
        fprintf(stderr, "local mutation self-test: layout pre-image mismatch\n");
        return 1;
    }

    // Exact proposed target mutation: decrement count and clear only the protection
    // bucket. Capacity/hash geometry and the readability bucket stay unchanged.
    words[1] = 0x0400000000000001ULL;
    words[2] = 0;
    words[3] = 0;

    BOOL ok = test.count == 1 &&
              [test[NSURLIsReadableKey] isEqual:@YES] &&
              test[NSURLFileProtectionKey] == nil;
    printf("local mutation self-test: count=%lu readable=%s protection=%s result=%s\n",
           (unsigned long)test.count,
           [test[NSURLIsReadableKey] description].UTF8String ?: "(nil)",
           [test[NSURLFileProtectionKey] description].UTF8String ?: "(nil)",
           ok ? "PASS" : "FAIL");
    printf("local mutation self-test values=%s\n", test.description.UTF8String);
    return ok ? 0 : 1;
}

static int apply_remote_mutation(task_t task, mach_vm_address_t object,
                                 const uint64_t words[8]) {
    const uint64_t expected[7] = {
        0x0400000000000002ULL,
        (uintptr_t)NSURLFileProtectionKey,
        (uintptr_t)NSURLFileProtectionNone,
        0,
        0,
        (uintptr_t)NSURLIsReadableKey,
        (uintptr_t)[NSNumber numberWithBool:YES],
    };
    if (memcmp(&words[1], expected, sizeof(expected)) != 0) {
        fprintf(stderr, "remote mutation: exact dictionary pre-image mismatch\n");
        return 1;
    }

    const uint64_t replacement[3] = {
        0x0400000000000001ULL,
        0,
        0,
    };

    kern_return_t kr = task_suspend(task);
    printf("task_suspend -> %d (%s)\n", kr, mach_error_string(kr));
    if (kr != KERN_SUCCESS) return 1;

    kr = mach_vm_write(task, object + 0x8, (vm_offset_t)replacement,
                       (mach_msg_type_number_t)sizeof(replacement));
    printf("mach_vm_write 24-byte contract -> %d (%s)\n", kr, mach_error_string(kr));

    kern_return_t resume_kr = task_resume(task);
    printf("task_resume -> %d (%s)\n", resume_kr, mach_error_string(resume_kr));
    if (resume_kr != KERN_SUCCESS) {
        resume_kr = task_resume(task);
        printf("task_resume retry -> %d (%s)\n", resume_kr, mach_error_string(resume_kr));
    }
    if (kr != KERN_SUCCESS || resume_kr != KERN_SUCCESS) return 1;

    uint64_t check[8] = {0};
    kr = read_remote(task, object, check, sizeof(check));
    printf("readback -> %d (%s)\n", kr, mach_error_string(kr));
    if (kr != KERN_SUCCESS ||
        memcmp(&check[1], replacement, sizeof(replacement)) != 0 ||
        check[6] != (uintptr_t)NSURLIsReadableKey ||
        check[7] != (uintptr_t)[NSNumber numberWithBool:YES]) {
        fprintf(stderr, "remote mutation: readback mismatch\n");
        return 1;
    }

    printf("remote mutation: PASS; protection bucket removed, readability retained\n");
    return 0;
}

int main(int argc, char **argv) {
    @autoreleasepool {
        if (argc < 2 || argc > 3) {
            fprintf(stderr, "usage: %s <PosterBoard-pid> [--local-selftest|--apply|--ensure]\n", argv[0]);
            return 2;
        }

        pid_t pid = (pid_t)strtol(argv[1], NULL, 10);
        if (pid <= 1) {
            fprintf(stderr, "invalid target pid: %s\n", argv[1]);
            return 2;
        }

        void *handle = dlopen(kPFPath, RTLD_NOW | RTLD_LOCAL);
        if (!handle) {
            fprintf(stderr, "dlopen PosterFoundation: %s\n", dlerror());
            return 1;
        }

        PFValuesFn values_fn = (PFValuesFn)dlsym(handle, "PFPosterPathURLResourceValues");
        if (!values_fn) {
            fprintf(stderr, "dlsym PFPosterPathURLResourceValues: %s\n", dlerror());
            return 1;
        }

        NSDictionary *local_values = values_fn(); // complete dispatch_once before reading
        uintptr_t live_fn = (uintptr_t)ptrauth_strip((void *)values_fn,
                                                     ptrauth_key_function_pointer);
        uintptr_t slide = live_fn - kPFFunctionPreferred;
        uintptr_t once_address = kPFOncePreferred + slide;
        uintptr_t slot_address = kPFObjectPreferred + slide;
        NSDictionary *local_slot_value = *(NSDictionary * const *)slot_address;

        printf("target pid=%d\n", pid);
        printf("PF function preferred=0x%llx live=0x%llx slide=0x%llx\n",
               (uint64_t)kPFFunctionPreferred, (uint64_t)live_fn, (uint64_t)slide);
        printf("PF once=0x%llx slot=0x%llx\n",
               (uint64_t)once_address, (uint64_t)slot_address);
        printf("local return=%p slot=%p class=%s malloc_size=%zu\n",
               local_values, local_slot_value, object_getClassName(local_values),
               malloc_size((__bridge const void *)local_values));
        printf("local values=%s\n", local_values.description.UTF8String);
        printf("local constants:\n");
        printf("  NSURLIsReadableKey=%p  @YES=%p\n",
               (__bridge const void *)NSURLIsReadableKey,
               (__bridge const void *)[NSNumber numberWithBool:YES]);
        printf("  NSURLFileProtectionKey=%p  NSURLFileProtectionNone=%p\n",
               (__bridge const void *)NSURLFileProtectionKey,
               (__bridge const void *)NSURLFileProtectionNone);

        if (local_values != local_slot_value) {
            fprintf(stderr, "local singleton verification failed; refusing target read\n");
            return 1;
        }

        task_t task = MACH_PORT_NULL;
        kern_return_t kr = task_for_pid(mach_task_self(), pid, &task);
        printf("task_for_pid -> %d (%s), port=0x%x\n", kr, mach_error_string(kr), task);
        if (kr != KERN_SUCCESS || task == MACH_PORT_NULL || task == MACH_PORT_DEAD) return 1;

        uint64_t remote_once = 0;
        uint64_t remote_object = 0;
        kr = read_remote(task, once_address, &remote_once, sizeof(remote_once));
        printf("read once -> %d (%s), value=0x%016llx\n",
               kr, mach_error_string(kr), remote_once);
        if (kr != KERN_SUCCESS) return 1;

        kr = read_remote(task, slot_address, &remote_object, sizeof(remote_object));
        printf("read slot -> %d (%s), value=0x%016llx\n",
               kr, mach_error_string(kr), remote_object);
        if (kr != KERN_SUCCESS || remote_object == 0) return 1;

        // malloc_size above is 0x40 for this __NSDictionaryI. Do not read beyond it:
        // adjacent heap contents are unrelated and can differ between processes.
        uint8_t local_bytes[0x40] = {0};
        uint8_t remote_bytes[0x40] = {0};
        memcpy(local_bytes, (__bridge const void *)local_values, sizeof(local_bytes));
        kr = read_remote(task, remote_object, remote_bytes, sizeof(remote_bytes));
        printf("read object -> %d (%s)\n", kr, mach_error_string(kr));
        if (kr != KERN_SUCCESS) return 1;

        dump_words("local object", local_bytes, sizeof(local_bytes));
        dump_words("remote object", remote_bytes, sizeof(remote_bytes));

        NSNumber *supports = nil;
        NSError *error = nil;
        NSURL *mobile = [NSURL fileURLWithPath:@"/var/mobile" isDirectory:YES];
        BOOL got = [mobile getResourceValue:&supports
                                     forKey:NSURLVolumeSupportsFileProtectionKey
                                      error:&error];
        printf("/var/mobile volumeSupportsFileProtection got=%d value=%s error=%s\n",
               got, supports.description.UTF8String ?: "(nil)",
               error.description.UTF8String ?: "(nil)");

        if (argc == 3) {
            BOOL selftest_only = strcmp(argv[2], "--local-selftest") == 0;
            BOOL apply = strcmp(argv[2], "--apply") == 0;
            BOOL ensure = strcmp(argv[2], "--ensure") == 0;
            if (!selftest_only && !apply && !ensure) {
                fprintf(stderr, "unknown option: %s\n", argv[2]);
                return 2;
            }

            if (ensure) {
                const uint64_t repaired[7] = {
                    0x0400000000000001ULL,
                    0,
                    0,
                    0,
                    0,
                    (uintptr_t)NSURLIsReadableKey,
                    (uintptr_t)[NSNumber numberWithBool:YES],
                };
                if (memcmp(&((const uint64_t *)remote_bytes)[1], repaired,
                           sizeof(repaired)) == 0) {
                    printf("remote mutation: already repaired\n");
                    return 0;
                }
            }

            int selftest = run_local_mutation_selftest();
            if (selftest != 0 || selftest_only) return selftest;
            return apply_remote_mutation(task, remote_object,
                                         (const uint64_t *)remote_bytes);
        }
    }
    return 0;
}
