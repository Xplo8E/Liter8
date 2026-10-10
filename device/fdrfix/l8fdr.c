/*
 * l8fdr.dylib - let CommCenter unseal baseband calibration from FDR.
 *
 * The problem, measured on n104ap 24B5099f:
 *
 *   CommCenter: BBUICE16UpdateSource: CAL: searching in FDR
 *   CommCenter: BBUFDRUtilities: DataClass: bbcl, DataInstance: "00000068-..."
 *   CommCenter: BBULog: _AMFDRDecodeVerifyChain: PKI: verify cert was issued
 *               by trusted root 0 (success)
 *   CommCenter: BBULog: _AMFDRDecodeVerifyChain: PKI: check payload hash with
 *               signature (success)
 *   CommCenter: BBULog: _AMFDRDecodeInstPropertyMatching:
 *               kFDRTag_inst propertyLength (sik) (130) != sikLength (96)
 *   CommCenter: BBUICE16UpdateSource: CAL: not found in FDR
 *
 * The certificate chain and the payload signature over the sealed calibration
 * both verify. The only thing that fails is the data *instance identity*. FDR
 * names each sealed instance after the AP sealing identity key, and
 * AMFDRDataCreateSikPubDigestIfNecessary keeps that key verbatim below 66 bytes
 * but SHA-384s it at 66 or more:
 *
 *     if ( a3 < 0x42 ) return CFDataCreate(a1, a2, a3);
 *     ... SHA-384 into 48 bytes ...
 *
 * FactoryData was sealed with a 65-byte key, so the stored instance carries 130
 * hex characters. This device's aks_system_key_get_public returns 66 bytes or
 * more, so it computes a 48-byte digest, 96 hex characters. The device is not
 * failing to produce an identity, it produces a newer one than the seal was made
 * with, and nothing on the device can turn one into the other.
 *
 * libFDR has a sanctioned path that skips exactly this comparison.
 * _AMFDRDecodeInstPropertyMatchingWithType guards it with
 * `if (sikLength != 0 && sikValue != NULL)` and returns a match when neither is
 * supplied, and _AMFDRSealingMapPrepareAMFDRForCopyLocalData decides whether to
 * supply them:
 *
 *     if (AMFDRIsNonDefaultDemotionState(amfdr) ||
 *         os_variant_is_recovery("com.apple.libFDR")) {
 *         log("AP is in NeRD or non-default demotion state, "
 *             "ignore sik verification");
 *         AMFDRSetOption(amfdr, <skip sik>, kCFBooleanTrue);
 *     }
 *
 * Everything else, including the PKI chain that already passes, is still
 * verified. The restore OS has no AP sealing identity either and still has to
 * read sealed data, which is why this path exists at all.
 *
 * Why the demotion term and not the os_variant one:
 *
 *   The os_variant_is_recovery route was tried first and does not work. A
 *   __DATA,__interpose replacement is never called, because libFDR and
 *   libsystem_darwin both live in the dyld shared cache and that call is bound
 *   inside the cache, where interposing from a late-loaded dylib does not reach
 *   it. Measured: the constructor logged on all three CommCenter launches and
 *   the replacement logged zero times, with `ignore sik verification` absent
 *   from 497624 lines of CommCenter log.
 *
 *   AMFDRIsNonDefaultDemotionState needs no interposing. It is three
 *   MobileGestalt queries and no SEP call:
 *
 *     v0 = AMFDRSealingMapCallMGCopyAnswer("CertificateSecurityMode", 0);
 *     v1 = AMFDRSealingMapCallMGCopyAnswer("EffectiveSecurityModeSEP", 0);
 *     v2 = AMFDRSealingMapCallMGCopyAnswer("EffectiveProductionStatusAp", 0);
 *     result = CFBooleanGetValue(v0) && CFBooleanGetValue(v1)
 *              && !CFBooleanGetValue(v2);
 *
 *   and AMFDRSealingMapCallMGCopyAnswerInternal consults a registry *before*
 *   asking MobileGestalt:
 *
 *     if (provider != NULL) {
 *         log("Overriding query for %@", key);
 *         return provider(key, error, context);
 *     }
 *
 *   That registry is filled by AMFDRSealingMapRegisterCustomQueryProvider, which
 *   libFDR exports. So the three answers can be supplied through libFDR's own
 *   published interface, with no patching, no interposing and no DeviceTree,
 *   iBoot or kernel change. The earlier attempts at the same three values failed
 *   precisely because they tried to change them further down: the /chosen
 *   DeviceTree properties are overwritten by iBoot, suppressing iBoot's write
 *   panics in early kernel init with an LLC PIO error, and real hardware
 *   demotion breaks IMG4 validation because the APTicket asserts CPRO=ff/CSEC=ff.
 *
 * Scope. Three guards, each of which alone reduces this to stock behaviour:
 * the host process must be CommCenter, the marker file must exist, and only
 * those three keys are answered. Every other MobileGestalt query in the process
 * is untouched, and nothing outside CommCenter is affected, so no other
 * consumer of these values starts believing the AP is demoted.
 *
 * Like l8pair, the marker is the recovery handle: deleting one file from SSHRD
 * restores stock behaviour without re-deploying a 40 MB re-signed binary.
 */

#include <CoreFoundation/CoreFoundation.h>

#include <dlfcn.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <syslog.h>

/* Both this dylib and its marker have to live on the sealed System volume.
 * Moving them to /var/jb/usr/lib so they could be updated without a DFU cycle
 * was tried and does not work: dyld silently declines to load the dylib into
 * CommCenter from there. See the comment in userland_fixups.py. */
static const char *kEnablePath = "/usr/lib/.liter8-fdr-sik-bypass";
static const char *kProcess = "CommCenter";

/* The provider is called as provider(key, errorOut, context) and its result is
 * consumed as a +1 reference, the same as the MobileGestalt answer it replaces. */
typedef CFTypeRef (*AMFDRCustomQueryProvider)(CFStringRef key, void *error, void *context);
typedef bool (*AMFDRRegisterCustomQueryProvider)(CFStringRef key,
                                                 AMFDRCustomQueryProvider provider,
                                                 void *context);

/* The three terms of AMFDRIsNonDefaultDemotionState, with the answer each one
 * has to give for it to report a demoted AP. */
static const struct {
    const char *key;
    bool answer;
} kDemotionAnswers[] = {
    { "CertificateSecurityMode", true },
    { "EffectiveSecurityModeSEP", true },
    { "EffectiveProductionStatusAp", false },
};

static bool bypass_enabled(void)
{
    struct stat status;
    if (lstat(kEnablePath, &status) != 0) {
        return false;
    }
    return S_ISREG(status.st_mode) && status.st_uid == 0 &&
           (status.st_mode & (S_IWGRP | S_IWOTH)) == 0;
}

/* The context carries the answer rather than a key lookup, so adding a key here
 * cannot accidentally answer a different one. */
static CFTypeRef demotion_answer(CFStringRef key, void *error, void *context)
{
    (void)error;
    CFBooleanRef value = context == NULL ? kCFBooleanFalse : kCFBooleanTrue;

    char name[64] = "?";
    if (key != NULL) {
        CFStringGetCString(key, name, sizeof(name), kCFStringEncodingUTF8);
    }
    syslog(LOG_NOTICE, "l8fdr: answering %s = %s so FDR treats the AP as demoted",
           name, value == kCFBooleanTrue ? "true" : "false");

    return CFRetain(value);
}

__attribute__((constructor))
static void install_demotion_answers(void)
{
    const char *program = getprogname();
    if (program == NULL || strcmp(program, kProcess) != 0) {
        return;
    }
    if (!bypass_enabled()) {
        syslog(LOG_NOTICE, "l8fdr: marker absent, leaving FDR stock");
        return;
    }

    // libFDR is already in the process: CommCenter's baseband updater links it.
    // RTLD_NOLOAD would also work, but a plain dlopen keeps this robust if the
    // load order ever changes.
    void *handle = dlopen("/usr/lib/libFDR.dylib", RTLD_LAZY);
    AMFDRRegisterCustomQueryProvider register_provider =
        (AMFDRRegisterCustomQueryProvider)dlsym(
            handle != NULL ? handle : RTLD_DEFAULT,
            "AMFDRSealingMapRegisterCustomQueryProvider");
    if (register_provider == NULL) {
        syslog(LOG_ERR, "l8fdr: AMFDRSealingMapRegisterCustomQueryProvider is "
                        "unavailable, FDR left stock");
        return;
    }

    size_t installed = 0;
    for (size_t i = 0; i < sizeof(kDemotionAnswers) / sizeof(kDemotionAnswers[0]); ++i) {
        CFStringRef key = CFStringCreateWithCString(
            kCFAllocatorDefault, kDemotionAnswers[i].key, kCFStringEncodingUTF8);
        if (key == NULL) {
            continue;
        }
        // A non-NULL context means "answer true". The registry stores the
        // pointer as-is, so it must not be a pointer into this frame.
        void *context = kDemotionAnswers[i].answer ? (void *)kCFBooleanTrue : NULL;
        if (register_provider(key, demotion_answer, context)) {
            installed++;
        } else {
            syslog(LOG_ERR, "l8fdr: could not register a provider for %s",
                   kDemotionAnswers[i].key);
        }
        // Deliberately not released. Whether the registry retains its keys is
        // not something this code can see, and three CFStrings held for the
        // life of the process cost nothing next to risking a use-after-free on
        // every MobileGestalt query libFDR makes.
    }

    syslog(LOG_NOTICE,
           "l8fdr: loaded in %s, registered %zu of 3 demotion-state answers",
           kProcess, installed);
}
