import Foundation

/// Names the resolver data selected for one firmware family.
///
/// Signatures and payloads are deliberately separate. A compiler update may
/// change the instructions used to locate a function while the patch itself
/// remains `mov w0, #0; ret`. Conversely, an ABI change may require a new
/// payload even when an anchor still resolves.
public struct ResolverVariantProfile: Equatable, Sendable {
    public enum Support: String, Equatable, Sendable {
        case supported
        case pendingResearch = "pending-research"
    }

    public let signature: String
    public let payload: String
    public let support: Support

    public init(signature: String, payload: String, support: Support = .supported) {
        self.signature = signature
        self.payload = payload
        self.support = support
    }
}

/// Kernel identity and resolver-variant selection for one known XNU build.
///
/// Apple build IDs such as `24A5390f` are not stored in a decompressed
/// kernelcache. The registry therefore detects the embedded XNU fingerprint
/// and maps it to build metadata plus the signature/payload variants that have
/// been recovered for individual kernel resolvers. This does not grant access
/// to the full device workflow; `DeviceWorkflowProfile` owns that decision.
///
/// What a fingerprint identifies is an XNU build, and that is deliberately not
/// the same thing as an Apple build ID: `24A435` and `24A437` both carry
/// `xnu-13432.2.10~2`, differing only in build metadata (host paths and
/// Mach-O UUIDs). `builds` is therefore a list. Reporting a single ID here
/// would be a claim the kernelcache does not support, and the whole point of
/// `detect` returning nil for unknown firmware is to avoid exactly that.
public struct KernelResolverProfile: Equatable, Sendable {
    public let id: String
    public let productVersion: String
    /// Every Apple build ID observed shipping this XNU fingerprint, in release
    /// order. More than one entry means the artifacts are indistinguishable by
    /// fingerprint alone, not that the profile is ambiguous.
    public let builds: [String]
    public let boards: [String]
    public let component: String
    public let embeddedFingerprint: String
    public let resolverVariants: [String: ResolverVariantProfile]
    /// Optional patch families this kernel leaves out of the composite boot
    /// plans, because they have not been ported to it. Naming one here is an
    /// explicit, reviewed decision; a kernel without a profile still has to
    /// resolve every family.
    public let omittedResolvers: Set<String>

    public init(
        id: String,
        productVersion: String,
        builds: [String],
        boards: [String],
        component: String,
        embeddedFingerprint: String,
        resolverVariants: [String: ResolverVariantProfile],
        omittedResolvers: Set<String> = []
    ) {
        self.id = id
        self.productVersion = productVersion
        self.builds = builds
        self.boards = boards
        self.component = component
        self.embeddedFingerprint = embeddedFingerprint
        self.resolverVariants = resolverVariants
        self.omittedResolvers = omittedResolvers
    }

    /// Whether this profile covers a specific Apple build ID.
    public func covers(build: String) -> Bool {
        builds.contains(build)
    }

    public func variants(for resolver: String) -> ResolverVariantProfile? {
        resolverVariants[resolver]
    }
}

/// The reviewed build-to-variant map.
///
/// This table contains no offsets. Offsets remain outputs of semantic
/// resolution and fixture-only verification oracles.
public enum KernelResolverProfileRegistry {
    public static let profiles: [KernelResolverProfile] = [
        KernelResolverProfile(
            id: "ios27-beta2-24A5370h-d421ap",
            productVersion: "27.0 beta 2",
            builds: ["24A5370h"],
            boards: ["d421ap", "d431ap"],
            component: "kernelcache.release.iphone12",
            embeddedFingerprint: "xnu-13432.0.5.502.4~1/RELEASE_ARM64_T8030",
            resolverVariants: [
                "kernel-credential-manager": ResolverVariantProfile(
                    signature: "ios27-early-beta-acm-v1",
                    payload: "acm-return-success-v1"
                ),
            ]
        ),
        KernelResolverProfile(
            id: "ios27-beta4-24A5390f-n104ap",
            productVersion: "27.0 beta 4",
            builds: ["24A5390f"],
            boards: ["n104ap"],
            component: "kernelcache.release.iphone12b",
            embeddedFingerprint: "xnu-13432.0.94.502.2~2/RELEASE_ARM64_T8030",
            resolverVariants: [
                "kernel-credential-manager": ResolverVariantProfile(
                    signature: "ios27-early-beta-acm-v1",
                    payload: "acm-return-success-v1"
                ),
            ]
        ),
        KernelResolverProfile(
            // Named for the first build ID seen with this fingerprint. The name
            // is kept stable across later builds that share it, because it is
            // an identifier rather than a claim about which build is loaded.
            id: "ios27-24A435-n104ap",
            productVersion: "27.0 RC/release, 27.0.1",
            // 24A437 is 24A435 rebuilt: identical iBSS/iBEC, TXM and SPTM, and
            // a kernelcache differing only in build-host paths and Mach-O
            // UUIDs. All 198 resolved records land on identical offsets with
            // identical original bytes, so both share this profile's variants.
            //
            // 27.0.1 (24A446) is the same relationship measured again against
            // 24A437: iBSS, iBEC, SPTM and TXM are byte-identical, and the
            // kernelcache differs in 6189 bytes spread over 778 runs, every one
            // of them inside __TEXT (one LC_UUID), __PRELINK_TEXT (kext LC_UUIDs
            // and `built <date> <time>` strings) or __PRELINK_INFO
            // (DTPlatformBuild 24A429 -> 24A440). Not one differing byte lands
            // in __TEXT_EXEC or __TEXT_BOOT_EXEC, and all 501 records resolved
            // by the ten kernel plans match 24A437 on id, offset, original bytes
            // and replacement bytes.
            builds: ["24A435", "24A437", "24A446"],
            boards: ["n104ap", "d421ap", "d431ap"],
            component: "kernelcache.release.iphone12b",
            embeddedFingerprint: "xnu-13432.2.10~2/RELEASE_ARM64_T8030",
            resolverVariants: [
                // All 26 release method bodies are now recorded in
                // KernelCredentialManagerSignatures.release24A435V1, recovered
                // from com.apple.driver.AppleSEPCredentialManager and checked to
                // keep beta 4's relative order.
                "kernel-credential-manager": ResolverVariantProfile(
                    signature: "ios27-24A435-acm-v1",
                    payload: "acm-return-success-v1"
                ),
            ]
        ),
        KernelResolverProfile(
            id: "ios272-24B5084k-n104ap",
            productVersion: "27.2 beta 1",
            builds: ["24B5084k"],
            boards: ["n104ap"],
            component: "kernelcache.release.iphone12b",
            embeddedFingerprint: "xnu-13432.40.144.0.1~55/RELEASE_ARM64_T8030",
            resolverVariants: [
                // A separate family from 24A435 even though 23 of its 26 shapes
                // still match: only cmdContextV3 changed, and recording that as
                // a shared variant would let either build's shapes stand in for
                // the other's. The payload is unchanged because the patch is
                // the same one, "return success without running the body".
                "kernel-credential-manager": ResolverVariantProfile(
                    signature: "ios272-24B5084k-acm-v1",
                    payload: "acm-return-success-v1"
                ),
            ]
        ),
        KernelResolverProfile(
            // A separate profile from beta 1 because the fingerprint differs,
            // which is what detection keys on. The two seeds cannot share one
            // entry the way 24A435 and 24A437 do: those carry the same XNU
            // string, these do not.
            id: "ios272b2-24B5089g-n104ap",
            productVersion: "27.2 beta 2",
            builds: ["24B5089g"],
            boards: ["n104ap"],
            component: "kernelcache.release.iphone12b",
            embeddedFingerprint: "xnu-13432.40.162~93/RELEASE_ARM64_T8030",
            resolverVariants: [
                // Shape-identical to beta 1, recorded separately because the
                // raw words differ in the fields masked as layout drift. See
                // KernelCredentialManagerSignatures.release24B5089gV1.
                "kernel-credential-manager": ResolverVariantProfile(
                    signature: "ios272b2-24B5089g-acm-v1",
                    payload: "acm-return-success-v1"
                ),
            ]
        ),
        KernelResolverProfile(
            // Third 27.2 seed, third XNU string, so a third profile.
            id: "ios272b3-24B5099f-n104ap",
            productVersion: "27.2 beta 3",
            builds: ["24B5099f"],
            boards: ["n104ap"],
            component: "kernelcache.release.iphone12b",
            embeddedFingerprint: "xnu-13432.40.177.0.3~16/RELEASE_ARM64_T8030",
            resolverVariants: [
                // Shape-identical to both earlier seeds, recorded separately
                // for the same reason beta 2 was. See
                // KernelCredentialManagerSignatures.release24B5099fV1.
                "kernel-credential-manager": ResolverVariantProfile(
                    signature: "ios272b3-24B5099f-acm-v1",
                    payload: "acm-return-success-v1"
                ),
            ]
        ),
        KernelResolverProfile(
            // Fourth 27.2 seed, fourth XNU string.
            id: "ios272b4-24B5110a-n104ap",
            productVersion: "27.2 beta 4",
            builds: ["24B5110a"],
            boards: ["n104ap"],
            component: "kernelcache.release.iphone12b",
            embeddedFingerprint: "xnu-13432.42.3~13/RELEASE_ARM64_T8030",
            resolverVariants: [
                // Shape-identical to beta 3; see
                // KernelCredentialManagerSignatures.release24B5110aV1.
                "kernel-credential-manager": ResolverVariantProfile(
                    signature: "ios272b4-24B5110a-acm-v1",
                    payload: "acm-return-success-v1"
                ),
            ]
        ),
        KernelResolverProfile(
            // iPad 8, A12 / T8020, iPadOS 26.7.1. A different SoC and XNU
            // major from every other profile here. The Wi-Fi and Cellular
            // boards share this kernelcache.
            id: "ios26-23H30-j171aap",
            productVersion: "26.7.1",
            builds: ["23H30"],
            boards: ["j171aap", "j172aap"],
            component: "kernelcache.release.ipad11b",
            embeddedFingerprint: "xnu-12377.162.13.700.38~2/RELEASE_ARM64_T8020",
            resolverVariants: [
                // T8020 PPL makes its own trust decision; see
                // KernelPPLTrustCacheResolver.
                "kernel-ppl-trust-cache": ResolverVariantProfile(
                    signature: "t8020-loaded-trust-cache-v1",
                    payload: "loaded-trust-cache-true-v1"
                ),
                // 25 entries, not 26. See
                // KernelCredentialManagerSignatures.release23H30V1.
                "kernel-credential-manager": ResolverVariantProfile(
                    signature: "ios26-23H30-acm-v1",
                    payload: "acm-return-success-v1"
                ),
                // Opt-in: include the code-signing-invalid patches in the
                // kernel-boot-jit plan so runtime tweak hooks are not killed.
                // Each resolves to one site on the 23H30 kernelcache. See
                // KernelCodeSigningResolver.
                "kernel-codesign-invalid": ResolverVariantProfile(
                    signature: "t8020-codesign-invalid-v1",
                    payload: "codesign-invalid-allow-v1"
                ),
            ],
            // No scoped Sandbox predecessor, so no Valeria cave. Not ported.
            //
            // The exception-port enforcement byte is not ported either. Its
            // resolver was written for 27.x kernels, where the byte is a
            // __DATA_CONST constant; in xnu-12377 it was a boot-arg tunable,
            // and the resolver has not been run against this kernel. The
            // exact boot-jit fixture was measured without the kernel record.
            // Consequence: a platform-binary app that registers an
            // EXCEPTION_DEFAULT handler (crash SDKs) can still be killed.
            omittedResolvers: [KernelValeriaResolver.name, KernelExceptionPortResolver.name]
        ),
        KernelResolverProfile(
            // iPad 8, iPadOS 26.7.2. A new XNU string, so a new profile, even
            // though it is a point update of the 23H30 kernel: every plan
            // resolves the same record ids with the same bytes apart from
            // ADRP/BL/LDR immediates and one moved policy-table pointer, at
            // offsets shifted by the new layout. The ACM roster reuses the
            // 23H30 shapes because all 25 still match one distinct function
            // each; give this build its own variant if one ever has to change.
            // See docs/runs/IPAD8_J171AAP_23H128.md.
            id: "ios26-23H128-j171aap",
            productVersion: "26.7.2",
            builds: ["23H128"],
            boards: ["j171aap", "j172aap"],
            component: "kernelcache.release.ipad11b",
            embeddedFingerprint: "xnu-12377.162.13.701.45~1/RELEASE_ARM64_T8020",
            resolverVariants: [
                "kernel-ppl-trust-cache": ResolverVariantProfile(
                    signature: "t8020-loaded-trust-cache-v1",
                    payload: "loaded-trust-cache-true-v1"
                ),
                "kernel-credential-manager": ResolverVariantProfile(
                    signature: "ios26-23H30-acm-v1",
                    payload: "acm-return-success-v1"
                ),
                "kernel-codesign-invalid": ResolverVariantProfile(
                    signature: "t8020-codesign-invalid-v1",
                    payload: "codesign-invalid-allow-v1"
                ),
            ],
            omittedResolvers: [KernelValeriaResolver.name, KernelExceptionPortResolver.name]
        ),
    ]

    /// Detect a profile using evidence embedded in the artifact itself.
    /// Returning nil is intentional: unknown firmware must never be silently
    /// labelled as one of the reviewed builds.
    public static func detect(in image: BinaryImage) -> KernelResolverProfile? {
        let matches = profiles.filter {
            !image.findAll(utf8: $0.embeddedFingerprint).isEmpty
        }
        return matches.count == 1 ? matches[0] : nil
    }
}
