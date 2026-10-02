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

    public init(
        id: String,
        productVersion: String,
        builds: [String],
        boards: [String],
        component: String,
        embeddedFingerprint: String,
        resolverVariants: [String: ResolverVariantProfile]
    ) {
        self.id = id
        self.productVersion = productVersion
        self.builds = builds
        self.boards = boards
        self.component = component
        self.embeddedFingerprint = embeddedFingerprint
        self.resolverVariants = resolverVariants
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
