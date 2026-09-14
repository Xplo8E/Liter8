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

/// Kernel identity and resolver-variant selection for one known build.
///
/// Apple build IDs such as `24A5390f` are not stored in a decompressed
/// kernelcache. The registry therefore detects the embedded XNU fingerprint
/// and maps it to build metadata plus the signature/payload variants that have
/// been recovered for individual kernel resolvers. This does not grant access
/// to the full device workflow; `DeviceWorkflowProfile` owns that decision.
public struct KernelResolverProfile: Equatable, Sendable {
    public let id: String
    public let productVersion: String
    public let build: String
    public let boards: [String]
    public let component: String
    public let embeddedFingerprint: String
    public let resolverVariants: [String: ResolverVariantProfile]

    public init(
        id: String,
        productVersion: String,
        build: String,
        boards: [String],
        component: String,
        embeddedFingerprint: String,
        resolverVariants: [String: ResolverVariantProfile]
    ) {
        self.id = id
        self.productVersion = productVersion
        self.build = build
        self.boards = boards
        self.component = component
        self.embeddedFingerprint = embeddedFingerprint
        self.resolverVariants = resolverVariants
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
            build: "24A5370h",
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
            build: "24A5390f",
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
            // Use the immutable build ID in the profile name. Whether this
            // artifact is called RC or final release does not affect matching.
            id: "ios27-24A435-n104ap",
            productVersion: "27.0 RC/release",
            build: "24A435",
            boards: ["n104ap"],
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
