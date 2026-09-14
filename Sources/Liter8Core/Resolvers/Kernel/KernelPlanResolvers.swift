import Foundation

/// Joins independently resolved kernel patch families in their canonical write
/// order.
///
/// Resolution is intentionally kept out of this helper. Production resolvers
/// still discover every component themselves, while fixture tests can validate
/// the exact same composition without rescanning a large kernelcache merely to
/// concatenate records they have already verified.
enum KernelBootPlanComposer {
    static func compose(
        restore: [PatchRecord],
        bootPolicy: [PatchRecord],
        sep: [PatchRecord],
        credentialManager: [PatchRecord],
        sandbox: [PatchRecord]
    ) -> [PatchRecord] {
        restore + bootPolicy + sep + credentialManager + sandbox
    }
}

/// Complete normal-boot kernel plan.
///
/// Keeping composition here, rather than teaching individual resolvers about
/// one another, preserves the useful diagnostic boundaries: each component can
/// still be resolved and verified alone, while this command produces the exact
/// image consumed by the normal boot chain.
public struct KernelBootResolver: Sendable {
    public static let name = "kernel-boot"
    public init() {}

    public func resolve(in image: BinaryImage) throws -> [PatchRecord] {
        try KernelBootPlanComposer.compose(
            restore: KernelRestoreResolver().resolve(in: image),
            bootPolicy: KernelBootPolicyResolver().resolve(in: image),
            sep: KernelSEPResolver().resolve(in: image),
            credentialManager: KernelCredentialManagerResolver().resolve(in: image),
            sandbox: KernelSandboxResolver().resolve(in: image)
        )
    }
}

/// Device-reviewed compatibility plan for the public Liter8 boot workflow.
///
/// This deliberately omits the later 35-record scoped vnode-open shim. It is
/// the plan shipped by the public Python `kc-boot` table and subsequently
/// validated on both iOS 27 beta 4 and 24A435. The compatibility contract is
/// the selected patch set, not either firmware build.
public struct KernelBootCompatibilityResolver: Sendable {
    public static let name = "kernel-boot-compatibility"
    public init() {}

    public func resolve(in image: BinaryImage) throws -> [PatchRecord] {
        try KernelBootPlanComposer.compose(
            restore: KernelRestoreResolver().resolve(in: image),
            bootPolicy: KernelBootPolicyResolver().resolve(in: image),
            sep: KernelSEPResolver().resolve(in: image),
            credentialManager: KernelCredentialManagerResolver().resolve(in: image),
            sandbox: KernelSandboxResolver(includeScopedVnodeOpen: false).resolve(in: image)
        )
    }
}

/// Diagnostic kernel plan: retain the anti-hang AKS changes, but deliberately
/// omit SEP panic silencing, CredentialManager suppression, USB restore-mode
/// forcing, persona changes, and Sandbox relaxation. If SEP still fails, this
/// build should preserve a useful panic rather than hiding the failing check.
public struct KernelDiagnosticResolver: Sendable {
    public static let name = "kernel-diagnostic"
    public init() {}

    public func resolve(in image: BinaryImage) throws -> [PatchRecord] {
        try KernelRestoreResolver().resolve(in: image)
            + KernelAKSResolver().resolve(in: image)
    }
}
