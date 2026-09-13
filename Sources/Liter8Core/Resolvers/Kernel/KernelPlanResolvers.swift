import Foundation

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
        try KernelRestoreResolver().resolve(in: image)
            + KernelBootPolicyResolver().resolve(in: image)
            + KernelSEPResolver().resolve(in: image)
            + KernelCredentialManagerResolver().resolve(in: image)
            + KernelSandboxResolver().resolve(in: image)
    }
}

/// Byte-compatible normal-boot plan for the public iOS 27 beta-4 scripts.
///
/// This deliberately omits the later 35-record scoped vnode-open shim. It is
/// the safe baseline while orchestration moves into Swift because it reproduces
/// the public `kc-boot` table without changing device behaviour.
public struct KernelBootPublicBeta4Resolver: Sendable {
    public static let name = "kernel-boot-public-beta4"
    public init() {}

    public func resolve(in image: BinaryImage) throws -> [PatchRecord] {
        try KernelRestoreResolver().resolve(in: image)
            + KernelBootPolicyResolver().resolve(in: image)
            + KernelSEPResolver().resolve(in: image)
            + KernelCredentialManagerResolver().resolve(in: image)
            + KernelSandboxResolver(includeScopedVnodeOpen: false).resolve(in: image)
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
