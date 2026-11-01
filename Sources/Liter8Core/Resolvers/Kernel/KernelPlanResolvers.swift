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
        sandbox: [PatchRecord],
        valeria: [PatchRecord]
    ) -> [PatchRecord] {
        restore + bootPolicy + sep + credentialManager + sandbox + valeria
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
            sandbox: KernelSandboxResolver().resolve(in: image),
            valeria: KernelValeriaResolver.compositeRecords(in: image)
        )
    }
}

/// Device-reviewed compatibility plan for the public Liter8 boot workflow.
///
/// This deliberately omits the later 35-record scoped vnode-open shim. It is
/// the stable normal-boot plan and includes the Valeria inactive-owner repair.
/// The compatibility contract is the selected patch set, not one firmware
/// build or a table of fixed offsets.
public struct KernelBootCompatibilityResolver: Sendable {
    public static let name = "kernel-boot-compatibility"
    public init() {}

    public func resolve(in image: BinaryImage) throws -> [PatchRecord] {
        try KernelBootPlanComposer.compose(
            restore: KernelRestoreResolver().resolve(in: image),
            bootPolicy: KernelBootPolicyResolver().resolve(in: image),
            sep: KernelSEPResolver().resolve(in: image),
            credentialManager: KernelCredentialManagerResolver().resolve(in: image),
            sandbox: KernelSandboxCompatibilityResolver().resolve(in: image),
            valeria: KernelValeriaResolver.compositeRecords(in: image)
        )
    }
}

/// Opt-in normal-boot plan that also lets running processes modify their own
/// code pages, which runtime tweak injection (ElleKit function hooks) needs.
///
/// This is `boot-public` plus the code-signing-invalid patches. It is kept
/// separate because those patches weaken the code-signing guarantee for every
/// process, so a boot opts into them explicitly rather than getting them in the
/// reviewed default. The extra records resolve only on a kernel profile that
/// registers the `kernel-codesign-invalid` variant; on any other kernel those
/// add nothing.
///
/// It also clears the exception-port behavior enforcement byte, because the
/// trust-cache patches make every app a platform binary and platform binaries
/// are killed for registering `EXCEPTION_DEFAULT` handlers, which crash SDKs do.
public struct KernelBootJITResolver: Sendable {
    public static let name = "kernel-boot-jit"
    public init() {}

    public func resolve(in image: BinaryImage) throws -> [PatchRecord] {
        try KernelBootCompatibilityResolver().resolve(in: image)
            + KernelCodeSigningResolver.requiredRecords(in: image)
            + KernelExceptionPortResolver().resolve(in: image)
    }
}

/// Normal boot with the profile-gated tfp0 patches.
public struct KernelBootTFP0Resolver: Sendable {
    public static let name = "kernel-boot-tfp0"
    public init() {}

    public func resolve(in image: BinaryImage) throws -> [PatchRecord] {
        let tfp0 = try KernelTFP0Resolver.requiredRecords(in: image)
        return try KernelBootJITResolver().resolve(in: image) + tfp0
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
