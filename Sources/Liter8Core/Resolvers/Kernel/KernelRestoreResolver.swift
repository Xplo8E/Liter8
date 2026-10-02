import Foundation

/// Kernel plan used by the restore environment, including profile-selected PPL policy.
///
/// Keeping composition here prevents the CLI and fixture verifier from
/// accidentally drifting into different patch sets. Normal-boot-only persona,
/// SEP, credential-manager, USB and sandbox work belongs in later resolvers.
public struct KernelRestoreResolver: Sendable {
    public static let name = "kernel-restore"

    public init() {}

    public func resolve(in image: BinaryImage) throws -> [PatchRecord] {
        try KernelIdentityResolver().resolve(in: image)
            + KernelPanicResolver().resolve(in: image)
            + KernelAMFIResolver().resolve(in: image)
            + KernelPPLTrustCacheResolver.requiredRecords(in: image)
    }
}
