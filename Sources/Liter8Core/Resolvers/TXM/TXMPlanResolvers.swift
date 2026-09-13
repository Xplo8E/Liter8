import Foundation

/// Six patches needed while restoring: trust-cache comparisons plus both
/// constraint-validation families. Normal-boot state changes are intentionally
/// excluded from the restore plan.
public struct TXMRestoreResolver: Sendable {
    public static let name = "txm-restore"
    public init() {}

    public func resolve(in image: BinaryImage) throws -> [PatchRecord] {
        try TXMQueryModuleResolver().resolve(in: image)
            + TXMConstraintsResolver().resolve(in: image)
    }
}

/// Nine-patch normal-boot plan: the restore-safe six plus secure-channel and
/// developer-mode state publication.
public struct TXMBootResolver: Sendable {
    public static let name = "txm-boot"
    public init() {}

    public func resolve(in image: BinaryImage) throws -> [PatchRecord] {
        try TXMRestoreResolver().resolve(in: image)
            + TXMBootStateResolver().resolve(in: image)
    }
}
