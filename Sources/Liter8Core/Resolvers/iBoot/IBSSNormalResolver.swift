import Foundation

/// The complete n104 normal-boot iBSS plan.
///
/// This type contains no additional pattern matcher. It composes two smaller,
/// independently explainable resolvers:
///
/// 1. make the Image4 callback return success;
/// 2. redirect the boot-argument `snprintf` format to our literal.
///
/// Keeping composition separate means either primitive can be tested or reused
/// for restore/ramdisk modes without duplicating its discovery logic.
public struct IBSSNormalResolver: Sendable {
    public static let name = "ibss-normal"

    public init() {}

    public func resolve(in image: BinaryImage) throws -> [PatchRecord] {
        try IBSSValidateResolver().resolve(in: image)
            + IBSSBootArgsResolver().resolve(in: image)
    }
}
