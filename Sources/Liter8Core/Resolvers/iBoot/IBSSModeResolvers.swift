import Foundation

/// Complete iBSS plans for the two ramdisk-oriented boot modes.
///
/// These are intentionally thin compositions, not copies of the underlying
/// patch logic. Image4 validation and boot-argument discovery each have one
/// semantic resolver; a boot mode merely chooses the literal installed by the
/// latter. That keeps all three modes on the same fail-closed discovery path.
public struct IBSSRestoreResolver: Sendable {
    public static let name = "ibss-restore"
    public static let bootArguments = "-v wdt=-1 rd=md0 -restore"

    public init() {}

    public func resolve(in image: BinaryImage) throws -> [PatchRecord] {
        try IBSSValidateResolver().resolve(in: image)
            + IBSSBootArgsResolver(bootArguments: Self.bootArguments).resolve(in: image)
    }
}

/// Boots the research ramdisk with verbose output and the same watchdog/debug
/// policy used by the existing beta-4 Python patch table. n104 uses an LCD, so
/// its backlight must be requested explicitly just like the normal boot path.
public struct IBSSRamdiskResolver: Sendable {
    public static let name = "ibss-ramdisk"
    public static let bootArguments =
        "rd=md0 -v wdt=-1 debug=0x2014e backlight-level=1024"

    public init() {}

    public func resolve(in image: BinaryImage) throws -> [PatchRecord] {
        try IBSSValidateResolver().resolve(in: image)
            + IBSSBootArgsResolver(bootArguments: Self.bootArguments).resolve(in: image)
    }
}
