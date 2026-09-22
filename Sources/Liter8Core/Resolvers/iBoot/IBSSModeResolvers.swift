import Foundation

/// Complete iBSS plans for the two ramdisk-oriented boot modes.
///
/// These are intentionally thin compositions, not copies of the underlying
/// patch logic. Image4 validation and boot-argument discovery each have one
/// semantic resolver; a boot mode merely chooses the literal installed by the
/// latter. That keeps all three modes on the same fail-closed discovery path.
public struct IBSSRestoreResolver: Sendable {
    public static let name = "ibss-restore"
    public static let bootArguments = "-v wdt=-1 rd=md0 -restore serial=3"

    public init() {}

    public func resolve(in image: BinaryImage) throws -> [PatchRecord] {
        try IBSSValidateResolver().resolve(in: image)
            + IBSSBootArgsResolver(bootArguments: Self.bootArguments).resolve(in: image)
    }
}

/// Restore iBEC needs one additional operation that restore iBSS deliberately
/// does not: preserve the AP nonce established before iBEC takes over. Without
/// it, iBEC generates a new nonce after the host has already obtained a ticket,
/// and the restore can reach ramrod with an AP/SEP ticket from another nonce
/// state. The resolver identifies the nonce-cache routine by its complete local
/// data-flow shape and changes only its cache-valid TBNZ into an unconditional
/// branch to the existing cached-nonce block.
public struct IBECRestoreResolver: Sendable {
    public static let name = "ibec-restore"

    public init() {}

    public func resolve(in image: BinaryImage) throws -> [PatchRecord] {
        var candidates: [(offset: UInt64, target: UInt64)] = []
        var cursor: UInt64 = 0
        while cursor + 0x3C <= UInt64(image.count) {
            // MOV/MOVK/MOVK materializes the nonce-cache MMIO address, followed
            // by LDR W8,[X19] and TBNZ W8,#1,cached. The uncached path starts
            // with MOV W0,#0; BL generator and stores the two nonce halves.
            guard try image.readUInt32(at: cursor) == 0xD290_0013,
                  try image.readUInt32(at: cursor + 4) == 0xF2A7_6173,
                  try image.readUInt32(at: cursor + 8) == 0xF2C0_0053,
                  try image.readUInt32(at: cursor + 12) == 0xB940_0268
            else {
                cursor += 4
                continue
            }

            let branchOffset = cursor + 16
            let branch = try image.readUInt32(at: branchOffset)
            guard branch & 0x7F08_001F == 0x3708_0008,
                  try image.readUInt32(at: branchOffset + 4) == ARM64.movW0Zero,
                  try image.readUInt32(at: branchOffset + 8) & 0xFC00_0000 == 0x9400_0000,
                  let target = ARM64.testBranchTarget(instruction: branch, at: branchOffset),
                  target == branchOffset + 0x28,
                  try image.readUInt32(at: target) == 0xB940_2A60,
                  try image.readUInt32(at: target + 4) == 0xB940_2E68
            else {
                cursor += 4
                continue
            }
            candidates.append((branchOffset, target))
            cursor += 4
        }

        guard candidates.count == 1, let candidate = candidates.first else {
            if candidates.isEmpty { throw PatchfinderError.noCandidate(Self.name) }
            throw PatchfinderError.ambiguousCandidate(
                Self.name,
                offsets: candidates.map(\.offset)
            )
        }
        guard let replacement = ARM64.encodeDirectBranch(
            link: false,
            instructionOffset: candidate.offset,
            target: candidate.target
        ) else {
            throw PatchfinderError.noCandidate("\(Self.name) cached-nonce branch encoding")
        }

        let nonceRecord = PatchRecord(
            id: "ibec.recovery-nonce.preserve",
            component: "iBEC",
            offset: candidate.offset,
            original: try image.readUInt32(at: candidate.offset),
            replacement: replacement,
            summary: "Reuse the recovery nonce cached before iBEC",
            evidence: [
                "unique nonce-cache MMIO materialization and load",
                "TBNZ W8,#1 targets the cached two-word nonce load",
                "uncached path calls the generator and stores both nonce halves",
            ]
        )
        return try IBSSRestoreResolver().resolve(in: image) + [nonceRecord]
    }
}

/// Boots the research ramdisk with verbose output and the same watchdog/debug
/// policy used by the existing beta-4 Python patch table. n104 uses an LCD, so
/// its backlight must be requested explicitly just like the normal boot path.
public struct IBSSRamdiskResolver: Sendable {
    public static let name = "ibss-ramdisk"
    // Length is not free here. The 24A435 iBSS page-tail zero run is 79 bytes at
    // 0x26cfb1, and after the 8-byte guard gap and 16-byte alignment the slot
    // holds 64, so 63 characters plus NUL. Anything longer fails to resolve.
    public static let bootArguments =
        "rd=md0 -v wdt=-1 debug=0x2014e serial=3 backlight-level=1024"

    public init() {}

    public func resolve(in image: BinaryImage) throws -> [PatchRecord] {
        try IBSSValidateResolver().resolve(in: image)
            + IBSSBootArgsResolver(bootArguments: Self.bootArguments).resolve(in: image)
    }
}
