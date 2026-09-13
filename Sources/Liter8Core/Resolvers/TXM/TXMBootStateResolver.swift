import Foundation

/// Resolves the three TXM patches needed only for normal boot.
///
/// Two functions share the state structure at file offset `0x80db0` on beta 4:
/// `allowedBeforeSecureChannelOperational` reads it, while an earlier routine
/// computes and publishes developer mode into it. The resolver first identifies
/// the secure-channel accessor by its full body, derives the structure address,
/// then uses that address as the anchor for the developer-mode branch.
///
/// The beta-4 offsets are intentionally absent from executable logic. This
/// avoids the historical failure where `0x2bcb4` from an older build pointed
/// into an unrelated function epilogue on beta 4.
public struct TXMBootStateResolver: Sendable {
    public static let name = "txm-boot-state"

    public init() {}

    public func resolve(in image: BinaryImage) throws -> [PatchRecord] {
        let layout = try MachOLayout(image: image)
        let secureEntry = try findSecureChannelAccessor(
            in: image,
            ranges: layout.executableFileRanges
        )
        let adrpOffset = secureEntry + 4
        let addOffset = secureEntry + 8

        guard let pc = layout.virtualAddress(forFileOffset: adrpOffset) else {
            throw PatchfinderError.invalidFixture("secure-channel accessor is outside mapped code")
        }
        let adrp = try image.readUInt32(at: adrpOffset)
        let add = try image.readUInt32(at: addOffset)
        let stateAddress = ARM64.adrpTarget(instruction: adrp, at: pc)
            + ARM64.addImmediate(instruction: add)
        guard let stateOffset = layout.fileOffset(forVirtualAddress: stateAddress) else {
            throw PatchfinderError.invalidFixture("TXM state structure is outside mapped segments")
        }

        let devModeBranch = try findDeveloperModeBranch(
            in: image,
            layout: layout,
            stateOffset: stateOffset
        )
        let sharedEvidence = [
            "unique secure-channel accessor body begins at \(secureEntry.hex)",
            "accessor and developer-mode routine reference state at \(stateOffset.hex)",
            "BTI landing pad is preserved; replacement begins after it",
        ]

        return [
            PatchRecord(
                id: "txm.secure-channel.return-one",
                component: "TXM",
                offset: adrpOffset,
                original: adrp,
                replacement: ARM64.movX0One,
                summary: "Make allowedBeforeSecureChannelOperational return true",
                evidence: sharedEvidence
            ),
            PatchRecord(
                id: "txm.secure-channel.return",
                component: "TXM",
                offset: addOffset,
                original: add,
                replacement: ARM64.ret,
                summary: "Return immediately after setting the secure-channel result",
                evidence: sharedEvidence
            ),
            PatchRecord(
                id: "txm.developer-mode.publish",
                component: "TXM",
                offset: devModeBranch,
                original: try image.readUInt32(at: devModeBranch),
                replacement: ARM64.nop,
                summary: "Take the existing path that publishes developer mode as true",
                evidence: sharedEvidence + [
                    "TBZ W9,#0 otherwise skips MOV W20,#1",
                    "NOP preserves TXM's existing propagation and final store",
                ]
            ),
        ]
    }

    private func findSecureChannelAccessor(
        in image: BinaryImage,
        ranges: [Range<UInt64>]
    ) throws -> UInt64 {
        var candidates: [UInt64] = []
        for range in ranges {
            var offset = (range.lowerBound + 3) & ~UInt64(3)
            while offset + 36 <= range.upperBound {
                guard try image.readUInt32(at: offset) == 0xD503_245F, // BTI C
                      try image.readUInt32(at: offset + 4) & 0x9F00_001F == 0x9000_0009, // ADRP X9,<page>
                      try image.readUInt32(at: offset + 8) & 0xFFC0_03FF == 0x9100_0129, // ADD X9,X9,#imm
                      try image.readUInt32(at: offset + 12) == 0x3940_012A, // LDRB W10,[X9]
                      try image.readUInt32(at: offset + 16) == 0x5280_0028, // MOV W8,#1
                      try image.readUInt32(at: offset + 20) & 0xFF00_001F == 0x3600_000A, // TBZ W10,#0,<target>
                      try image.readUInt32(at: offset + 24) == 0x7940_192A, // LDRH W10,[X9,#0xc]
                      try image.readUInt32(at: offset + 28) & 0xFF00_001F == 0x3500_000A, // CBNZ W10,<target>
                      try image.readUInt32(at: offset + 32) == 0x3940_0528 // LDRB W8,[X9,#1]
                else {
                    offset += 4
                    continue
                }
                candidates.append(offset)
                offset += 4
            }
        }
        guard let candidate = candidates.only else {
            if candidates.isEmpty { throw PatchfinderError.noCandidate("\(Self.name) secure accessor") }
            throw PatchfinderError.ambiguousCandidate(
                "\(Self.name) secure accessor",
                offsets: candidates
            )
        }
        return candidate
    }

    private func findDeveloperModeBranch(
        in image: BinaryImage,
        layout: MachOLayout,
        stateOffset: UInt64
    ) throws -> UInt64 {
        let references = try layout.adrpAddReferences(toFileOffset: stateOffset)
        var candidates: [UInt64] = []

        for reference in references {
            let adrp = try image.readUInt32(at: reference.adrpOffset)
            let add = try image.readUInt32(at: reference.addOffset)
            guard adrp & 0x1F == 19,
                  add & 0x1F == 19,
                  (add >> 5) & 0x1F == 19,
                  reference.addOffset + 12 < UInt64(image.count)
            else { continue }

            let branchOffset = reference.addOffset + 4
            let branch = try image.readUInt32(at: branchOffset)
            let setTrue = try image.readUInt32(at: branchOffset + 4)
            let forward = try image.readUInt32(at: branchOffset + 8)
            guard branch & 0xFF00_001F == 0x3600_0009, // TBZ W9,#0
                  setTrue == 0x5280_0034, // MOV W20,#1
                  forward & 0xFC00_0000 == 0x1400_0000 // B
            else { continue }
            candidates.append(branchOffset)
        }

        guard let candidate = candidates.only else {
            if candidates.isEmpty { throw PatchfinderError.noCandidate("\(Self.name) developer mode") }
            throw PatchfinderError.ambiguousCandidate(
                "\(Self.name) developer mode",
                offsets: candidates
            )
        }
        return candidate
    }
}

private extension Collection {
    var only: Element? { count == 1 ? first : nil }
}
