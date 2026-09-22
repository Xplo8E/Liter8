import Foundation

/// Finds the final status return of the FDR recovery routine in
/// `usr/local/bin/restored_external`.
///
/// The patch is easy to describe but dangerous to locate by instruction shape
/// alone: many functions end with `MOV X0, <saved status>; LDP X29,X30`. The
/// string `RestoredFDRRecover` identifies the correct routine. Its sole code
/// reference and the epilogue shape together identify one return site.
public struct RestoredExternalResolver: Sendable {
    public static let name = "restored-external-fdr"
    private static let anchor = "RestoredFDRRecover"

    public init() {}

    public func resolve(in image: BinaryImage) throws -> [PatchRecord] {
        let layout = try MachOLayout(image: image)
        let anchors = image.findAll(utf8: Self.anchor, nulTerminated: true)
        guard let anchorOffset = anchors.only else {
            if anchors.isEmpty { throw PatchfinderError.missingAnchor(Self.anchor) }
            throw PatchfinderError.ambiguousAnchor(Self.anchor, count: anchors.count)
        }

        let references = try layout.adrpAddReferences(toFileOffset: anchorOffset)
        guard let reference = references.only else {
            if references.isEmpty { throw PatchfinderError.noCandidate("\(Self.name) string xref") }
            throw PatchfinderError.ambiguousCandidate(
                "\(Self.name) string xref",
                offsets: references.map(\.adrpOffset)
            )
        }

        let disassembler = try ARM64Disassembler()
        let scanLength = min(0x400, image.count - Int(reference.adrpOffset))
        let instructions = try disassembler.instructions(
            in: image,
            offset: reference.adrpOffset,
            count: scanLength
        )
        var candidates: [UInt64] = []

        for index in 0..<max(0, instructions.count - 1) {
            let move = instructions[index]
            let epilogue = instructions[index + 1]

            // This is the value-return boundary, not merely any MOV near the
            // anchor: status moves into X0 immediately before the authenticated
            // function epilogue restores FP/LR from its 0x90-byte frame.
            guard move.mnemonic == "mov",
                  disassembler.registerName(of: move, operandAt: 0) == "x0",
                  disassembler.registerName(of: move, operandAt: 1)?.hasPrefix("x") == true,
                  epilogue.mnemonic == "ldp",
                  disassembler.registerName(of: epilogue, operandAt: 0) == "x29",
                  disassembler.registerName(of: epilogue, operandAt: 1) == "x30",
                  disassembler.memoryBaseName(of: epilogue, operandAt: 2) == "sp",
                  let operands = epilogue.aarch64?.operands,
                  operands.indices.contains(2), operands[2].mem.disp == 0x90
            else { continue }
            candidates.append(move.address)
        }

        guard let patchOffset = candidates.only else {
            if candidates.isEmpty { throw PatchfinderError.noCandidate(Self.name) }
            throw PatchfinderError.ambiguousCandidate(Self.name, offsets: candidates)
        }

        let original = try image.readUInt32(at: patchOffset)
        let fdrRecord = PatchRecord(
            id: "restored-external.fdr-result",
            component: "restored_external",
            offset: patchOffset,
            original: original,
            replacement: ARM64.movX0Zero,
            summary: "Return success from RestoredFDRRecover",
            evidence: [
                "unique RestoredFDRRecover string at \(anchorOffset.hex)",
                "unique ADRP+ADD reference at \(reference.adrpOffset.hex)",
                "MOV X0,status immediately precedes LDP X29,X30,[SP,#0x90]",
            ]
        )
        return [fdrRecord] + (try resolveBasebandPredicates(in: image))
    }

    /// Locate the adjacent modern and legacy baseband-presence predicates.
    /// Both read the same cached byte, while the legacy wrapper additionally
    /// consults the device tree. Their adjacency and complete control-flow
    /// shapes make a considerably stronger anchor than either prologue alone.
    private func resolveBasebandPredicates(in image: BinaryImage) throws -> [PatchRecord] {
        var modernCandidates: [UInt64] = []
        var cursor: UInt64 = 0
        while cursor + 0x1C <= UInt64(image.count) {
            let adrp = try image.readUInt32(at: cursor)
            let load = try image.readUInt32(at: cursor + 4)
            let branch = try image.readUInt32(at: cursor + 12)
            guard adrp & 0x9F00_001F == 0x9000_0008,
                  load & 0xFFC0_03FF == 0xF940_0108,
                  try image.readUInt32(at: cursor + 8) == 0xB100_051F,
                  branch & 0xFF00_001F == 0x5400_0001,
                  ARM64.conditionalTarget(instruction: branch, at: cursor + 12) == cursor + 0x1C,
                  try image.readUInt32(at: cursor + 16) & 0x9F00_001F == 0x9000_0008,
                  try image.readUInt32(at: cursor + 20) & 0xFFC0_03FF == 0x3940_0100,
                  try image.readUInt32(at: cursor + 24) == ARM64.ret
            else {
                cursor += 4
                continue
            }
            if try matchesLegacyBasebandPredicate(
                in: image,
                modern: cursor,
                modernADRP: adrp,
                modernLoad: load
            ) {
                modernCandidates.append(cursor)
            }
            cursor += 4
        }

        guard modernCandidates.count == 1, let modern = modernCandidates.first else {
            if modernCandidates.isEmpty {
                throw PatchfinderError.noCandidate("\(Self.name) baseband predicate")
            }
            throw PatchfinderError.ambiguousCandidate(
                "\(Self.name) baseband predicate",
                offsets: modernCandidates
            )
        }
        guard modern >= 0x78 else {
            throw PatchfinderError.noCandidate("\(Self.name) legacy baseband predicate")
        }
        let legacy = modern - 0x78
        let modernADRP = try image.readUInt32(at: modern)
        let modernLoad = try image.readUInt32(at: modern + 4)
        let legacyBranch = try image.readUInt32(at: legacy + 0x48)
        guard try image.readUInt32(at: legacy) == 0xD503_237F,
              try image.readUInt32(at: legacy + 4) == 0xA9BE_4FF4,
              try image.readUInt32(at: legacy + 8) == 0xA901_7BFD,
              try image.readUInt32(at: legacy + 12) == 0x9100_43FD,
              try image.readUInt32(at: legacy + 0x3C) == modernADRP,
              try image.readUInt32(at: legacy + 0x40) == modernLoad,
              try image.readUInt32(at: legacy + 0x44) == 0xB100_051F,
              legacyBranch & 0xFF00_001F == 0x5400_0001,
              ARM64.conditionalTarget(instruction: legacyBranch, at: legacy + 0x48) == legacy + 0x70,
              try image.readUInt32(at: legacy + 0x60) == 0x1200_0100
        else {
            throw PatchfinderError.noCandidate("\(Self.name) legacy baseband predicate")
        }

        let evidence = [
            "unique cached-baseband byte predicate",
            "adjacent legacy predicate reads the same cache address",
            "both predicate control-flow shapes validated before entry replacement",
        ]
        return [
            PatchRecord(
                id: "restored-external.baseband.present",
                component: "restored_external",
                offset: modern,
                original: modernADRP,
                replacement: ARM64.movX0Zero,
                summary: "Report that the device has no baseband",
                evidence: evidence
            ),
            PatchRecord(
                id: "restored-external.baseband.present-return",
                component: "restored_external",
                offset: modern + 4,
                original: modernLoad,
                replacement: ARM64.ret,
                summary: "Return immediately from the baseband predicate",
                evidence: evidence
            ),
            PatchRecord(
                id: "restored-external.baseband.legacy",
                component: "restored_external",
                offset: legacy,
                original: try image.readUInt32(at: legacy),
                replacement: ARM64.movX0Zero,
                summary: "Report no baseband from the legacy predicate",
                evidence: evidence
            ),
            PatchRecord(
                id: "restored-external.baseband.legacy-return",
                component: "restored_external",
                offset: legacy + 4,
                original: try image.readUInt32(at: legacy + 4),
                replacement: ARM64.ret,
                summary: "Return immediately from the legacy baseband predicate",
                evidence: evidence
            ),
        ]
    }

    private func matchesLegacyBasebandPredicate(
        in image: BinaryImage,
        modern: UInt64,
        modernADRP: UInt32,
        modernLoad: UInt32
    ) throws -> Bool {
        guard modern >= 0x78 else { return false }
        let legacy = modern - 0x78
        let branch = try image.readUInt32(at: legacy + 0x48)
        return try image.readUInt32(at: legacy) == 0xD503_237F
            && image.readUInt32(at: legacy + 4) == 0xA9BE_4FF4
            && image.readUInt32(at: legacy + 8) == 0xA901_7BFD
            && image.readUInt32(at: legacy + 12) == 0x9100_43FD
            && image.readUInt32(at: legacy + 0x3C) == modernADRP
            && image.readUInt32(at: legacy + 0x40) == modernLoad
            && image.readUInt32(at: legacy + 0x44) == 0xB100_051F
            && branch & 0xFF00_001F == 0x5400_0001
            && ARM64.conditionalTarget(instruction: branch, at: legacy + 0x48) == legacy + 0x70
            && image.readUInt32(at: legacy + 0x60) == 0x1200_0100
    }
}

private extension Collection {
    var only: Element? { count == 1 ? first : nil }
}
