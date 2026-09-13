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
        return [PatchRecord(
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
        )]
    }
}

private extension Collection {
    var only: Element? { count == 1 ? first : nil }
}
