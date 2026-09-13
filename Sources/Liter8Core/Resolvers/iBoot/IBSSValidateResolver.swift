import Capstone
import Foundation

public struct IBSSValidateResolver: Sendable {
    public static let name = "ibss-validate-asn1"
    static let anchor = "Unknown ASN1 type %llu\n"

    public init() {}

    /// Find the Image4 validation callback's final status gate.
    ///
    /// Searching only for `BL; B.NE; MOV X0,X20` is unsafe: beta 4 contains 95
    /// similar shapes. The error path for the correct callback, however, is the
    /// sole user of "Unknown ASN1 type %llu\n". We start at that string, recover
    /// its code xref, and then prove the branch reaches that exact error block.
    public func resolve(in image: BinaryImage) throws -> [PatchRecord] {
        // The diagnostic string is the stable semantic anchor. The known
        // beta-4 patch offset is intentionally absent from production code.
        let anchors = image.findAll(utf8: Self.anchor, nulTerminated: true)
        guard let anchorOffset = anchors.only else {
            if anchors.isEmpty { throw PatchfinderError.missingAnchor(Self.anchor) }
            throw PatchfinderError.ambiguousAnchor(Self.anchor, count: anchors.count)
        }

        // Apple arm64 code normally materializes a nearby string with ADRP for
        // its 4 KiB page followed by ADD for the within-page offset.
        let references = try ARM64.adrpAddReferences(in: image, to: anchorOffset)
        guard !references.isEmpty else {
            throw PatchfinderError.noCandidate("\(Self.name) anchor xref")
        }

        let disassembler = try ARM64Disassembler()
        var candidates: [UInt64] = []
        for reference in references {
            // The validation branch is in the same small routine as the
            // diagnostic path. Search locally, then prove the control-flow
            // relationship and epilogue shape below.
            let lowerBound = reference.adrpOffset > 0x800 ? reference.adrpOffset - 0x800 : 0
            var cursor = lowerBound & ~UInt64(3)
            while cursor < reference.adrpOffset {
                if try matchesValidateSequence(
                    in: image,
                    branchOffset: cursor,
                    referenceOffset: reference.adrpOffset,
                    disassembler: disassembler
                ) {
                    candidates.append(cursor)
                }
                cursor += 4
            }
        }

        // Multiple xrefs may converge on the same branch; deduplicate that
        // harmless case but reject genuinely different candidates.
        candidates = Array(Set(candidates)).sorted()
        guard let branchOffset = candidates.only else {
            if candidates.isEmpty { throw PatchfinderError.noCandidate(Self.name) }
            throw PatchfinderError.ambiguousCandidate(Self.name, offsets: candidates)
        }

        // Read the pre-image from the selected binary rather than copying the
        // known beta-4 words. GuardedPatchApplier will require these exact bytes
        // before it writes anything.
        let originalBranch = try image.readUInt32(at: branchOffset)
        let originalMove = try image.readUInt32(at: branchOffset + 4)
        let commonEvidence = [
            "unique string anchor at \(anchorOffset.hex)",
            "ADRP+ADD xref at \(references.first { $0.adrpOffset == branchTarget(of: originalBranch, at: branchOffset)! + 8 }?.adrpOffset.hex ?? (branchTarget(of: originalBranch, at: branchOffset)! + 8).hex)",
            "conditional branch target contains anchor xref at target+8",
            "preceding BL and following mov x0,x20 / ldp x29,x30,[sp,#0xd0]",
        ]

        return [
            PatchRecord(
                id: "ibss.validate-asn1.branch",
                component: "iBSS",
                offset: branchOffset,
                original: originalBranch,
                replacement: ARM64.nop,
                summary: "Bypass the ASN.1 validation failure branch",
                evidence: commonEvidence
            ),
            PatchRecord(
                id: "ibss.validate-asn1.result",
                component: "iBSS",
                offset: branchOffset + 4,
                original: originalMove,
                replacement: ARM64.movX0Zero,
                summary: "Return success after bypassing validation",
                evidence: commonEvidence
            ),
        ]
    }

    private func matchesValidateSequence(
        in image: BinaryImage,
        branchOffset: UInt64,
        referenceOffset: UInt64,
        disassembler: ARM64Disassembler
    ) throws -> Bool {
        guard branchOffset >= 4, branchOffset + 8 <= UInt64(image.count) else { return false }
        // Expected local shape:
        //   BL validator; B.NE failure; MOV X0,X20; ...;
        //   failure+8 materializes the unique string; ...; LDP FP,LR,[SP,#D0]
        let instructions = try disassembler.instructions(
            in: image,
            offset: branchOffset - 4,
            count: Int(min(UInt64(0x80), UInt64(image.count) - (branchOffset - 4)))
        )
        guard instructions.count >= 4 else { return false }

        let previous = instructions[0]
        let branch = instructions[1]
        let move = instructions[2]
        guard previous.address == branchOffset - 4, previous.mnemonic == "bl",
              branch.address == branchOffset, branch.mnemonic == "b.ne",
              move.address == branchOffset + 4, move.mnemonic == "mov",
              disassembler.registerName(of: move, operandAt: 0) == "x0",
              disassembler.registerName(of: move, operandAt: 1) == "x20",
              let immediate = branch.aarch64?.operands.first?.imm,
              UInt64(bitPattern: immediate) + 8 == referenceOffset
        else { return false }

        return instructions.dropFirst(3).contains { instruction in
            guard instruction.mnemonic == "ldp",
                  disassembler.registerName(of: instruction, operandAt: 0) == "x29",
                  disassembler.registerName(of: instruction, operandAt: 1) == "x30",
                  disassembler.memoryBaseName(of: instruction, operandAt: 2) == "sp",
                  let operands = instruction.aarch64?.operands,
                  operands.indices.contains(2)
            else { return false }
            return operands[2].mem.disp == 0xD0
        }
    }

    private func branchTarget(of instruction: UInt32, at offset: UInt64) -> UInt64? {
        // Match B.cond and decode its signed imm19 branch displacement.
        guard instruction & 0xFF00_0010 == 0x5400_0000 else { return nil }
        let encoded = Int64((instruction >> 5) & 0x7FFFF)
        let signed = (encoded & (1 << 18)) == 0 ? encoded : encoded - (1 << 19)
        return UInt64(bitPattern: Int64(bitPattern: offset) &+ (signed << 2))
    }
}

private extension Collection {
    var only: Element? { count == 1 ? first : nil }
}
