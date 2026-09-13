import Capstone
import Foundation

struct ADRPAddReference: Equatable {
    let adrpOffset: UInt64
    let addOffset: UInt64
    let target: UInt64
}

enum ARM64 {
    // Common patch payload instructions. Keeping their mnemonics beside the
    // words makes call sites readable without mentally decoding ARM64 hex.
    static let nop: UInt32 = 0xD503_201F       // NOP
    static let movX0Zero: UInt32 = 0xD280_0000 // MOV X0,#0
    static let movX0One: UInt32 = 0xD280_0020  // MOV X0,#1
    static let movW0One: UInt32 = 0x5280_0020  // MOV W0,#1
    static let movW0Zero: UInt32 = 0x5280_0000 // MOV W0,#0
    static let ret: UInt32 = 0xD65F_03C0       // RET

    /// Encode `ADRP Xn, target@page` using file-relative addresses.
    ///
    /// Raw iBoot payloads use the same relative coordinate system for the code
    /// and nearby data addressed by these instructions. We still validate the
    /// signed 21-bit page range instead of truncating an unreachable target.
    static func encodeADRP(register: UInt32, instructionOffset: UInt64, target: UInt64) -> UInt32? {
        guard register < 32 else { return nil }
        let pcPage = Int64(bitPattern: instructionOffset & ~UInt64(0xFFF))
        let targetPage = Int64(bitPattern: target & ~UInt64(0xFFF))
        let byteDelta = targetPage &- pcPage
        guard byteDelta.isMultiple(of: 0x1000) else { return nil }

        let pageDelta = byteDelta / 0x1000
        guard pageDelta >= -(1 << 20), pageDelta < (1 << 20) else { return nil }
        let immediate = UInt32(truncatingIfNeeded: pageDelta) & 0x1F_FFFF
        let immlo = immediate & 0x3
        let immhi = (immediate >> 2) & 0x7_FFFF
        // 0x90000000 is the fixed opcode field for ADRP Xd,<page>.
        return 0x9000_0000 | (immlo << 29) | (immhi << 5) | register
    }

    /// Encode the 64-bit `ADD Xd, Xn, #imm12` form used to finish an
    /// ADRP+ADD address materialization pair.
    static func encodeAddImmediate(destination: UInt32, source: UInt32, immediate: UInt32) -> UInt32? {
        guard destination < 32, source < 32, immediate < 0x1000 else { return nil }
        // 0x91000000 selects 64-bit ADD (immediate), without LSL #12.
        return 0x9100_0000 | (immediate << 10) | (source << 5) | destination
    }

    /// Retarget a CBZ/CBNZ while preserving its width, sense and tested
    /// register. Useful when the existing branch has exactly the right
    /// predicate but the desired outcome is a different local basic block.
    static func encodeCompareBranch(
        like instruction: UInt32,
        at instructionAddress: UInt64,
        target: UInt64
    ) -> UInt32? {
        guard instruction & 0x7E00_0000 == 0x3400_0000 else { return nil }
        let delta = Int64(bitPattern: target) - Int64(bitPattern: instructionAddress)
        guard delta.isMultiple(of: 4) else { return nil }
        let words = delta / 4
        guard words >= -(1 << 18), words < (1 << 18) else { return nil }
        let immediate = UInt32(truncatingIfNeeded: words) & 0x7_FFFF
        return (instruction & 0xFF00_001F) | (immediate << 5)
    }

    static func encodeMOVZ32(destination: UInt32, immediate: UInt16) -> UInt32? {
        guard destination < 32 else { return nil }
        // 0x52800000 is MOVZ Wd,#imm16 (normally printed as MOV).
        return 0x5280_0000 | (UInt32(immediate) << 5) | destination
    }

    static func encodeMOVK32Shift16(destination: UInt32, immediate: UInt16) -> UInt32? {
        guard destination < 32 else { return nil }
        // 0x72A00000 is MOVK Wd,#imm16,LSL#16.
        return 0x72A0_0000 | (UInt32(immediate) << 5) | destination
    }

    static func adrpAddReferences(
        in image: BinaryImage,
        to target: UInt64,
        maximumInstructionGap: Int = 8,
        scanRanges: [Range<UInt64>]? = nil,
        addressForFileOffset: (UInt64) -> UInt64 = { $0 }
    ) throws -> [ADRPAddReference] {
        guard maximumInstructionGap > 0 else { return [] }

        // Raw decoding is deliberate here: an ADRP+ADD xref is cheap to scan
        // across the whole image and Capstone is reserved for local semantic
        // validation once an anchor has narrowed the search space.
        var references: [ADRPAddReference] = []
        let ranges = scanRanges ?? [UInt64(0)..<UInt64(image.count)]

        for range in ranges where range.lowerBound < range.upperBound {
            var adrpOffset = (range.lowerBound + 3) & ~UInt64(3)
            let rangeEnd = min(range.upperBound, UInt64(image.count))
            guard rangeEnd >= 4 else { continue }
            let lastInstruction = rangeEnd - 4

            while adrpOffset <= lastInstruction {
                let adrp = try image.readUInt32(at: adrpOffset)
                guard isADRP(adrp) else {
                    adrpOffset += 4
                    continue
                }

                // ADRP uses the runtime PC. For flat iBoot payloads the caller
                // supplies identity mapping; Mach-O callers provide vmaddr.
                let page = adrpTarget(
                    instruction: adrp,
                    at: addressForFileOffset(adrpOffset)
                )
                let adrpRegister = Int(adrp & 0x1F)

                // Compilers may schedule independent instructions between the
                // page materialization and the ADD, so do not require adjacency.
                for distance in 1...maximumInstructionGap {
                    let addOffset = adrpOffset + UInt64(distance * 4)
                    guard addOffset <= lastInstruction else { break }
                    let add = try image.readUInt32(at: addOffset)
                    guard isImmediateADD(add) else { continue }

                    let destination = Int(add & 0x1F)
                    let source = Int((add >> 5) & 0x1F)
                    guard destination == adrpRegister, source == adrpRegister else { continue }

                    let resolved = page &+ addImmediate(instruction: add)
                    if resolved == target {
                        references.append(.init(
                            adrpOffset: adrpOffset,
                            addOffset: addOffset,
                            target: resolved
                        ))
                    }
                }
                adrpOffset += 4
            }
        }
        return references
    }

    private static func isADRP(_ instruction: UInt32) -> Bool {
        // Opcode-class test for ADRP Xd,<page>; immediate and register vary.
        instruction & 0x9F00_0000 == 0x9000_0000
    }

    private static func isImmediateADD(_ instruction: UInt32) -> Bool {
        // Opcode-class test for ADD W/Xd,W/Xn,#imm.
        instruction & 0x7F00_0000 == 0x1100_0000
    }

    static func adrpTarget(instruction: UInt32, at offset: UInt64) -> UInt64 {
        let immlo = Int64((instruction >> 29) & 0x3)
        let immhi = Int64((instruction >> 5) & 0x7FFFF)
        let encoded = (immhi << 2) | immlo
        // ADRP carries a signed 21-bit page displacement split across immhi
        // and immlo. Explicit subtraction avoids relying on signed shift rules.
        let signedPages = (encoded & (1 << 20)) == 0 ? encoded : encoded - (1 << 21)
        let page = Int64(bitPattern: offset & ~UInt64(0xFFF))
        return UInt64(bitPattern: page &+ (signedPages << 12))
    }

    static func addImmediate(instruction: UInt32) -> UInt64 {
        let immediate = UInt64((instruction >> 10) & 0xFFF)
        return ((instruction >> 22) & 1) == 1 ? immediate << 12 : immediate
    }

    static func branchLinkTarget(instruction: UInt32, at offset: UInt64) -> UInt64? {
        guard instruction & 0xFC00_0000 == 0x9400_0000 else { return nil }
        let encoded = Int64(instruction & 0x03FF_FFFF)
        let signed = (encoded & (1 << 25)) == 0 ? encoded : encoded - (1 << 26)
        return UInt64(bitPattern: Int64(bitPattern: offset) &+ signed * 4)
    }

    /// Encode a direct B or BL after every semantic destination has been
    /// resolved. Keeping this in one checked helper prevents injected shims
    /// from silently truncating an out-of-range 26-bit displacement.
    static func encodeDirectBranch(
        link: Bool,
        instructionOffset: UInt64,
        target: UInt64
    ) -> UInt32? {
        let delta = Int64(bitPattern: target) - Int64(bitPattern: instructionOffset)
        guard delta.isMultiple(of: 4) else { return nil }
        let words = delta / 4
        guard words >= -(1 << 25), words < (1 << 25) else { return nil }
        // BL has opcode 0x94000000; B has opcode 0x14000000.
        let opcode: UInt32 = link ? 0x9400_0000 : 0x1400_0000
        return opcode | (UInt32(truncatingIfNeeded: words) & 0x03FF_FFFF)
    }

    /// Decode either direct B form. BL-only callers should continue using
    /// `branchLinkTarget` so their intent remains explicit.
    static func directBranchTarget(instruction: UInt32, at offset: UInt64) -> UInt64? {
        let opcode = instruction & 0xFC00_0000
        guard opcode == 0x1400_0000 || opcode == 0x9400_0000 else { return nil }
        let encoded = Int64(instruction & 0x03FF_FFFF)
        let signed = (encoded & (1 << 25)) == 0 ? encoded : encoded - (1 << 26)
        return UInt64(bitPattern: Int64(bitPattern: offset) &+ signed * 4)
    }

    static func conditionalTarget(instruction: UInt32, at offset: UInt64) -> UInt64? {
        let isCompareBranch = instruction & 0x7E00_0000 == 0x3400_0000
        let isConditionalBranch = instruction & 0xFF00_0010 == 0x5400_0000
        guard isCompareBranch || isConditionalBranch else { return nil }

        let encoded = Int64((instruction >> 5) & 0x7_FFFF)
        let signed = (encoded & (1 << 18)) == 0 ? encoded : encoded - (1 << 19)
        return UInt64(bitPattern: Int64(bitPattern: offset) &+ signed * 4)
    }

    static func testBranchTarget(instruction: UInt32, at offset: UInt64) -> UInt64? {
        guard instruction & 0x7E00_0000 == 0x3600_0000 else { return nil }
        // TBZ/TBNZ use a signed imm14 in bits 18...5. Do not confuse it
        // with CBZ/B.cond's wider imm19 field.
        let encoded = Int64((instruction >> 5) & 0x3FFF)
        let signed = (encoded & (1 << 13)) == 0 ? encoded : encoded - (1 << 14)
        return UInt64(bitPattern: Int64(bitPattern: offset) &+ signed * 4)
    }

    static func anyConditionalTarget(instruction: UInt32, at offset: UInt64) -> UInt64? {
        conditionalTarget(instruction: instruction, at: offset)
            ?? testBranchTarget(instruction: instruction, at: offset)
    }

    static func isReturn(_ instruction: UInt32) -> Bool {
        // Plain RET plus the arm64e authenticated return forms RETAA/RETAB.
        instruction == 0xD65F_03C0  // RET
            || instruction == 0xD65F_0BFF // RETAA
            || instruction == 0xD65F_0FFF // RETAB
    }
}

final class ARM64Disassembler {
    private let capstone: Disassembler

    init() throws {
        capstone = try Disassembler(arch: CS_ARCH_AARCH64, mode: CS_MODE_LITTLE_ENDIAN)
        // Operand details are disabled by default in Capstone. The resolver
        // validates registers and memory operands, not only mnemonic strings.
        capstone.detail = true
    }

    func instructions(in image: BinaryImage, offset: UInt64, count: Int) throws -> [Instruction] {
        let bytes = try image.bytes(at: offset, count: count)
        let instructions = capstone.disassemble(code: bytes, address: offset)
        guard !instructions.isEmpty else {
            throw PatchfinderError.disassemblyFailed(offset: offset, length: count)
        }
        return instructions
    }

    func registerName(of instruction: Instruction, operandAt index: Int) -> String? {
        guard let operands = instruction.aarch64?.operands, operands.indices.contains(index) else {
            return nil
        }
        return capstone.registerName(UInt32(operands[index].reg.rawValue))
    }

    func memoryBaseName(of instruction: Instruction, operandAt index: Int) -> String? {
        guard let operands = instruction.aarch64?.operands, operands.indices.contains(index) else {
            return nil
        }
        return capstone.registerName(UInt32(operands[index].mem.base.rawValue))
    }
}
