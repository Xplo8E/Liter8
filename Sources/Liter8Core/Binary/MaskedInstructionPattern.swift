import Foundation

/// A relocation-tolerant ARM64 instruction signature.
///
/// `values[index]` is already masked, so a word matches when:
///
///     inputWord & masks[index] == values[index]
///
/// The hexadecimal entries in `masks` are bit-selection fields, not ARM64
/// instructions: 1 means "compare this bit" and 0 means "ignore this bit."
///
/// Masks remove only fields that the kernelcache linker must rewrite: branch
/// displacements, ADRP page deltas and literal-load offsets. Register choices,
/// opcodes, constants, stack layout and local data flow remain significant.
/// This is the same conservative signature model used by `sigmatch.py` and
/// vphone; it is not a wildcard byte search.
struct MaskedInstructionPattern: Sendable {
    let name: String
    let values: [UInt32]
    let masks: [UInt32]

    init(name: String, values: [UInt32], masks: [UInt32]) {
        precondition(!values.isEmpty && values.count == masks.count)
        self.name = name
        self.values = values
        self.masks = masks
    }

    /// Build a signature from instructions captured in a known-good reference
    /// build. The reference offset is intentionally not retained: the shipped
    /// resolver knows code shape, not where either firmware happened to place
    /// that code.
    ///
    /// `allowDataLayoutDrift` additionally masks the immediate of unsigned
    /// load/store instructions. Kernel C++ objects move fields between builds,
    /// while the base register, destination register, width and operation stay
    /// stable. No other arithmetic or register fields are relaxed.
    init(name: String, referenceWords: [UInt32], allowDataLayoutDrift: Bool = false) {
        let masks = referenceWords.map {
            Self.mask(for: $0, allowDataLayoutDrift: allowDataLayoutDrift)
        }
        self.init(
            name: name,
            values: zip(referenceWords, masks).map { $0 & $1 },
            masks: masks
        )
    }

    func matches(in image: BinaryImage, at offset: UInt64) throws -> Bool {
        for index in values.indices {
            let word = try image.readUInt32(at: offset + UInt64(index * 4))
            if word & masks[index] != values[index] { return false }
        }
        return true
    }

    func uniqueMatch(in image: BinaryImage, layout: MachOLayout) throws -> UInt64 {
        var hits: [UInt64] = []
        let byteCount = UInt64(values.count * 4)
        for range in layout.executableFileRanges
            where range.upperBound - range.lowerBound >= byteCount
        {
            var offset = (range.lowerBound + 3) & ~UInt64(3)
            while offset + byteCount <= range.upperBound {
                if try matches(in: image, at: offset) { hits.append(offset) }
                offset += 4
            }
        }
        guard let hit = hits.only else {
            if hits.isEmpty { throw PatchfinderError.noCandidate(name) }
            throw PatchfinderError.ambiguousCandidate(name, offsets: hits)
        }
        return hit
    }

    /// Count matching instructions without imposing a pass/fail threshold.
    /// This is used only after exact neighboring functions have bounded a
    /// drifted function to a small ordered window.
    func matchingWordCount(in image: BinaryImage, at offset: UInt64) throws -> Int {
        var count = 0
        for index in values.indices {
            let word = try image.readUInt32(at: offset + UInt64(index * 4))
            if word & masks[index] == values[index] { count += 1 }
        }
        return count
    }

    private static func mask(for word: UInt32, allowDataLayoutDrift: Bool) -> UInt32 {
        // B / BL: preserve the opcode, ignore the relinked destination.
        if word & 0xFC00_0000 == 0x1400_0000 || word & 0xFC00_0000 == 0x9400_0000 {
            return 0xFC00_0000
        }
        // B.cond: preserve the condition code.
        if word & 0xFF00_0010 == 0x5400_0000 { return 0xFF00_001F }
        // CBZ / CBNZ: preserve width, sense, and tested register.
        if word & 0x7E00_0000 == 0x3400_0000 { return 0xFF00_001F }
        // TBZ / TBNZ: also preserve the tested bit number.
        if word & 0x7E00_0000 == 0x3600_0000 { return 0xFFF8_001F }
        // ADRP: preserve the destination register and opcode.
        if word & 0x9F00_0000 == 0x9000_0000 { return 0x9F00_001F }
        // Literal LDR: preserve its operation and destination register.
        if word & 0x3B00_0000 == 0x1800_0000 { return 0xFF00_001F }
        // Unsigned-offset LDR/STR: preserve operation, width and registers;
        // only the C/C++ object-field displacement is allowed to move.
        if allowDataLayoutDrift && word & 0x3B00_0000 == 0x3900_0000 {
            return 0xFFC0_03FF
        }
        // ADD (immediate, 64-bit, LSL #0): the second half of an ADRP+ADD pair
        // forming a global's address. The ADRP page is already relaxed above,
        // but the in-page offset moves with it, so pinning it pins an address
        // rather than a code shape. iOS 27 RC moved current_thread_ro's global
        // from page 0xbc3000+0x1f0 to 0xbcb000+0xd0 without changing a single
        // instruction otherwise. Registers, width and opcode stay significant.
        if allowDataLayoutDrift && word & 0xFF80_0000 == 0x9100_0000 {
            return 0xFFC0_03FF
        }
        return 0xFFFF_FFFF
    }
}

private extension Collection {
    var only: Element? { count == 1 ? first : nil }
}
