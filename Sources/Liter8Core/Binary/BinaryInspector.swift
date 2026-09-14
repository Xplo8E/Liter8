import Foundation

/// Read-only diagnostic queries over an already-loaded firmware payload.
///
/// When a semantic resolver reports `no candidate`, the useful question is
/// which link in its anchor -> xref -> function -> instruction-shape chain
/// broke. Answering that previously meant instrumenting a Swift build or
/// re-deriving the Mach-O address arithmetic in a throwaway script, which then
/// disagrees with the resolvers in exactly the cases that matter. The inspector
/// reuses `BinaryImage`, `MachOLayout` and `ARM64` so a diagnosis and a
/// resolver always see the same bytes and the same boundaries.
public struct BinaryInspector {
    private let image: BinaryImage
    private let layout: MachOLayout
    private let disassembler: ARM64Disassembler

    public init(image: BinaryImage) throws {
        self.image = image
        layout = try MachOLayout(image: image)
        disassembler = try ARM64Disassembler()
    }

    // MARK: - Layout

    public func segmentReport() -> [String] {
        layout.segments.map { segment in
            let file = "\(segment.fileOffset.hex)..\(segment.fileRange.upperBound.hex)"
            let kind = segment.isExecutable ? "X" : "-"
            return "\(segment.name.padded(18)) vm \(segment.virtualAddress.hex) file \(file) \(kind)"
        }
    }

    // MARK: - Anchors

    /// Every occurrence of a literal, with the segment that holds it. A count
    /// other than one is the most common reason an anchor-based resolver stops.
    public func stringOccurrences(_ text: String, nulTerminated: Bool = false) -> [String] {
        image.findAll(utf8: text, nulTerminated: nulTerminated).map { offset in
            let segment = layout.segments.first { $0.fileRange.contains(offset) }
            return "\(offset.hex)  \(segment?.name ?? "<unmapped>")"
        }
    }

    /// ADRP+ADD references to a file offset, each attributed to the arm64e
    /// function that contains it.
    public func references(toFileOffset target: UInt64) throws -> [String] {
        try layout.adrpAddReferences(toFileOffset: target).map { reference in
            let owner = functionStart(beforeOrAt: reference.adrpOffset)
            let ownerText = owner.map { "in function \($0.hex)" } ?? "no enclosing prologue"
            return "adrp \(reference.adrpOffset.hex)  add \(reference.addOffset.hex)  \(ownerText)"
        }
    }

    // MARK: - Functions

    /// Nearest function entry at or before `offset`, or nil within `limit`.
    /// Delegates to `ARM64` so a diagnosis can never disagree with a resolver
    /// about where a function begins.
    public func functionStart(beforeOrAt offset: UInt64, limit: UInt64 = 0x4000) -> UInt64? {
        ARM64.functionStart(beforeOrAt: offset, in: image, layout: layout, limit: limit)
    }

    /// Next function entry after `start`, bounded by `limit` and the segment end.
    public func nextFunctionStart(after start: UInt64, limit: UInt64 = 0x2000) -> UInt64 {
        ARM64.nextFunctionStart(after: start, in: image, layout: layout, limit: limit)
    }

    /// Distinct direct B/BL destinations inside one function, in address order.
    public func directCallTargets(inFunctionContaining offset: UInt64) throws -> [UInt64] {
        guard let start = functionStart(beforeOrAt: offset) else { return [] }
        let end = nextFunctionStart(after: start)
        var targets: Set<UInt64> = []
        var cursor = start
        while cursor < end {
            let word = try image.readUInt32(at: cursor)
            if let address = ARM64.branchLinkTarget(instruction: word, at: cursor) {
                targets.insert(address)
            }
            cursor += 4
        }
        return targets.sorted()
    }

    // MARK: - Objective-C

    /// Every Objective-C implementation of one selector, with the first words
    /// of each. A selector implemented by several classes is the normal case,
    /// so the count matters as much as the addresses.
    public func objcMethods(named selector: String, words: Int = 2) throws -> [String] {
        let metadata = try ObjCMetadata(image: image)
        return try metadata.methods(named: selector).map { method in
            let encodings = try (0..<words).map { index -> String in
                let word = try image.readUInt32(at: method.implementationOffset + UInt64(index * 4))
                return String(format: "%08x", word)
            }
            return "imp \(method.implementationOffset.hex)  va \(method.implementationAddress.hex)"
                + "  entry \(method.entryOffset.hex)  \(encodings.joined(separator: " "))"
        }
    }

    // MARK: - Instructions

    public func disassembly(at offset: UInt64, words: Int) throws -> [String] {
        let instructions = try disassembler.instructions(
            in: image,
            offset: offset,
            count: words * 4
        )
        return try instructions.map { instruction in
            let word = try image.readUInt32(at: instruction.address)
            let virtual = layout.virtualAddress(forFileOffset: instruction.address)
            let virtualText = virtual.map(\.hex) ?? "-"
            let encoding = String(format: "%08x", word)
            return "\(instruction.address.hex)  \(virtualText)  \(encoding)  "
                + "\(instruction.mnemonic.padded(10)) \(instruction.operandString)"
        }
    }

    /// Every offset whose words satisfy a masked signature. Unlike
    /// `MaskedInstructionPattern.uniqueMatch` this never throws on zero or many
    /// hits, because seeing the real count is the point of a diagnosis.
    public func patternMatches(values: [UInt32], masks: [UInt32]) throws -> [UInt64] {
        let pattern = MaskedInstructionPattern(name: "inspect", values: values, masks: masks)
        var hits: [UInt64] = []
        let byteCount = UInt64(values.count * 4)
        for range in layout.executableFileRanges
            where range.upperBound - range.lowerBound >= byteCount
        {
            var offset = (range.lowerBound + 3) & ~UInt64(3)
            while offset + byteCount <= range.upperBound {
                if try pattern.matches(in: image, at: offset) { hits.append(offset) }
                offset += 4
            }
        }
        return hits
    }

    /// How many words of a signature survive at a candidate offset. Used to
    /// find which instruction inside a drifted function changed shape.
    public func patternWordReport(
        values: [UInt32],
        masks: [UInt32],
        at offset: UInt64
    ) throws -> [String] {
        try values.indices.map { index in
            let wordOffset = offset + UInt64(index * 4)
            let word = try image.readUInt32(at: wordOffset)
            let matched = word & masks[index] == values[index]
            let expected = String(format: "%08x/%08x", values[index], masks[index])
            let found = String(format: "%08x", word)
            return "\(matched ? "ok  " : "DIFF") \(wordOffset.hex)  want \(expected)  found \(found)"
        }
    }
}

private extension String {
    func padded(_ width: Int) -> String {
        count >= width ? self : self + String(repeating: " ", count: width - count)
    }
}
