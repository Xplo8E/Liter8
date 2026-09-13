import Foundation

/// Resolves the restore path's AMFI and code-signing patches from code shape.
///
/// The resolver intentionally returns individual instruction patches. That
/// keeps the guarded applier honest: every word is checked against the input
/// image before any output is written, and the resulting manifest explains
/// which part of a multi-instruction stub changed.
struct KernelAMFIResolver: Sendable {
    func resolve(in image: BinaryImage) throws -> [PatchRecord] {
        let layout = try MachOLayout(image: image)
        return try trustCacheStub(in: image, layout: layout)
            + launchConstraintsStub(in: image, layout: layout)
            + debuggerStub(in: image, layout: layout)
            + developerModeStub(in: image, layout: layout)
            + [postValidationCompare(in: image, layout: layout)]
            + dyldPolicyCalls(in: image, layout: layout)
    }

    // MARK: - AMFIIsCDHashInTrustCache

    /// Locate AMFI's trust-cache query by its out-parameter data flow rather
    /// than by a fixed prologue offset. On beta 4 the caller supplies that
    /// out-parameter in x3; older implementations used x2, so the register is
    /// decoded from the function body and reused by the generated stub.
    private func trustCacheStub(in image: BinaryImage, layout: MachOLayout) throws -> [PatchRecord] {
        var hits: [(start: UInt64, outRegister: UInt32)] = []

        for range in layout.executableFileRanges {
            var start = alignedStart(of: range)
            while start + 0x40 <= range.upperBound {
                guard try image.readUInt32(at: start) == 0xD503_237F else { // PACIBSP
                    start += 4
                    continue
                }

                let words = try (0..<24).map { try image.readUInt32(at: start + UInt64($0 * 4)) }
                for outRegister in UInt32(0)..<31 {
                    let saveOutParameter = 0xAA00_03F3 | (outRegister << 16) // mov x19, xN
                    let passStackSlot = 0x9100_03E0 | outRegister           // mov xN, sp
                    guard let saveIndex = words.firstIndex(of: saveOutParameter),
                          // Do not let a short wrapper borrow the body of the
                          // next function merely because our lookahead spans it.
                          !words[1..<saveIndex].contains(0xD503_237F), // no nested PACIBSP/function start
                          let zeroIndex = words.indices.dropFirst(saveIndex + 1).first(where: {
                              words[$0] & 0xFFC0_7FFF == 0xA900_7FFF
                          }),
                          let stackIndex = words.indices.dropFirst(zeroIndex + 1).first(where: {
                              words[$0] == passStackSlot
                          }),
                          let callIndex = words.indices.dropFirst(stackIndex + 1).first(where: {
                              words[$0] & 0xFC00_0000 == 0x9400_0000
                          }),
                          let resultIndex = words.indices.dropFirst(callIndex + 1).first(where: {
                              words[$0] == 0xAA00_03F4 // mov x20, x0
                          }),
                          words.indices.dropFirst(resultIndex + 1).contains(where: {
                              $0 < min(words.count, resultIndex + 8)
                                  && words[$0] & 0x7F00_001F == 0x3500_0000 // cbnz w0
                          }),
                          words.indices.dropFirst(resultIndex + 1).contains(where: {
                              $0 < min(words.count, resultIndex + 8)
                                  && words[$0] & 0xFF00_001F == 0xB400_0013 // cbz x19
                          })
                    else { continue }

                    hits.append((start, outRegister))
                }
                start += 4
            }
        }

        guard let hit = hits.only else {
            if hits.isEmpty { throw PatchfinderError.noCandidate("AMFI trust-cache function") }
            throw PatchfinderError.ambiguousCandidate(
                "AMFI trust-cache function",
                offsets: hits.map(\.start)
            )
        }

        let replacements: [UInt32] = [
            0xD503_245F,                         // bti c
            ARM64.movX0One,                      // mov x0, #1
            0xB400_0040 | hit.outRegister,       // cbz xN, +8
            0xF900_0000 | (hit.outRegister << 5),// str x0, [xN]
            ARM64.ret,
        ]
        return try replacements.enumerated().map { index, replacement in
            let offset = hit.start + UInt64(index * 4)
            return try wordPatch(
                id: "kernel.amfi.trust-cache.\(index)",
                offset: offset,
                replacement: replacement,
                summary: "Make AMFI trust-cache lookup succeed (word \(index + 1)/5)",
                evidence: [
                    "unique PACIBSP function with saved x\(hit.outRegister) out-parameter",
                    "stack result is passed to a lookup call and followed by result/out-parameter guards",
                ],
                image: image
            )
        }
    }

    // MARK: - Small entry-point stubs

    private func launchConstraintsStub(in image: BinaryImage, layout: MachOLayout) throws -> [PatchRecord] {
        let reference = try uniqueStringReference(
            "AMFI: Validation Category info",
            in: image,
            layout: layout
        )
        let start = try functionStart(beforeOrAt: reference.adrpOffset, in: image, layout: layout)
        return try [
            wordPatch(
                id: "kernel.amfi.launch-constraints.result",
                offset: start,
                replacement: ARM64.movW0Zero,
                summary: "Return success from AMFI launch-constraint validation",
                evidence: ["function uniquely owns the Validation Category diagnostic"],
                image: image
            ),
            wordPatch(
                id: "kernel.amfi.launch-constraints.return",
                offset: start + 4,
                replacement: ARM64.ret,
                summary: "Return immediately after the launch-constraint result",
                evidence: ["paired entry-point stub"],
                image: image
            ),
        ]
    }

    /// PE_i_can_has_debugger is tiny and has no stable string. Its durable
    /// fingerprint is a page load through x8 plus its optional x0 output
    /// pointer contract: CBZ x0, compute a W result, STR it through [x0], then
    /// return it. Direct-call counts rank structurally valid leaves; they are
    /// not used as a build-specific numeric threshold.
    private func debuggerStub(in image: BinaryImage, layout: MachOLayout) throws -> [PatchRecord] {
        let callCounts = try directCallCounts(in: image, layout: layout)
        var candidates: [(offset: UInt64, callers: Int)] = []

        for range in layout.executableFileRanges {
            var offset = max(alignedStart(of: range), range.lowerBound + 4)
            while offset + 52 <= range.upperBound {
                let previous = try image.readUInt32(at: offset - 4)
                guard try image.readUInt32(at: offset) & 0x9F00_001F == 0x9000_0008,
                      ARM64.isReturn(previous) || previous == 0xD503_237F, // RET* or PACIBSP boundary
                      try image.readUInt32(at: offset + 4) & 0xFF00_001F == 0xB400_0000 // CBZ X0,<target>
                else {
                    offset += 4
                    continue
                }

                let hasLoad = try (1...8).contains { index in
                    let word = try image.readUInt32(at: offset + UInt64(index * 4))
                    return word & 0xFFC0_03E0 == 0xB940_0100 // ldr wN, [x8, #imm]
                }
                let storesThroughOutput = try (2...10).contains { index in
                    let word = try image.readUInt32(at: offset + UInt64(index * 4))
                    return word & 0xFFC0_03E0 == 0xB900_0000 // str wN, [x0, #imm]
                }
                let returnsLocally = try (2...12).contains { index in
                    ARM64.isReturn(try image.readUInt32(at: offset + UInt64(index * 4)))
                }
                if hasLoad, storesThroughOutput, returnsLocally {
                    candidates.append((offset, callCounts[offset, default: 0]))
                }
                offset += 4
            }
        }

        guard let maximum = candidates.map(\.callers).max() else {
            throw PatchfinderError.noCandidate("PE_i_can_has_debugger")
        }
        let winners = candidates.filter { $0.callers == maximum }
        guard let start = winners.only?.offset else {
            throw PatchfinderError.ambiguousCandidate(
                "PE_i_can_has_debugger",
                offsets: winners.map(\.offset)
            )
        }
        return try [
            wordPatch(
                id: "kernel.debugger.result",
                offset: start,
                replacement: ARM64.movX0One,
                summary: "Report that the platform permits a debugger",
                evidence: ["unique highest-call-count ADRP x8 leaf with optional x0 output-pointer data flow"],
                image: image
            ),
            wordPatch(
                id: "kernel.debugger.return",
                offset: start + 4,
                replacement: ARM64.ret,
                summary: "Return the forced debugger result",
                evidence: ["paired leaf-function stub"],
                image: image
            ),
        ]
    }

    /// developer_mode_state is recognized by following an indirect shared
    /// pointer, checking it for nil, loading one byte, masking bit zero, and
    /// returning. Register immediates may move; the instruction relationship
    /// is what identifies the accessor.
    private func developerModeStub(in image: BinaryImage, layout: MachOLayout) throws -> [PatchRecord] {
        var hits: [UInt64] = []
        for range in layout.executableFileRanges {
            var offset = alignedStart(of: range)
            while offset + 24 <= range.upperBound {
                let words = try (0..<6).map { try image.readUInt32(at: offset + UInt64($0 * 4)) }
                let isAdrpX8 = words[0] & 0x9F00_001F == 0x9000_0008 // ADRP X8,<page>
                let isLdrX8FromX8 = words[1] & 0xFFC0_03FF == 0xF940_0108 // LDR X8,[X8,#imm]
                let isCbzX8 = words[2] & 0xFF00_001F == 0xB400_0008 // CBZ X8,<target>
                let isLdrbW8FromX8 = words[3] & 0xFFC0_03FF == 0x3940_0108 // LDRB W8,[X8,#imm]
                let isAndW0W8One = words[4] == 0x1200_0100 // AND W0,W8,#1
                if isAdrpX8, isLdrX8FromX8, isCbzX8,
                   isLdrbW8FromX8, isAndW0W8One, ARM64.isReturn(words[5]) {
                    hits.append(offset)
                }
                offset += 4
            }
        }
        guard let start = hits.only else {
            if hits.isEmpty { throw PatchfinderError.noCandidate("developer_mode_state") }
            throw PatchfinderError.ambiguousCandidate("developer_mode_state", offsets: hits)
        }
        return try [
            wordPatch(
                id: "kernel.amfi.developer-mode.result",
                offset: start,
                replacement: ARM64.movW0One,
                summary: "Report developer mode enabled",
                evidence: ["unique shared-pointer byte accessor masked to bit zero"],
                image: image
            ),
            wordPatch(
                id: "kernel.amfi.developer-mode.return",
                offset: start + 4,
                replacement: ARM64.ret,
                summary: "Return the forced developer-mode result",
                evidence: ["paired accessor stub"],
                image: image
            ),
        ]
    }

    // MARK: - Validation and dyld policy call sites

    private func postValidationCompare(in image: BinaryImage, layout: MachOLayout) throws -> PatchRecord {
        let references = try stringReferences(
            "AMFI: code signature validation failed",
            in: image,
            layout: layout
        )
        var callees = Set<UInt64>()
        var callers = Set<UInt64>()
        for reference in references {
            let callerStart = try functionStart(
                beforeOrAt: reference.adrpOffset,
                in: image,
                layout: layout
            )
            guard callers.insert(callerStart).inserted else { continue }
            let callerEnd = try nextFunctionStart(
                after: callerStart,
                maximumDistance: 0x2000,
                in: image,
                layout: layout
            )
            var offset = callerStart
            while offset < callerEnd {
                if let target = try directCallTarget(at: offset, in: image, layout: layout) {
                    callees.insert(target)
                }
                offset += 4
            }
        }

        var hits: [UInt64] = []
        for callee in callees where layout.executableFileRanges.contains(where: { $0.contains(callee) }) {
            let end = try nextFunctionStart(after: callee, maximumDistance: 0x200, in: image, layout: layout)
            var cursor = callee + 8
            while cursor + 4 < end {
                let compare = try image.readUInt32(at: cursor)
                let branch = try image.readUInt32(at: cursor + 4)
                // SUBS WZR,W0,#imm is the CMP W0,#imm alias; B.NE has cond=1.
                let comparesW0Immediate = compare & 0x7F00_03FF == 0x7100_001F // CMP W0,#imm
                let isBNE = branch & 0xFF00_001F == 0x5400_0001 // B.NE <target>
                let hasNearbyCall = try [cursor - 4, cursor - 8].contains {
                    try directCallTarget(at: $0, in: image, layout: layout) != nil
                }
                if comparesW0Immediate, isBNE, hasNearbyCall { hits.append(cursor) }
                cursor += 4
            }
        }
        let uniqueHits = Array(Set(hits)).sorted()
        guard let site = uniqueHits.only else {
            if uniqueHits.isEmpty { throw PatchfinderError.noCandidate("AMFI postValidation compare") }
            throw PatchfinderError.ambiguousCandidate("AMFI postValidation compare", offsets: uniqueHits)
        }
        return try wordPatch(
            id: "kernel.amfi.post-validation.compare",
            offset: site,
            replacement: 0x6B00_001F, // cmp w0, w0: Z is always set
            summary: "Make the post-validation comparison equal",
            evidence: [
                "callee of the function owning the code-signature validation diagnostic",
                "CMP W0,#imm follows a BL and is immediately consumed by B.NE",
            ],
            image: image
        )
    }

    private func dyldPolicyCalls(in image: BinaryImage, layout: MachOLayout) throws -> [PatchRecord] {
        let references = try allStringReferences(
            "com.apple.developer.swift-playgrounds-app.development-build",
            in: image,
            layout: layout
        )
        var candidates: [[UInt64]] = []
        for reference in references {
            let lower = reference.adrpOffset - min(reference.adrpOffset, 80)
            var pairs: [(site: UInt64, target: UInt64)] = []
            var cursor = reference.adrpOffset
            while cursor >= lower + 4 {
                cursor -= 4
                guard let target = try directCallTarget(at: cursor, in: image, layout: layout) else { continue }
                let next = try image.readUInt32(at: cursor + 4)
                let isCompareBranch = next & 0x7E00_0000 == 0x3400_0000 // CBZ/CBNZ
                let isTestBranch = next & 0x7E00_0000 == 0x3600_0000 // TBZ/TBNZ
                if (isCompareBranch || isTestBranch), next & 0x1F == 0 {
                    pairs.append((cursor, target))
                }
            }
            guard pairs.count >= 2, pairs[0].target != pairs[1].target else { continue }
            let sites = [pairs[1].site, pairs[0].site].sorted()
            if !candidates.contains(sites) { candidates.append(sites) }
        }
        guard let selected = candidates.only else {
            if candidates.isEmpty { throw PatchfinderError.noCandidate("dyld policy helper-call pair") }
            throw PatchfinderError.ambiguousCandidate(
                "dyld policy helper-call pair",
                offsets: candidates.flatMap { $0 }
            )
        }
        return try selected.enumerated().map { index, site in
            try wordPatch(
                id: "kernel.amfi.dyld-policy.\(index)",
                offset: site,
                replacement: ARM64.movW0One,
                summary: "Make dyld policy helper \(index + 1) succeed",
                evidence: [
                    "within 80 bytes of the Swift Playgrounds development entitlement xref",
                    "BL is immediately followed by a conditional test of w0 and the two helpers differ",
                ],
                image: image
            )
        }
    }

    // MARK: - Shared kernel decoding helpers

    private func uniqueStringReference(
        _ phrase: String,
        in image: BinaryImage,
        layout: MachOLayout
    ) throws -> ADRPAddReference {
        let references = try stringReferences(phrase, in: image, layout: layout)
        guard let reference = references.only else {
            throw PatchfinderError.ambiguousCandidate(
                "kernel xref: \(phrase)",
                offsets: references.map(\.adrpOffset)
            )
        }
        return reference
    }

    /// A string can be used by several error sites. Callers decide whether
    /// multiplicity is expected; this helper only proves that the literal is
    /// unique and that at least one executable ADRP+ADD reaches it.
    private func stringReferences(
        _ phrase: String,
        in image: BinaryImage,
        layout: MachOLayout
    ) throws -> [ADRPAddReference] {
        let occurrences = image.findAll(utf8: phrase)
        guard let occurrence = occurrences.only else {
            if occurrences.isEmpty { throw PatchfinderError.missingAnchor(phrase) }
            throw PatchfinderError.ambiguousAnchor(phrase, count: occurrences.count)
        }
        let stringStart = containingCStringStart(beforeOrAt: occurrence, in: image)
        let references = try layout.adrpAddReferences(toFileOffset: stringStart)
        guard !references.isEmpty else {
            throw PatchfinderError.noCandidate("kernel xref: \(phrase)")
        }
        return references
    }

    /// Return xrefs for every copy of a literal. Kernel filesets can contain
    /// identical constants in multiple embedded images; the owning code shape,
    /// not an arbitrary first occurrence, must disambiguate them.
    private func allStringReferences(
        _ phrase: String,
        in image: BinaryImage,
        layout: MachOLayout
    ) throws -> [ADRPAddReference] {
        let occurrences = image.findAll(utf8: phrase)
        guard !occurrences.isEmpty else { throw PatchfinderError.missingAnchor(phrase) }
        let starts = Set(occurrences.map { containingCStringStart(beforeOrAt: $0, in: image) })
        var references: [ADRPAddReference] = []
        for start in starts {
            references.append(contentsOf: try layout.adrpAddReferences(toFileOffset: start))
        }
        guard !references.isEmpty else {
            throw PatchfinderError.noCandidate("kernel xref: \(phrase)")
        }
        return references
    }

    private func containingCStringStart(beforeOrAt offset: UInt64, in image: BinaryImage) -> UInt64 {
        var cursor = Int(offset)
        while cursor > 0, image.data[cursor - 1] != 0 { cursor -= 1 }
        return UInt64(cursor)
    }

    private func functionStart(
        beforeOrAt offset: UInt64,
        in image: BinaryImage,
        layout: MachOLayout
    ) throws -> UInt64 {
        guard let range = layout.executableFileRanges.first(where: { $0.contains(offset) }) else {
            throw PatchfinderError.noCandidate("containing executable range")
        }
        let floor = max(range.lowerBound, offset - min(offset - range.lowerBound, 0x4000))
        var cursor = offset & ~UInt64(3)
        while cursor >= floor + 4 {
            if try image.readUInt32(at: cursor) == 0xD503_237F { return cursor } // PACIBSP
            cursor -= 4
        }
        throw PatchfinderError.noCandidate("arm64e function start before \(offset.hex)")
    }

    private func nextFunctionStart(
        after start: UInt64,
        maximumDistance: UInt64,
        in image: BinaryImage,
        layout: MachOLayout
    ) throws -> UInt64 {
        guard let range = layout.executableFileRanges.first(where: { $0.contains(start) }) else {
            return start + maximumDistance
        }
        let limit = min(range.upperBound, start + maximumDistance)
        var cursor = start + 4
        while cursor < limit {
            if try image.readUInt32(at: cursor) == 0xD503_237F { return cursor } // PACIBSP
            cursor += 4
        }
        return limit
    }

    private func directCallTarget(
        at offset: UInt64,
        in image: BinaryImage,
        layout: MachOLayout
    ) throws -> UInt64? {
        guard let sourceAddress = layout.virtualAddress(forFileOffset: offset),
              let targetAddress = ARM64.branchLinkTarget(
                instruction: try image.readUInt32(at: offset),
                at: sourceAddress
              )
        else { return nil }
        return layout.fileOffset(forVirtualAddress: targetAddress)
    }

    private func directCallCounts(in image: BinaryImage, layout: MachOLayout) throws -> [UInt64: Int] {
        var counts: [UInt64: Int] = [:]
        for range in layout.executableFileRanges {
            var offset = alignedStart(of: range)
            while offset + 4 <= range.upperBound {
                if let target = try directCallTarget(at: offset, in: image, layout: layout) {
                    counts[target, default: 0] += 1
                }
                offset += 4
            }
        }
        return counts
    }

    private func alignedStart(of range: Range<UInt64>) -> UInt64 {
        (range.lowerBound + 3) & ~UInt64(3)
    }

    private func wordPatch(
        id: String,
        offset: UInt64,
        replacement: UInt32,
        summary: String,
        evidence: [String],
        image: BinaryImage
    ) throws -> PatchRecord {
        PatchRecord(
            id: id,
            component: "kernelcache",
            offset: offset,
            original: try image.readUInt32(at: offset),
            replacement: replacement,
            summary: summary,
            evidence: evidence
        )
    }
}

private extension Collection {
    var only: Element? { count == 1 ? first : nil }
}
