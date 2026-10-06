import Foundation

/// Resolves the iBoot `snprintf` call that copies boot arguments and redirects
/// its format-string pointer to verified section-tail padding.
///
/// This is deliberately not a search for the text "%s" alone. That string is
/// common in iBoot. The useful identity is the surrounding calling convention:
///
///     ADRP X2, format@page
///     ADD  X2, X2, format@pageoff
///     ADD  X0, SP, #bufferOffset
///     MOV  W1, #0x400
///     BL   snprintf-like helper
///
/// X0/X1/X2 are therefore the destination, capacity and format arguments. The
/// complete shape has exactly one match in the n104 beta-4 iBSS/iBEC payload.
///
/// On 24A5390f the resolver currently rediscovers, rather than assumes:
///
///     call site       0x2aa28
///     old "%s"        0x1391cf
///     zero-tail run   0xd0e24..<0xd1000
///     aligned slot    0xd0e30
///
/// Those numbers appear here only to help a human compare the resolver with a
/// disassembly. They are never consulted by the implementation below.
public struct IBSSBootArgsResolver: Sendable {
    public static let name = "ibss-bootargs"

    /// Current normal-boot arguments from the validated beta-4 Python patcher.
    /// Callers may supply a different literal, but `%` is rejected because the
    /// selected pointer remains an `snprintf` format string.
    ///
    /// `serial=3` is appended only when `--serial` was passed to the command
    /// that builds the artifact. See `SerialConsole`: it moves the console to
    /// the UART and the screen stops showing this log, so it cannot be the
    /// default.
    public static var normalBootArguments: String {
        SerialConsole.applied(to: "-v debug=0x2014e launchd_unsecure_cache=1 wdt=-1")
    }

    public let bootArguments: String

    public init(bootArguments: String = Self.normalBootArguments) {
        self.bootArguments = bootArguments
    }

    public func resolve(in image: BinaryImage) throws -> [PatchRecord] {
        let argumentBytes = try encodedArguments()
        let sites = try findCallSites(in: image)
        guard let site = sites.only else {
            if sites.isEmpty { throw PatchfinderError.noCandidate(Self.name) }
            throw PatchfinderError.ambiguousCandidate(Self.name, offsets: sites.map(\.adrpOffset))
        }

        let slots = findPageTailSlots(in: image, requiredLength: argumentBytes.count)
        guard let slot = slots.only else {
            if slots.isEmpty { throw PatchfinderError.noCandidate("\(Self.name) page-tail string slot") }
            throw PatchfinderError.ambiguousCandidate(
                "\(Self.name) page-tail string slot",
                offsets: slots.map(\.writeOffset)
            )
        }

        // Do not transplant the known beta-4 instruction words. Re-encoding
        // from the discovered call site and slot is what makes the resolver
        // survive when either address moves in another build.
        guard let replacementADRP = ARM64.encodeADRP(
            register: 2,
            instructionOffset: site.adrpOffset,
            target: slot.writeOffset
        ), let replacementADD = ARM64.encodeAddImmediate(
            destination: 2,
            source: 2,
            immediate: UInt32(slot.writeOffset & 0xFFF)
        ) else {
            throw PatchfinderError.invalidPatch(
                id: Self.name,
                reason: "selected string slot cannot be encoded by ADRP+ADD X2"
            )
        }

        let originalADRP = try image.readUInt32(at: site.adrpOffset)
        let originalADD = try image.readUInt32(at: site.addOffset)
        let evidence = [
            "unique ADRP X2 / ADD X2 / ADD X0,SP / MOV W1,#0x400 / BL call shape",
            "original pointer resolves to isolated %s string at \(site.formatOffset.hex)",
            "zero run ends \(slot.endAlignment)-byte aligned at \(slot.runEnd.hex)",
            "aligned string slot \(slot.writeOffset.hex) has \(slot.capacity) bytes available",
        ]

        return [
            PatchRecord(
                id: "ibss.boot-args.adrp",
                component: "iBSS",
                offset: site.adrpOffset,
                original: originalADRP,
                replacement: replacementADRP,
                summary: "Redirect the boot-args format pointer to the selected page",
                evidence: evidence
            ),
            PatchRecord(
                id: "ibss.boot-args.add",
                component: "iBSS",
                offset: site.addOffset,
                original: originalADD,
                replacement: replacementADD,
                summary: "Redirect the boot-args format pointer within the selected page",
                evidence: evidence
            ),
            PatchRecord(
                id: "ibss.boot-args.string",
                component: "iBSS",
                offset: slot.writeOffset,
                originalBytes: Data(repeating: 0, count: argumentBytes.count),
                replacementBytes: argumentBytes,
                // The resolver serves restore, SSHRD and normal plans with
                // different literals, so naming one of them here mislabels the
                // other two in every manifest and evidence dump.
                summary: "Install the literal boot argument string",
                evidence: evidence
            ),
        ]
    }

    private func encodedArguments() throws -> Data {
        guard !bootArguments.isEmpty else {
            throw PatchfinderError.invalidPatch(id: Self.name, reason: "boot arguments are empty")
        }
        guard !bootArguments.contains("\0") else {
            throw PatchfinderError.invalidPatch(id: Self.name, reason: "boot arguments contain NUL")
        }
        // X2 is still passed as snprintf's format argument after patching. A
        // stray "%n" or "%s" would make snprintf consume registers as varargs;
        // literal boot arguments therefore must not contain conversions.
        guard !bootArguments.contains("%") else {
            throw PatchfinderError.invalidPatch(
                id: Self.name,
                reason: "boot arguments contain a printf conversion"
            )
        }
        guard var bytes = bootArguments.data(using: .ascii) else {
            throw PatchfinderError.invalidPatch(id: Self.name, reason: "boot arguments are not ASCII")
        }
        bytes.append(0)
        return bytes
    }

    private func findCallSites(in image: BinaryImage) throws -> [BootArgsCallSite] {
        guard image.count >= 20 else { return [] }
        var matches: [BootArgsCallSite] = []
        var offset: UInt64 = 0

        while offset + 20 <= UInt64(image.count) {
            let adrp = try image.readUInt32(at: offset)
            let add = try image.readUInt32(at: offset + 4)
            let destination = try image.readUInt32(at: offset + 8)
            let capacity = try image.readUInt32(at: offset + 12)
            let call = try image.readUInt32(at: offset + 16)

            // Read these guards as a description of the calling convention:
            //
            //   ADRP X2, <any page>       X2 will be snprintf's format
            //   ADD  X2, X2, <any imm>    finish that format pointer
            //   ADD  X0, SP, <any imm>    destination is a stack buffer, or
            //   SUB  X0, X29, <any imm>   the same buffer addressed via the FP
            //   MOV  W1, #0x400           destination capacity is 1024
            //   BL   <any target>          make the call
            //
            // The masks keep opcode and register fields fixed but deliberately
            // erase page/stack immediates that are expected to move by build.
            // The destination buffer may be formed off SP (n104, iOS 27) or off
            // the frame pointer (j171a, iPadOS 26: `SUB X0, X29, #imm`); both
            // put a stack-buffer address in X0 and the capacity constant below
            // still pins this to the single boot-argument copy.
            guard adrp & 0x9F00_001F == 0x9000_0002, // ADRP X2,<page>
                  add & 0xFFC0_03FF == 0x9100_0042, // ADD X2,X2,#imm
                  (destination & 0xFFC0_03FF == 0x9100_03E0 // ADD X0,SP,#imm
                      || destination & 0xFFC0_03FF == 0xD100_03A0), // SUB X0,X29,#imm
                  capacity == 0x5280_8001, // MOV W1,#0x400
                  call >> 26 == 0b100101
            else {
                offset += 4
                continue
            }

            // A matching instruction shape is still only a candidate. Resolve
            // the old pointer and require an isolated "%s\0" before trusting it
            // as the boot-argument copy rather than an unrelated snprintf.
            let formatOffset = ARM64.adrpTarget(instruction: adrp, at: offset)
                &+ ARM64.addImmediate(instruction: add)
            guard isIsolatedPercentS(in: image, at: formatOffset) else {
                offset += 4
                continue
            }

            matches.append(.init(
                adrpOffset: offset,
                addOffset: offset + 4,
                formatOffset: formatOffset
            ))
            offset += 4
        }
        return matches
    }

    private func isIsolatedPercentS(in image: BinaryImage, at offset: UInt64) -> Bool {
        guard offset > 0, offset + 3 <= UInt64(image.count),
              let bytes = try? image.bytes(at: offset - 1, count: 4)
        else { return false }
        return bytes == Data([0, UInt8(ascii: "%"), UInt8(ascii: "s"), 0])
    }

    /// Preferred string alignments, widest first. Narrower entries are reached
    /// only when the zero run cannot hold the literal at a wider one.
    private static let alignments = [16, 8, 4, 2, 1]

    /// Every zero run in the payload, largest first, with the alignment its end
    /// satisfies.
    ///
    /// `endAlignment` is the largest power of two dividing the run's end offset,
    /// which is what lets padding be told apart from data further down.
    private func zeroRuns(in image: BinaryImage) -> [(start: Int, end: Int, endAlignment: Int)] {
        var runs: [(start: Int, end: Int, endAlignment: Int)] = []
        var runStart: Int?
        for offset in 0...image.count {
            let isZero = offset < image.count && image.data[offset] == 0
            if isZero, runStart == nil {
                runStart = offset
            } else if !isZero, let start = runStart {
                runStart = nil
                // offset & -offset isolates the lowest set bit: the largest
                // power of two that divides it.
                runs.append((start, offset, offset == 0 ? 0 : offset & -offset))
            }
        }
        return runs.sorted { $0.end - $0.start > $1.end - $1.start }
    }

    /// Every zero run that ends on a 4 KiB boundary, largest first.
    ///
    /// A run is accepted only when it reaches the boundary. This models linker
    /// padding at the end of a mapped section and excludes arbitrary zero-filled
    /// structures elsewhere in the image.
    public func pageTailRuns(in image: BinaryImage) -> [(start: Int, end: Int)] {
        zeroRuns(in: image)
            .filter { $0.end.isMultiple(of: 0x1000) }
            .map { ($0.start, $0.end) }
    }

    /// Zero runs that carry the arithmetic signature of alignment padding.
    ///
    /// Padding inserted to align the next structure to N bytes is always
    /// shorter than N, because a full N bytes would mean the structure was
    /// already aligned. Requiring `length < endAlignment` therefore admits
    /// genuine inter-structure padding while rejecting large zero-filled
    /// regions, which are the ones that might be written at runtime.
    ///
    /// The 256-byte floor keeps incidental short gaps inside packed tables out:
    /// a few zero bytes before a 16-byte-aligned record is not a free slot.
    func alignmentPaddingRuns(in image: BinaryImage) -> [(start: Int, end: Int)] {
        zeroRuns(in: image)
            .filter { $0.endAlignment >= 256 && ($0.end - $0.start) < $0.endAlignment }
            .map { ($0.start, $0.end) }
    }

    func findPageTailSlots(in image: BinaryImage, requiredLength: Int) -> [PageTailSlot] {
        // Identify the run by what it *is* -- the section-tail padding, i.e. the
        // largest page-boundary zero run in the payload -- not by whether a
        // particular literal happens to fit it.
        //
        // Selecting by fit is what used to make this resolver unstable. The
        // previous fixed 16-byte alignment excluded the runner-up run only by
        // arithmetic accident, so widening the alignment to fit RC's shorter run
        // silently admitted a second candidate and broke the restore plan on
        // both builds. Both payloads have one clearly dominant run
        // (beta 4: 476 bytes vs 35; RC 24A435: 79 vs 35), so requiring a unique
        // maximum is a stronger identity than any length test.
        let runs = pageTailRuns(in: image)

        // While page-tail padding big enough for the literal exists, this rule
        // is authoritative -- including its refusal to choose between equal
        // candidates. Falling through to the fallback on ambiguity would turn
        // that deliberate refusal into a silent guess by a different criterion,
        // which is the one behaviour this selection must never have.
        if runs.contains(where: { slot(in: $0, requiredLength: requiredLength) != nil }) {
            guard let best = runs.first else { return [] }
            let bestLength = best.end - best.start
            guard runs.count == 1 || runs[1].end - runs[1].start < bestLength else { return [] }
            return slot(in: best, requiredLength: requiredLength).map { [$0] } ?? []
        }

        // Fall back only when no page-tail run can hold the literal at all.
        //
        // That test was never a property of padding. iOS 27.2 grew the embedded
        // device tree by 2048 bytes, which shifted the rest of iBSS by half a
        // page: the same 79-byte gap that 24A435 used still exists, byte for
        // byte, but now ends 2048-aligned instead of 4096-aligned and every
        // page-tail run in the image is under 12 bytes.
        //
        // The primary rule is kept ahead of this one so builds that do have
        // page-tail padding keep selecting exactly what they selected before,
        // which is what the pinned fixtures record.
        //
        // Smallest-that-fits rather than largest: the literal needs one slot,
        // and a tight gap is more certainly inter-structure padding than a
        // roomy one. On 27.2 this lands on the same device-tree padding 24A435
        // used, which is the strongest evidence available that the fallback
        // selects the same kind of place.
        let padding = alignmentPaddingRuns(in: image)
            .sorted { $0.end - $0.start < $1.end - $1.start }
        for run in padding {
            if let slot = slot(in: run, requiredLength: requiredLength) { return [slot] }
        }
        return []
    }

    /// Place the literal inside one accepted run, or report that it cannot fit.
    ///
    /// Leaves eight bytes after the last non-zero contents, then aligns the
    /// string. Alignment is a convention, not a requirement: the slot holds a
    /// NUL-terminated C string read by a byte copy, and ADRP+ADD can address any
    /// byte in the page. Take the widest alignment the run can accommodate. The
    /// guard gap is never traded away.
    private func slot(
        in run: (start: Int, end: Int),
        requiredLength: Int
    ) -> PageTailSlot? {
        let guarded = run.start + 8
        guard let writeOffset = Self.alignments.lazy
            .map({ (guarded + $0 - 1) & ~($0 - 1) })
            .first(where: { $0 + requiredLength <= run.end })
        else { return nil }

        return PageTailSlot(
            endAlignment: run.end == 0 ? 0 : run.end & -run.end,
            writeOffset: UInt64(writeOffset),
            runEnd: UInt64(run.end),
            capacity: run.end - writeOffset
        )
    }
}

private struct BootArgsCallSite {
    let adrpOffset: UInt64
    let addOffset: UInt64
    let formatOffset: UInt64
}

struct PageTailSlot {
    /// Power-of-two boundary the run's end satisfies.
    ///
    /// Recorded so the evidence can state which boundary was actually found
    /// rather than asserting a page. 24A435's run ends 4096-aligned and 27.2's
    /// ends 2048-aligned, and a fixture that claimed "page boundary" for the
    /// second would be recording something untrue.
    let endAlignment: Int
    let writeOffset: UInt64
    let runEnd: UInt64
    let capacity: Int
}

private extension Collection {
    var only: Element? { count == 1 ? first : nil }
}
