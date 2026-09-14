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
    public static let normalBootArguments =
        "-v debug=0x2014e launchd_unsecure_cache=1 wdt=-1 backlight-level=1024"

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
            "unique zero run ending at page boundary \(slot.runEnd.hex)",
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
            //   ADD  X0, SP, <any imm>    destination is a stack buffer
            //   MOV  W1, #0x400           destination capacity is 1024
            //   BL   <any target>          make the call
            //
            // The masks keep opcode and register fields fixed but deliberately
            // erase page/stack immediates that are expected to move by build.
            guard adrp & 0x9F00_001F == 0x9000_0002, // ADRP X2,<page>
                  add & 0xFFC0_03FF == 0x9100_0042, // ADD X2,X2,#imm
                  destination & 0xFFC0_03FF == 0x9100_03E0, // ADD X0,SP,#imm
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

    /// Every zero run that ends on a 4 KiB boundary, largest first.
    ///
    /// A run is accepted only when it reaches the boundary. This models linker
    /// padding at the end of a mapped section and excludes arbitrary zero-filled
    /// structures elsewhere in the image.
    func pageTailRuns(in image: BinaryImage) -> [(start: Int, end: Int)] {
        var runs: [(start: Int, end: Int)] = []
        var runStart: Int?
        for offset in 0...image.count {
            let isZero = offset < image.count && image.data[offset] == 0
            if isZero, runStart == nil {
                runStart = offset
            } else if !isZero, let start = runStart {
                runStart = nil
                if offset.isMultiple(of: 0x1000) { runs.append((start, offset)) }
            }
        }
        return runs.sorted { $0.end - $0.start > $1.end - $1.start }
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
        guard let best = runs.first else { return [] }
        let bestLength = best.end - best.start
        guard runs.count == 1 || runs[1].end - runs[1].start < bestLength else { return [] }

        // Leave eight bytes after the last non-zero section contents, then align
        // the string. Alignment is a convention, not a requirement: the slot
        // holds a NUL-terminated C string read by a byte copy, and ADRP+ADD can
        // address any byte in the page. Take the widest alignment the run can
        // actually accommodate. The guard gap is never traded away.
        let guarded = best.start + 8
        guard let writeOffset = Self.alignments.lazy
            .map({ (guarded + $0 - 1) & ~($0 - 1) })
            .first(where: { $0 + requiredLength <= best.end })
        else { return [] }

        return [.init(
            writeOffset: UInt64(writeOffset),
            runEnd: UInt64(best.end),
            capacity: best.end - writeOffset
        )]
    }

}

private struct BootArgsCallSite {
    let adrpOffset: UInt64
    let addOffset: UInt64
    let formatOffset: UInt64
}

struct PageTailSlot {
    let writeOffset: UInt64
    let runEnd: UInt64
    let capacity: Int
}

private extension Collection {
    var only: Element? { count == 1 ? first : nil }
}
