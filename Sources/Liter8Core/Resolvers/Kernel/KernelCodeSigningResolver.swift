import Foundation

/// Static kernel patches that let an already-running process modify its own
/// executable pages without being killed for a code-signing violation. This is
/// what a runtime function hook (ElleKit's `MSHookFunction`) needs: the AMFI
/// PPL trust-cache stub alone lets an ad-hoc binary *launch*, but the first
/// time a tweak rewrites an instruction in a signed page the process dies with
/// `CODESIGNING / Invalid Page` unless these three decisions are relaxed.
///
/// The patterns are ported from the palera1n/PongoOS KPF (MIT), the `t8020`
/// bring-up branch for the PPL producer, with Liter8's own guards layered on:
/// the composed plan is gated on a kernel profile that opts in, every resolver
/// requires a single unambiguous match, and every record carries the exact
/// original word so the guarded applier refuses a kernel whose bytes differ. A
/// kernel that does not match produces no candidate rather than a wrong patch.
///
/// The individual resolvers are not gated, so `liter8 resolve kernel
/// ppl-allow-invalid <kc>` can probe an unregistered kernel on purpose. Only
/// `requiredRecords`, which feeds `boot-jit`, requires the profile opt-in.
///
/// These are deliberately NOT part of `boot-public`. They weaken code signing
/// for every process, so they live in the separate `boot-jit` plan, which `fw
/// get-boot` always builds. On a kernel profile without the opt-in it is
/// identical to `boot-public`.
public enum KernelCodeSigningResolver {
    /// Opt-in variant key a kernel profile sets to request these patches.
    static let variantKey = "kernel-codesign-invalid"

    /// Records for the composed JIT plan. Empty unless the detected profile
    /// opts in, so a kernel with no entry here is never touched by boot-jit.
    static func requiredRecords(in image: BinaryImage) throws -> [PatchRecord] {
        guard KernelResolverProfileRegistry.detect(in: image)?
            .variants(for: variantKey) != nil else {
            return []
        }
        return try KernelPPLAllowInvalidResolver().resolve(in: image)
            + KernelVMFaultCSBypassResolver().resolve(in: image)
            + KernelVMMapProtectResolver().resolve(in: image)
    }
}

/// Kernel resolvers that composed plans use only when the detected kernel
/// profile opts in, keyed by the profile variant that opts in. `survey` asks
/// this so a plan a profile never uses reads as not applicable, not failed.
public enum KernelOptInResolvers {
    public static func optInKey(forResolver name: String) -> String? {
        switch name {
        case KernelPPLTrustCacheResolver.name:
            return KernelPPLTrustCacheResolver.name
        case KernelPPLAllowInvalidResolver.name, KernelVMFaultCSBypassResolver.name,
             KernelVMMapProtectResolver.name:
            return KernelCodeSigningResolver.variantKey
        default:
            return nil
        }
    }

    /// Whether `survey` reports this resolver as not used. Only a detected
    /// profile without the opt-in skips it: on an unregistered kernel the
    /// standalone resolver is still probed, because whether it matches a new
    /// build is the porting evidence `survey` exists to collect.
    ///
    /// A family the detected profile explicitly omits (`omittedResolvers`) is
    /// reported the same way: the composite plans leave it out by a reviewed
    /// decision, so its standalone "no candidate" is not a porting failure.
    public static func isUnused(resolver name: String, by profile: KernelResolverProfile?) -> Bool {
        guard let profile else { return false }
        if profile.omittedResolvers.contains(name) { return true }
        guard let key = optInKey(forResolver: name) else { return false }
        return profile.variants(for: key) == nil
    }
}

// MARK: - PPL: every pmap is created allow-invalid

/// On T8020, PPL (not just AMFI) decides whether a page whose hash no longer
/// matches its signature may stay executable. The decision is a per-pmap byte
/// at `pmap + 0xc2`, initialised to 0 in `pmap_create_options_internal`. Set it
/// to 1 for every pmap at creation.
///
/// The producer stores `w8 = 1` as a halfword to `pmap + 0xc1`, which writes
/// `+0xc1 = 1` and `+0xc2 = 0`, and then reuses the same `w8` as the reference
/// count at `pmap + 0xb0`. Raising the immediate to `0x101` sets `+0xc2 = 1`
/// but would also make the reference count `0x101`, so the count store is
/// narrowed to a byte. Both edits are required and are applied together.
public struct KernelPPLAllowInvalidResolver: Sendable {
    public static let name = "kernel-ppl-allow-invalid"
    public init() {}

    private enum Opcode {
        static let movW8One: UInt32 = 0x5280_0028        // mov  w8, #1
        static let movW8_0x101: UInt32 = 0x5280_2028     // mov  w8, #0x101
        static let strW8X19_0xb0: UInt32 = 0xb900_b268   // str  w8, [x19, #0xb0]
        static let strbW8X19_0xb0: UInt32 = 0x3902_c268  // strb w8, [x19, #0xb0]
    }

    // The 13-word final-state producer, exact for T8020. Index 10 has two
    // encodings (STP of two words vs a 64-bit STUR) depending on the Darwin 25
    // point release; both clear pmap+0xb4. Nothing here is masked: this is an
    // exact byte signature, and a build that differs must be re-confirmed.
    private static let producer: [UInt32] = [
        0x6f00_e400, // movi.2d v0, #0
        0x3c85_8260, // stur q0, [x19, #0x58]
        0xf900_3e7f, // str xzr, [x19, #0x78]
        0xb900_827f, // str wzr, [x19, #0x80]
        0x780c_527f, // sturh wzr, [x19, #0xc5]
        0x3c88_8260, // stur q0, [x19, #0x88]
        0x3d80_2a60, // str q0, [x19, #0xa0]
        0x3902_627f, // strb wzr, [x19, #0x98]
        Opcode.movW8One,
        0x780c_1268, // sturh w8, [x19, #0xc1]
        0x2916_fe7f, // stp wzr, wzr, [x19, #0xb4]   (variant A)
        0xd503_3bbf, // dmb ish
        Opcode.strW8X19_0xb0,
    ]
    private static let producerVariantBWord10: UInt32 = 0xf80b_427f // stur xzr, [x19, #0xb4]

    public func resolve(in image: BinaryImage) throws -> [PatchRecord] {
        let layout = try MachOLayout(image: image)

        var hits: [UInt64] = []
        let count = Self.producer.count
        let byteCount = UInt64(count * 4)
        for range in layout.executableFileRanges
            where range.upperBound - range.lowerBound >= byteCount {
            var offset = (range.lowerBound + 3) & ~UInt64(3)
            while offset + byteCount <= range.upperBound {
                if try Self.matchesProducer(in: image, at: offset) { hits.append(offset) }
                offset += 4
            }
        }
        guard hits.count == 1, let entry = hits.first else {
            if hits.isEmpty { throw PatchfinderError.noCandidate("PPL pmap allow-invalid producer") }
            throw PatchfinderError.ambiguousCandidate("PPL pmap allow-invalid producer", offsets: hits)
        }

        let immOffset = entry + 8 * 4
        let refcountOffset = entry + 12 * 4
        let evidence = [
            "exact 13-word T8020 pmap_create_options_internal final-state producer",
            "unique match in executable kernel segments",
            "allow-invalid byte pmap+0xc2 set via the existing +0xc1 halfword store",
            "reference-count store narrowed to a byte so pmap+0xb0 stays 1",
        ]
        return [
            PatchRecord(
                id: "kernel.codesign.ppl-allow-invalid.immediate",
                component: "kernelcache",
                offset: immOffset,
                original: Opcode.movW8One,
                replacement: Opcode.movW8_0x101,
                summary: "Initialise every pmap with the PPL allow-invalid byte set",
                evidence: evidence
            ),
            PatchRecord(
                id: "kernel.codesign.ppl-allow-invalid.refcount",
                component: "kernelcache",
                offset: refcountOffset,
                original: Opcode.strW8X19_0xb0,
                replacement: Opcode.strbW8X19_0xb0,
                summary: "Keep the pmap reference count a byte after widening the init immediate",
                evidence: evidence
            ),
        ]
    }

    private static func matchesProducer(in image: BinaryImage, at offset: UInt64) throws -> Bool {
        for index in producer.indices {
            let word = try image.readUInt32(at: offset + UInt64(index * 4))
            if index == 10 {
                if word != producer[10] && word != producerVariantBWord10 { return false }
            } else if word != producer[index] {
                return false
            }
        }
        return true
    }
}

// MARK: - XNU: take the cs_bypass branch in vm_fault_enter

/// `vm_fault_enter` validates an executable page unless the fault carries
/// `cs_bypass`:
///
///     if (cs_bypass) {
///         cs_violation = FALSE;      // tbz wF, #3, else ; mov wV, #0 ; ...
///     } else if (m->vmp_cs_tainted) {
///         ...                        // a rewritten page ends up here
///     }
///
/// Removing the `tbz wF, #3` makes every fault take the bypass block, so a
/// page that a tweak has rewritten is not treated as a violation.
///
/// This is KPF's `vm_fault_enter_callback14` (iOS 14 and later): the candidate
/// is `tbz w*, #3` followed by `mov w*, #0` (optionally with a `mov xD, x23`,
/// xD >= 16, between them), and the nearest preceding `tbz w16-31, #2`
/// within 0x20 instructions must branch to the candidate or at most two
/// instructions before it. KPF takes the first such site; Liter8 requires
/// exactly one across the kernel.
public struct KernelVMFaultCSBypassResolver: Sendable {
    public static let name = "kernel-vm-fault-cs-bypass"
    public init() {}

    public func resolve(in image: BinaryImage) throws -> [PatchRecord] {
        let layout = try MachOLayout(image: image)

        var candidates: [UInt64] = []
        for range in layout.executableFileRanges {
            var offset = (range.lowerBound + 3) & ~UInt64(3)
            while offset + 8 <= range.upperBound {
                if try Self.isCandidate(at: offset, in: image, range: range) {
                    candidates.append(offset)
                }
                offset += 4
            }
        }
        guard candidates.count == 1, let site = candidates.first else {
            if candidates.isEmpty {
                throw PatchfinderError.noCandidate("vm_fault_enter cs_bypass test")
            }
            throw PatchfinderError.ambiguousCandidate("vm_fault_enter cs_bypass test", offsets: candidates)
        }
        return [PatchRecord(
            id: "kernel.codesign.vm-fault-cs-bypass",
            component: "kernelcache",
            offset: site,
            original: try image.readUInt32(at: site),
            replacement: ARM64.nop,
            summary: "Always take the cs_bypass branch in vm_fault_enter",
            evidence: [
                "tbz w*, #3 followed by mov w*, #0 (cs_violation = FALSE)",
                "nearest preceding tbz w16-31, #2 branches to it",
                "unique match in executable kernel segments",
            ]
        )]
    }

    private static func isCandidate(at offset: UInt64, in image: BinaryImage,
                                    range: Range<UInt64>) throws -> Bool {
        // tbz w*, #3, <label>
        guard try image.readUInt32(at: offset) & 0xFFF8_0000 == 0x3618_0000 else { return false }
        // mov w*, #0, directly or after one mov xD, x23 (xD >= 16), as KPF masks it
        let next = try image.readUInt32(at: offset + 4)
        var followedByZero = next & 0xFFFF_FFE0 == 0x5280_0000
        if !followedByZero, next & 0xFFFF_FE10 == 0xAA17_0210, offset + 12 <= range.upperBound {
            followedByZero = try image.readUInt32(at: offset + 8) & 0xFFFF_FFE0 == 0x5280_0000
        }
        guard followedByZero else { return false }

        // Nearest preceding tbz w16-31, #2 within 0x20 instructions.
        var back: UInt64 = 1
        while back <= 0x20, offset >= range.lowerBound + back * 4 {
            let at = offset - back * 4
            let word = try image.readUInt32(at: at)
            if word & 0xFFF8_0010 == 0x3610_0010 {
                guard let target = ARM64.testBranchTarget(instruction: word, at: at) else { return false }
                return target <= offset && offset - target <= 8
            }
            back += 1
        }
        return false
    }
}

// MARK: - XNU: allow RW->RX reprotect and ignore map_disallow_new_exec

/// `vm_map_protect` drops `VM_PROT_EXECUTE` from a request that also asks for
/// write, and refuses new execute permission on a map with
/// `map_disallow_new_exec`. A runtime hook that makes a code page writable,
/// edits it and restores execute needs both decisions relaxed.
///
/// Ported from KPF's `vm_map_protect` family. Two Darwin 25 encodings of the
/// same preflight gate are accepted, and exactly one site must match across
/// both:
///
///   XNU 25.5 (KPF matches_255)          iOS 26.4 (KPF matches_264)
///     and  wF, wE, #0x400000              ldr  x?, [x?, #0x10]
///     mov  wM, #6                         mov  wM, #6
///     bic  wM, wM, wP                     bic  wM, wM, wP
///     cmp  wM, #0                         and  wF, wE, #0x400000
///     ccmp wF, #0, #0, eq                 cmp  wM, #0
///     b.ne skip                           ccmp wF, #0, #0, eq
///                                         b.ne skip
///
/// In both, the `b.ne` becomes an unconditional branch to its own target. The
/// follow-up differs, exactly as in KPF:
///   - 25.5: at the target, the `tbnz w0-15, #7` (map_disallow_new_exec)
///     within the next three instructions becomes a NOP.
///   - 26.4: at the target, the `tb(n)z w0-15, #9` within the next eight
///     instructions is neutralised: a `tbnz` becomes a NOP, a `tbz` becomes an
///     unconditional branch to its own target.
public struct KernelVMMapProtectResolver: Sendable {
    public static let name = "kernel-vm-map-protect"
    public init() {}

    private enum Shape { case darwin255, darwin264 }

    private static let gate255 = MaskedInstructionPattern(name: "vm_map_protect 25.5 gate", values: [
        0x120a_0000, 0x5280_00c0, 0x0a20_0000, 0x7100_001f, 0x7a40_0800, 0x5400_0001,
    ], masks: [
        0xffff_fc00, 0xffff_ffe0, 0xffe0_fc00, 0xffff_fc1f, 0xffff_fe1f, 0xff00_001f,
    ])

    private static let gate264 = MaskedInstructionPattern(name: "vm_map_protect 26.4 gate", values: [
        0xf940_0800, 0x5280_00c0, 0x0a20_0000, 0x120a_0000, 0x7100_001f, 0x7a40_0800, 0x5400_0001,
    ], masks: [
        0xffff_fc00, 0xffff_ffe0, 0xffe0_fc00, 0xffff_fc00, 0xffff_fc1f, 0xffff_fe1f, 0xff00_001f,
    ])

    public func resolve(in image: BinaryImage) throws -> [PatchRecord] {
        let layout = try MachOLayout(image: image)

        var hits: [(offset: UInt64, shape: Shape)] = []
        for range in layout.executableFileRanges {
            var offset = (range.lowerBound + 3) & ~UInt64(3)
            while offset + 24 <= range.upperBound {
                if try Self.gate255.matches(in: image, at: offset),
                   Self.registersFlow(try Self.words(6, at: offset, in: image), shape: .darwin255) {
                    hits.append((offset, .darwin255))
                } else if offset + 28 <= range.upperBound,
                          try Self.gate264.matches(in: image, at: offset),
                          Self.registersFlow(try Self.words(7, at: offset, in: image), shape: .darwin264) {
                    hits.append((offset, .darwin264))
                }
                offset += 4
            }
        }
        guard hits.count == 1, let hit = hits.first else {
            if hits.isEmpty { throw PatchfinderError.noCandidate("vm_map_protect execute-downgrade gate") }
            throw PatchfinderError.ambiguousCandidate(
                "vm_map_protect execute-downgrade gate", offsets: hits.map(\.offset)
            )
        }

        // The executable range holding the gate, so the follow-up stays in code.
        // `conditionalTarget` yields a file offset and
        // `virtualAddress(forFileOffset:)` succeeds for any mapped offset, so
        // without this a branch that drifted to point outside the code would
        // still encode, and `uniqueWord` would then scan raw bytes: a data word
        // that happens to encode the expected TBNZ/TBZ would be accepted as the
        // follow-up decision and patched. The result is a kernel patch against
        // data, emitted with no sign that anything was wrong.
        guard let code = layout.executableFileRanges.first(where: { $0.contains(hit.offset) }) else {
            throw PatchfinderError.noCandidate("vm_map_protect gate outside any executable range")
        }

        let branchOffset = hit.offset + (hit.shape == .darwin255 ? 5 : 6) * 4
        let branch = try image.readUInt32(at: branchOffset)
        guard let skipTarget = ARM64.conditionalTarget(instruction: branch, at: branchOffset),
              code.contains(skipTarget),
              let unconditional = try Self.encodeBranch(from: branchOffset, to: skipTarget, layout: layout)
        else {
            throw PatchfinderError.noCandidate("vm_map_protect skip branch")
        }
        var records = [PatchRecord(
            id: "kernel.codesign.vm-map-protect.keep-execute",
            component: "kernelcache",
            offset: branchOffset,
            original: branch,
            replacement: unconditional,
            summary: "Always skip vm_map_protect's execute downgrade",
            evidence: [
                hit.shape == .darwin255
                    ? "XNU 25.5 arm64e preflight gate (KPF matches_255)"
                    : "iOS 26.4 preflight gate (KPF matches_264)",
                "unique match across both Darwin 25 encodings",
                "branch forced to its existing target, not a fabricated one",
            ]
        )]

        switch hit.shape {
        case .darwin255:
            // tbnz w0-15, #7 within the next three instructions.
            guard let site = try Self.uniqueWord(
                "map_disallow_new_exec decision",
                from: skipTarget, count: 3, in: image, within: code, where: {
                    $0 & 0xfff8_0010 == 0x3738_0000
                }
            ) else {
                throw PatchfinderError.noCandidate("map_disallow_new_exec decision")
            }
            records.append(PatchRecord(
                id: "kernel.codesign.vm-map-protect.disallow-new-exec",
                component: "kernelcache",
                offset: site,
                original: try image.readUInt32(at: site),
                replacement: ARM64.nop,
                summary: "Ignore map_disallow_new_exec in vm_map_protect",
                evidence: ["tbnz #7 within three instructions of the skip target"]
            ))
        case .darwin264:
            // tb(n)z w0-15, #9 within the next eight instructions.
            guard let site = try Self.uniqueWord(
                "vm_map_protect bit-9 test",
                from: skipTarget, count: 8, in: image, within: code, where: {
                    $0 & 0xfef8_0010 == 0x3648_0000
                }
            ) else {
                throw PatchfinderError.noCandidate("vm_map_protect bit-9 test")
            }
            let word = try image.readUInt32(at: site)
            let replacement: UInt32
            if word & 0x0100_0000 != 0 {
                replacement = ARM64.nop                      // tbnz: never take it
            } else {
                // Same constraint the skip branch above gets, and for the same
                // reason: encodeBranch only needs both offsets to map to
                // virtual addresses, so a tbz drifted to point outside the code
                // would encode an unconditional branch into data rather than
                // failing closed. Constraining the skip branch and the search
                // window was not enough on its own; this is the third place a
                // branch target is taken, and it was the one left unchecked.
                guard let target = ARM64.testBranchTarget(instruction: word, at: site),
                      code.contains(target),
                      let always = try Self.encodeBranch(from: site, to: target, layout: layout) else {
                    throw PatchfinderError.noCandidate("vm_map_protect bit-9 branch")
                }
                replacement = always                         // tbz: always take it
            }
            records.append(PatchRecord(
                id: "kernel.codesign.vm-map-protect.bit9",
                component: "kernelcache",
                offset: site,
                original: word,
                replacement: replacement,
                summary: "Neutralise vm_map_protect's bit-9 execute test",
                evidence: ["tb(n)z #9 within eight instructions of the skip target"]
            ))
        }
        return records
    }

    /// The one matching word in the window, or nil if there is none.
    ///
    /// Scans the whole window rather than stopping at the first hit. Taking the
    /// first would mean that on compiler drift placing a second matching bit
    /// test nearby, this patches whichever happens to come earlier and reports
    /// nothing unusual, which in a boot kernel means altering the wrong
    /// decision. The primary gate above is unique; that says nothing about the
    /// follow-up window.
    ///
    /// `range` is the executable range holding the gate, and the scan stops at
    /// its end rather than at the end of the image. Bounding by the image meant
    /// a window starting near the end of a code segment read on into whatever
    /// followed it, and a data word encoding the expected bit test would be
    /// taken for the decision.
    private static func uniqueWord(_ name: String, from start: UInt64, count: Int,
                                   in image: BinaryImage, within range: Range<UInt64>,
                                   where matches: (UInt32) -> Bool) throws -> UInt64? {
        var hits: [UInt64] = []
        for index in 0..<count {
            let at = start + UInt64(index * 4)
            guard at + 4 <= range.upperBound else { break }
            if matches(try image.readUInt32(at: at)) { hits.append(at) }
        }
        guard hits.count <= 1 else {
            throw PatchfinderError.ambiguousCandidate(name, offsets: hits)
        }
        return hits.first
    }

    private static func words(_ count: Int, at offset: UInt64,
                              in image: BinaryImage) throws -> [UInt32] {
        try (0..<count).map { try image.readUInt32(at: offset + UInt64($0 * 4)) }
    }

    /// Does the matched gate's data flow the way the shape says it does?
    ///
    /// The masks pin every opcode and immediate but leave the register fields
    /// free, so a drift or mutation that changed one operand still matched
    /// uniquely and the resolver went on to force an unrelated conditional
    /// branch in a boot kernel. Three relationships carry the gate's meaning:
    ///
    ///   - the `#6` the MOV produces is what the BIC clears bits from
    ///   - the BIC result is what the CMP tests
    ///   - the AND result is what the CCMP tests
    ///
    /// Deliberately not more than that. Requiring the BIC to write back to its
    /// own source, which is what both observed encodings happen to do, would
    /// reject an equivalent form that used a separate temporary.
    private static func registersFlow(_ words: [UInt32], shape: Shape) -> Bool {
        let and: UInt32, mov: UInt32, bic: UInt32, cmp: UInt32, ccmp: UInt32
        switch shape {
        case .darwin255:
            (and, mov, bic, cmp, ccmp) = (words[0], words[1], words[2], words[3], words[4])
        case .darwin264:
            // Same five, one slot later and with the AND after the BIC.
            (and, mov, bic, cmp, ccmp) = (words[3], words[1], words[2], words[4], words[5])
        }
        return rd(mov) == rn(bic) && rd(bic) == rn(cmp) && rd(and) == rn(ccmp)
    }

    private static func rd(_ word: UInt32) -> UInt32 { word & 0x1f }
    private static func rn(_ word: UInt32) -> UInt32 { (word >> 5) & 0x1f }

    private static func encodeBranch(from source: UInt64, to target: UInt64,
                                     layout: MachOLayout) throws -> UInt32? {
        guard let sourceVA = layout.virtualAddress(forFileOffset: source),
              let targetVA = layout.virtualAddress(forFileOffset: target) else { return nil }
        return ARM64.encodeDirectBranch(link: false, instructionOffset: sourceVA, target: targetVA)
    }
}
