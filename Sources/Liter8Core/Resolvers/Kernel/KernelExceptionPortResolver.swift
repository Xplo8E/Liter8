import Foundation

/// Clears the switch that kills a process for registering a non-identity-protected
/// exception handler.
///
/// XNU's `set_exception_behavior_allowed` (osfmk/kern/ipc_tt.c) requires tasks
/// whose IPC space policy is enhanced, which includes every platform binary, to
/// register exception ports with `EXCEPTION_STATE` or an identity-protected
/// behavior. Anything else raises `EXC_GUARD` flavor 6
/// (`kGUARD_EXC_EXCEPTION_BEHAVIOR_ENFORCE`) and returns `KERN_DENIED` while the
/// byte `thid_should_crash` is set. Liter8's trust-cache patches make every
/// binary a platform binary, so App Store apps whose crash SDK registers
/// `EXCEPTION_DEFAULT` die at launch (measured on n104 24B5099f: IPC policy 0x407
/// for the apps, identical to SpringBoard). With the byte clear the violation is
/// ignored and the handler is registered normally.
///
/// The byte was a boot-arg tunable in xnu-12377; 27.x kernels no longer carry the
/// boot-arg string, so it is patched in the image. It lives in `__DATA_CONST`,
/// holds 1, and no instruction writes it. It is found from the policy function,
/// the only code referencing `com.apple.security.only-one-exception-port`:
///
/// - every ADRP+LDRB in that function loads the same byte;
/// - one load is followed directly by TBZ/TBNZ on the loaded register, and the
///   function's only `MOV W2,#6 ; BL` (the guard call) is on that path;
/// - `SBFX Wd,Wt,#0,#1 ; MOV Wx,#0x35 ; AND` turns the byte into the
///   `KERN_DENIED` result.
public struct KernelExceptionPortResolver: Sendable {
    public static let name = "kernel-exception-port"
    static let anchor = "com.apple.security.only-one-exception-port"

    /// MOVZ W2,#6: the guard flavor argument.
    private static let movW2Flavor6: UInt32 = 0x5280_00C2

    public init() {}

    /// Records for the composite boot plans. A kernel profile may omit this
    /// family (j171aap/23H30 does, see its profile); `resolve` itself never
    /// skips, so the standalone plan still fails on an unported kernel.
    static func compositeRecords(in image: BinaryImage) throws -> [PatchRecord] {
        if KernelResolverProfileRegistry.detect(in: image)?.omittedResolvers.contains(name) == true {
            return []
        }
        return try Self().resolve(in: image)
    }

    public func resolve(in image: BinaryImage) throws -> [PatchRecord] {
        let layout = try MachOLayout(image: image)
        let anchors = image.findAll(Data([0]) + Data(Self.anchor.utf8) + Data([0]))
        guard let anchor = anchors.only else {
            if anchors.isEmpty { throw PatchfinderError.missingAnchor(Self.anchor) }
            throw PatchfinderError.ambiguousAnchor(Self.anchor, count: anchors.count)
        }
        let refs = try layout.adrpAddReferences(toFileOffset: anchor + 1)
        guard let ref = refs.only else {
            if refs.isEmpty { throw PatchfinderError.missingAnchor("\(Self.name) \(Self.anchor) reference") }
            throw PatchfinderError.ambiguousAnchor("\(Self.name) \(Self.anchor) reference", count: refs.count)
        }
        guard let start = ARM64.functionStart(beforeOrAt: ref.adrpOffset, in: image, layout: layout) else {
            throw PatchfinderError.noCandidate("\(Self.name) policy function")
        }
        let end = ARM64.nextFunctionStart(after: start, in: image, layout: layout)

        var loads: [(offset: UInt64, target: UInt64, rt: UInt32)] = []
        var guardCalls: [UInt64] = []
        var cursor = start
        while cursor + 8 <= end {
            let word = try image.readUInt32(at: cursor)
            let next = try image.readUInt32(at: cursor + 4)
            if let load = try byteLoad(adrp: word, at: cursor, next: next, layout: layout) {
                loads.append((cursor + 4, load.target, load.rt))
            }
            if word == Self.movW2Flavor6, ARM64.branchLinkTarget(instruction: next, at: cursor + 4) != nil {
                guardCalls.append(cursor)
            }
            cursor += 4
        }

        let targets = Set(loads.map(\.target))
        guard let byte = targets.only else {
            if targets.isEmpty { throw PatchfinderError.noCandidate("\(Self.name) enforcement byte load") }
            throw PatchfinderError.ambiguousCandidate("\(Self.name) enforcement byte", offsets: targets.sorted())
        }
        guard let guardCall = guardCalls.only else {
            if guardCalls.isEmpty { throw PatchfinderError.noCandidate("\(Self.name) flavor-6 guard call") }
            throw PatchfinderError.ambiguousCandidate("\(Self.name) flavor-6 guard call", offsets: guardCalls)
        }
        guard try loads.contains(where: { try gates(load: $0, guardCall: guardCall, image: image) }) else {
            throw PatchfinderError.noCandidate("\(Self.name) byte test whose bypass derives KERN_DENIED and skips the guard call")
        }
        guard let segment = layout.segments.first(where: { $0.fileRange.contains(byte) }),
              segment.name == "__DATA_CONST", !segment.isExecutable
        else {
            throw PatchfinderError.invalidPatch(id: Self.name, reason: "enforcement byte \(byte.hex) is not in __DATA_CONST")
        }
        // Stock is 1. 0 is this patch already applied; the record still names
        // 1 as the original so GuardedPatchApplier reports it as already applied.
        let current = try image.bytes(at: byte, count: 1)
        guard current == Data([1]) || current == Data([0]) else {
            throw PatchfinderError.invalidPatch(id: Self.name, reason: "enforcement byte \(byte.hex) is \(String(format: "%02x", current.first ?? 0)), expected 01")
        }

        return [
            PatchRecord(
                id: "kernel.exception-port.behavior-enforcement",
                component: "kernelcache",
                offset: byte,
                originalBytes: Data([1]),
                replacementBytes: Data([0]),
                summary: "Ignore non-identity-protected exception-port registrations instead of killing the caller",
                evidence: [
                    "only function referencing \(Self.anchor): \(start.hex)",
                    "all \(loads.count) ADRP+LDRB loads in it read \(byte.hex) (__DATA_CONST, value 1)",
                    "a load of it is tested by TBZ/TBNZ #0: one edge reaches MOV W2,#6 ; BL at \(guardCall.hex)",
                    "the other edge skips that call and turns the loaded register into KERN_DENIED (SBFX/MOV #0x35/AND W0)",
                ]
            ),
        ]
    }

    /// ADRP Xd,page followed by LDRB Wt,[Xd,#imm] (unsigned offset, fixed
    /// 0x39400000 with imm12/Rn/Rt varying). The page is computed in virtual
    /// addresses so code and data segments may slide differently.
    private func byteLoad(
        adrp: UInt32,
        at offset: UInt64,
        next: UInt32,
        layout: MachOLayout
    ) throws -> (target: UInt64, rt: UInt32)? {
        guard adrp & 0x9F00_0000 == 0x9000_0000,
              next & 0xFFC0_0000 == 0x3940_0000,
              (next >> 5) & 0x1F == adrp & 0x1F,
              let pc = layout.virtualAddress(forFileOffset: offset)
        else { return nil }
        let address = ARM64.adrpTarget(instruction: adrp, at: pc) + UInt64((next >> 10) & 0xFFF)
        guard let target = layout.fileOffset(forVirtualAddress: address) else { return nil }
        return (target, next & 0x1F)
    }

    /// The word after the load is TBZ/TBNZ Wt,#0 on the loaded register. One
    /// edge reaches the guard call: TBZ falls through into it, TBNZ branches to
    /// it, allowing the two argument moves before `MOV W2,#6`. The other edge,
    /// taken when the byte is clear, must reach `B` without the guard call and
    /// on the way compute the result from the same register: `SBFX Wd,Wt,#0,#1`,
    /// `MOVZ Wm,#0x35`, `AND W0,Wd,Wm` (either operand order).
    private func gates(
        load: (offset: UInt64, target: UInt64, rt: UInt32),
        guardCall: UInt64,
        image: BinaryImage
    ) throws -> Bool {
        let testSite = load.offset + 4
        let test = try image.readUInt32(at: testSite)
        // TBZ is 0x36000000, TBNZ 0x37000000; b5 and b40 zero select bit 0 of W.
        guard test & 0xFEF8_0000 == 0x3600_0000, test & 0x1F == load.rt,
              let target = ARM64.testBranchTarget(instruction: test, at: testSite)
        else { return false }
        let isTBNZ = test & 0x0100_0000 != 0
        let guardEdge = isTBNZ ? target : testSite + 4
        let bypassEdge = isTBNZ ? testSite + 4 : target
        guard guardCall >= guardEdge, guardCall - guardEdge <= 8 else { return false }
        // The guard path: from the guarded edge through MOV W2,#6 and its BL.
        let guardPath = guardEdge..<(guardCall + 8)
        return try bypassDeniesFromByte(from: bypassEdge, register: load.rt, guardPath: guardPath, image: image)
    }

    /// Straight-line walk of at most eight words from `start`, ending at a `B`
    /// whose target returns.
    private func bypassDeniesFromByte(
        from start: UInt64,
        register: UInt32,
        guardPath: Range<UInt64>,
        image: BinaryImage
    ) throws -> Bool {
        var derived = false
        var cursor = start
        for _ in 0..<8 {
            guard !guardPath.contains(cursor) else { return false }
            let word = try image.readUInt32(at: cursor)
            // B (unconditional): the path leaves, and must leave the function.
            if word & 0xFC00_0000 == 0x1400_0000 {
                guard let target = ARM64.directBranchTarget(instruction: word, at: cursor) else { return false }
                return try derived && returns(from: target, avoiding: guardPath, image: image)
            }
            // SBFX Wd,Wn,#0,#1 is SBFM Wd,Wn,#0,#0: 0x13000000 | Rn<<5 | Rd.
            if !derived, word & 0xFFFF_FC00 == 0x1300_0000, (word >> 5) & 0x1F == register {
                let sbfxRd = word & 0x1F
                let mov = try image.readUInt32(at: cursor + 4)
                let and = try image.readUInt32(at: cursor + 8)
                // MOVZ Wm,#0x35 is 0x528006A0 | Rd. AND Wd,Wn,Wm (shifted
                // register, LSL #0) is 0x0A000000 | Rm<<16 | Rn<<5 | Rd.
                guard mov & 0xFFFF_FFE0 == 0x5280_06A0,
                      and & 0xFFE0_FC00 == 0x0A00_0000,
                      and & 0x1F == 0
                else { return false }
                let operands = Set([(and >> 16) & 0x1F, (and >> 5) & 0x1F])
                guard operands == Set([sbfxRd, mov & 0x1F]) else { return false }
                derived = true
                cursor += 12
                continue
            }
            // Before the SBFX, anything that could overwrite the loaded register
            // breaks the data flow. Branches that only test registers are fine.
            let isTestBranch = word & 0x7E00_0000 == 0x3400_0000 || word & 0x7E00_0000 == 0x3600_0000
            if !derived, !isTestBranch, word & 0x1F == register { return false }
            cursor += 4
        }
        return false
    }

    /// The exit target is the function epilogue: straight-line code (register
    /// restores, AUTIBSP) reaching RET/RETAA/RETAB within twelve words, with no
    /// branch and nothing inside the guard path. A self-branch or a jump into
    /// the guard's BL fails here.
    private func returns(from start: UInt64, avoiding guardPath: Range<UInt64>, image: BinaryImage) throws -> Bool {
        var cursor = start
        for _ in 0..<12 {
            guard !guardPath.contains(cursor) else { return false }
            let word = try image.readUInt32(at: cursor)
            if ARM64.isReturn(word) { return true }
            // Any other branch: B/BL (0x14/0x94), B.cond (0x54, bit 4 clear),
            // CBZ/CBNZ/TBZ/TBNZ (0x34-0x37), and register branches (0xD6).
            let isBranch = word & 0x7C00_0000 == 0x1400_0000
                || word & 0xFF00_0010 == 0x5400_0000
                || word & 0x7C00_0000 == 0x3400_0000
                || word & 0xFE00_0000 == 0xD600_0000
            if isBranch { return false }
            cursor += 4
        }
        return false
    }
}

private extension Collection {
    var only: Element? { count == 1 ? first : nil }
}
