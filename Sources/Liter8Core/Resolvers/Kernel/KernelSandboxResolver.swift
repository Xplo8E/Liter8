import Foundation

/// Resolves the scoped Seatbelt patch used by the normal-boot kernel plan.
///
/// Unlike the other kernel families, the primary anchors here are data
/// structures rather than function bodies:
///
///     "Sandbox" + "Seatbelt sandbox policy"
///         -> mac_policy_conf
///         -> mpc_ops
///         -> authenticated MACF hook pointers
///
/// The resolver follows those pointers to the native functions, discovers two
/// helper routines by instruction semantics, selects verified executable
/// padding, and assembles the three PC-relative branches for that exact cave.
public struct KernelSandboxResolver: Sendable {
    public static let name = "kernel-sandbox"
    /// The public beta-4 workflow originally shipped only the 11 established
    /// MACF table/function patches. The scoped vnode-open shim was developed
    /// later and adds 35 records. Keeping this choice explicit prevents the
    /// workflow migration from silently widening the published plan.
    private let includeScopedVnodeOpen: Bool

    public init(includeScopedVnodeOpen: Bool = true) {
        self.includeScopedVnodeOpen = includeScopedVnodeOpen
    }

    public func resolve(in image: BinaryImage) throws -> [PatchRecord] {
        let operations = try sandboxOperationsTable(in: image)

        let fileCheckMmap = try operationTarget(index: 36, table: operations, image: image)
        let mountCheckMount = try operationTarget(index: 87, table: operations, image: image)
        let mountCheckRemount = try operationTarget(index: 88, table: operations, image: image)
        let mountCheckUnmount = try operationTarget(index: 91, table: operations, image: image)
        let vnodeCheckRename = try operationTarget(index: 120, table: operations, image: image)
        let vnodeCheckExecSlot = operations + UInt64(258 * 8)
        var patches: [PatchRecord] = []

        if includeScopedVnodeOpen {
            let layout = try MachOLayout(image: image)
            let vnodeCheckOpenSlot = operations + UInt64(267 * 8)
            let vnodeCheckOpen = UInt64(try image.readUInt32(at: vnodeCheckOpenSlot))
            let currentThreadRO = try Self.currentThreadRO.uniqueMatch(in: image, layout: layout)
            let procBestName = try resolveProcBestName(in: image, layout: layout)
            let cave = try resolveExecutableCave(in: image, layout: layout)
            let shim = try buildOpenShim(
                at: cave,
                currentThreadRO: currentThreadRO,
                procBestName: procBestName,
                vnodeCheckOpen: vnodeCheckOpen
            )

            patches.append(try sandboxPatch(
                id: "kernel.sandbox.vnode-check-open.target",
                offset: vnodeCheckOpenSlot,
                replacement: UInt32(cave),
                summary: "Retarget vnode_check_open to the scoped process-name shim",
                evidence: ["mac_policy_conf -> mpc_ops[267]", "low chained-pointer target only"],
                image: image
            ))
            // This no-op record is intentional. It makes the fixture assert
            // that the authenticated-pointer discriminator belongs to slot
            // 267 while leaving those metadata bits byte-for-byte unchanged.
            patches.append(try sandboxPatch(
                id: "kernel.sandbox.vnode-check-open.metadata",
                offset: vnodeCheckOpenSlot + 4,
                replacement: try image.readUInt32(at: vnodeCheckOpenSlot + 4),
                summary: "Assert and preserve vnode_check_open PAC metadata",
                evidence: ["high chained-pointer word from mpc_ops[267]"],
                image: image
            ))

            for (index, item) in shim.enumerated() {
                patches.append(try sandboxPatch(
                    id: "kernel.sandbox.vnode-check-open.shim.\(index)",
                    offset: cave + UInt64(index * 4),
                    replacement: item.word,
                    summary: "Scoped vnode_check_open shim: \(item.summary)",
                    evidence: ["unique executable cave after reviewed function tail"],
                    image: image
                ))
            }
        }

        // vnode_check_exec is redirected to ops[36], which is converted to an
        // allow stub below. Only the low target word changes; its own PAC
        // metadata remains in the untouched high word.
        patches.append(try sandboxPatch(
            id: "kernel.sandbox.vnode-check-exec.target",
            offset: vnodeCheckExecSlot,
            replacement: UInt32(fileCheckMmap),
            summary: "Retarget vnode_check_exec to the existing allow stub",
            evidence: ["mac_policy_conf -> mpc_ops[258]", "mpc_ops[36] target"],
            image: image
        ))

        let stubs: [(id: String, name: String, offset: UInt64)] = [
            ("file-check-mmap", "file_check_mmap", fileCheckMmap),
            ("mount-check-mount", "mount_check_mount", mountCheckMount),
            ("mount-check-remount", "mount_check_remount", mountCheckRemount),
            ("mount-check-unmount", "mount_check_umount", mountCheckUnmount),
            ("vnode-check-rename", "vnode_check_rename", vnodeCheckRename),
        ]
        for stub in stubs {
            // An mpc_ops slot stores the address a call lands on. On a BTI
            // build that is the landing pad, so the stub starts one word later
            // and the pad survives: every one of these is reached only through
            // this table, i.e. always by indirect branch.
            let start = ARM64.stubStart(atEntry: stub.offset, in: image)
            guard try image.readUInt32(at: start) == ARM64.pacibsp else {
                throw PatchfinderError.noCandidate("\(stub.name) PACIBSP entry")
            }
            patches.append(try sandboxPatch(
                id: "kernel.sandbox.\(stub.id).result",
                offset: start,
                replacement: ARM64.movX0Zero,
                summary: "Return success from \(stub.name)",
                evidence: ["native target read from its mpc_ops slot"],
                image: image
            ))
            patches.append(try sandboxPatch(
                id: "kernel.sandbox.\(stub.id).return",
                offset: start + 4,
                replacement: ARM64.ret,
                summary: "Return the forced Seatbelt result",
                evidence: ["paired entry-point stub"],
                image: image
            ))
        }

        return patches
    }

    /// Find the one `mac_policy_conf` whose first two authenticated pointers
    /// name Apple's Sandbox policy, then follow its `mpc_ops` field at +0x20.
    private func sandboxOperationsTable(in image: BinaryImage) throws -> UInt64 {
        let sandboxStrings = image.findAll(utf8: "Sandbox", nulTerminated: true)
        let descriptionStrings = image.findAll(
            utf8: "Seatbelt sandbox policy",
            nulTerminated: true
        )
        guard !sandboxStrings.isEmpty else { throw PatchfinderError.missingAnchor("Sandbox") }
        guard !descriptionStrings.isEmpty else {
            throw PatchfinderError.missingAnchor("Seatbelt sandbox policy")
        }
        let sandboxTargets = Set(sandboxStrings.map { UInt32($0) })
        let descriptionTargets = Set(descriptionStrings.map { UInt32($0) })
        var candidates: [UInt64] = []

        var offset: UInt64 = 0
        while offset + 40 <= UInt64(image.count) {
            let namePointer = try image.readUInt64(at: offset)
            let descriptionPointer = try image.readUInt64(at: offset + 8)
            if sandboxTargets.contains(UInt32(truncatingIfNeeded: namePointer)),
               descriptionTargets.contains(UInt32(truncatingIfNeeded: descriptionPointer))
            {
                candidates.append(offset)
            }
            offset += 8
        }
        guard let policy = candidates.only else {
            if candidates.isEmpty { throw PatchfinderError.noCandidate("Sandbox mac_policy_conf") }
            throw PatchfinderError.ambiguousCandidate("Sandbox mac_policy_conf", offsets: candidates)
        }

        let operations = UInt64(try image.readUInt32(at: policy + 0x20))
        guard operations.isMultiple(of: 8), operations + UInt64(268 * 8) <= UInt64(image.count) else {
            throw PatchfinderError.invalidFixture("Sandbox mpc_ops pointer is outside the image")
        }
        return operations
    }

    private func operationTarget(index: Int, table: UInt64, image: BinaryImage) throws -> UInt64 {
        let slot = table + UInt64(index * 8)
        let target = UInt64(try image.readUInt32(at: slot))
        guard target + 8 <= UInt64(image.count) else {
            throw PatchfinderError.invalidFixture("mpc_ops[\(index)] target is outside the image")
        }
        return target
    }

    /// Resolve the six-instruction `proc_best_name` leaf by data flow. Register
    /// allocation and structure offsets may move, but p_name must immediately
    /// follow the 17-byte p_comm field and the CSEL must implement the empty-
    /// name fallback into x0.
    private func resolveProcBestName(in image: BinaryImage, layout: MachOLayout) throws -> UInt64 {
        var hits: [UInt64] = []
        for range in layout.executableFileRanges where range.upperBound - range.lowerBound >= 24 {
            var offset = (range.lowerBound + 3) & ~UInt64(3)
            while offset + 24 <= range.upperBound {
                let words = try (0..<6).map { try image.readUInt32(at: offset + UInt64($0 * 4)) }
                if isProcBestName(words) { hits.append(offset) }
                offset += 4
            }
        }
        guard let hit = hits.only else {
            if hits.isEmpty { throw PatchfinderError.noCandidate("proc_best_name data flow") }
            throw PatchfinderError.ambiguousCandidate("proc_best_name data flow", offsets: hits)
        }
        return hit
    }

    private func isProcBestName(_ words: [UInt32]) -> Bool {
        guard let firstAdd = decodeAdd(words[0]),
              let byteLoad = decodeByteLoad(words[1]),
              let secondAdd = decodeAdd(words[2]),
              let compared = decodeCompareZero(words[3]),
              let select = decodeSelect(words[4]),
              words[5] == ARM64.ret
        else { return false }

        return firstAdd.base == byteLoad.base
            && firstAdd.base == secondAdd.base
            && byteLoad.immediate == firstAdd.immediate
            && firstAdd.immediate == secondAdd.immediate + 0x11
            && compared == byteLoad.destination
            && select.destination == 0
            && select.trueRegister == secondAdd.destination
            && select.falseRegister == firstAdd.destination
            && select.condition == 0 // EQ: empty p_name chooses p_comm
    }

    private func decodeAdd(_ word: UInt32) -> (destination: UInt32, base: UInt32, immediate: UInt32)? {
        // Match ADD Xd,Xn,#imm12 while allowing registers and immediate to vary.
        guard word & 0xFFC0_0000 == 0x9100_0000 else { return nil }
        return (word & 0x1F, (word >> 5) & 0x1F, (word >> 10) & 0xFFF)
    }

    private func decodeByteLoad(_ word: UInt32) -> (destination: UInt32, base: UInt32, immediate: UInt32)? {
        // Match LDRB Wt,[Xn,#imm12] while allowing its operands to vary.
        guard word & 0xFFC0_0000 == 0x3940_0000 else { return nil }
        return (word & 0x1F, (word >> 5) & 0x1F, (word >> 10) & 0xFFF)
    }

    private func decodeCompareZero(_ word: UInt32) -> UInt32? {
        // Match CMP Wn,#0 (the SUBS-immediate alias) and return Wn.
        guard word & 0xFFFF_FC1F == 0x7100_001F else { return nil }
        return (word >> 5) & 0x1F
    }

    private func decodeSelect(
        _ word: UInt32
    ) -> (destination: UInt32, trueRegister: UInt32, falseRegister: UInt32, condition: UInt32)? {
        // Match CSEL Xd,Xn,Xm,cond while allowing registers and condition.
        guard word & 0xFFE0_0C00 == 0x9A80_0000 else { return nil }
        return (word & 0x1F, (word >> 5) & 0x1F, (word >> 16) & 0x1F, (word >> 12) & 0xF)
    }

    /// Select zero-filled executable padding immediately following a unique
    /// completed-function tail. Static ownership work established this tail as
    /// the boundary before unclaimed file-backed __text space; the runtime
    /// checks below additionally reject any direct branch or chained pointer
    /// into the 132 bytes we will occupy.
    private func resolveExecutableCave(in image: BinaryImage, layout: MachOLayout) throws -> UInt64 {
        let tail = try Self.cavePredecessor.uniqueMatch(in: image, layout: layout)
        let cave = tail + UInt64(Self.cavePredecessor.values.count * 4)
        let caveRange = cave..<(cave + UInt64(Self.shimTemplate.count * 4))
        guard layout.executableFileRanges.contains(where: {
            $0.lowerBound <= caveRange.lowerBound && $0.upperBound >= caveRange.upperBound
        }) else {
            throw PatchfinderError.noCandidate("file-backed executable Sandbox cave")
        }
        guard try image.bytes(at: cave, count: Self.shimTemplate.count * 4).allSatisfy({ $0 == 0 }) else {
            throw PatchfinderError.noCandidate("zero-filled Sandbox cave")
        }

        for range in layout.executableFileRanges {
            var offset = (range.lowerBound + 3) & ~UInt64(3)
            while offset + 4 <= range.upperBound {
                let word = try image.readUInt32(at: offset)
                if let target = ARM64.directBranchTarget(instruction: word, at: offset),
                   caveRange.contains(target)
                {
                    throw PatchfinderError.invalidFixture(
                        "direct branch at \(offset.hex) targets the proposed Sandbox cave"
                    )
                }
                offset += 4
            }
        }

        var pointerOffset: UInt64 = 0
        while pointerOffset + 8 <= UInt64(image.count) {
            let pointer = try image.readUInt64(at: pointerOffset)
            let target = UInt64(UInt32(truncatingIfNeeded: pointer))
            if pointer >> 32 != 0, caveRange.contains(target) {
                throw PatchfinderError.invalidFixture(
                    "chained pointer at \(pointerOffset.hex) targets the proposed Sandbox cave"
                )
            }
            pointerOffset += 8
        }
        return cave
    }

    private func buildOpenShim(
        at cave: UInt64,
        currentThreadRO: UInt64,
        procBestName: UInt64,
        vnodeCheckOpen: UInt64
    ) throws -> [(word: UInt32, summary: String)] {
        var shim = Self.shimTemplate
        let branches: [(index: Int, target: UInt64, link: Bool)] = [
            (5, currentThreadRO, true),
            (8, procBestName, true),
            (32, vnodeCheckOpen, false),
        ]
        for branch in branches {
            let instructionOffset = cave + UInt64(branch.index * 4)
            guard let encoded = ARM64.encodeDirectBranch(
                link: branch.link,
                instructionOffset: instructionOffset,
                target: branch.target
            ) else {
                throw PatchfinderError.noCandidate(
                    "Sandbox shim branch from \(instructionOffset.hex) to \(branch.target.hex)"
                )
            }
            shim[branch.index].word = encoded
        }
        return shim
    }
}

// MARK: - Stable instruction shapes and position-independent shim body

private extension KernelSandboxResolver {
    // PACIBSP; save FP/LR; establish FP; MRS X0,TPIDR_EL1;
    // LDR X1,[X0,#0x408]; ADRP X8,<page>; ADD X8,X8,#0x1f0;
    // LDP X9,X8,[X8]. The ADRP page is intentionally allowed to drift.
    static let currentThreadRO = MaskedInstructionPattern(
        name: "current_thread_ro",
        referenceWords: [
            0xD503_237F, 0xA9BF_7BFD, 0x9100_03FD, 0xD538_D080,
            0xF942_0401, 0xB0FE_C908, 0x9107_C108, 0xA940_2109,
        ],
        allowDataLayoutDrift: true
    )

    // LDR X15,[SP,#8]; STR X15,[X12,X13,LSL#3]; B <target>;
    // ADD SP,SP,#0x10; RET. The branch destination is masked out.
    static let cavePredecessor = MaskedInstructionPattern(
        name: "completed function immediately before Sandbox executable cave",
        values: [0xF940_07EF, 0xF82D_798F, 0x1400_0000, 0x9100_43FF, 0xD65F_03C0],
        masks:  [0xFFFF_FFFF, 0xFFFF_FFFF, 0xFC00_0000, 0xFFFF_FFFF, 0xFFFF_FFFF]
    )

    /// Every nonzero word below is an ARM64 instruction; its summary starts
    /// with the human-readable mnemonic. The three zero-valued external branch
    /// placeholders are rewritten by `buildOpenShim`. Internal branches remain
    /// valid because their source and destination move with the whole shim.
    static let shimTemplate: [(word: UInt32, summary: String)] = [
        (0xD503237F, "PACIBSP - sign LR with the B key and SP"),
        (0xA9BD7BFD, "STP FP,LR,[SP,#-0x30]! - save frame and signed LR"),
        (0x910003FD, "MOV FP,SP - establish the frame pointer"),
        (0xA90107E0, "STP X0,X1,[SP,#0x10] - save vnode hook arguments"),
        (0xA9020FE2, "STP X2,X3,[SP,#0x20] - save vnode hook arguments"),
        (0, "BL current_thread_ro - encoded after resolving the target"),
        (0xF9400C00, "LDR X0,[X0,#0x18] - load thread_ro->tro_proc"),
        (0xB4000240, "CBZ X0,native - null proc takes the native policy path"),
        (0, "BL proc_best_name - encoded after resolving the target"),
        (0xF9400008, "LDR X8,[X0] - load the first eight process-name bytes"),
        (0xD28CAA49, "MOV X9,#0x6552 - materialize Resolver bytes 0..1"),
        (0xF2ADEE69, "MOVK X9,#0x6f73,LSL#16 - Resolver bytes 2..3"),
        (0xF2CECD89, "MOVK X9,#0x766c,LSL#32 - Resolver bytes 4..5"),
        (0xF2EE4CA9, "MOVK X9,#0x7265,LSL#48 - Resolver bytes 6..7"),
        (0xEB09011F, "CMP X8,X9 - compare the Resolver prefix"),
        (0x54000140, "B.EQ native - Resolver takes the native policy path"),
        (0xD28D2CC9, "MOV X9,#0x6966 - materialize fileprov bytes 0..1"),
        (0xF2ACAD89, "MOVK X9,#0x656c,LSL#16 - fileprov bytes 2..3"),
        (0xF2CE4E09, "MOVK X9,#0x7270,LSL#32 - fileprov bytes 4..5"),
        (0xF2EECDE9, "MOVK X9,#0x766f,LSL#48 - fileprov bytes 6..7"),
        (0xEB09011F, "CMP X8,X9 - compare the fileprov prefix"),
        (0x54000080, "B.EQ native - fileprov takes the native policy path"),
        (0x52800000, "MOV W0,#0 - return success for other processes"),
        (0xA8C37BFD, "LDP FP,LR,[SP],#0x30 - restore the allow-path frame"),
        (0xD65F0FFF, "RETAB - authenticated allow-path return"),
        (0xA94107E0, "LDP X0,X1,[SP,#0x10] - restore native arguments"),
        (0xA9420FE2, "LDP X2,X3,[SP,#0x20] - restore native arguments"),
        (0xA8C37BFD, "LDP FP,LR,[SP],#0x30 - restore native-path frame"),
        (0xD50323FF, "AUTIBSP - authenticate LR before the original PACIBSP"),
        (0xCA1E07D0, "EOR X16,X30,X30,LSL#1 - prepare the LR integrity test"),
        (0xB6F00050, "TBZ X16,#62,native - valid LR proceeds to the tail call"),
        (0xD4388E20, "BRK #0xc471 - trap if LR authentication failed"),
        (0, "B vnode_check_open - encoded after resolving the target"),
    ]
}

private func sandboxPatch(
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

private extension Collection {
    var only: Element? { count == 1 ? first : nil }
}
