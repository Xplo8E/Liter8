import Foundation

/// Makes `CommCenter` stop refusing a cellular data context because the device
/// has no real activation.
///
/// Two gates sit in series on the same path and both are resolved here. The
/// outer one, `canActivateWithoutOverrides`, refuses before it evaluates
/// anything; the inner one, `canActivateDataSettings`, refuses during the
/// evaluation. Fixing only the inner gate changes nothing observable for the
/// Internet connection, because the outer gate returns first and the evaluation
/// never runs.
///
/// Without this, on a device whose activation was short-circuited rather than
/// performed, the failure chain is:
///
///     kDataNotSupported{ActivationStatus failed in DataSettings }
///     kDataNotSupported{context is not assigned }
///     IMS APN: false      ims '' QS:kNotConfigured
///     dialed over CS because of no IMS reg     Call ended. VoIP: false
///
/// Activation fails first, so no data context is assigned, so IMS has no PDN,
/// so there is no VoLTE and voice falls back to a circuit-switched path the
/// network may not offer. `mobileactivationd` logs what the existing patch
/// does: "Hactivation is enabled, short circuiting activation state to
/// Activated." That satisfies lockdown and Setup, which only ask for the
/// state, but CommCenter reads an `ActivationStatus` whose default
/// construction is `fManifestResult = 2, State = 3` with both flags clear, and
/// nothing ever fills it in.
///
/// The inner gate is the second of two in `canActivateDataSettings`:
///
///     if (a1->fFatalActivationBlocker[a2] == 1) { code = 67;  ... }   // passes
///     if ((vtable[1216](a1, a2) & 1) == 0)      { code = -3;  ... }   // fails
///
/// This resolver neutralises the branch that enters the `-3` block, so the
/// function falls through to its success path whatever the Registry-resolved
/// `DataServiceInterface` answered.
///
/// The outer gate is the first thing `canActivateWithoutOverrides` does:
///
///     index = -1;
///     fetchContextIndex(&index, ...);     // 0x921f8 on 24B5099f
///     if (index == -2) {                  // patch this branch
///         status = -3; reason = "context is not assigned"; return;
///     }
///     settings = this->vtable[0x90](1);   // -> canActivateDataSettings
///     settings = this->vtable[0x90](0);   // -> canActivateDataSettings
///
/// `-2` means no PDP context index has been allocated for this connection. The
/// allocation itself works on this device: `OTAActivation` and
/// `BootstrapRoamingInternetBypass` both hold one, and both are published as
/// network agents on `pdp_ip0`. `Internet` holds none, and cannot get one while
/// activation is refused, which is the circle this breaks.
///
/// Falling through is safe rather than merely convenient. The fetched index is
/// read exactly once in the whole function, by the comparison being patched,
/// and is never used again, so nothing downstream can index anything with it.
/// The replacement is an unconditional branch to the comparison's own target
/// rather than a `NOP`: a `NOP` would leave the flags undefined, since the
/// instruction before the branch is a load, and would fall into the `-3` block
/// every time, which is the opposite of the intent.
///
/// Why a binary patch rather than a runtime hook: the obvious approach is to
/// replace the virtual in the DataSettings vtable from an injected dylib, and
/// that does not work on this platform. Measured on n104ap 24B5099f,
/// `vm_protect` on those pages returns `KERN_PROTECTION_FAILURE` both with and
/// without `VM_PROT_COPY`, because `__DATA_CONST` max protection no longer
/// carries write once dyld has applied fixups, even though the Mach-O header
/// advertises `maxprot=rw-`. The device boots SPTM and TXM, so page
/// permissions are enforced below the kernel and the process cannot grant
/// itself write. Patching the file and re-signing, the way `coreauthd`,
/// `ctkd`, `mobileactivationd` and `lockdownd` already are, sidesteps that
/// entirely and needs no marker to survive a reboot.
///
/// Locating it. The anchor is the error string, which is deliberately not the
/// patch site:
///
///     blraa x8, x16            <- the ActivationStatus virtual call
///     tbz   w0, #0, failure    <- patch this to NOP
///     ...
///     failure: mov w8, #-3     <- the -3 status
///              str w8, [x19]
///              adrp x8, "ActivationStatus failed in DataSettings"
///
/// so the string reference gives the failure block, `MOVN W8,#2` gives its
/// first instruction, and the branch is then required to target that address
/// *and* to be immediately preceded by a `BLRAA`. The `BLRAA` requirement is
/// what distinguishes this branch from the unconditional jump the
/// FatalActivationBlocker path uses to reach the shared tail of the same block.
///
/// The outer gate is anchored the same way, on its own reason string, and then
/// on the exact three-instruction shape that precedes it:
///
///     cmn   w8, #2                              <- required
///     b.ne  <evaluation>                         <- patch this
///     mov   w8, #-3                             <- required
///     adrp  x9, "context is not assigned"       <- the anchor
///
/// Requiring the `CMN` as well as the `MOVN` is what makes this unambiguous
/// without an offset: `CommCenter` holds ten of these reason strings in one
/// table and each is referenced from exactly one site, but only this one is
/// reached by a comparison against `-2`.
public struct CommCenterDataActivationResolver: Sendable {
    public static let name = "commcenter-data-activation"
    private static let anchor = "ActivationStatus failed in DataSettings"
    private static let contextAnchor = "context is not assigned"

    /// `MOVN W8, #2`, i.e. `MOV W8, #-3`: the status stored by the failure
    /// block, and therefore its first instruction.
    private static let movnW8Three: UInt32 = 0x1280_0048

    /// `CMN W8, #2`, encoded as `ADDS WZR, W8, #2`: the comparison against the
    /// unassigned-context sentinel.
    private static let cmnW8Two: UInt32 = 0x3100_091F

    /// `B.cond` opcode class, and the `NE` condition in its low nibble.
    private static let conditionalBranchMask: UInt32 = 0xFF00_0010
    private static let conditionalBranchOpcode: UInt32 = 0x5400_0000
    private static let conditionNotEqual: UInt32 = 0x1

    /// How far back from the string reference the `-3` store may sit. It is two
    /// instructions in 24B5099f; a small window tolerates a reordering without
    /// letting an unrelated constant elsewhere in the function match.
    private static let failureBlockSearchWords = 6

    public init() {}

    public func resolve(in image: BinaryImage) throws -> [PatchRecord] {
        let layout = try MachOLayout(image: image)
        return try [
            resolveContextGate(in: image, layout: layout),
            resolveActivationStatusGate(in: image, layout: layout),
        ]
    }

    /// The outer gate: stop `canActivateWithoutOverrides` returning before it
    /// has evaluated anything, just because no context index exists yet.
    private func resolveContextGate(
        in image: BinaryImage,
        layout: MachOLayout
    ) throws -> PatchRecord {
        let anchorOffset = try uniqueLiteral(Self.contextAnchor, in: image)
        let reference = try uniqueReference(
            toFileOffset: anchorOffset,
            layout: layout,
            describedAs: "\(Self.name) context message xref"
        )

        // The anchor is the reason string, so the patch site is three
        // instructions ahead of it and all three are checked.
        guard reference.adrpOffset >= 12 else {
            throw PatchfinderError.noCandidate("\(Self.name) context gate window")
        }
        let branchOffset = reference.adrpOffset - 8
        guard try image.readUInt32(at: reference.adrpOffset - 4) == Self.movnW8Three else {
            throw PatchfinderError.noCandidate("\(Self.name) context gate status store")
        }
        guard try image.readUInt32(at: reference.adrpOffset - 12) == Self.cmnW8Two else {
            throw PatchfinderError.noCandidate("\(Self.name) context gate sentinel compare")
        }

        let branch = try image.readUInt32(at: branchOffset)
        guard branch & Self.conditionalBranchMask == Self.conditionalBranchOpcode,
              branch & 0xF == Self.conditionNotEqual
        else {
            throw PatchfinderError.noCandidate("\(Self.name) context gate branch")
        }

        guard let branchAddress = layout.virtualAddress(forFileOffset: branchOffset),
              let target = ARM64.conditionalTarget(instruction: branch, at: branchAddress),
              let replacement = ARM64.encodeDirectBranch(
                  link: false,
                  instructionOffset: branchAddress,
                  target: target
              )
        else {
            throw PatchfinderError.noCandidate("\(Self.name) context gate retarget")
        }

        return PatchRecord(
            id: "commcenter.data-connection.context-index",
            component: "CommCenter",
            offset: branchOffset,
            original: branch,
            replacement: replacement,
            summary: "Stop canActivateWithoutOverrides refusing before it evaluates, for want of a context index",
            evidence: [
                "unique \"\(Self.contextAnchor)\" literal at \(anchorOffset.hex)",
                "unique ADRP+ADD reference at \(reference.adrpOffset.hex)",
                "preceded by CMN W8,#2 and MOVN W8,#2",
                "B.NE retargeted to its own destination \(target.hex) unconditionally",
            ]
        )
    }

    /// The inner gate: stop `canActivateDataSettings` refusing because the
    /// device's `ActivationStatus` was never filled in.
    private func resolveActivationStatusGate(
        in image: BinaryImage,
        layout: MachOLayout
    ) throws -> PatchRecord {
        let anchorOffset = try uniqueLiteral(Self.anchor, in: image)
        let reference = try uniqueReference(
            toFileOffset: anchorOffset,
            layout: layout,
            describedAs: "\(Self.name) message xref"
        )

        // Walk back from the string reference to the instruction that stores
        // the -3 status. That is the address the branch under test must target.
        var failureOffset: UInt64?
        var step = 1
        while step <= Self.failureBlockSearchWords {
            let candidate = reference.adrpOffset - UInt64(step * 4)
            guard candidate + 4 <= reference.adrpOffset else { break }
            if try image.readUInt32(at: candidate) == Self.movnW8Three {
                failureOffset = candidate
                break
            }
            step += 1
        }
        guard let failureOffset else {
            throw PatchfinderError.noCandidate("\(Self.name) failure block entry")
        }
        guard let failureAddress = layout.virtualAddress(forFileOffset: failureOffset) else {
            throw PatchfinderError.noCandidate("\(Self.name) failure block address")
        }

        var candidates: [UInt64] = []
        for range in layout.executableFileRanges {
            var offset = (range.lowerBound + 3) & ~UInt64(3)
            while offset + 4 <= range.upperBound {
                defer { offset += 4 }
                let branch = try image.readUInt32(at: offset)

                // TBZ W0, #0, <target>: 32-bit form, bit 0, Rt = W0.
                guard branch & 0xFFF8_001F == 0x3600_0000, offset >= 4 else { continue }
                guard let address = layout.virtualAddress(forFileOffset: offset),
                      ARM64.testBranchTarget(instruction: branch, at: address) == failureAddress
                else { continue }

                // The gate is the branch on the virtual call's result, so the
                // preceding instruction must be an authenticated indirect call.
                let previous = try image.readUInt32(at: offset - 4)
                guard previous & 0xFFFF_FC00 == 0xD73F_0800 else { continue }

                candidates.append(offset)
            }
        }

        guard let patchOffset = candidates.only else {
            if candidates.isEmpty { throw PatchfinderError.noCandidate(Self.name) }
            throw PatchfinderError.ambiguousCandidate(Self.name, offsets: candidates)
        }

        return PatchRecord(
            id: "commcenter.data-settings.activation-status",
            component: "CommCenter",
            offset: patchOffset,
            original: try image.readUInt32(at: patchOffset),
            replacement: ARM64.nop,
            summary: "Stop canActivateDataSettings refusing a data context for activation status",
            evidence: [
                "unique \"\(Self.anchor)\" literal at \(anchorOffset.hex)",
                "unique ADRP+ADD reference at \(reference.adrpOffset.hex)",
                "MOVN W8,#2 failure-block entry at \(failureOffset.hex)",
                "single TBZ W0,#0 to that block preceded by BLRAA",
            ]
        )
    }

    private func uniqueLiteral(_ literal: String, in image: BinaryImage) throws -> UInt64 {
        let anchors = image.findAll(utf8: literal, nulTerminated: true)
        guard let anchorOffset = anchors.only else {
            if anchors.isEmpty { throw PatchfinderError.missingAnchor(literal) }
            throw PatchfinderError.ambiguousAnchor(literal, count: anchors.count)
        }
        return anchorOffset
    }

    private func uniqueReference(
        toFileOffset offset: UInt64,
        layout: MachOLayout,
        describedAs description: String
    ) throws -> ADRPAddReference {
        let references = try layout.adrpAddReferences(toFileOffset: offset)
        guard let reference = references.only else {
            if references.isEmpty { throw PatchfinderError.noCandidate(description) }
            throw PatchfinderError.ambiguousCandidate(
                description,
                offsets: references.map(\.adrpOffset)
            )
        }
        return reference
    }
}

private extension Collection {
    var only: Element? { count == 1 ? first : nil }
}
