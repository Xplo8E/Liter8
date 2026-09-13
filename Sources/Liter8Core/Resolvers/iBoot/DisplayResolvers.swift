import Foundation

/// Stops iBSS from calling the top-level display wrapper so iBEC becomes the
/// first stage that performs panel initialization.
///
/// Apply this to iBSS only. The payload bytes happen to be identical to iBEC on
/// 24A5390f, so no static resolver can infer which boot stage the caller intends
/// to send. Keeping the operation under an explicit iBSS-only resolver name is
/// therefore part of the safety boundary.
public struct IBSSSkipDisplayInitResolver: Sendable {
    public static let name = "ibss-skip-display-init"

    public init() {}

    public func resolve(in image: BinaryImage) throws -> [PatchRecord] {
        var candidates: [UInt64] = []
        var offset: UInt64 = 0
        while offset + 24 <= UInt64(image.count) {
            let powerCall = try image.readUInt32(at: offset)
            let displayCall = try image.readUInt32(at: offset + 4)
            let resultBranch = try image.readUInt32(at: offset + 8)
            let markFailed = try image.readUInt32(at: offset + 12)
            let storeFailed = try image.readUInt32(at: offset + 16)
            let returnSuccess = try image.readUInt32(at: offset + 20)

            // Full local behavior:
            //   BL power_gate; BL display_init; CBZ W0,<success>;
            //   MOV W8,#1; STRB W8,[X20,#state]; MOV W0,#0
            // Replacing only the second call with MOV W0,#1 deliberately enters
            // the routine's existing handled-failure path.
            if powerCall >> 26 == 0b100101,
               displayCall >> 26 == 0b100101,
               resultBranch & 0xFF00_001F == 0x3400_0000, // CBZ W0,<target>
               markFailed == 0x5280_0028, // MOV W8,#1
               storeFailed & 0xFFC0_03FF == 0x3900_0288, // STRB W8,[X20,#imm]
               returnSuccess == ARM64.movW0Zero {
                candidates.append(offset + 4)
            }
            offset += 4
        }
        guard let callOffset = candidates.only else {
            if candidates.isEmpty { throw PatchfinderError.noCandidate(Self.name) }
            throw PatchfinderError.ambiguousCandidate(Self.name, offsets: candidates)
        }
        return [PatchRecord(
            id: "ibss.display.skip-initialization",
            component: "iBSS",
            offset: callOffset,
            original: try image.readUInt32(at: callOffset),
            replacement: ARM64.movW0One,
            summary: "Skip iBSS display initialization and take its handled-failure path",
            evidence: [
                "BL power / BL display / CBZ result sequence",
                "failure path writes one to an X20 state byte then returns zero",
                "explicit iBSS-only operation because iBSS and iBEC payloads are identical",
            ]
        )]
    }
}

/// Diagnostic only: if Pinot's panel-ID read leaves zero, report success by
/// branching to the routine's existing success return instead of its failure
/// teardown. It does not attempt panel programming with an invalid zero ID.
public struct IBECPinotIgnoreFailureResolver: Sendable {
    public static let name = "ibec-diag-ignore-pinot-id-failure"

    public init() {}

    public func resolve(in image: BinaryImage) throws -> [PatchRecord] {
        var candidates: [(branch: UInt64, success: UInt64)] = []
        var loadOffset: UInt64 = 0
        while loadOffset + 8 <= UInt64(image.count) {
            let load = try image.readUInt32(at: loadOffset)
            let branchOffset = loadOffset + 4
            let branch = try image.readUInt32(at: branchOffset)
            guard load & 0xFFC0_03FF == 0xB940_0328, // LDR W8,[X25,#imm]
                  branch & 0xFF00_001F == 0x3400_0008, // CBZ W8,<failure>
                  let failure = ARM64.conditionalTarget(
                    instruction: branch,
                    at: branchOffset
                  ),
                  failure >= 8,
                  failure + 8 <= UInt64(image.count),
                  try image.readUInt32(at: failure - 8) == ARM64.movW0Zero,
                  try image.readUInt32(at: failure - 4) >> 26 == 0b000101,
                  try image.readUInt32(at: failure) >> 26 == 0b100101,
                  try image.readUInt32(at: failure + 4) == 0x1280_0000 // MOV W0,#-1
            else {
                loadOffset += 4
                continue
            }
            candidates.append((branchOffset, failure - 8))
            loadOffset += 4
        }
        guard let candidate = candidates.only,
              let original = try? image.readUInt32(at: candidate.branch),
              let replacement = ARM64.encodeCompareBranch(
                like: original,
                at: candidate.branch,
                target: candidate.success
              )
        else {
            if candidates.isEmpty { throw PatchfinderError.noCandidate(Self.name) }
            throw PatchfinderError.ambiguousCandidate(
                Self.name,
                offsets: candidates.map(\.branch)
            )
        }
        return [PatchRecord(
            id: "ibec.pinot.zero-panel-id.return-success",
            component: "iBEC diagnostic",
            offset: candidate.branch,
            original: original,
            replacement: replacement,
            summary: "Redirect zero panel-ID failure to Pinot's existing success return",
            evidence: [
                "LDR W8,[X25,#panel_id] / CBZ W8 failure",
                "failure target calls teardown then returns -1",
                "replacement target sets W0 to zero and enters the shared epilogue",
            ]
        )]
    }
}

/// Diagnostic only: replace the panel-ID environment lookup with a caller-
/// supplied 32-bit ID. No default is provided because inventing a panel ID can
/// select the wrong hardware programming path.
public struct IBECPinotForceIDResolver: Sendable {
    public static let name = "ibec-diag-force-pinot-id"
    public let panelID: UInt32

    public init(panelID: UInt32) {
        self.panelID = panelID
    }

    public func resolve(in image: BinaryImage) throws -> [PatchRecord] {
        var candidates: [UInt64] = []
        var offset: UInt64 = 0
        while offset + 16 <= UInt64(image.count) {
            let defaultValue = try image.readUInt32(at: offset)
            let lookup = try image.readUInt32(at: offset + 4)
            let store = try image.readUInt32(at: offset + 8)
            let skipRead = try image.readUInt32(at: offset + 12)
            if defaultValue == 0xD280_0004, // MOV X4,#0
               lookup >> 26 == 0b100101,
               store & 0xFFC0_03FF == 0xB900_0320, // STR W0,[X25,#imm]
               skipRead & 0xFF00_001F == 0x3500_0000 { // CBNZ W0
                candidates.append(offset)
            }
            offset += 4
        }
        guard let patchOffset = candidates.only,
              let low = ARM64.encodeMOVZ32(
                destination: 0,
                immediate: UInt16(panelID & 0xFFFF)
              ),
              let high = ARM64.encodeMOVK32Shift16(
                destination: 0,
                immediate: UInt16(panelID >> 16)
              )
        else {
            if candidates.isEmpty { throw PatchfinderError.noCandidate(Self.name) }
            throw PatchfinderError.ambiguousCandidate(Self.name, offsets: candidates)
        }
        let evidence = [
            "MOV X4,#0 / BL env_get_uint / STR W0,[X25,#panel_id] / CBNZ W0",
            "MOVZ+MOVK preserves all 32 caller-supplied panel-ID bits",
            "non-zero result follows the existing branch that skips the MIPI read",
        ]
        return [
            PatchRecord(
                id: "ibec.pinot.force-panel-id.low",
                component: "iBEC diagnostic",
                offset: patchOffset,
                original: try image.readUInt32(at: patchOffset),
                replacement: low,
                summary: "Load the low 16 bits of the supplied panel ID",
                evidence: evidence
            ),
            PatchRecord(
                id: "ibec.pinot.force-panel-id.high",
                component: "iBEC diagnostic",
                offset: patchOffset + 4,
                original: try image.readUInt32(at: patchOffset + 4),
                replacement: high,
                summary: "Load the high 16 bits and skip the panel-ID environment lookup",
                evidence: evidence
            ),
        ]
    }
}

private extension Collection {
    var only: Element? { count == 1 ? first : nil }
}
