import Foundation

public enum PatchDisposition: String, Codable, Sendable {
    case applied
    case alreadyApplied
}

public struct PatchApplicationResult: Sendable {
    public let data: Data
    public let dispositions: [String: PatchDisposition]
}

public enum GuardedPatchApplier {
    /// Apply a resolved plan to an in-memory copy.
    ///
    /// There are only three acceptable states for each range:
    ///
    /// - original bytes: apply the replacement;
    /// - replacement bytes: record that it was already applied;
    /// - anything else: abort the whole plan.
    ///
    /// The second pass performs writes only after every range passes, so patch
    /// number ten cannot leave patches one through nine partially installed.
    public static func apply(
        _ records: [PatchRecord],
        to image: BinaryImage
    ) throws -> PatchApplicationResult {
        let sorted = records.sorted { $0.offset < $1.offset }

        // Preflight the complete plan before changing a byte. A failure in the
        // final record must leave callers with no partially patched artifact.
        for record in sorted {
            guard !record.originalBytes.isEmpty else {
                throw PatchfinderError.invalidPatch(id: record.id, reason: "empty byte range")
            }
            guard record.originalBytes.count == record.replacementBytes.count else {
                throw PatchfinderError.invalidPatch(
                    id: record.id,
                    reason: "original and replacement lengths differ"
                )
            }
        }

        for pair in zip(sorted, sorted.dropFirst()) {
            guard pair.0.offset + UInt64(pair.0.replacementBytes.count) <= pair.1.offset else {
                throw PatchfinderError.overlappingPatches(offset: pair.1.offset)
            }
        }

        var dispositions: [String: PatchDisposition] = [:]
        for record in sorted {
            let found = try image.bytes(at: record.offset, count: record.originalBytes.count)
            if found == record.originalBytes {
                dispositions[record.id] = .applied
            } else if found == record.replacementBytes {
                dispositions[record.id] = .alreadyApplied
            } else {
                throw PatchfinderError.preimageMismatch(
                    id: record.id,
                    offset: record.offset,
                    expected: record.originalBytes,
                    found: found
                )
            }
        }

        var output = image.data
        for record in sorted where dispositions[record.id] == .applied {
            output.replaceSubrange(
                Int(record.offset)..<(Int(record.offset) + record.replacementBytes.count),
                with: record.replacementBytes
            )
        }
        return PatchApplicationResult(data: output, dispositions: dispositions)
    }
}
