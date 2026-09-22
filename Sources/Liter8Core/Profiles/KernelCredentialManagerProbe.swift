import Foundation

/// Reports how a recorded AppleCredentialManager signature family fares against
/// an arbitrary kernelcache.
///
/// Porting this resolver to a new build is the single most expensive step in
/// supporting that build: twenty-six method bodies have to be located before
/// anything can be patched. Without a report the only signal available is the
/// resolver's own failure, which says one function did not match uniquely and
/// nothing about the other twenty-five.
///
/// Knowing *which* functions survived, and how many leading instructions of the
/// ones that did not still agree, is what turns the port from a rewrite into a
/// diff. On builds that only drifted slightly, most entries match outright and
/// the remainder need a handful of words re-recorded.
public enum KernelCredentialManagerProbe: Sendable {
    /// How one recorded function fared.
    public struct FunctionReport: Sendable {
        public let name: String
        /// Words in the recorded signature.
        public let recordedWords: Int
        /// Longest leading run of the signature that still matches somewhere,
        /// and where. Equal to `recordedWords` when the whole shape survived.
        public let matchedWords: Int
        /// Offsets matched by that longest surviving prefix.
        public let offsets: [UInt64]

        /// Usable as-is: the complete recorded shape occurs exactly once.
        public var isExact: Bool { matchedWords == recordedWords && offsets.count == 1 }
    }

    /// Prefix lengths tried when the full signature fails, longest first.
    ///
    /// A shorter prefix is weaker evidence, so the point is not to accept one
    /// as a locator. It is to distinguish "this function was rewritten" from
    /// "this function is intact and one later instruction moved", which need
    /// very different amounts of work.
    private static let prefixFractions = [1.0, 0.75, 0.5, 0.375, 0.25]

    /// Probe every function in `variant` against `image`.
    ///
    /// Ordering follows the recorded family so the output can be read straight
    /// down against the existing Swift table.
    public static func probe(
        image: BinaryImage,
        variant id: String
    ) throws -> [FunctionReport] {
        guard let variant = KernelCredentialManagerSignatures.variant(named: id) else {
            throw PatchfinderError.invalidFixture("unknown ACM signature variant: \(id)")
        }
        let layout = try MachOLayout(image: image)

        return try variant.functions.map { descriptor in
            let pattern = descriptor.pattern
            let total = pattern.values.count

            for fraction in prefixFractions {
                let count = max(4, Int((Double(total) * fraction).rounded(.down)))
                guard count <= total else { continue }
                let prefix = MaskedInstructionPattern(
                    name: pattern.name,
                    values: Array(pattern.values.prefix(count)),
                    masks: Array(pattern.masks.prefix(count))
                )
                let hits = try allMatches(of: prefix, in: image, layout: layout)
                // Keep searching with a shorter prefix only while nothing at
                // all matched. A prefix that matches many places has still
                // located the shape; the ambiguity is the finding.
                if !hits.isEmpty {
                    return FunctionReport(
                        name: descriptor.name,
                        recordedWords: total,
                        matchedWords: count,
                        offsets: hits
                    )
                }
            }
            return FunctionReport(
                name: descriptor.name,
                recordedWords: total,
                matchedWords: 0,
                offsets: []
            )
        }
    }

    /// Every offset matching `pattern`, rather than requiring uniqueness.
    ///
    /// `uniqueMatch` throws on zero or many, which is right for a resolver and
    /// wrong here: the count is the diagnostic.
    private static func allMatches(
        of pattern: MaskedInstructionPattern,
        in image: BinaryImage,
        layout: MachOLayout
    ) throws -> [UInt64] {
        var hits: [UInt64] = []
        let byteCount = UInt64(pattern.values.count * 4)
        for range in layout.executableFileRanges
            where range.upperBound - range.lowerBound >= byteCount
        {
            var offset = (range.lowerBound + 3) & ~UInt64(3)
            while offset + byteCount <= range.upperBound {
                if try pattern.matches(in: image, at: offset) {
                    hits.append(offset)
                    // Stop early on a badly ambiguous prefix. The exact count
                    // stops being informative well before it stops growing.
                    if hits.count > 32 { return hits }
                }
                offset += 4
            }
        }
        return hits
    }
}
