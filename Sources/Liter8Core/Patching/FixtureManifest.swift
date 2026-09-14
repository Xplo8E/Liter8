import CryptoKit
import Foundation

public struct FixtureManifest: Codable, Sendable {
    public struct Target: Codable, Sendable {
        public let device: String
        public let board: String
        public let build: String
        public let component: String

        public init(device: String, board: String, build: String, component: String) {
            self.device = device
            self.board = board
            self.build = build
            self.component = component
        }
    }

    public struct ExpectedPatch: Codable, Sendable {
        public let id: String
        public let offset: UInt64
        public let originalBytes: String
        public let replacementBytes: String

        public init(id: String, offset: UInt64, originalBytes: String, replacementBytes: String) {
            self.id = id
            self.offset = offset
            self.originalBytes = originalBytes
            self.replacementBytes = replacementBytes
        }
    }

    public let resolver: String
    public let target: Target
    public let expectedSize: Int
    public let sha256: String
    public let expectedPatches: [ExpectedPatch]
    /// Optional hash of the complete in-memory result. Patch-by-patch oracles
    /// catch incorrect sites; this additionally catches ordering, overlap or an
    /// accidental write outside every declared range.
    public let expectedOutputSHA256: String?

    public init(
        resolver: String,
        target: Target,
        expectedSize: Int,
        sha256: String,
        expectedPatches: [ExpectedPatch],
        expectedOutputSHA256: String?
    ) {
        self.resolver = resolver
        self.target = target
        self.expectedSize = expectedSize
        self.sha256 = sha256
        self.expectedPatches = expectedPatches
        self.expectedOutputSHA256 = expectedOutputSHA256
    }

    /// Lowercase SHA-256, in the single spelling every manifest field uses.
    public static func digest(of data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }

    public static func load(from url: URL) throws -> Self {
        try JSONDecoder().decode(Self.self, from: Data(contentsOf: url))
    }

    public func verify(binaryAt url: URL) throws -> [PatchRecord] {
        let image = try BinaryImage(contentsOf: url)
        let actual = try resolve(in: image)
        try verify(resolved: actual, in: image)
        return actual
    }

    /// Verify already-resolved records against this fixture's exact input and
    /// output oracles.
    ///
    /// Keeping verification separate from resolution lets the test suite reuse
    /// one expensive, read-only kernel scan across several assertions. Nothing
    /// is trusted merely because it came from the cache: we still bind the
    /// records to the exact input size and digest, compare every patch, apply
    /// the guarded writes, and check the complete output digest.
    func verify(resolved actual: [PatchRecord], in image: BinaryImage) throws {
        // Bind every oracle to an exact artifact before comparing offsets.
        // This prevents a correct offset from the wrong build looking valid.
        guard image.count == expectedSize else {
            throw PatchfinderError.fixtureMismatch("size \(image.count), expected \(expectedSize)")
        }

        let digest = SHA256.hash(data: image.data).map { String(format: "%02x", $0) }.joined()
        guard digest.caseInsensitiveCompare(sha256) == .orderedSame else {
            throw PatchfinderError.fixtureMismatch("SHA-256 \(digest), expected \(sha256)")
        }

        // Known offsets are verification oracles only. Resolution has already
        // completed without access to expectedPatches.
        let actualByID = Dictionary(uniqueKeysWithValues: actual.map { ($0.id, $0) })
        guard actualByID.count == expectedPatches.count else {
            throw PatchfinderError.fixtureMismatch("resolved \(actualByID.count) patches, expected \(expectedPatches.count)")
        }
        for expected in expectedPatches {
            guard let record = actualByID[expected.id] else {
                throw PatchfinderError.fixtureMismatch("missing patch \(expected.id)")
            }
            guard let original = Data(hexadecimalString: expected.originalBytes),
                  let replacement = Data(hexadecimalString: expected.replacementBytes)
            else {
                throw PatchfinderError.invalidFixture("\(expected.id) contains invalid hexadecimal bytes")
            }
            guard record.offset == expected.offset,
                  record.originalBytes == original,
                  record.replacementBytes == replacement
            else {
                throw PatchfinderError.fixtureMismatch(
                    "\(expected.id): got \(record.offset.hex) \(record.originalBytes.hexadecimalString) -> \(record.replacementBytes.hexadecimalString)"
                )
            }
        }

        if let expectedOutputSHA256 {
            let result = try GuardedPatchApplier.apply(actual, to: image)
            let outputDigest = SHA256.hash(data: result.data)
                .map { String(format: "%02x", $0) }
                .joined()
            guard outputDigest.caseInsensitiveCompare(expectedOutputSHA256) == .orderedSame else {
                throw PatchfinderError.fixtureMismatch(
                    "output SHA-256 \(outputDigest), expected \(expectedOutputSHA256)"
                )
            }
        }
    }

    /// Resolve the plan named by the fixture. This remains the production/CLI
    /// path; tests that deliberately share a completed resolution call the
    /// verification-only overload above.
    private func resolve(in image: BinaryImage) throws -> [PatchRecord] {
        switch resolver {
        case IBSSValidateResolver.name:
            return try IBSSValidateResolver().resolve(in: image)
        case IBSSNormalResolver.name:
            return try IBSSNormalResolver().resolve(in: image)
        case IBSSRestoreResolver.name:
            return try IBSSRestoreResolver().resolve(in: image)
        case IBSSRamdiskResolver.name:
            return try IBSSRamdiskResolver().resolve(in: image)
        case RestoredExternalResolver.name:
            return try RestoredExternalResolver().resolve(in: image)
        case ASRSignatureResolver.name:
            return try ASRSignatureResolver().resolve(in: image)
        case TXMRestoreResolver.name:
            return try TXMRestoreResolver().resolve(in: image)
        case TXMBootResolver.name:
            return try TXMBootResolver().resolve(in: image)
        case CoreAuthDResolver.name:
            return try CoreAuthDResolver().resolve(in: image)
        case CTKDResolver.name:
            return try CTKDResolver().resolve(in: image)
        case MobileActivationDResolver.name:
            return try MobileActivationDResolver().resolve(in: image)
        case IBSSSkipDisplayInitResolver.name:
            return try IBSSSkipDisplayInitResolver().resolve(in: image)
        case IBECPinotIgnoreFailureResolver.name:
            return try IBECPinotIgnoreFailureResolver().resolve(in: image)
        case KernelRestoreResolver.name:
            return try KernelRestoreResolver().resolve(in: image)
        case KernelBootPolicyResolver.name:
            return try KernelBootPolicyResolver().resolve(in: image)
        case KernelAKSResolver.name:
            return try KernelAKSResolver().resolve(in: image)
        case KernelSEPSilenceResolver.name:
            return try KernelSEPSilenceResolver().resolve(in: image)
        case KernelSEPResolver.name:
            return try KernelSEPResolver().resolve(in: image)
        case KernelCredentialManagerResolver.name:
            return try KernelCredentialManagerResolver().resolve(in: image)
        case KernelSandboxResolver.name:
            return try KernelSandboxResolver().resolve(in: image)
        case KernelBootResolver.name:
            return try KernelBootResolver().resolve(in: image)
        case KernelBootCompatibilityResolver.name:
            return try KernelBootCompatibilityResolver().resolve(in: image)
        case KernelDiagnosticResolver.name:
            return try KernelDiagnosticResolver().resolve(in: image)
        default:
            throw PatchfinderError.invalidFixture("unknown resolver \(resolver)")
        }
    }
}
