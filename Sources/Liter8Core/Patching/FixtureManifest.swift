import CryptoKit
import Foundation

public struct FixtureManifest: Codable, Sendable {
    public struct Target: Codable, Sendable {
        public let device: String
        public let board: String
        public let build: String
        public let component: String
    }

    public struct ExpectedPatch: Codable, Sendable {
        public let id: String
        public let offset: UInt64
        public let originalBytes: String
        public let replacementBytes: String
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

    public static func load(from url: URL) throws -> Self {
        try JSONDecoder().decode(Self.self, from: Data(contentsOf: url))
    }

    public func verify(binaryAt url: URL) throws -> [PatchRecord] {
        let image = try BinaryImage(contentsOf: url)
        // Bind every oracle to an exact artifact before comparing offsets.
        // This prevents a correct offset from the wrong build looking valid.
        guard image.count == expectedSize else {
            throw PatchfinderError.fixtureMismatch("size \(image.count), expected \(expectedSize)")
        }

        let digest = SHA256.hash(data: image.data).map { String(format: "%02x", $0) }.joined()
        guard digest.caseInsensitiveCompare(sha256) == .orderedSame else {
            throw PatchfinderError.fixtureMismatch("SHA-256 \(digest), expected \(sha256)")
        }

        let actual: [PatchRecord]
        switch resolver {
        case IBSSValidateResolver.name:
            actual = try IBSSValidateResolver().resolve(in: image)
        case IBSSNormalResolver.name:
            actual = try IBSSNormalResolver().resolve(in: image)
        case IBSSRestoreResolver.name:
            actual = try IBSSRestoreResolver().resolve(in: image)
        case IBSSRamdiskResolver.name:
            actual = try IBSSRamdiskResolver().resolve(in: image)
        case RestoredExternalResolver.name:
            actual = try RestoredExternalResolver().resolve(in: image)
        case ASRSignatureResolver.name:
            actual = try ASRSignatureResolver().resolve(in: image)
        case TXMRestoreResolver.name:
            actual = try TXMRestoreResolver().resolve(in: image)
        case TXMBootResolver.name:
            actual = try TXMBootResolver().resolve(in: image)
        case CoreAuthDResolver.name:
            actual = try CoreAuthDResolver().resolve(in: image)
        case CTKDResolver.name:
            actual = try CTKDResolver().resolve(in: image)
        case MobileActivationDResolver.name:
            actual = try MobileActivationDResolver().resolve(in: image)
        case IBSSSkipDisplayInitResolver.name:
            actual = try IBSSSkipDisplayInitResolver().resolve(in: image)
        case IBECPinotIgnoreFailureResolver.name:
            actual = try IBECPinotIgnoreFailureResolver().resolve(in: image)
        case KernelRestoreResolver.name:
            actual = try KernelRestoreResolver().resolve(in: image)
        case KernelBootPolicyResolver.name:
            actual = try KernelBootPolicyResolver().resolve(in: image)
        case KernelAKSResolver.name:
            actual = try KernelAKSResolver().resolve(in: image)
        case KernelSEPSilenceResolver.name:
            actual = try KernelSEPSilenceResolver().resolve(in: image)
        case KernelSEPResolver.name:
            actual = try KernelSEPResolver().resolve(in: image)
        case KernelCredentialManagerResolver.name:
            actual = try KernelCredentialManagerResolver().resolve(in: image)
        case KernelSandboxResolver.name:
            actual = try KernelSandboxResolver().resolve(in: image)
        case KernelBootResolver.name:
            actual = try KernelBootResolver().resolve(in: image)
        case KernelBootPublicBeta4Resolver.name:
            actual = try KernelBootPublicBeta4Resolver().resolve(in: image)
        case KernelDiagnosticResolver.name:
            actual = try KernelDiagnosticResolver().resolve(in: image)
        default:
            throw PatchfinderError.invalidFixture("unknown resolver \(resolver)")
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
        return actual
    }
}
