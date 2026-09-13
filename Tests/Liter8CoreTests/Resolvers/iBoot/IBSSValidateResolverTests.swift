import Foundation
import XCTest
@testable import Liter8Core

final class IBSSValidateResolverTests: XCTestCase {
    private var packageRoot: URL {
        liter8PackageRoot(from: #filePath)
    }

    private var beta4IBSS: URL {
        liter8PrivateFixtureRoot(from: #filePath)
            .appendingPathComponent("offsets/ibss/iBSS.raw")
    }

    func testBeta4ResolverMatchesKnownOracle() throws {
        guard FileManager.default.fileExists(atPath: beta4IBSS.path) else {
            throw XCTSkip("local beta-4 iBSS fixture is absent")
        }
        let image = try BinaryImage(contentsOf: beta4IBSS)
        let records = try IBSSValidateResolver().resolve(in: image)

        XCTAssertEqual(records.map(\.offset), [0x23728, 0x2372C])
        XCTAssertEqual(records.compactMap(\.originalWord), [0x54000701, 0xAA1403E0])
        XCTAssertEqual(records.compactMap(\.replacementWord), [0xD503201F, 0xD2800000])
    }

    func testMissingAnchorDoesNotFallBackToKnownOffset() throws {
        // Keep the buffer large enough to contain the known beta-4 offset. A
        // pass here therefore proves there is no hidden fixed-offset fallback.
        let fixture = Data(repeating: 0, count: 0x24000)
        XCTAssertThrowsError(try IBSSValidateResolver().resolve(in: BinaryImage(data: fixture))) { error in
            XCTAssertEqual(error as? PatchfinderError, .missingAnchor(IBSSValidateResolver.anchor))
        }
    }

    func testADRPAddResolvesBeta4AnchorReference() throws {
        guard FileManager.default.fileExists(atPath: beta4IBSS.path) else {
            throw XCTSkip("local beta-4 iBSS fixture is absent")
        }
        let image = try BinaryImage(contentsOf: beta4IBSS)
        let anchor = try XCTUnwrap(image.findAll(utf8: IBSSValidateResolver.anchor, nulTerminated: true).first)
        let references = try ARM64.adrpAddReferences(in: image, to: anchor)
        XCTAssertTrue(references.contains { $0.adrpOffset == 0x23810 })
    }

    func testManifestVerifiesExactBeta4Fixture() throws {
        guard FileManager.default.fileExists(atPath: beta4IBSS.path) else {
            throw XCTSkip("local beta-4 iBSS fixture is absent")
        }
        let manifestURL = packageRoot.appendingPathComponent(
            "fixtures/24A5390f/n104ap/ibss-n104-24A5390f.json"
        )
        let manifest = try FixtureManifest.load(from: manifestURL)
        XCTAssertEqual(try manifest.verify(binaryAt: beta4IBSS).count, 2)
    }

    func testGuardedApplierProducesExpectedWords() throws {
        guard FileManager.default.fileExists(atPath: beta4IBSS.path) else {
            throw XCTSkip("local beta-4 iBSS fixture is absent")
        }
        let image = try BinaryImage(contentsOf: beta4IBSS)
        let records = try IBSSValidateResolver().resolve(in: image)
        let result = try GuardedPatchApplier.apply(records, to: image)
        let patched = BinaryImage(data: result.data)

        XCTAssertEqual(try patched.readUInt32(at: 0x23728), 0xD503201F)
        XCTAssertEqual(try patched.readUInt32(at: 0x2372C), 0xD2800000)
        XCTAssertEqual(result.dispositions["ibss.validate-asn1.branch"], .applied)
    }

    func testGuardedApplierRejectsWrongPreimageWithoutOutput() throws {
        let record = PatchRecord(
            id: "test",
            component: "fixture",
            offset: 4,
            original: 0x11111111,
            replacement: 0x22222222,
            summary: "test",
            evidence: []
        )
        let image = BinaryImage(data: Data(repeating: 0xAA, count: 16))

        XCTAssertThrowsError(try GuardedPatchApplier.apply([record], to: image)) { error in
            XCTAssertEqual(
                error as? PatchfinderError,
                .preimageMismatch(
                    id: "test",
                    offset: 4,
                    expected: Data([0x11, 0x11, 0x11, 0x11]),
                    found: Data([0xAA, 0xAA, 0xAA, 0xAA])
                )
            )
        }
    }

    func testBeta4BootArgsResolverMatchesKnownOracle() throws {
        guard FileManager.default.fileExists(atPath: beta4IBSS.path) else {
            throw XCTSkip("local beta-4 iBSS fixture is absent")
        }
        let image = try BinaryImage(contentsOf: beta4IBSS)
        let records = try IBSSBootArgsResolver().resolve(in: image)
        let byID = Dictionary(uniqueKeysWithValues: records.map { ($0.id, $0) })

        XCTAssertEqual(byID["ibss.boot-args.adrp"]?.offset, 0x2AA28)
        XCTAssertEqual(byID["ibss.boot-args.adrp"]?.originalWord, 0xF0000862)
        XCTAssertEqual(byID["ibss.boot-args.adrp"]?.replacementWord, 0xD0000522)
        XCTAssertEqual(byID["ibss.boot-args.add"]?.offset, 0x2AA2C)
        XCTAssertEqual(byID["ibss.boot-args.add"]?.originalWord, 0x91073C42)
        XCTAssertEqual(byID["ibss.boot-args.add"]?.replacementWord, 0x9138C042)
        XCTAssertEqual(byID["ibss.boot-args.string"]?.offset, 0xD0E30)

        var expectedString = Data(IBSSBootArgsResolver.normalBootArguments.utf8)
        expectedString.append(0)
        XCTAssertEqual(byID["ibss.boot-args.string"]?.replacementBytes, expectedString)
    }

    func testBootArgsResolverRejectsFormatConversions() throws {
        let image = BinaryImage(data: Data(repeating: 0, count: 0x1000))
        XCTAssertThrowsError(
            try IBSSBootArgsResolver(bootArguments: "-v %s").resolve(in: image)
        ) { error in
            XCTAssertEqual(
                error as? PatchfinderError,
                .invalidPatch(
                    id: IBSSBootArgsResolver.name,
                    reason: "boot arguments contain a printf conversion"
                )
            )
        }
    }

    func testCombinedBeta4IBSSPlanAppliesAllFiveRanges() throws {
        guard FileManager.default.fileExists(atPath: beta4IBSS.path) else {
            throw XCTSkip("local beta-4 iBSS fixture is absent")
        }
        let image = try BinaryImage(contentsOf: beta4IBSS)
        let records = try IBSSNormalResolver().resolve(in: image)
        let result = try GuardedPatchApplier.apply(records, to: image)
        let patched = BinaryImage(data: result.data)

        XCTAssertEqual(records.count, 5)
        XCTAssertEqual(try patched.readUInt32(at: 0x23728), 0xD503201F)
        XCTAssertEqual(try patched.readUInt32(at: 0x2372C), 0xD2800000)
        XCTAssertEqual(try patched.readUInt32(at: 0x2AA28), 0xD0000522)
        XCTAssertEqual(try patched.readUInt32(at: 0x2AA2C), 0x9138C042)
        XCTAssertEqual(result.dispositions.values.filter { $0 == .applied }.count, 5)
    }

    func testNormalManifestVerifiesSitesAndCompleteOutput() throws {
        guard FileManager.default.fileExists(atPath: beta4IBSS.path) else {
            throw XCTSkip("local beta-4 iBSS fixture is absent")
        }
        let manifestURL = packageRoot
            .appendingPathComponent("fixtures/24A5390f/n104ap/ibss-normal-n104-24A5390f.json")
        let manifest = try FixtureManifest.load(from: manifestURL)

        // The manifest checks the pristine input identity, all five records and
        // the SHA-256 of the fully patched result.
        XCTAssertEqual(try manifest.verify(binaryAt: beta4IBSS).count, 5)
    }

    func testRestoreAndRamdiskPlansMatchReviewedOutputs() throws {
        guard FileManager.default.fileExists(atPath: beta4IBSS.path) else {
            throw XCTSkip("local beta-4 iBSS fixture is absent")
        }

        // Each manifest binds the resolver to the pristine payload, checks all
        // five selected ranges, then hashes the entire result. The output hashes
        // come from the reviewed mode-specific manifests. The restore oracle
        // retains Python parity; the SSHRD oracle additionally records the
        // n104 backlight handoff that still needs visual device confirmation.
        for fixture in [
            "ibss-restore-n104-24A5390f.json",
            "ibss-ramdisk-n104-24A5390f.json",
        ] {
            let manifest = try FixtureManifest.load(
                from: packageRoot.appendingPathComponent("fixtures/24A5390f/n104ap/\(fixture)")
            )
            XCTAssertEqual(try manifest.verify(binaryAt: beta4IBSS).count, 5)
        }
    }
}
