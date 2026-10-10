import Foundation
import XCTest
@testable import Liter8Core

final class RestoreComponentResolverTests: XCTestCase {
    private var packageRoot: URL {
        liter8PackageRoot(from: #filePath)
    }

    private func fixture(_ relativePath: String) throws -> URL {
        let url = liter8PrivateFixtureRoot(from: #filePath).appendingPathComponent(relativePath)
        guard FileManager.default.fileExists(atPath: url.path) else {
            throw XCTSkip("local fixture is absent: \(relativePath)")
        }
        return url
    }

    /// One record, and only one. This resolver used to emit five: the FDR
    /// result plus four baseband-presence records that made `restored` skip the
    /// baseband updater and cost cellular entirely. Asserting the count is the
    /// regression guard: if a baseband-presence patch ever comes back, whether
    /// through a resurrected flag or a copy-paste, this fails rather than
    /// silently shipping a CFW with no modem firmware.
    func testRestoredExternalResolverEmitsOnlyTheFDRRecord() throws {
        let binary = try fixture("offsets/rd/b4_n104/restored_external")
        let records = try RestoredExternalResolver().resolve(
            in: BinaryImage(contentsOf: binary)
        )

        XCTAssertEqual(records.count, 1)
        let record = try XCTUnwrap(records.first)
        XCTAssertEqual(record.id, "restored-external.fdr-result")
        XCTAssertEqual(record.offset, 0x7E558)
        XCTAssertEqual(record.originalWord, 0xAA1A03E0)
        XCTAssertEqual(record.replacementWord, 0xD2800000)
        XCTAssertFalse(records.contains { $0.id.hasPrefix("restored-external.baseband") })
    }

    func testASRResolverFollowsReporterCallChain() throws {
        let binary = try fixture("offsets/rd/b4_n104/asr")
        let records = try ASRSignatureResolver().resolve(
            in: BinaryImage(contentsOf: binary)
        )

        XCTAssertEqual(records.count, 1)
        XCTAssertEqual(records[0].offset, 0x1F654)
        XCTAssertEqual(records[0].originalWord, 0x35003120)
        XCTAssertEqual(records[0].replacementWord, 0xD503201F)
    }

    func testRestoreComponentManifestsVerifyCompleteOutputs() throws {
        let cases = [
            ("fixtures/24A5390f/n104ap/restored-external-n104-24A5390f.json", "offsets/rd/b4_n104/restored_external"),
            ("fixtures/24A5390f/n104ap/asr-n104-24A5390f.json", "offsets/rd/b4_n104/asr"),
        ]

        for (manifestPath, binaryPath) in cases {
            let manifest = try FixtureManifest.load(
                from: packageRoot.appendingPathComponent(manifestPath)
            )
            // Resolve the optional private fixture before entering XCTest's
            // assertion autoclosure. If it is absent, XCTSkip must escape the
            // test normally instead of being converted into a failed assert.
            let binary = try fixture(binaryPath)
            let records = try manifest.verify(binaryAt: binary)
            XCTAssertEqual(records.count, 1, manifestPath)
        }
    }
}
