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

    func testRestoredExternalResolverMatchesBeta4Oracle() throws {
        let binary = try fixture("offsets/rd/b4_n104/restored_external")
        let records = try RestoredExternalResolver().resolve(
            in: BinaryImage(contentsOf: binary)
        )

        XCTAssertEqual(records.count, 1)
        XCTAssertEqual(records[0].offset, 0x7E558)
        XCTAssertEqual(records[0].originalWord, 0xAA1A03E0)
        XCTAssertEqual(records[0].replacementWord, 0xD2800000)
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
            XCTAssertEqual(
                try manifest.verify(binaryAt: fixture(binaryPath)).count,
                1,
                manifestPath
            )
        }
    }
}
