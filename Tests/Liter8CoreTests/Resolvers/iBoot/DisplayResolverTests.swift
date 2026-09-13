import Foundation
import XCTest
@testable import Liter8Core

final class DisplayResolverTests: XCTestCase {
    private var packageRoot: URL {
        liter8PackageRoot(from: #filePath)
    }

    private var beta4Payload: URL {
        liter8PrivateFixtureRoot(from: #filePath)
            .appendingPathComponent("offsets/ibss/iBSS.raw")
    }

    func testDisplayResolversRediscoverKnownSites() throws {
        guard FileManager.default.fileExists(atPath: beta4Payload.path) else {
            throw XCTSkip("local beta-4 iBSS fixture is absent")
        }
        let image = try BinaryImage(contentsOf: beta4Payload)
        XCTAssertEqual(
            try IBSSSkipDisplayInitResolver().resolve(in: image).map(\.offset),
            [0x351C8]
        )
        XCTAssertEqual(
            try IBECPinotIgnoreFailureResolver().resolve(in: image).map(\.offset),
            [0x9E504]
        )
    }

    func testRamdiskBootKeepsTheN104BacklightEnabled() {
        XCTAssertTrue(IBSSRamdiskResolver.bootArguments.contains("backlight-level=1024"))
    }

    func testForcePanelIDPreservesAll32Bits() throws {
        guard FileManager.default.fileExists(atPath: beta4Payload.path) else {
            throw XCTSkip("local beta-4 iBSS fixture is absent")
        }
        let records = try IBECPinotForceIDResolver(panelID: 0x1234_5678)
            .resolve(in: BinaryImage(contentsOf: beta4Payload))

        XCTAssertEqual(records.map(\.offset), [0x9E3D4, 0x9E3D8])
        XCTAssertEqual(records.compactMap(\.replacementWord), [0x528A_CF00, 0x72A2_4680])
    }

    func testFixedDisplayManifestsMatchPythonOutputs() throws {
        guard FileManager.default.fileExists(atPath: beta4Payload.path) else {
            throw XCTSkip("local beta-4 iBSS fixture is absent")
        }
        for fixture in [
            "ibss-skip-display-n104-24A5390f.json",
            "ibec-ignore-pinot-n104-24A5390f.json",
        ] {
            let manifest = try FixtureManifest.load(
                from: packageRoot.appendingPathComponent("fixtures/24A5390f/n104ap/\(fixture)")
            )
            XCTAssertEqual(try manifest.verify(binaryAt: beta4Payload).count, 1)
        }
    }
}
