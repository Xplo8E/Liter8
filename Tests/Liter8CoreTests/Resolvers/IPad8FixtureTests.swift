import Foundation
import XCTest
@testable import Liter8Core

/// Exact-build oracles for the clean 23H30 iPad 8 Wi-Fi artifacts. Firmware
/// binaries remain private; set LITER8_FIXTURE_ROOT to a directory containing
/// offsets/23H30/{kernelcache,iBEC.raw,mobileactivationd,asr}.
final class IPad8FixtureTests: XCTestCase {
    private var packageRoot: URL { liter8PackageRoot(from: #filePath) }

    func testT8020KernelRepackKeepsCompressionAndExactPAYPChild() throws {
        let source = packageRoot.appendingPathComponent(
            ".liter8-ipad8-23H30/CFW/kernelcache.release.ipad11b.bak"
        )
        guard FileManager.default.fileExists(atPath: source.path) else {
            throw XCTSkip("local 23H30 kernel IM4P is absent")
        }
        let original = try Data(contentsOf: source)
        let artifact = try FirmwareArtifact(data: original)
        XCTAssertEqual(artifact.fourcc, "krnl")

        let marker = Data("PAYP".utf8)
        guard let markerRange = original.range(of: marker, options: .backwards) else {
            return XCTFail("23H30 kernel has no PAYP metadata")
        }
        // The T8020 PAYP starts with A0 81 B9 30 81 B6 16 04 PAYP.
        // Copying ten bytes before the text also copies two unrelated bytes
        // from the preceding compression descriptor and breaks DER parsing.
        let paypStart = markerRange.lowerBound - 8
        XCTAssertEqual(original[paypStart], 0xA0)
        XCTAssertEqual(Data(original[(markerRange.lowerBound - 2)..<markerRange.lowerBound]),
                       Data([0x16, 0x04]))

        let rebuilt = try artifact.encoded(replacingPayloadWith: artifact.payload)
        XCTAssertNotNil(rebuilt.range(of: Data("bvx2".utf8)))
        XCTAssertTrue(rebuilt.suffix(original.count - paypStart)
            .elementsEqual(original[paypStart..<original.endIndex]))
        XCTAssertEqual(try FirmwareArtifact(data: rebuilt).payload, artifact.payload)
    }

    func testRecoveredBootAndUserlandPlans() throws {
        let cases: [(String, String, Int)] = [
            ("kernel-credential-manager-j171aap-23H30.json", "kernelcache", 50),
            ("kernel-sandbox-public-j171aap-23H30.json", "kernelcache", 11),
            ("kernel-boot-public-j171aap-23H30.json", "kernelcache", 118),
            ("kernel-ppl-trust-cache-j171aap-23H30.json", "kernelcache", 1),
            ("ibec-restore-j171aap-23H30.json", "iBEC.raw", 6),
            ("mobileactivationd-j171aap-23H30.json", "mobileactivationd", 5),
            ("asr-j171aap-23H30.json", "asr", 1),
        ]
        for (filename, binaryName, count) in cases {
            let binary = liter8PrivateFixtureRoot(from: #filePath)
                .appendingPathComponent("offsets/23H30/\(binaryName)")
            guard FileManager.default.fileExists(atPath: binary.path) else {
                throw XCTSkip("local 23H30 fixture is absent: \(binaryName)")
            }
            let manifest = try FixtureManifest.load(
                from: packageRoot.appendingPathComponent(
                    "fixtures/23H30/j171aap/\(filename)"
                )
            )
            XCTAssertEqual(try manifest.verify(binaryAt: binary).count, count, filename)
        }
    }
}
