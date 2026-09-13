import CryptoKit
import Foundation
import XCTest
@testable import Liter8Core

final class DeviceTreeAndIM4PTests: XCTestCase {
    private var researchRoot: URL {
        // Large Apple firmware files are local research inputs and are never
        // committed to the public package.
        liter8PrivateFixtureRoot(from: #filePath)
    }

    private func localFile(_ relativePath: String) throws -> URL {
        let url = researchRoot.appendingPathComponent(relativePath)
        guard FileManager.default.fileExists(atPath: url.path) else {
            throw XCTSkip("local firmware fixture is absent: \(relativePath)")
        }
        return url
    }

    private func sha256(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }

    func testRestoreDeviceTreeMatchesPythonReferenceExactly() throws {
        let source = try Data(contentsOf: localFile("work-27.0b4-n104/DeviceTree.raw"))
        let result = try DeviceTreePatcher.patch(source, plan: .restore)

        XCTAssertEqual(result.data.count, 234_928)
        XCTAssertEqual(sha256(result.data), "f5bb2e901a5261051ee481af26348498c5697222d22a542cc6ef0b22aec4f54a")
        XCTAssertEqual(result.changes, [
            DeviceTreeChange(
                operation: "del-prop",
                path: "/defaults/content-protect",
                disposition: .removed
            ),
        ])
    }

    func testNormalDeviceTreeIsByteIdenticalToReviewedPythonOutput() throws {
        let source = try Data(contentsOf: localFile("work-27.0b4-n104/DeviceTree.raw"))
        let pythonOutput = try Data(contentsOf: localFile("work-27.0b4-n104/DeviceTree_patched.raw"))
        let result = try DeviceTreePatcher.patch(source, plan: .normal)

        XCTAssertEqual(result.data, pythonOutput)
        XCTAssertEqual(sha256(result.data), "bc942f707c4e3db063bdc2f8519d19d6c6d8baa77d11c9c0822618ce142c459b")
        XCTAssertEqual(result.changes.map(\.disposition), [.removed, .added, .added, .updated])
    }

    func testNormalDeviceTreePlanIsIdempotent() throws {
        let source = try Data(contentsOf: localFile("work-27.0b4-n104/DeviceTree.raw"))
        let first = try DeviceTreePatcher.patch(source, plan: .normal)
        let second = try DeviceTreePatcher.patch(first.data, plan: .normal)

        XCTAssertEqual(second.data, first.data)
        XCTAssertTrue(second.changes.allSatisfy { $0.disposition == .alreadyApplied })
    }

    func testVendorExtractsAndRepackagesDeviceTreeIM4P() throws {
        let im4pURL = try localFile("ipsw/n104_24A5390f/Firmware/all_flash/DeviceTree.n104ap.im4p")
        let rawURL = try localFile("work-27.0b4-n104/DeviceTree.raw")
        let expectedPayload = try Data(contentsOf: rawURL)
        let artifact = try FirmwareArtifact(contentsOf: im4pURL)

        XCTAssertEqual(artifact.kind, .im4p)
        XCTAssertEqual(artifact.fourcc, "dtre")
        XCTAssertEqual(artifact.payload, expectedPayload)

        let rebuilt = try artifact.encoded(replacingPayloadWith: expectedPayload)
        let roundTrip = try FirmwareArtifact(data: rebuilt)
        XCTAssertEqual(roundTrip.kind, .im4p)
        XCTAssertEqual(roundTrip.fourcc, "dtre")
        XCTAssertEqual(roundTrip.payload, expectedPayload)
    }

    func testDeviceTreeCanPatchAnIM4PWithoutLeavingSwift() throws {
        let im4pURL = try localFile("ipsw/n104_24A5390f/Firmware/all_flash/DeviceTree.n104ap.im4p")
        let artifact = try FirmwareArtifact(contentsOf: im4pURL)
        let patched = try DeviceTreePatcher.patch(artifact.payload, plan: .normal)
        let encoded = try artifact.encoded(replacingPayloadWith: patched.data)
        let reopened = try FirmwareArtifact(data: encoded)

        XCTAssertEqual(reopened.kind, .im4p)
        XCTAssertEqual(reopened.fourcc, "dtre")
        XCTAssertEqual(reopened.payload, patched.data)
        try DeviceTreePatcher.verify(reopened.payload, plan: .normal)
    }

    func testTXMRepackPreservesApplePAYPTail() throws {
        let url = try localFile("ipsw/n104_24A5390f/Firmware/txm.iphoneos.release.im4p")
        let original = try Data(contentsOf: url)
        let artifact = try FirmwareArtifact(data: original)
        XCTAssertEqual(artifact.fourcc, "trxm")

        // PAYP begins ten bytes before its ASCII marker. Preserve that entire
        // DER child, not merely the marker and bytes that follow it.
        let marker = Data("PAYP".utf8)
        guard let markerRange = original.range(of: marker, options: .backwards) else {
            return XCTFail("beta-4 TXM fixture has no PAYP metadata")
        }
        XCTAssertGreaterThanOrEqual(markerRange.lowerBound, 10)
        let expectedTail = original[(markerRange.lowerBound - 10)..<original.endIndex]

        let rebuilt = try artifact.encoded(replacingPayloadWith: artifact.payload)
        XCTAssertTrue(rebuilt.suffix(expectedTail.count).elementsEqual(expectedTail))

        let reopened = try FirmwareArtifact(data: rebuilt)
        XCTAssertEqual(reopened.fourcc, "trxm")
        XCTAssertEqual(reopened.payload, artifact.payload)
    }
}
