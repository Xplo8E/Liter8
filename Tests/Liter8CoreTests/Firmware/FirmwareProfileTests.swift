import Foundation
import XCTest
@testable import Liter8Core

final class FirmwareProfileTests: XCTestCase {
    func testKnownKernelFingerprintsSelectTheirBuildProfiles() throws {
        for expected in FirmwareProfileRegistry.profiles {
            // Real kernelcaches contain the XNU fingerprint among unrelated
            // binary data. Padding both sides catches accidental assumptions
            // that the fingerprint begins at offset zero.
            let data = Data([0xAA, 0xBB])
                + Data(expected.embeddedFingerprint.utf8)
                + Data([0x00, 0xCC])
            let detected = FirmwareProfileRegistry.detect(in: BinaryImage(data: data))
            XCTAssertEqual(detected?.id, expected.id)
            XCTAssertEqual(detected?.build, expected.build)
        }
    }

    func testUnknownKernelIsNotAssignedAReviewedProfile() {
        let image = BinaryImage(data: Data("xnu-unknown/RELEASE_ARM64_T8030".utf8))
        XCTAssertNil(FirmwareProfileRegistry.detect(in: image))
    }

    func testEarlyBetasShareACMSignaturesAndPayload() throws {
        let beta2 = try XCTUnwrap(
            FirmwareProfileRegistry.profiles.first { $0.build == "24A5370h" }
        )
        let beta4 = try XCTUnwrap(
            FirmwareProfileRegistry.profiles.first { $0.build == "24A5390f" }
        )
        let beta2Variants = try XCTUnwrap(beta2.variants(for: KernelCredentialManagerResolver.name))
        let beta4Variants = try XCTUnwrap(beta4.variants(for: KernelCredentialManagerResolver.name))

        XCTAssertEqual(beta2Variants.signature, beta4Variants.signature)
        XCTAssertEqual(beta2Variants.payload, beta4Variants.payload)
        XCTAssertEqual(beta2Variants.support, .supported)
    }

    func testReleaseProfileCannotFallBackToEarlyBetaACMSignatures() throws {
        let release = try XCTUnwrap(
            FirmwareProfileRegistry.profiles.first { $0.build == "24A435" }
        )
        let variants = try XCTUnwrap(release.variants(for: KernelCredentialManagerResolver.name))
        let image = BinaryImage(data: Data(release.embeddedFingerprint.utf8))

        XCTAssertEqual(variants.support, .pendingResearch)
        XCTAssertThrowsError(try KernelCredentialManagerResolver().resolve(in: image)) { error in
            XCTAssertEqual(
                error as? PatchfinderError,
                .unsupportedFirmwareProfile(
                    resolver: KernelCredentialManagerResolver.name,
                    profile: release.id,
                    variant: variants.signature
                )
            )
        }
    }
}
