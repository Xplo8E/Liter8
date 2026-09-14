import Foundation
import XCTest
@testable import Liter8Core

final class FirmwareProfileTests: XCTestCase {
    func testKnownKernelFingerprintsSelectTheirBuildProfiles() throws {
        for expected in KernelResolverProfileRegistry.profiles {
            // Real kernelcaches contain the XNU fingerprint among unrelated
            // binary data. Padding both sides catches accidental assumptions
            // that the fingerprint begins at offset zero.
            let data = Data([0xAA, 0xBB])
                + Data(expected.embeddedFingerprint.utf8)
                + Data([0x00, 0xCC])
            let detected = KernelResolverProfileRegistry.detect(in: BinaryImage(data: data))
            XCTAssertEqual(detected?.id, expected.id)
            XCTAssertEqual(detected?.build, expected.build)
        }
    }

    func testUnknownKernelIsNotAssignedAReviewedProfile() {
        let image = BinaryImage(data: Data("xnu-unknown/RELEASE_ARM64_T8030".utf8))
        XCTAssertNil(KernelResolverProfileRegistry.detect(in: image))
    }

    func testEarlyBetasShareACMSignaturesAndPayload() throws {
        let beta2 = try XCTUnwrap(
            KernelResolverProfileRegistry.profiles.first { $0.build == "24A5370h" }
        )
        let beta4 = try XCTUnwrap(
            KernelResolverProfileRegistry.profiles.first { $0.build == "24A5390f" }
        )
        let beta2Variants = try XCTUnwrap(beta2.variants(for: KernelCredentialManagerResolver.name))
        let beta4Variants = try XCTUnwrap(beta4.variants(for: KernelCredentialManagerResolver.name))

        XCTAssertEqual(beta2Variants.signature, beta4Variants.signature)
        XCTAssertEqual(beta2Variants.payload, beta4Variants.payload)
        XCTAssertEqual(beta2Variants.support, .supported)
    }

    /// The release build must use its own ACM signature family.
    ///
    /// This started life asserting `pendingResearch`, which was the right
    /// guarantee while the release bodies were unreversed. Now that they are
    /// recorded, the guarantee that still matters is the same one stated
    /// differently: RC keeps a separate family and must never be served the
    /// early-beta shapes. iOS 27 RC enabled BTI for the kernelcache, so every
    /// one of these methods gained a landing pad that the beta descriptors do
    /// not describe.
    func testReleaseProfileUsesItsOwnACMSignatureFamily() throws {
        let release = try XCTUnwrap(
            KernelResolverProfileRegistry.profiles.first { $0.build == "24A435" }
        )
        let beta4 = try XCTUnwrap(
            KernelResolverProfileRegistry.profiles.first { $0.build == "24A5390f" }
        )
        let releaseVariants = try XCTUnwrap(
            release.variants(for: KernelCredentialManagerResolver.name)
        )
        let beta4Variants = try XCTUnwrap(beta4.variants(for: KernelCredentialManagerResolver.name))

        XCTAssertNotEqual(releaseVariants.signature, beta4Variants.signature)
        XCTAssertEqual(releaseVariants.signature, "ios27-24A435-acm-v1")
        XCTAssertEqual(releaseVariants.support, .supported)
    }

    func testACMSignatureFamiliesDescribeTheSameMethodsWithDifferentShapes() throws {
        let beta = try XCTUnwrap(
            KernelCredentialManagerSignatures.variant(named: "ios27-early-beta-acm-v1")
        )
        let release = try XCTUnwrap(
            KernelCredentialManagerSignatures.variant(named: "ios27-24A435-acm-v1")
        )

        XCTAssertEqual(beta.functions.count, 26)
        XCTAssertEqual(
            beta.functions.map(\.name),
            release.functions.map(\.name),
            "both families must cover the same methods, in the same order"
        )
        // Some individual prologues really are byte-identical between the two
        // builds, so requiring every descriptor to differ would be false. What
        // must hold is that the families are not interchangeable: at least one
        // method's recorded shape moved, which is why they cannot be merged.
        let differing = zip(beta.functions, release.functions).filter {
            $0.pattern.values != $1.pattern.values || $0.pattern.masks != $1.pattern.masks
        }
        XCTAssertFalse(
            differing.isEmpty,
            "the release family must be recovered from the release build, not aliased to the beta one"
        )
    }

    /// RC may become reviewed only after the exact-device restore and repeat
    /// boot acceptance sequence has passed. This pins that promotion so the
    /// CLI no longer demands the research-only --experimental opt-in.
    func testReleaseWorkflowIsReviewedAfterDeviceValidation() {
        let release = DeviceWorkflowRegistry.profiles.first { $0.build == "24A435" }
        let beta = DeviceWorkflowRegistry.profiles.first { $0.build == "24A5390f" }
        XCTAssertEqual(release?.validationState, .reviewed)
        XCTAssertEqual(release?.launchdCacheDaemonCount, 729)
        XCTAssertEqual(release?.setupControllerMethodCount, 66)
        XCTAssertEqual(beta?.validationState, .reviewed)
        XCTAssertEqual(beta?.launchdCacheDaemonCount, 731)
        XCTAssertEqual(beta?.setupControllerMethodCount, 65)
    }
}
