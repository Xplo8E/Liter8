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
            XCTAssertEqual(detected?.builds, expected.builds)
        }
    }

    func testUnknownKernelIsNotAssignedAReviewedProfile() {
        let image = BinaryImage(data: Data("xnu-unknown/RELEASE_ARM64_T8030".utf8))
        XCTAssertNil(KernelResolverProfileRegistry.detect(in: image))
    }

    /// A build ID must resolve to at most one profile.
    ///
    /// `builds` exists because one XNU fingerprint can ship under several Apple
    /// build IDs, but the reverse must never happen: if two profiles claimed the
    /// same build ID, `covers(build:)` would silently return whichever was
    /// declared first and the ACM signature family could be picked from the
    /// wrong kernel.
    func testNoBuildIDIsClaimedByTwoProfiles() {
        let claimed = KernelResolverProfileRegistry.profiles.flatMap(\.builds)
        XCTAssertEqual(
            claimed.count, Set(claimed).count,
            "a build ID appears in more than one profile: \(claimed.sorted())"
        )
    }

    /// Fingerprints must stay unique, or `detect` silently answers nil.
    ///
    /// Two profiles sharing a fingerprint makes `matches.count == 1` false and
    /// every kernel plan loses its variant selection with no error. Builds that
    /// share an XNU version belong in one profile's `builds`, not in two.
    func testFingerprintsAreUniqueAcrossProfiles() {
        let fingerprints = KernelResolverProfileRegistry.profiles.map(\.embeddedFingerprint)
        XCTAssertEqual(fingerprints.count, Set(fingerprints).count)
    }

    /// 27.2 gets its own ACM family even though most shapes still match.
    ///
    /// Probing 24A435's signatures against 24B5084k matches 23 of 26, which is
    /// exactly the situation where sharing a variant looks harmless and then
    /// lets one build's shapes stand in for another's. The registry must keep
    /// them apart, and both must still resolve to a real recorded family.
    func testTwoSevenTwoUsesItsOwnACMFamily() throws {
        let release = try XCTUnwrap(
            KernelResolverProfileRegistry.profiles.first { $0.covers(build: "24A435") }
        )
        let twoSevenTwo = try XCTUnwrap(
            KernelResolverProfileRegistry.profiles.first { $0.covers(build: "24B5084k") }
        )
        let releaseVariant = try XCTUnwrap(
            release.variants(for: KernelCredentialManagerResolver.name)
        )
        let newVariant = try XCTUnwrap(
            twoSevenTwo.variants(for: KernelCredentialManagerResolver.name)
        )

        XCTAssertNotEqual(newVariant.signature, releaseVariant.signature)
        // The patch itself did not change, only where to apply it.
        XCTAssertEqual(newVariant.payload, releaseVariant.payload)
        XCTAssertNotNil(KernelCredentialManagerSignatures.variant(named: newVariant.signature))
    }

    /// Every registered ACM signature variant must name 26 methods, in one order.
    ///
    /// The resolver scores four bodies against the entries either side of them,
    /// so a family that dropped or reordered an entry would still resolve and
    /// would silently patch the wrong function.
    func testEveryACMVariantDescribesTheSameTwentySixMethods() throws {
        let ids = KernelResolverProfileRegistry.profiles.compactMap {
            $0.variants(for: KernelCredentialManagerResolver.name)?.signature
        }
        XCTAssertFalse(ids.isEmpty)

        var reference: [String]?
        for id in ids {
            let variant = try XCTUnwrap(KernelCredentialManagerSignatures.variant(named: id))
            let names = variant.functions.map(\.name)
            XCTAssertEqual(names.count, 26, "\(id) must describe 26 methods")
            if let reference {
                XCTAssertEqual(names, reference, "\(id) must keep the shared method order")
            } else {
                reference = names
            }
        }
    }

    /// 24A437 is 24A435 rebuilt and 24A446 is 27.0.1 on the same XNU. All three
    /// must select the same reviewed profile.
    func testReleaseProfileCoversEveryShippedBuildID() throws {
        let release = try XCTUnwrap(
            KernelResolverProfileRegistry.profiles.first { $0.covers(build: "24A435") }
        )
        XCTAssertTrue(release.covers(build: "24A437"))
        XCTAssertTrue(release.covers(build: "24A446"))
        XCTAssertFalse(release.covers(build: "24A5390f"))
    }

    func testEarlyBetasShareACMSignaturesAndPayload() throws {
        let beta2 = try XCTUnwrap(
            KernelResolverProfileRegistry.profiles.first { $0.covers(build: "24A5370h") }
        )
        let beta4 = try XCTUnwrap(
            KernelResolverProfileRegistry.profiles.first { $0.covers(build: "24A5390f") }
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
            KernelResolverProfileRegistry.profiles.first { $0.covers(build: "24A435") }
        )
        let beta4 = try XCTUnwrap(
            KernelResolverProfileRegistry.profiles.first { $0.covers(build: "24A5390f") }
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

    /// 27.0.1 became reviewed after its own erase restore, normal boot, repeat
    /// boot and finalization on hardware.
    ///
    /// Its launchd digest and Setup count match 24A435 because those two files
    /// are byte-identical across the builds. The service cache digest is what
    /// proves the images are nevertheless different, so it is pinned here: two
    /// entries agreeing on every oracle would be the signature of one having
    /// been copied from the other instead of measured.
    func testPointReleaseWorkflowIsReviewedAfterItsOwnDeviceRun() throws {
        let release = try XCTUnwrap(DeviceWorkflowRegistry.profiles.first { $0.build == "24A435" })
        let point = try XCTUnwrap(DeviceWorkflowRegistry.profiles.first { $0.build == "24A446" })
        XCTAssertEqual(point.validationState, .reviewed)
        XCTAssertEqual(point.productVersion, "27.0.1")
        XCTAssertEqual(point.launchdSHA256, release.launchdSHA256)
        XCTAssertEqual(point.setupControllerMethodCount, release.setupControllerMethodCount)
        XCTAssertNotEqual(point.launchdCacheSHA256, release.launchdCacheSHA256)
    }
}
