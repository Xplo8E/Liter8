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

    func testTFP0SupportCoversIPhone11From270Through272() {
        let resolverBuilds = KernelResolverProfileRegistry.profiles
            .filter { $0.variants(for: KernelTFP0Resolver.variantKey) != nil }
            .flatMap(\.builds)
            .sorted()
        XCTAssertEqual(resolverBuilds, [
            "24A435", "24A437", "24A446",
            "24B119", "24B5084k", "24B5089g", "24B5099f", "24B5110a",
        ])

        let enabledProfiles = DeviceWorkflowRegistry.profiles
            .filter { $0.bootPlan.supportsTFP0KernelTaskPort }
        XCTAssertTrue(enabledProfiles.allSatisfy {
            $0.productType == "iPhone12,1" && $0.deviceClass == "n104ap"
        })

        XCTAssertEqual(enabledProfiles.map(\.id).sorted(), [
            "iphone12,1-n104ap-24A435",
            "iphone12,1-n104ap-24A446",
            "iphone12,1-n104ap-24B119",
            "iphone12,1-n104ap-24B5084k",
            "iphone12,1-n104ap-24B5089g",
            "iphone12,1-n104ap-24B5099f",
            "iphone12,1-n104ap-24B5110a",
        ])
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

    /// Every 27.2 seed, the release included, names its own ACM family.
    ///
    /// The early betas deliberately share one family, so this is not a global
    /// rule: it is the 27.2 rule, and it exists because these builds are
    /// shape-identical. `MaskedInstructionPattern` pre-masks its values at
    /// construction and does not retain the raw reference words, so two
    /// shape-identical families compare equal however differently they were
    /// recorded. The difference a shared family would hide is therefore not
    /// observable here, which is exactly why the separation has to be enforced
    /// by identity instead: each profile must point at a family of its own,
    /// registered under its own id.
    func testEveryTwoSevenTwoSeedNamesItsOwnACMFamily() throws {
        let builds = ["24B5084k", "24B5089g", "24B5099f", "24B5110a", "24B119"]
        var signatures: [String] = []

        for build in builds {
            let profile = try XCTUnwrap(
                KernelResolverProfileRegistry.profiles.first { $0.covers(build: build) },
                "no kernel profile covers \(build)"
            )
            let variants = try XCTUnwrap(
                profile.variants(for: KernelCredentialManagerResolver.name)
            )
            let family = try XCTUnwrap(
                KernelCredentialManagerSignatures.variant(named: variants.signature),
                "\(build) names an unregistered ACM family"
            )
            // Catches a profile pointed at another build's family, and a
            // `variant(named:)` case that returns the wrong one.
            XCTAssertEqual(family.id, variants.signature)
            XCTAssertEqual(variants.payload, "acm-return-success-v1")
            XCTAssertEqual(variants.support, .supported)
            signatures.append(variants.signature)
        }

        XCTAssertEqual(
            signatures.count, Set(signatures).count,
            "two 27.2 seeds share an ACM family: \(signatures)"
        )
    }

    /// The 27.2 release family must describe the same 26 methods as beta 4, and
    /// locate the same two of them positionally.
    ///
    /// The scored entries are ranked inside the interval their exact-matching
    /// neighbours establish, so their identity depends on their index in this
    /// list. A family that scored a different pair, or kept the pair but moved
    /// it, would still resolve and would silently patch another function.
    func testTwoSevenTwoReleaseScoresTheSameTwoMethodsAsBeta4() throws {
        let beta4 = try XCTUnwrap(
            KernelCredentialManagerSignatures.variant(named: "ios272b4-24B5110a-acm-v1")
        )
        let release = try XCTUnwrap(
            KernelCredentialManagerSignatures.variant(named: "ios272-24B119-acm-v1")
        )

        XCTAssertEqual(release.functions.map(\.name), beta4.functions.map(\.name))
        XCTAssertEqual(
            release.functions.filter(\.needsScoring).map(\.name),
            ["updateAnalytics", "unlockItem"]
        )
        XCTAssertEqual(
            release.functions.map(\.needsScoring),
            beta4.functions.map(\.needsScoring)
        )
        // Word counts are part of the shape: a shortened descriptor would
        // match more sites, and the scored entries are sized to span the
        // drifted tail that makes them ambiguous in the first place.
        XCTAssertEqual(
            release.functions.map { $0.pattern.values.count },
            beta4.functions.map { $0.pattern.values.count }
        )
    }

    /// 27.2 release became reviewed after its own erase restore and repeat boot.
    ///
    /// This test started life asserting `.experimental`, which was the right
    /// guarantee while the build had resolved and been measured but never
    /// booted. The guarantee that matters now is the same one stated forwards:
    /// the promotion happened, so the entry must keep carrying the oracles that
    /// were measured from this build rather than quietly inheriting beta 4's.
    ///
    /// Device run on 2026-10-31: erase restore, SSHRD provisioning, normal
    /// boot, repeat boot, finalization and setup-debugger. Repeat boot is the
    /// gate that took the longest to meet, and /var/mobile/jbboot.log carrying
    /// two appended `=== jbboot start ===` blocks is what closed it.
    ///
    /// The oracles are pinned against beta 4's as well. Two entries agreeing on
    /// every oracle would be the signature of one having been copied from the
    /// other instead of measured: these share the Setup count and differ on the
    /// daemon count and both digests.
    func testTwoSevenTwoReleaseWorkflowIsReviewedAfterItsOwnDeviceRun() throws {
        let release = try XCTUnwrap(
            DeviceWorkflowRegistry.profiles.first { $0.build == "24B119" }
        )
        let beta4 = try XCTUnwrap(
            DeviceWorkflowRegistry.profiles.first { $0.build == "24B5110a" }
        )

        XCTAssertEqual(release.validationState, .reviewed)
        XCTAssertEqual(release.productVersion, "27.2")
        XCTAssertEqual(release.deviceClass, "n104ap")
        XCTAssertEqual(release.launchdCacheDaemonCount, 732)
        XCTAssertEqual(release.setupControllerMethodCount, 64)

        XCTAssertEqual(release.setupControllerMethodCount, beta4.setupControllerMethodCount)
        XCTAssertNotEqual(release.launchdCacheDaemonCount, beta4.launchdCacheDaemonCount)
        XCTAssertNotEqual(release.launchdSHA256, beta4.launchdSHA256)
        XCTAssertNotEqual(release.launchdCacheSHA256, beta4.launchdCacheSHA256)
    }
}
