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

    func testTFP0SupportCoversEveryIPhone11BuildFrom270On() {
        let resolverBuilds = KernelResolverProfileRegistry.profiles
            .filter { $0.variants(for: KernelTFP0Resolver.variantKey) != nil }
            .flatMap(\.builds)
            .sorted()
        XCTAssertEqual(resolverBuilds, [
            "24A435", "24A437", "24A446",
            "24B119", "24B156", "24B5084k", "24B5089g", "24B5099f", "24B5110a",
            "24C5037i",
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
            "iphone12,1-n104ap-24B156",
            "iphone12,1-n104ap-24B5084k",
            "iphone12,1-n104ap-24B5089g",
            "iphone12,1-n104ap-24B5099f",
            "iphone12,1-n104ap-24B5110a",
            "iphone12,1-n104ap-24C5037i",
        ])
    }

    /// Two builds must never claim one XNU string: `detect` returns nil on a
    /// tie, which would silently disable every kernel resolver for both.
    func testKernelResolverFingerprintsAreUnique() {
        let fingerprints = KernelResolverProfileRegistry.profiles.map(\.embeddedFingerprint)
        XCTAssertEqual(
            fingerprints.count,
            Set(fingerprints).count,
            "duplicate embedded fingerprint: \(fingerprints.sorted())"
        )
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
        // By id, not by build: 24B119 also carries two experimental Pro
        // entries, and `first { $0.build == ... }` would depend on array order
        // to keep finding the iPhone 11 one.
        let release = try XCTUnwrap(
            DeviceWorkflowRegistry.profiles.first { $0.id == "iphone12,1-n104ap-24B119" }
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

    /// The 27.2 Pro entries must stay experimental and keep their own measured
    /// service-cache digest.
    ///
    /// They legitimately share `launchdSHA256`, the daemon count and the Setup
    /// count with the iPhone 11 entry, because /sbin/launchd is byte-identical
    /// across the boards and the other two were read from the Pro rootfs and
    /// came back equal. That makes the service-cache digest the only oracle
    /// that can show these were measured rather than copied from the reviewed
    /// n104 entry, so it is pinned as different here.
    func testTwoSevenTwoProEntriesAreExperimentalAndMeasuredSeparately() throws {
        let n104 = try XCTUnwrap(
            DeviceWorkflowRegistry.profiles.first { $0.id == "iphone12,1-n104ap-24B119" }
        )
        let pro = DeviceWorkflowRegistry.profiles.filter {
            $0.build == "24B119" && $0.deviceClass.hasPrefix("d4")
        }
        XCTAssertEqual(pro.map(\.id).sorted(), [
            "iphone12,3-d421ap-24B119",
            "iphone12,5-d431ap-24B119",
        ])

        for entry in pro {
            XCTAssertEqual(entry.validationState, .experimental)
            XCTAssertEqual(entry.productVersion, "27.2")
            XCTAssertEqual(entry.chipID, 0x8030)
            XCTAssertEqual(entry.launchdSHA256, n104.launchdSHA256)
            XCTAssertEqual(entry.launchdCacheDaemonCount, n104.launchdCacheDaemonCount)
            XCTAssertEqual(entry.setupControllerMethodCount, n104.setupControllerMethodCount)
            XCTAssertNotEqual(entry.launchdCacheSHA256, n104.launchdCacheSHA256)

            // No device has run these, so neither the n104 display workaround
            // nor the n104-only tfp0 runtime evidence may leak onto them.
            XCTAssertEqual(entry.bootPlan.normalIBSSAdditionalPlans, [])
            XCTAssertEqual(entry.bootPlan.restoreIBSSAdditionalPlans, [])
            XCTAssertFalse(entry.bootPlan.supportsTFP0KernelTaskPort)
        }
    }

    /// One XNU fingerprint covers all three 24B119 boards, so the kernel
    /// profile has to name them rather than being split in two.
    ///
    /// Splitting would give two profiles the same fingerprint, and `detect`
    /// returns nil on a tie: every kernel plan would silently lose variant
    /// selection on both. The `builds` list must stay single-entry for the
    /// same reason `testNoBuildIDIsClaimedByTwoProfiles` exists.
    func testTwoSevenTwoKernelProfileCoversBothProBoards() throws {
        let profile = try XCTUnwrap(
            KernelResolverProfileRegistry.profiles.first { $0.id == "ios272-24B119-n104ap" }
        )
        XCTAssertEqual(profile.boards.sorted(), ["d421ap", "d431ap", "n104ap"])
        // 24B156 (27.2.1) is this build's point release: same XNU string,
        // kernelcache byte-identical apart from UUID/version metadata, and
        // every kernel plan resolving to identical records, so it joins the
        // same profile's `builds` the way 24A446 joined 24A435's.
        XCTAssertEqual(profile.builds, ["24B119", "24B156"])

        let claiming = KernelResolverProfileRegistry.profiles.filter { $0.covers(build: "24B119") }
        XCTAssertEqual(claiming.map(\.id), [profile.id])

        let claimingPoint = KernelResolverProfileRegistry.profiles
            .filter { $0.covers(build: "24B156") }
        XCTAssertEqual(claimingPoint.map(\.id), [profile.id])
    }

    /// 27.3 beta 1 must name its own ACM family, for the same reason every
    /// 27.2 seed does: the shapes match the previous build and the raw words
    /// differ in the masked fields, so a shared family would work today while
    /// letting one build's addresses stand in for the other's.
    func testTwoSevenThreeBetaOneNamesItsOwnACMFamily() throws {
        let profile = try XCTUnwrap(
            KernelResolverProfileRegistry.profiles.first { $0.covers(build: "24C5037i") },
            "no kernel profile covers 27.3 beta 1"
        )
        let variants = try XCTUnwrap(
            profile.variants(for: KernelCredentialManagerResolver.name)
        )
        let family = try XCTUnwrap(
            KernelCredentialManagerSignatures.variant(named: variants.signature),
            "24C5037i names an unregistered ACM family"
        )
        XCTAssertEqual(family.id, variants.signature)
        XCTAssertEqual(variants.signature, "ios273b1-24C5037i-acm-v1")
        XCTAssertEqual(variants.payload, "acm-return-success-v1")
        XCTAssertEqual(variants.support, .supported)

        // The scored pair and the method order are load-bearing: the scored
        // entries are ranked inside the interval their neighbours establish,
        // so a family that moved or rescored them would silently patch
        // another function.
        let reference = try XCTUnwrap(
            KernelCredentialManagerSignatures.variant(named: "ios272-24B119-acm-v1")
        )
        XCTAssertEqual(family.functions.map(\.name), reference.functions.map(\.name))
        XCTAssertEqual(
            family.functions.filter(\.needsScoring).map(\.name),
            ["updateAnalytics", "unlockItem"]
        )
        XCTAssertEqual(family.functions.map(\.needsScoring), reference.functions.map(\.needsScoring))
        XCTAssertEqual(
            family.functions.map { $0.pattern.values.count },
            reference.functions.map { $0.pattern.values.count }
        )
    }

    /// The 27.3 beta 1 kernel profile covers all three boards under one
    /// fingerprint, measured from both shipped IPSWs.
    ///
    /// `kernelcache.release.iphone12b` (iPhone 11) and
    /// `kernelcache.release.iphone12` (11 Pro / Pro Max) are different
    /// artifacts embedding the same XNU string, so they cannot be separate
    /// profiles without making `detect` ambiguous.
    func testTwoSevenThreeBetaOneKernelProfileCoversAllThreeBoards() throws {
        let profile = try XCTUnwrap(
            KernelResolverProfileRegistry.profiles.first { $0.id == "ios273b1-24C5037i-n104ap" }
        )
        XCTAssertEqual(profile.boards.sorted(), ["d421ap", "d431ap", "n104ap"])
        XCTAssertEqual(profile.builds, ["24C5037i"])
        XCTAssertEqual(
            profile.embeddedFingerprint,
            "xnu-13432.60.57~17/RELEASE_ARM64_T8030"
        )

        let claiming = KernelResolverProfileRegistry.profiles.filter { $0.covers(build: "24C5037i") }
        XCTAssertEqual(claiming.map(\.id), [profile.id])
    }

    /// The 27.3 beta 1 device entries: n104 reviewed after its own device
    /// run, the Pro boards still experimental, all with measured oracles.
    ///
    /// Measured, not carried: the daemon count moved (737, against 732 on
    /// 24B119), the Setup count held at 64, `/sbin/launchd` is byte-identical
    /// across the boards so all three share its digest, and the two service
    /// caches differ from each other and from every other entry in the
    /// registry - which is what shows the volumes were measured separately
    /// rather than one entry copied and edited. The digests are pinned
    /// verbatim so a re-measurement that drifts fails loudly here instead of
    /// failing at provision time on the device.
    func testTwoSevenThreeDeviceEntriesAreMeasuredAndReviewedOnN104() throws {
        let n104 = try XCTUnwrap(
            DeviceWorkflowRegistry.profiles.first { $0.id == "iphone12,1-n104ap-24C5037i" }
        )
        XCTAssertEqual(n104.validationState, .reviewed)
        XCTAssertEqual(n104.productVersion, "27.3")
        XCTAssertEqual(n104.build, "24C5037i")
        XCTAssertEqual(n104.launchdSHA256,
                       "4e338d7aef1a1f77572dec5ef14eb64987080b1d22f5e0a580536cfd645bd078")
        XCTAssertEqual(n104.launchdCacheSHA256,
                       "0396c1683b660728c24b16ab599989d9a87b1ac4d12cd9273dfe1efcc7ac9e75")
        XCTAssertEqual(n104.launchdCacheDaemonCount, 737)
        XCTAssertEqual(n104.setupControllerMethodCount, 64)
        // n104 display behaviour carried from five device-run builds; tfp0
        // stays off until this build has runtime evidence of its own.
        XCTAssertEqual(n104.bootPlan.normalIBSSAdditionalPlans, [.skipDisplayInitialization])
        XCTAssertEqual(n104.bootPlan.restoreIBSSAdditionalPlans, [.skipDisplayInitialization])
        // On with runtime evidence: kernel task port, live slide via the
        // cave, kernel-map write/read round trip, and a patched byte read
        // back at slide+unslid. See docs/runs/IOS_273_24C5037i_TFP0.md.
        XCTAssertTrue(n104.bootPlan.supportsTFP0KernelTaskPort)

        let pro = DeviceWorkflowRegistry.profiles.filter {
            $0.build == "24C5037i" && $0.deviceClass.hasPrefix("d4")
        }
        XCTAssertEqual(pro.map(\.id).sorted(), [
            "iphone12,3-d421ap-24C5037i",
            "iphone12,5-d431ap-24C5037i",
        ])
        for entry in pro {
            XCTAssertEqual(entry.validationState, .experimental)
            XCTAssertEqual(entry.launchdSHA256, n104.launchdSHA256)
            XCTAssertEqual(entry.launchdCacheDaemonCount, n104.launchdCacheDaemonCount)
            XCTAssertEqual(entry.setupControllerMethodCount, n104.setupControllerMethodCount)
            XCTAssertNotEqual(entry.launchdCacheSHA256, n104.launchdCacheSHA256)
            XCTAssertEqual(entry.bootPlan.normalIBSSAdditionalPlans, [])
            XCTAssertEqual(entry.bootPlan.restoreIBSSAdditionalPlans, [])
            XCTAssertFalse(entry.bootPlan.supportsTFP0KernelTaskPort)
        }
        XCTAssertEqual(
            pro.map(\.launchdCacheSHA256),
            ["369991684c9173cfd3be3b3c27aea2f0214a60cc038591b92cddca06e88802fe",
             "369991684c9173cfd3be3b3c27aea2f0214a60cc038591b92cddca06e88802fe"]
        )

        // No service-cache digest may appear under two builds. Boards of one
        // build family may share a digest - d421 and d431 ship one OS volume
        // between them - but a digest that spans builds is the signature of
        // an entry copied instead of measured.
        let cachesPerBuild = Dictionary(grouping: DeviceWorkflowRegistry.profiles, by: \.build)
            .mapValues { Set($0.map(\.launchdCacheSHA256)) }
        let allCaches = Set(cachesPerBuild.values.flatMap { $0 })
        XCTAssertEqual(
            allCaches.count,
            cachesPerBuild.values.flatMap { $0 }.count,
            "a launchd.plist digest is shared across builds: \(cachesPerBuild)"
        )
    }

    /// The 27.2.1 (24B156) entries: measured, still experimental, sharing
    /// 24B119's kernel profile and ACM family the way 24A446 shares 24A435's.
    ///
    /// 24B156 is 24B119's point release. Its kernelcache embeds the same XNU
    /// string and is byte-identical to 24B119's apart from 1871 bytes in 155
    /// UUID/version-metadata runs, and all fifteen kernel plans resolve to
    /// record-for-record identical JSON on both caches, so one profile and
    /// one ACM family cover both build IDs. The device entries were measured
    /// from this build's own root filesystem: `launchdSHA256` reproduces
    /// 24B119's recorded digest (byte-identical /sbin/launchd, and a live
    /// check that the measurement method still returns a known answer), the
    /// service-cache digest is new against every other registry entry, and
    /// the counts that equal 24B119's were read from an image the differing
    /// digests prove is not 24B119's.
    func testTwoSevenTwoPointOneEntriesAreExperimentalAndMeasured() throws {
        // Kernel profile: same profile and family as 24B119, no new entry.
        let kernel = try XCTUnwrap(
            KernelResolverProfileRegistry.profiles.first { $0.covers(build: "24B156") }
        )
        XCTAssertEqual(kernel.id, "ios272-24B119-n104ap")
        let variants = try XCTUnwrap(
            kernel.variants(for: KernelCredentialManagerResolver.name)
        )
        XCTAssertEqual(variants.signature, "ios272-24B119-acm-v1")
        XCTAssertEqual(variants.payload, "acm-return-success-v1")
        XCTAssertEqual(variants.support, .supported)

        let n104 = try XCTUnwrap(
            DeviceWorkflowRegistry.profiles.first { $0.id == "iphone12,1-n104ap-24B156" }
        )
        // No device run yet: the promotion to `.reviewed` happens only after
        // this build's own erase restore and repeat boot.
        XCTAssertEqual(n104.validationState, .experimental)
        XCTAssertEqual(n104.productVersion, "27.2.1")
        XCTAssertEqual(n104.build, "24B156")
        XCTAssertEqual(n104.deviceClass, "n104ap")
        XCTAssertEqual(n104.launchdSHA256,
                       "0776cff26027264644dbf7a36049e8bc9c10fa296a787d1c62f174ccccaf40d3")
        XCTAssertEqual(n104.launchdCacheSHA256,
                       "a07c37e3ffa51167cc43c1212008a25cb650c964bafaf281a298e5c01d9f597d")
        XCTAssertEqual(n104.launchdCacheDaemonCount, 732)
        XCTAssertEqual(n104.setupControllerMethodCount, 64)
        // n104 display behaviour carried from the device-run builds on this
        // display hardware; tfp0 on by kernel identity to 24B119, whose
        // two-boot runtime evidence is recorded in docs/runs.
        XCTAssertEqual(n104.bootPlan.normalIBSSAdditionalPlans, [.skipDisplayInitialization])
        XCTAssertEqual(n104.bootPlan.restoreIBSSAdditionalPlans, [.skipDisplayInitialization])
        XCTAssertTrue(n104.bootPlan.supportsTFP0KernelTaskPort)

        // The oracles relate to 24B119's exactly as a point release should:
        // launchd equal (byte-identical file), service cache different
        // (different volume image).
        let previous = try XCTUnwrap(
            DeviceWorkflowRegistry.profiles.first { $0.id == "iphone12,1-n104ap-24B119" }
        )
        XCTAssertEqual(n104.launchdSHA256, previous.launchdSHA256)
        XCTAssertNotEqual(n104.launchdCacheSHA256, previous.launchdCacheSHA256)
    }
}
