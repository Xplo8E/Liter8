import CryptoKit
import Foundation
import XCTest
@testable import Liter8Core

final class KernelResolverTests: XCTestCase {
    private var packageRoot: URL {
        liter8PackageRoot(from: #filePath)
    }

    private var privateFixtureRoot: URL {
        liter8PrivateFixtureRoot(from: #filePath)
    }

    func testKernelRestoreManifestRediscoversBeta4SitesAndOutput() throws {
        let beta4Kernel = privateFixtureRoot.appendingPathComponent("offsets/kc/kc_b4_n104.raw")
        guard FileManager.default.fileExists(atPath: beta4Kernel.path) else {
            throw XCTSkip("local beta-4 kernelcache fixture is absent")
        }
        let manifest = try FixtureManifest.load(
            from: packageRoot.appendingPathComponent(
                "fixtures/24A5390f/n104ap/kernel-restore-n104-24A5390f.json"
            )
        )
        XCTAssertEqual(try manifest.verify(binaryAt: beta4Kernel).count, 20)
    }

    func testKernelBootPolicyRediscoversBeta4Sites() throws {
        let beta4Kernel = privateFixtureRoot.appendingPathComponent("offsets/kc/kc_b4_n104.raw")
        guard FileManager.default.fileExists(atPath: beta4Kernel.path) else {
            throw XCTSkip("local beta-4 kernelcache fixture is absent")
        }
        let manifest = try FixtureManifest.load(
            from: packageRoot.appendingPathComponent(
                "fixtures/24A5390f/n104ap/kernel-boot-policy-n104-24A5390f.json"
            )
        )
        XCTAssertEqual(try manifest.verify(binaryAt: beta4Kernel).count, 4)
    }

    func testKernelSEPFamilyRediscoversBeta4Sites() throws {
        let beta4Kernel = privateFixtureRoot.appendingPathComponent("offsets/kc/kc_b4_n104.raw")
        guard FileManager.default.fileExists(atPath: beta4Kernel.path) else {
            throw XCTSkip("local beta-4 kernelcache fixture is absent")
        }
        let manifest = try FixtureManifest.load(
            from: packageRoot.appendingPathComponent(
                "fixtures/24A5390f/n104ap/kernel-sep-n104-24A5390f.json"
            )
        )

        // The fixture checks input identity, all 32 discovered sites, guarded
        // original bytes, replacements, and the final patched-image digest.
        XCTAssertEqual(try manifest.verify(binaryAt: beta4Kernel).count, 32)
    }

    func testKernelCredentialManagerRediscoversBeta4Entries() throws {
        let beta4Kernel = privateFixtureRoot.appendingPathComponent("offsets/kc/kc_b4_n104.raw")
        guard FileManager.default.fileExists(atPath: beta4Kernel.path) else {
            throw XCTSkip("local beta-4 kernelcache fixture is absent")
        }
        let manifest = try FixtureManifest.load(
            from: packageRoot.appendingPathComponent(
                "fixtures/24A5390f/n104ap/kernel-credential-manager-n104-24A5390f.json"
            )
        )

        // This checks every resolved entry and the complete patched-image hash,
        // not just the number of functions the resolver happened to return.
        XCTAssertEqual(try manifest.verify(binaryAt: beta4Kernel).count, 52)
    }

    func testKernelSandboxRediscoversBeta4Plan() throws {
        let beta4Kernel = privateFixtureRoot.appendingPathComponent("offsets/kc/kc_b4_n104.raw")
        guard FileManager.default.fileExists(atPath: beta4Kernel.path) else {
            throw XCTSkip("local beta-4 kernelcache fixture is absent")
        }
        let manifest = try FixtureManifest.load(
            from: packageRoot.appendingPathComponent(
                "fixtures/24A5390f/n104ap/kernel-sandbox-n104-24A5390f.json"
            )
        )

        // This includes the generated cave words and final output digest, so a
        // branch-encoding error cannot pass merely by finding the right sites.
        XCTAssertEqual(try manifest.verify(binaryAt: beta4Kernel).count, 46)
    }

    func testPublicBeta4KernelPlanKeepsPublishedPatchCount() throws {
        let beta4Kernel = privateFixtureRoot.appendingPathComponent("offsets/kc/kc_b4_n104.raw")
        guard FileManager.default.fileExists(atPath: beta4Kernel.path) else {
            throw XCTSkip("local beta-4 kernelcache fixture is absent")
        }

        let image = try BinaryImage(contentsOf: beta4Kernel)
        let records = try KernelBootPublicBeta4Resolver().resolve(in: image)

        // 20 restore + 2 persona + 32 SEP + 52 CredentialManager +
        // 2 USB + 11 published Sandbox records = 119.
        XCTAssertEqual(records.count, 119)
        XCTAssertFalse(records.contains { $0.id.contains("vnode-check-open") })

        // This digest was produced independently by the public Python
        // `apply_patches.py kc-boot` table. Matching it proves that the Swift
        // compatibility plan changes the same bytes, not merely 119 bytes.
        let patched = try GuardedPatchApplier.apply(records, to: image)
        let digest = SHA256.hash(data: patched.data)
            .map { String(format: "%02x", $0) }
            .joined()
        XCTAssertEqual(
            digest,
            "3a95ffe9cab7e191164ca23fc6eb9ee49ed6380659155e3f831c6bc584ec8ecb"
        )
    }
}
