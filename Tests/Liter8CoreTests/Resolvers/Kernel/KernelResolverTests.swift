import CryptoKit
import Foundation
import XCTest
@testable import Liter8Core

/// Exact beta-4 kernel oracles backed by a process-local resolution cache.
///
/// These remain integration tests against the real kernelcache. The cache only
/// removes duplicate scans; each test still checks its complete fixture and
/// patched-image digest independently.
final class KernelFixtureTests: XCTestCase {
    private var packageRoot: URL {
        liter8PackageRoot(from: #filePath)
    }

    private var privateFixtureRoot: URL {
        liter8PrivateFixtureRoot(from: #filePath)
    }

    private var beta4Fixture: KernelFixtureIdentity {
        KernelFixtureIdentity(
            build: "24A5390f",
            board: "n104ap",
            binaryPath: privateFixtureRoot
                .appendingPathComponent("offsets/kc/kc_b4_n104.raw")
                .path
        )
    }

    private func requireBeta4Fixture() throws -> KernelFixtureIdentity {
        let fixture = beta4Fixture
        guard FileManager.default.fileExists(atPath: fixture.binaryPath) else {
            throw XCTSkip("local beta-4 kernelcache fixture is absent")
        }
        return fixture
    }

    private func manifest(_ name: String) throws -> FixtureManifest {
        try FixtureManifest.load(
            from: packageRoot.appendingPathComponent("fixtures/24A5390f/n104ap/\(name)")
        )
    }

    func testKernelRestoreManifestRediscoversBeta4SitesAndOutput() async throws {
        let fixture = try requireBeta4Fixture()
        let snapshot = try await KernelFixtureStore.shared.snapshot(for: fixture)
        let records = try await KernelFixtureStore.shared.records(for: .restore, fixture: fixture)
        let manifest = try manifest("kernel-restore-n104-24A5390f.json")
        try manifest.verify(resolved: records, in: snapshot.image)
        XCTAssertEqual(records.count, 20)
    }

    func testKernelBootPolicyRediscoversBeta4Sites() async throws {
        let fixture = try requireBeta4Fixture()
        let snapshot = try await KernelFixtureStore.shared.snapshot(for: fixture)
        let records = try await KernelFixtureStore.shared.records(for: .bootPolicy, fixture: fixture)
        let manifest = try manifest("kernel-boot-policy-n104-24A5390f.json")
        try manifest.verify(resolved: records, in: snapshot.image)
        XCTAssertEqual(records.count, 4)
    }

    func testKernelSEPFamilyRediscoversBeta4Sites() async throws {
        let fixture = try requireBeta4Fixture()
        let snapshot = try await KernelFixtureStore.shared.snapshot(for: fixture)
        let records = try await KernelFixtureStore.shared.records(for: .sep, fixture: fixture)
        let manifest = try manifest("kernel-sep-n104-24A5390f.json")

        // The fixture checks input identity, all 32 discovered sites, guarded
        // original bytes, replacements, and the final patched-image digest.
        try manifest.verify(resolved: records, in: snapshot.image)
        XCTAssertEqual(records.count, 32)
    }

    func testKernelCredentialManagerRediscoversBeta4Entries() async throws {
        let fixture = try requireBeta4Fixture()
        let snapshot = try await KernelFixtureStore.shared.snapshot(for: fixture)
        let records = try await KernelFixtureStore.shared.records(for: .credentialManager, fixture: fixture)
        let manifest = try manifest("kernel-credential-manager-n104-24A5390f.json")

        // This checks every resolved entry and the complete patched-image hash,
        // not just the number of functions the resolver happened to return.
        try manifest.verify(resolved: records, in: snapshot.image)
        XCTAssertEqual(records.count, 52)
    }

    func testKernelSandboxRediscoversBeta4Plan() async throws {
        let fixture = try requireBeta4Fixture()
        let snapshot = try await KernelFixtureStore.shared.snapshot(for: fixture)
        let records = try await KernelFixtureStore.shared.records(for: .sandbox, fixture: fixture)
        let manifest = try manifest("kernel-sandbox-n104-24A5390f.json")

        // This includes the generated cave words and final output digest, so a
        // branch-encoding error cannot pass merely by finding the right sites.
        try manifest.verify(resolved: records, in: snapshot.image)
        XCTAssertEqual(records.count, 46)
    }

    func testCompatibilityKernelPlanCompositionAgainstBeta4Oracle() async throws {
        let fixture = try requireBeta4Fixture()

        // Start every missing component together. The actor memoizes each task,
        // so component tests and this composition test converge on one scan per
        // plan regardless of which XCTest begins first.
        async let restore = KernelFixtureStore.shared.records(for: .restore, fixture: fixture)
        async let bootPolicy = KernelFixtureStore.shared.records(for: .bootPolicy, fixture: fixture)
        async let sep = KernelFixtureStore.shared.records(for: .sep, fixture: fixture)
        async let credentialManager = KernelFixtureStore.shared.records(for: .credentialManager, fixture: fixture)
        async let sandbox = KernelFixtureStore.shared.records(for: .compatibilitySandbox, fixture: fixture)

        let records = try await KernelBootPlanComposer.compose(
            restore: restore,
            bootPolicy: bootPolicy,
            sep: sep,
            credentialManager: credentialManager,
            sandbox: sandbox
        )

        // 20 restore + 2 persona + 32 SEP + 52 CredentialManager +
        // 2 USB + 11 published Sandbox records = 119.
        XCTAssertEqual(records.count, 119)
        XCTAssertFalse(records.contains { $0.id.contains("vnode-check-open") })

        let snapshot = try await KernelFixtureStore.shared.snapshot(for: fixture)
        let patched = try GuardedPatchApplier.apply(records, to: snapshot.image)
        let digest = SHA256.hash(data: patched.data)
            .map { String(format: "%02x", $0) }
            .joined()
        XCTAssertEqual(
            digest,
            "3a95ffe9cab7e191164ca23fc6eb9ee49ed6380659155e3f831c6bc584ec8ecb"
        )
    }
}

/// Deliberately uncached verification of the production composite resolver.
///
/// This repeats the expensive scans because it answers a different question:
/// does the public production plan still call the right component resolvers in
/// the right configuration? Keep it in the explicit end-to-end test tier.
final class KernelEndToEndTests: XCTestCase {
    func testCompatibilityKernelProductionWiringAgainstBeta4Oracle() throws {
        let privateFixtureRoot = liter8PrivateFixtureRoot(from: #filePath)
        let beta4Kernel = privateFixtureRoot.appendingPathComponent("offsets/kc/kc_b4_n104.raw")
        guard FileManager.default.fileExists(atPath: beta4Kernel.path) else {
            throw XCTSkip("local beta-4 kernelcache fixture is absent")
        }

        let image = try BinaryImage(contentsOf: beta4Kernel)
        let records = try KernelBootCompatibilityResolver().resolve(in: image)

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
