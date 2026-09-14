import Foundation
@testable import Liter8Core

enum KernelFixtureStoreError: Error, Sendable {
    case missingBinary(String)
}

/// Identifies one immutable kernel fixture.
///
/// The build and board are part of the key deliberately. Liter8 now researches
/// more than one iOS build, so a process-local cache must never return beta-4
/// records to an RC test merely because both tests requested `.restore`.
struct KernelFixtureIdentity: Hashable, Sendable {
    let build: String
    let board: String
    let binaryPath: String
}

/// The expensive resolver operations that fixture tests are allowed to share.
enum KernelFixturePlan: Hashable, Sendable {
    case restore
    case bootPolicy
    case sep
    case credentialManager
    case sandbox
    case compatibilitySandbox

    func resolve(in image: BinaryImage) throws -> [PatchRecord] {
        switch self {
        case .restore:
            return try KernelRestoreResolver().resolve(in: image)
        case .bootPolicy:
            return try KernelBootPolicyResolver().resolve(in: image)
        case .sep:
            return try KernelSEPResolver().resolve(in: image)
        case .credentialManager:
            return try KernelCredentialManagerResolver().resolve(in: image)
        case .sandbox:
            return try KernelSandboxResolver().resolve(in: image)
        case .compatibilitySandbox:
            return try KernelSandboxResolver(includeScopedVnodeOpen: false).resolve(in: image)
        }
    }
}

/// Process-local, single-flight storage for real kernel fixture work.
///
/// We cache `Task`s rather than completed arrays. If two parallel tests request
/// the same plan, the first creates the scan and the second immediately awaits
/// that exact in-flight scan instead of starting another ten-minute duplicate.
/// Nothing is persisted to disk; every new `swift test` process starts clean.
actor KernelFixtureStore {
    static let shared = KernelFixtureStore()

    struct Snapshot: Sendable {
        let image: BinaryImage
    }

    private struct ResolutionKey: Hashable, Sendable {
        let fixture: KernelFixtureIdentity
        let plan: KernelFixturePlan
    }

    private var snapshotTasks: [KernelFixtureIdentity: Task<Snapshot, Error>] = [:]
    private var resolutionTasks: [ResolutionKey: Task<[PatchRecord], Error>] = [:]

    func snapshot(for fixture: KernelFixtureIdentity) async throws -> Snapshot {
        try await snapshotTask(for: fixture).value
    }

    func records(
        for plan: KernelFixturePlan,
        fixture: KernelFixtureIdentity
    ) async throws -> [PatchRecord] {
        let key = ResolutionKey(fixture: fixture, plan: plan)
        if let existing = resolutionTasks[key] {
            return try await existing.value
        }

        // Capture the input task before leaving actor isolation. Resolver work
        // is synchronous and CPU-heavy, so it belongs on a detached executor;
        // the actor should only coordinate ownership of shared tasks.
        let inputTask = snapshotTask(for: fixture)
        let task = Task.detached(priority: .userInitiated) {
            let snapshot = try await inputTask.value
            return try plan.resolve(in: snapshot.image)
        }

        // Store before the first await. A concurrent caller can now discover
        // and join this task even while the scan is still running.
        resolutionTasks[key] = task
        return try await task.value
    }

    private func snapshotTask(
        for fixture: KernelFixtureIdentity
    ) -> Task<Snapshot, Error> {
        if let existing = snapshotTasks[fixture] {
            return existing
        }

        let path = fixture.binaryPath
        let task = Task.detached(priority: .utility) {
            guard FileManager.default.fileExists(atPath: path) else {
                throw KernelFixtureStoreError.missingBinary(path)
            }
            return Snapshot(image: try BinaryImage(contentsOf: URL(fileURLWithPath: path)))
        }

        snapshotTasks[fixture] = task
        return task
    }
}
