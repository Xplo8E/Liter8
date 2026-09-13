import Foundation

/// Find the package root without assuming how deeply a test is grouped.
///
/// Resolver tests live beside their component, so counting parent directories
/// from `#filePath` would make harmless folder moves break the test suite.
func liter8PackageRoot(from filePath: String) -> URL {
    var candidate = URL(fileURLWithPath: filePath).deletingLastPathComponent()
    let fileManager = FileManager.default

    while candidate.path != "/" {
        if fileManager.fileExists(atPath: candidate.appendingPathComponent("Package.swift").path) {
            return candidate
        }
        candidate.deleteLastPathComponent()
    }

    preconditionFailure("could not locate Liter8 Package.swift from \(filePath)")
}

/// Locate private Apple binaries without baking the old monorepo layout into
/// public tests. Existing research checkouts keep working through the parent
/// directory default; standalone contributors can set LITER8_FIXTURE_ROOT.
func liter8PrivateFixtureRoot(from filePath: String) -> URL {
    if let configured = ProcessInfo.processInfo.environment["LITER8_FIXTURE_ROOT"],
       !configured.isEmpty {
        return URL(fileURLWithPath: configured).standardizedFileURL
    }
    return liter8PackageRoot(from: filePath).deletingLastPathComponent()
}
