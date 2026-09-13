import Foundation

/// Small, explicit boundary around mature command-line ZIP implementations.
///
/// Liter8 still owns firmware selection, staging and verification. 7-Zip owns
/// full IPSW extraction; macOS `unzip` remains only for reading one small plist
/// and `zipinfo` supplies the independent safety inventory.
public enum IPSWUnzip {
    private static let unzipExecutable = URL(fileURLWithPath: "/usr/bin/unzip")
    private static let zipinfoExecutable = URL(fileURLWithPath: "/usr/bin/zipinfo")
    private static let defaultSevenZipExecutable = URL(fileURLWithPath: "/opt/homebrew/bin/7zz")

    // These are sanity limits, not estimates of one particular firmware. They
    // leave ample room for Apple IPSWs while refusing archive metadata that
    // could otherwise consume the complete destination volume.
    private static let maximumEntryCount = 250_000
    private static let maximumUncompressedSize: UInt64 = 64 * 1024 * 1024 * 1024
    private static let maximumListingSize = 64 * 1024 * 1024
    private static let maximumDiagnosticSize = 16 * 1024

    private enum EntryKind {
        case file
        case directory
    }

    private struct ArchiveEntry {
        let path: String
        let kind: EntryKind
        let uncompressedSize: UInt64
    }

    private struct ArchiveInventory {
        let entries: [ArchiveEntry]

        var totalUncompressedSize: UInt64 {
            entries.reduce(0) { $0 + $1.uncompressedSize }
        }
    }

    /// Read one small archive member without extracting the complete IPSW.
    public static func read(
        _ member: String,
        from ipsw: URL,
        maximumSize: Int = 32 * 1024 * 1024
    ) throws -> Data {
        try captureStandardOutput(
            executable: unzipExecutable,
            arguments: ["-p", ipsw.path, member],
            maximumSize: maximumSize,
            operation: "read \(member) from \(ipsw.lastPathComponent)"
        )
    }

    /// Extract the IPSW into a caller-created empty staging directory.
    ///
    /// Normal member listings are captured instead of printed. On failure, only
    /// a bounded tail is included in the error, so useful warnings survive but
    /// hundreds of successful member paths never flood the terminal.
    public static func extract(_ ipsw: URL, to destination: URL) throws {
        let fileManager = FileManager.default
        var isDirectory: ObjCBool = false
        guard fileManager.fileExists(atPath: destination.path, isDirectory: &isDirectory),
              isDirectory.boolValue,
              (try fileManager.contentsOfDirectory(atPath: destination.path)).isEmpty else {
            throw PatchfinderError.invalidFixture(
                "IPSW extraction destination must be an empty directory: \(destination.path)"
            )
        }

        // Inspect metadata before writing anything. This restores the strict
        // path, duplicate, size and symlink checks from the native ZIP reader.
        let archiveInventory = try inventory(of: ipsw)
        let sevenZip = sevenZipExecutable()
        guard FileManager.default.isExecutableFile(atPath: sevenZip.path) else {
            throw PatchfinderError.invalidFixture(
                "7-Zip is required for IPSW extraction: \(sevenZip.path) is not executable"
            )
        }
        let diagnostics = try temporaryCaptureFile()
        defer {
            try? diagnostics.handle.close()
            try? fileManager.removeItem(at: diagnostics.url)
        }

        let process = Process()
        process.executableURL = sevenZip
        process.arguments = [
            "x",
            "-y",       // Never stop for an overwrite prompt inside staging.
            "-bd",      // Disable percentage/progress rendering.
            "-bb0",     // Keep the successful member listing quiet.
            "-bso0",    // Suppress routine stdout; diagnostics remain bounded.
            "-bsp0",    // Do not emit progress on another output stream.
            "-o\(destination.path)",
            ipsw.path,
        ]
        process.standardInput = FileHandle.standardInput
        // Sharing one file handle between both streams prevents pipe deadlocks
        // and preserves a bounded failure tail without flooding the terminal.
        process.standardOutput = diagnostics.handle
        process.standardError = diagnostics.handle

        let finished = DispatchSemaphore(value: 0)
        process.terminationHandler = { _ in finished.signal() }
        try process.run()
        while finished.wait(timeout: .now() + 5) == .timedOut {
            let extracted = logicalFileSize(of: destination)
            let total = archiveInventory.totalUncompressedSize
            let percent = total == 0 ? 100 : min(100, Int(extracted * 100 / total))
            print(
                String(
                    format: "  extracted %.2f / %.2f GB (%d%%)",
                    Double(extracted) / 1_000_000_000,
                    Double(total) / 1_000_000_000,
                    percent
                )
            )
            fflush(stdout)
        }
        process.waitUntilExit()
        try diagnostics.handle.close()
        guard process.terminationReason == .exit, process.terminationStatus == 0 else {
            throw commandError(
                operation: "extract \(ipsw.lastPathComponent)",
                status: process.terminationStatus,
                diagnostics: try boundedTail(of: diagnostics.url)
            )
        }

        // 7-Zip validates CRCs. This second pass validates the filesystem it
        // actually created before the caller can publish the staging tree.
        try verify(archiveInventory, at: destination)
    }

    /// Sum logical file lengths, including the currently growing 7-Zip output.
    /// IPSWs contain few entries, so this five-second progress probe is cheap
    /// and, unlike carriage-return output, remains visible in captured logs.
    private static func logicalFileSize(of directory: URL) -> UInt64 {
        guard let enumerator = FileManager.default.enumerator(
            at: directory,
            includingPropertiesForKeys: [.isRegularFileKey, .fileSizeKey]
        ) else { return 0 }
        var total: UInt64 = 0
        for case let file as URL in enumerator {
            guard let values = try? file.resourceValues(forKeys: [
                .isRegularFileKey, .fileSizeKey,
            ]), values.isRegularFile == true, let size = values.fileSize else {
                continue
            }
            total += UInt64(size)
        }
        return total
    }

    /// Production uses the requested Homebrew binary. Tests may point at a
    /// compatible local shim without installing packages into the host.
    private static func sevenZipExecutable() -> URL {
        if let override = ProcessInfo.processInfo.environment["LITER8_7ZZ"],
           !override.isEmpty {
            return URL(fileURLWithPath: override).standardizedFileURL
        }
        return defaultSevenZipExecutable
    }

    /// Recheck a completed extraction against the archive supplied now.
    /// This catches deleted, truncated, replaced and symlinked cached members.
    public static func verifyExtractedTree(_ ipsw: URL, at destination: URL) throws {
        try verify(inventory(of: ipsw), at: destination)
    }

    private static func inventory(of ipsw: URL) throws -> ArchiveInventory {
        let listing = try captureStandardOutput(
            executable: zipinfoExecutable,
            arguments: ["-l", ipsw.path],
            maximumSize: maximumListingSize,
            operation: "inspect \(ipsw.lastPathComponent)"
        )
        let text = String(decoding: listing, as: UTF8.self)
        let lines = text.split(separator: "\n", omittingEmptySubsequences: false)

        guard let countLine = lines.first(where: { $0.contains("number of entries:") }),
              let countMarker = countLine.range(of: "number of entries:") else {
            throw PatchfinderError.invalidFixture("zipinfo returned an unrecognized archive listing")
        }
        let expectedCountText = countLine[countMarker.upperBound...]
            .trimmingCharacters(in: .whitespaces)
        guard let expectedCount = Int(expectedCountText), expectedCount <= maximumEntryCount else {
            throw PatchfinderError.invalidFixture("IPSW has an invalid or excessive entry count")
        }

        var entries: [ArchiveEntry] = []
        entries.reserveCapacity(expectedCount)
        var paths = Set<String>()
        var totalSize: UInt64 = 0

        for lineSlice in lines {
            guard let first = lineSlice.first, "?-dlcbps".contains(first) else { continue }
            let fields = lineSlice.split(
                maxSplits: 9,
                omittingEmptySubsequences: true,
                whereSeparator: { $0 == " " || $0 == "\t" }
            )
            guard fields.count == 10,
                  fields[0].count == 10,
                  let size = UInt64(fields[3]) else {
                throw PatchfinderError.invalidFixture("zipinfo returned a malformed entry record")
            }

            let path = String(fields[9])
            let normalizedPath = try validate(path: path)
            guard paths.insert(normalizedPath).inserted else {
                throw PatchfinderError.invalidFixture(
                    "IPSW contains duplicate member path: \(printable(path))"
                )
            }

            let kind: EntryKind
            switch first {
            case "-", "?":
                // Python's standard zipfile module leaves the Unix file type
                // unspecified and zipinfo renders that ordinary file as `?`.
                kind = .file
            case "d":
                kind = .directory
            case "l":
                throw PatchfinderError.invalidFixture(
                    "IPSW contains unsupported symbolic link: \(printable(path))"
                )
            default:
                throw PatchfinderError.invalidFixture(
                    "IPSW contains unsupported special member: \(printable(path))"
                )
            }

            let (nextSize, overflow) = totalSize.addingReportingOverflow(size)
            guard !overflow, nextSize <= maximumUncompressedSize else {
                throw PatchfinderError.invalidFixture("IPSW expanded size exceeds the 64-GiB limit")
            }
            totalSize = nextSize
            entries.append(ArchiveEntry(path: path, kind: kind, uncompressedSize: size))
        }

        guard entries.count == expectedCount else {
            throw PatchfinderError.invalidFixture(
                "zipinfo described \(expectedCount) entries but Liter8 parsed \(entries.count)"
            )
        }
        return ArchiveInventory(entries: entries)
    }

    private static func validate(path: String) throws -> String {
        let scalars = path.unicodeScalars
        let hasControl = scalars.contains(where: { CharacterSet.controlCharacters.contains($0) })
        let components = path.split(
            omittingEmptySubsequences: false,
            whereSeparator: { $0 == "/" || $0 == "\\" }
        )
        let meaningfulComponents = path.hasSuffix("/") ? components.dropLast() : components[...]
        guard !path.isEmpty,
              !path.hasPrefix("/"),
              !path.hasPrefix("\\"),
              !hasControl,
              !meaningfulComponents.isEmpty,
              meaningfulComponents.allSatisfy({ !$0.isEmpty && $0 != "." && $0 != ".." }) else {
            throw PatchfinderError.invalidFixture(
                "IPSW contains unsafe member path: \(printable(path))"
            )
        }
        return meaningfulComponents.joined(separator: "/")
    }

    private static func verify(_ inventory: ArchiveInventory, at destination: URL) throws {
        for entry in inventory.entries {
            let output = destination.appendingPathComponent(entry.path)
            let values: URLResourceValues
            do {
                values = try output.resourceValues(forKeys: [
                    .isRegularFileKey, .isDirectoryKey, .isSymbolicLinkKey, .fileSizeKey,
                ])
            } catch {
                throw PatchfinderError.invalidFixture(
                    "extracted IPSW member is missing: \(printable(entry.path))"
                )
            }
            guard values.isSymbolicLink != true else {
                throw PatchfinderError.invalidFixture(
                    "extracted IPSW member is a symbolic link: \(printable(entry.path))"
                )
            }

            switch entry.kind {
            case .file:
                guard values.isRegularFile == true,
                      let fileSize = values.fileSize,
                      UInt64(fileSize) == entry.uncompressedSize else {
                    throw PatchfinderError.invalidFixture(
                        "extracted IPSW member is missing or has the wrong size: \(printable(entry.path))"
                    )
                }
            case .directory:
                guard values.isDirectory == true else {
                    throw PatchfinderError.invalidFixture(
                        "extracted IPSW directory is missing: \(printable(entry.path))"
                    )
                }
            }
        }
    }

    /// Capture stderr in a real file while stdout is streamed. A file cannot
    /// fill up like a pipe, so malformed archives cannot deadlock the child.
    private static func captureStandardOutput(
        executable: URL,
        arguments: [String],
        maximumSize: Int,
        operation: String
    ) throws -> Data {
        let standardOutput = Pipe()
        let diagnostics = try temporaryCaptureFile()
        defer {
            try? diagnostics.handle.close()
            try? FileManager.default.removeItem(at: diagnostics.url)
        }

        let process = Process()
        process.executableURL = executable
        process.arguments = arguments
        process.standardOutput = standardOutput
        process.standardError = diagnostics.handle

        try process.run()
        var result = Data()
        while let chunk = try standardOutput.fileHandleForReading.read(upToCount: 64 * 1024),
              !chunk.isEmpty {
            guard chunk.count <= maximumSize,
                  result.count <= maximumSize - chunk.count else {
                process.terminate()
                process.waitUntilExit()
                throw PatchfinderError.invalidFixture(
                    "\(operation) exceeded the \(maximumSize)-byte output limit"
                )
            }
            result.append(chunk)
        }

        process.waitUntilExit()
        try diagnostics.handle.close()
        guard process.terminationReason == .exit, process.terminationStatus == 0 else {
            throw commandError(
                operation: operation,
                status: process.terminationStatus,
                diagnostics: try boundedTail(of: diagnostics.url)
            )
        }
        return result
    }

    private static func temporaryCaptureFile() throws -> (url: URL, handle: FileHandle) {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("liter8-zip-\(UUID().uuidString).log")
        guard FileManager.default.createFile(atPath: url.path, contents: nil) else {
            throw PatchfinderError.invalidFixture("could not create temporary ZIP diagnostics")
        }
        return (url, try FileHandle(forWritingTo: url))
    }

    private static func boundedTail(of url: URL) throws -> Data {
        let handle = try FileHandle(forReadingFrom: url)
        defer { try? handle.close() }
        let size = try handle.seekToEnd()
        let start = size > UInt64(maximumDiagnosticSize)
            ? size - UInt64(maximumDiagnosticSize)
            : 0
        try handle.seek(toOffset: start)
        return try handle.readToEnd() ?? Data()
    }

    private static func commandError(
        operation: String,
        status: Int32,
        diagnostics: Data
    ) -> PatchfinderError {
        let detail = String(decoding: diagnostics, as: UTF8.self)
            .trimmingCharacters(in: .whitespacesAndNewlines)
        return .invalidFixture(
            "could not \(operation) with status \(status)"
                + (detail.isEmpty ? "" : ": \(detail)")
        )
    }

    private static func printable(_ path: String) -> String {
        let clean = path.unicodeScalars.map { scalar in
            CharacterSet.controlCharacters.contains(scalar) ? "?" : String(scalar)
        }.joined()
        return clean.count <= 240 ? clean : String(clean.prefix(239)) + "…"
    }
}
