import ArgumentParser
import Foundation
import Liter8Core

/// `inspect` keeps `<binary> <mode> [parameters]`, binary first.
///
/// ArgumentParser subcommands would have to come before the binary, and that
/// order is what the repo's own notes and docs/plans use, so the modes are
/// dispatched here instead. The trade is that `inspect --help` documents every
/// mode rather than each mode owning a separate help page.
struct Inspect: ParsableCommand {
    static let configuration = CommandConfiguration(
        abstract: "Read-only queries against a firmware binary.",
        discussion: """
        MODES:
          segments                      list segments and their file ranges
          strings <text>                count and locate a literal string
          objc-methods <selector> [words]
                                        every Objective-C implementation
          xrefs <offset>                ADRP+ADD references to a file offset
          func <offset>                 the function containing an offset
          calls <offset>                distinct direct call targets in it
          dis <offset> [words]          disassemble, 16 words by default
          pattern <word[/mask]> ...     every match of a masked signature
          pattern-at <offset> <word[/mask]> ...
                                        which words still match at one offset
          page-tail-runs [count]        page-tail zero runs, largest first

        Offsets take decimal or 0x hex. A bare signature word is compared in
        full; <word>/<mask> relaxes the masked bits.

        iBoot is raw ARM64 rather than a Mach-O, so only page-tail-runs works on
        it. Every other mode needs a Mach-O.
        """
    )

    @Argument(help: ArgumentHelp("IM4P or raw payload to read.", valueName: "binary"))
    var binary: String

    @Argument(help: ArgumentHelp("Query to run. See MODES below.", valueName: "mode"))
    var mode: String

    @Argument(
        parsing: .captureForPassthrough,
        help: ArgumentHelp("Parameters for the mode.", valueName: "parameters")
    )
    var parameters: [String] = []

    static let modes: Set<String> = [
        "segments", "strings", "objc-methods", "xrefs", "func", "calls",
        "dis", "pattern", "pattern-at", "page-tail-runs",
    ]

    // Checked here rather than in run() so an unknown mode is reported against
    // `liter8 inspect`, whose help lists the modes.
    func validate() throws {
        // `.captureForPassthrough` deliberately swallows built-in flags, so
        // ArgumentParser never sees a help request that follows the mode. Without
        // this, `inspect <binary> segments --help` reported "segments takes no
        // parameters", and `inspect <binary> dis 0x1000 --help` ignored the flag
        // and disassembled. The strategy is kept because a parameter may legally
        // begin with a dash, so the request is detected here instead.
        if parameters.contains(where: { $0 == "--help" || $0 == "-h" }) {
            throw CleanExit.helpRequest(self)
        }
        guard Self.modes.contains(mode) else {
            throw ValidationError(
                "unknown inspect mode '\(mode)'. Modes: "
                    + Self.modes.sorted().joined(separator: ", ")
            )
        }
    }

    private func offset(_ text: String?, mode: String) throws -> UInt64 {
        guard let text, let value = parseNumber(text) else {
            throw ValidationError("inspect \(mode) needs an offset, decimal or 0x hex")
        }
        return value
    }

    func run() throws {
        let artifact = try FirmwareArtifact(contentsOf: URL(fileURLWithPath: binary))
        let image = BinaryImage(data: artifact.payload)

        // Answered from the bytes alone, before BinaryInspector, which cannot even
        // be constructed for raw iBoot. Putting it after would make the mode
        // unavailable on exactly the component it was added to debug.
        if mode == "page-tail-runs" {
            guard parameters.count <= 1 else {
                throw ValidationError("inspect page-tail-runs takes at most a count")
            }
            let limit = parameters.first.flatMap(Int.init) ?? 12
            let runs = IBSSBootArgsResolver().pageTailRuns(in: image)
            print("page-tail zero runs, largest first: \(runs.count)")
            for run in runs.prefix(limit) {
                let span = String(format: "0x%llx..0x%llx", UInt64(run.start), UInt64(run.end))
                print("  \(span)  \(run.end - run.start) bytes")
            }
            return
        }

        let inspector = try BinaryInspector(image: image)
        switch mode {
        case "segments":
            guard parameters.isEmpty else {
                throw ValidationError("inspect segments takes no parameters")
            }
            inspector.segmentReport().forEach { print($0) }

        case "objc-methods":
            guard let selector = parameters.first, parameters.count <= 2 else {
                throw ValidationError("inspect objc-methods needs <selector> [words]")
            }
            let words = parameters.count > 1 ? Int(parameters[1]) ?? 2 : 2
            let methods = try inspector.objcMethods(named: selector, words: words)
            print("implementations: \(methods.count)")
            methods.forEach { print("  \($0)") }

        case "strings":
            guard parameters.count == 1 else {
                throw ValidationError("inspect strings needs exactly one <text>")
            }
            let occurrences = inspector.stringOccurrences(parameters[0])
            print("occurrences: \(occurrences.count)")
            occurrences.forEach { print("  \($0)") }

        case "xrefs":
            guard parameters.count == 1 else {
                throw ValidationError("inspect xrefs needs exactly one <offset>")
            }
            let references = try inspector.references(
                toFileOffset: try offset(parameters[0], mode: "xrefs")
            )
            print("adrp+add references: \(references.count)")
            references.forEach { print("  \($0)") }

        case "func":
            guard parameters.count == 1 else {
                throw ValidationError("inspect func needs exactly one <offset>")
            }
            let target = try offset(parameters[0], mode: "func")
            guard let start = inspector.functionStart(beforeOrAt: target) else {
                print("no enclosing arm64e prologue within 0x4000 bytes")
                return
            }
            let end = inspector.nextFunctionStart(after: start)
            print("start \(hex(start))  end \(hex(end))  words \((end - start) / 4)")

        case "calls":
            guard parameters.count == 1 else {
                throw ValidationError("inspect calls needs exactly one <offset>")
            }
            let targets = try inspector.directCallTargets(
                inFunctionContaining: try offset(parameters[0], mode: "calls")
            )
            print("distinct direct call targets: \(targets.count)")
            targets.forEach { print("  \(hex($0))") }

        case "dis":
            let start = try offset(parameters.first, mode: "dis")
            let words = parameters.count > 1 ? Int(parameters[1]) ?? 16 : 16
            try inspector.disassembly(at: start, words: words).forEach { print($0) }

        case "pattern":
            guard !parameters.isEmpty, let signature = parseMaskedWords(parameters) else {
                throw ValidationError("inspect pattern needs <word[/mask]> ...")
            }
            let hits = try inspector.patternMatches(
                values: signature.values, masks: signature.masks
            )
            print("matches: \(hits.count)")
            hits.forEach { print("  \(hex($0))") }

        case "pattern-at":
            // Report which words of a signature survive at one candidate, so a
            // drifted function reveals the single instruction that changed.
            guard parameters.count >= 2,
                  let signature = parseMaskedWords(Array(parameters.dropFirst()))
            else {
                throw ValidationError("inspect pattern-at needs <offset> <word[/mask]> ...")
            }
            try inspector.patternWordReport(
                values: signature.values,
                masks: signature.masks,
                at: try offset(parameters[0], mode: "pattern-at")
            ).forEach { print($0) }

        default:
            throw ValidationError(
                "unknown inspect mode '\(mode)'. See liter8 inspect --help"
            )
        }
    }
}

struct SurveyCommand: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "survey",
        abstract: "Run every applicable plan against an extracted firmware directory.",
        discussion: """
        Identifies components by fourcc rather than filename, prints the kernel \
        fingerprint, and exits non-zero if any plan failed.
        """
    )

    @Argument(help: ArgumentHelp("Extracted firmware directory.", valueName: "directory"))
    var directory: String

    @Flag(
        name: .customLong("guards"),
        help: """
        Also measure the boot guards. Opt-in because it decrypts and mounts an \
        8 GB root filesystem, unlike plain resolution which only reads files.
        """
    )
    var guards = false

    func run() throws {
        let url = URL(fileURLWithPath: directory).standardizedFileURL
        let status = try Survey.run(directory: url)
        if guards {
            try Survey.measureGuards(directory: url, python: nil)
        }
        throw ExitCode(status)
    }
}

struct ACMProbe: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "acm-probe",
        abstract: "Report how well a recorded ACM signature variant still matches."
    )

    @Argument(help: ArgumentHelp("Kernelcache to probe.", valueName: "kernelcache"))
    var kernelcache: String

    @Argument(help: ArgumentHelp("Signature variant to try.", valueName: "signature-variant"))
    var variant: String

    func run() throws {
        let artifact = try FirmwareArtifact(contentsOf: URL(fileURLWithPath: kernelcache))
        let reports = try KernelCredentialManagerProbe.probe(
            image: BinaryImage(data: artifact.payload),
            variant: variant
        )
        let exact = reports.filter(\.isExact).count
        print("FUNCTION                                     WORDS  RESULT")
        print("-------------------------------------------------------------------")
        for report in reports {
            let result: String
            if report.isExact {
                result = "exact at 0x\(String(report.offsets[0], radix: 16))"
            } else if report.matchedWords == 0 {
                result = "NO MATCH even at quarter length"
            } else if report.offsets.count == 1 {
                result = "\(report.matchedWords)/\(report.recordedWords) words"
                    + " at 0x\(String(report.offsets[0], radix: 16))"
            } else {
                result = "\(report.matchedWords)/\(report.recordedWords) words,"
                    + " \(report.offsets.count) sites (ambiguous)"
            }
            print("\(report.name.padding(toLength: 44, withPad: " ", startingAt: 0))"
                + "\(String(report.recordedWords).padding(toLength: 7, withPad: " ", startingAt: 0))\(result)")
        }
        print("-------------------------------------------------------------------")
        print("\(exact)/\(reports.count) usable as recorded")
    }
}

struct Profile: ParsableCommand {
    static let configuration = CommandConfiguration(
        abstract: "Identify which resolver profile a kernelcache matches."
    )

    @Argument(help: ArgumentHelp("Kernelcache to identify.", valueName: "binary"))
    var binary: String

    func run() throws {
        let artifact = try FirmwareArtifact(contentsOf: URL(fileURLWithPath: binary))
        let image = BinaryImage(data: artifact.payload)
        guard let profile = KernelResolverProfileRegistry.detect(in: image) else {
            throw PatchfinderError.unsupportedFirmwareProfile(
                resolver: "profile", profile: "unidentified", variant: "none"
            )
        }
        printProfile(profile)
    }
}

struct Profiles: ParsableCommand {
    static let configuration = CommandConfiguration(
        abstract: "List every known resolver profile."
    )

    func run() throws {
        for (index, profile) in KernelResolverProfileRegistry.profiles.enumerated() {
            if index > 0 { print("") }
            printProfile(profile)
        }
    }
}

struct PreflightCommand: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "preflight",
        abstract: "Report every host tool the workflow needs, missing ones included.",
        discussion: """
        Reports all of them at once on purpose. Resolving them one at a time as the \
        workflow reaches them means a missing SSHRD tool is discovered after the \
        restore has already erased the phone.
        """
    )

    func run() throws {
        let results = Preflight.run()
        let width = results.map(\.tool.displayName.count).max() ?? 0
        // A bundled tool reads better as `tools/gtar` than as the absolute path to
        // wherever this checkout happens to live.
        let resourceRoot = (try? Liter8Resources.resolve().base.path).map { $0 + "/" }
        let display: (URL) -> String = { url in
            guard let resourceRoot, url.path.hasPrefix(resourceRoot) else { return url.path }
            return String(url.path.dropFirst(resourceRoot.count))
        }
        for stage in Preflight.Stage.allCases {
            let inStage = results.filter { $0.tool.stage == stage }
            guard !inStage.isEmpty else { continue }
            print("\(stage.rawValue):")
            for result in inStage {
                let name = result.tool.displayName.padding(
                    toLength: width, withPad: " ", startingAt: 0
                )
                if let resolved = result.resolved {
                    print("  ok      \(name)  \(display(resolved))")
                } else {
                    print("  MISSING \(name)  \(result.tool.purpose)")
                    print("          \(String(repeating: " ", count: width))  \(result.tool.installHint)")
                }
            }
        }
        let missing = results.filter { !$0.isSatisfied }
        guard missing.isEmpty else {
            // Flush first: stdout is buffered and stderr is not, so without this
            // the summary prints above the report it summarises.
            fflush(stdout)
            let names = missing.map(\.tool.displayName).joined(separator: ", ")
            FileHandle.standardError.write(
                Data("\n\(missing.count) required tool(s) missing: \(names)\n".utf8)
            )
            throw ExitCode(1)
        }
        print("\nall required host tools resolved")
    }
}

struct Setup: ParsableCommand {
    static let configuration = CommandConfiguration(
        abstract: "Report the resolved resource directory and Python runtime."
    )

    @Option(
        name: .customLong("resource-dir"),
        help: ArgumentHelp("Liter8 resource directory to use.", valueName: "directory")
    )
    var resourceDirectory: String?

    func run() throws {
        let resources = try Liter8Resources.resolve(
            override: resourceDirectory.map {
                URL(fileURLWithPath: $0, isDirectory: true).standardizedFileURL
            }
        )
        let python = try Liter8PythonRuntime.executable(explicit: nil, resources: resources)
        print("Liter8 resources: \(resources.base.path)")
        print("Liter8 Python: \(python.path)")
    }
}
