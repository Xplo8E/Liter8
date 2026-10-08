import ArgumentParser
import Darwin
import Foundation
import Liter8Core

/// Root of the CLI.
///
/// The previous hand-rolled parser printed one global usage block for every
/// `--help`, so `liter8 fw boot --help` described the whole program rather than
/// `fw boot`. Declaring the tree gives scoped help at every level, and makes each
/// action's accepted options structural instead of a list of manual guards.
struct Liter8: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "liter8",
        abstract: "Semantic firmware patcher and device workflow for iPhone 11.",
        discussion: """
        Offsets are outputs, never inputs: every patch site is rediscovered in the \
        binary in front of it. Run `liter8 fw actions` for the device workflow, or \
        `liter8 <command> --help` for anything below.
        """,
        subcommands: [
            Firmware.self,
            Resolve.self,
            Apply.self,
            Inspect.self,
            // Named apart from the Liter8Core types they call into.
            SurveyCommand.self,
            Fixture.self,
            Verify.self,
            IM4P.self,
            IMG4.self,
            Profile.self,
            Profiles.self,
            ACMProbe.self,
            PreflightCommand.self,
            Setup.self,
        ]
    )
}

/// Entry point.
///
/// ArgumentParser owns parsing, help and its own error formatting. Everything a
/// command throws at runtime is reported the way this CLI always has: the full
/// interpolated error and exit status 1.
///
/// That distinction is not cosmetic. ArgumentParser reports a generic error by its
/// `localizedDescription`, which for a Foundation file error drops the path and
/// leaves "the file could not be opened" with no clue which file. Interpolating
/// keeps `NSFilePath`, and keeps what scripts around this CLI already match on.
@main
enum Liter8Main {
    static func main() {
        var command: ParsableCommand
        do {
            command = try Liter8.parseAsRoot()
        } catch {
            // Help requests, unknown options, bad argument counts, and the
            // ValidationErrors the commands throw before doing any work.
            Liter8.exit(withError: error)
        }
        do {
            try command.run()
        } catch let exit as ExitCode {
            Darwin.exit(exit.rawValue)
        } catch let clean as CleanExit {
            Liter8.exit(withError: clean)
        } catch let validation as ValidationError {
            Liter8.exit(withError: validation)
        } catch {
            FileHandle.standardError.write(Data("error: \(error)\n".utf8))
            Darwin.exit(1)
        }
    }
}
