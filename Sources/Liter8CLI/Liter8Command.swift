import ArgumentParser
import Foundation
import Liter8Core

/// Root of the CLI.
///
/// The previous hand-rolled parser printed one global usage block for every
/// `--help`, so `liter8 fw boot --help` described the whole program rather than
/// `fw boot`. Declaring the tree gives scoped help at every level, and makes each
/// action's accepted options structural instead of a list of manual guards.
///
/// ArgumentParser owns the entry point. A custom `main` was tried, to keep the old
/// `error: <interpolated>` formatting for runtime failures, and it broke every
/// `--help`: `parseAsRoot()` succeeds for a help request, and the request then
/// surfaces as an error thrown from `run()`, where a hand-written catch swallows
/// it. Slightly longer error text is not worth owning that.
@main
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
