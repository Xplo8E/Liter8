import ArgumentParser
import Foundation
import Liter8Core

struct IM4P: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "im4p",
        abstract: "Inspect, extract from, and repack IM4P containers.",
        subcommands: [Info.self, Extract.self, Repack.self]
    )

    /// Every mode requires an IM4P, so the check lives in one place.
    static func requireIM4P(at url: URL) throws -> FirmwareArtifact {
        let artifact = try FirmwareArtifact(contentsOf: url)
        guard artifact.kind == .im4p else {
            throw PatchfinderError.invalidFirmwareContainer(
                "\(url.lastPathComponent) is not an IM4P"
            )
        }
        return artifact
    }

    struct Info: ParsableCommand {
        static let configuration = CommandConfiguration(
            abstract: "Print the fourcc, description and payload size."
        )

        @Argument(help: ArgumentHelp("IM4P to read.", valueName: "input.im4p"))
        var input: String

        func run() throws {
            let url = URL(fileURLWithPath: input).standardizedFileURL
            let artifact = try IM4P.requireIM4P(at: url)
            print("type: IM4P")
            print("fourcc: \(artifact.fourcc ?? "unknown")")
            print("description: \(artifact.containerDescription ?? "")")
            print("payload size: \(artifact.payload.count)")
        }
    }

    struct Extract: ParsableCommand {
        static let configuration = CommandConfiguration(
            abstract: "Write the decompressed payload to a file."
        )

        @Argument(help: ArgumentHelp("IM4P to read.", valueName: "input.im4p"))
        var input: String

        @Argument(help: ArgumentHelp("Payload file to write.", valueName: "output"))
        var output: String

        func run() throws {
            let inputURL = URL(fileURLWithPath: input).standardizedFileURL
            let outputURL = URL(fileURLWithPath: output).standardizedFileURL
            guard inputURL != outputURL else {
                throw PatchfinderError.invalidFirmwareContainer("input and output paths must differ")
            }
            let artifact = try IM4P.requireIM4P(at: inputURL)
            try artifact.payload.write(to: outputURL, options: .atomic)
            print("extracted \(artifact.fourcc ?? "IM4P") payload (\(artifact.payload.count) bytes)")
            print("wrote \(outputURL.path)")
        }
    }

    struct Repack: ParsableCommand {
        static let configuration = CommandConfiguration(
            abstract: "Rebuild an IM4P around a replacement payload."
        )

        @Argument(help: ArgumentHelp("IM4P to take the container from.", valueName: "input.im4p"))
        var input: String

        @Argument(help: ArgumentHelp("Replacement payload.", valueName: "payload"))
        var payload: String

        @Argument(help: ArgumentHelp("IM4P to write.", valueName: "output.im4p"))
        var output: String

        func run() throws {
            let inputURL = URL(fileURLWithPath: input).standardizedFileURL
            let payloadURL = URL(fileURLWithPath: payload).standardizedFileURL
            let outputURL = URL(fileURLWithPath: output).standardizedFileURL
            guard outputURL != inputURL, outputURL != payloadURL else {
                throw PatchfinderError.invalidFirmwareContainer("output must differ from both inputs")
            }
            let artifact = try IM4P.requireIM4P(at: inputURL)
            let replacement = try Data(contentsOf: payloadURL, options: [.mappedIfSafe])
            let encoded = try artifact.encoded(replacingPayloadWith: replacement)
            try encoded.write(to: outputURL, options: .atomic)

            // Re-open our own result and compare the extracted payload. This
            // catches DER-length or PAYP mistakes before reporting success.
            let roundTrip = try FirmwareArtifact(data: encoded)
            guard roundTrip.kind == .im4p, roundTrip.payload == replacement else {
                throw PatchfinderError.invalidFirmwareContainer(
                    "repacked payload failed round-trip verification"
                )
            }
            print("repacked \(artifact.fourcc ?? "IM4P") and verified \(replacement.count)-byte payload")
            print("wrote \(outputURL.path)")
        }
    }
}

struct IMG4: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "img4",
        abstract: "Create ticket-bearing IMG4 containers and extract their manifests.",
        subcommands: [Create.self, ExtractManifest.self]
    )

    struct Create: ParsableCommand {
        static let configuration = CommandConfiguration(
            abstract: "Combine an IM4P and an APTicket into a signed IMG4."
        )

        @Argument(help: ArgumentHelp("Payload container.", valueName: "input.im4p"))
        var input: String

        @Argument(help: ArgumentHelp("APTicket to embed.", valueName: "ticket.im4m"))
        var ticket: String

        @Argument(help: ArgumentHelp("IMG4 to write.", valueName: "output.img4"))
        var output: String

        @Option(
            name: .customLong("fourcc"),
            help: ArgumentHelp("Override the payload fourcc.", valueName: "type")
        )
        var fourcc: String?

        func run() throws {
            let outputURL = URL(fileURLWithPath: output).standardizedFileURL
            let data = try IMG4Signing.create(
                im4pData: try Data(contentsOf: URL(fileURLWithPath: input).standardizedFileURL),
                im4mData: try Data(contentsOf: URL(fileURLWithPath: ticket).standardizedFileURL),
                fourcc: fourcc
            )
            try data.write(to: outputURL, options: .atomic)
            print("created and verified ticket-bearing IMG4: \(outputURL.path)")
        }
    }

    struct ExtractManifest: ParsableCommand {
        static let configuration = CommandConfiguration(
            commandName: "extract-manifest",
            abstract: "Write an IMG4's embedded APTicket to a file."
        )

        @Argument(help: ArgumentHelp("IMG4 to read.", valueName: "input.img4"))
        var input: String

        @Argument(help: ArgumentHelp("APTicket to write.", valueName: "output.im4m"))
        var output: String

        func run() throws {
            let outputURL = URL(fileURLWithPath: output).standardizedFileURL
            let im4m = try IMG4Signing.extractManifest(
                from: try Data(contentsOf: URL(fileURLWithPath: input).standardizedFileURL)
            )
            try im4m.write(to: outputURL, options: .atomic)
            print("extracted IM4M (\(im4m.count) bytes): \(outputURL.path)")
        }
    }
}
