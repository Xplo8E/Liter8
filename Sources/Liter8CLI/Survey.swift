import Foundation
import Liter8Core

/// Answers "what still resolves on this build?" in one command.
///
/// Porting to a new firmware starts the same way every time: extract it, find
/// the components, run every plan, and read off which ones stopped resolving.
/// Doing that by hand means a shell loop around `resolve`, which is fragile for
/// a reason that has nothing to do with firmware: the per-plan record count
/// only comes back as JSON, so counting means a pipeline of `sed` and a JSON
/// parser, and one stray character in that quoting breaks the sweep rather than
/// reporting a resolver problem.
///
/// The information is already in the process. This prints it.
enum Survey {
    /// Components are matched by IM4P fourcc rather than filename.
    ///
    /// Filenames carry a device and a build (`iBSS.n104.RELEASE.im4p`,
    /// `kernelcache.release.iphone12b`) and move between releases; the
    /// container type does not. Matching on fourcc means this keeps working on
    /// a device whose components are named differently.
    private static let componentForFourCC = [
        "ibss": "iboot",
        "ibec": "iboot",
        "trxm": "txm",
        "krnl": "kernel",
    ]

    /// Plans needing a value that only the caller can supply. Running them with
    /// defaults would report a resolver failure that is really a missing
    /// argument, so they are reported as skipped instead.
    private static let requiresArgument = [
        "ibec-force-pinot-id": "--pinot-id",
    ]

    private struct Candidate {
        let url: URL
        let fourcc: String
        let image: BinaryImage
    }

    private struct Row {
        let component: String
        let plan: String
        let count: Int?
        let note: String?
    }

    static func run(directory: URL) throws -> Int32 {
        let candidates = try discover(in: directory)
        guard !candidates.isEmpty else {
            throw PatchfinderError.invalidFixture(
                "no IM4P firmware components found under \(directory.path); "
                    + "run fw prepare on the IPSW first"
            )
        }

        print("surveying \(directory.path)")
        for candidate in candidates.sorted(by: { $0.fourcc < $1.fourcc }) {
            let name = candidate.url.lastPathComponent
            print("  \(candidate.fourcc)  \(name) (\(candidate.image.count) bytes)")
        }

        // The kernel identity decides how much of a port this is, so report it
        // before the table rather than leaving it to a separate command.
        if let kernel = candidates.first(where: { $0.fourcc == "krnl" }) {
            print("")
            reportKernelIdentity(kernel.image)
        }

        var rows: [Row] = []
        for component in ["iboot", "txm", "kernel"] {
            guard let plans = resolverGroups[component] else { continue }
            for plan in plans.keys.sorted() {
                guard let resolver = resolverName(component: component, plan: plan) else { continue }
                if let argument = requiresArgument[plan] {
                    rows.append(Row(component: component, plan: plan, count: nil,
                                    note: "skipped, needs \(argument)"))
                    continue
                }
                guard let candidate = artifact(for: component, plan: plan, in: candidates) else {
                    continue
                }
                do {
                    let records = try resolveRecords(
                        named: resolver,
                        in: candidate.image,
                        options: ResolverOptions()
                    )
                    rows.append(Row(component: component, plan: plan,
                                    count: records.count, note: nil))
                } catch {
                    rows.append(Row(component: component, plan: plan, count: nil,
                                    note: reason(for: error)))
                }
            }
        }

        return report(rows)
    }

    /// Pick which boot-loader image a plan belongs to.
    ///
    /// iBSS and iBEC are separate components that happen to be byte-identical
    /// on some devices. Selecting by plan prefix keeps the result meaningful on
    /// a device where they diverge, and falls back so a directory holding only
    /// one of them still surveys every iBoot plan.
    private static func artifact(
        for component: String,
        plan: String,
        in candidates: [Candidate]
    ) -> Candidate? {
        guard component == "iboot" else {
            let wanted = component == "txm" ? "trxm" : "krnl"
            return candidates.first { $0.fourcc == wanted }
        }
        let preferred = plan.hasPrefix("ibec") ? "ibec" : "ibss"
        return candidates.first { $0.fourcc == preferred }
            ?? candidates.first { $0.fourcc == "ibss" || $0.fourcc == "ibec" }
    }

    private static func discover(in directory: URL) throws -> [Candidate] {
        let fileManager = FileManager.default
        guard let walker = fileManager.enumerator(
            at: directory,
            includingPropertiesForKeys: [.isRegularFileKey, .fileSizeKey],
            options: [.skipsHiddenFiles]
        ) else { return [] }

        var found: [String: Candidate] = [:]
        for case let url as URL in walker {
            let values = try? url.resourceValues(forKeys: [.isRegularFileKey, .fileSizeKey])
            guard values?.isRegularFile == true else { continue }
            // Skip the multi-GB disk images rather than reading them looking
            // for a container they cannot hold.
            if let size = values?.fileSize, size > 128 * 1024 * 1024 { continue }

            guard let artifact = try? FirmwareArtifact(contentsOf: url),
                  let fourcc = artifact.fourcc,
                  componentForFourCC[fourcc] != nil
            else { continue }

            // A RESEARCH_RELEASE build sits beside the RELEASE one and carries
            // the same fourcc. Keep the first by sorted name so the choice is
            // deterministic rather than filesystem-order dependent.
            if let existing = found[fourcc],
               existing.url.lastPathComponent <= url.lastPathComponent {
                continue
            }
            found[fourcc] = Candidate(
                url: url,
                fourcc: fourcc,
                image: BinaryImage(data: artifact.payload)
            )
        }
        return Array(found.values)
    }

    private static func reportKernelIdentity(_ image: BinaryImage) {
        if let profile = KernelResolverProfileRegistry.detect(in: image) {
            print("kernel profile: \(profile.id)")
            print("  builds: \(profile.builds.joined(separator: ", "))")
            print("  fingerprint: \(profile.embeddedFingerprint)")
            return
        }
        print("kernel profile: unidentified")
        // Printing the fingerprint is the whole point of saying "unidentified":
        // it is the exact string a new KernelResolverProfile entry needs, and
        // hunting for it with strings(1) was a manual step for no reason.
        if let fingerprint = embeddedFingerprint(in: image) {
            print("  fingerprint: \(fingerprint)")
            print("  add a KernelResolverProfile with this fingerprint to enable")
            print("  build-specific resolver variants (credential-manager needs one)")
        } else {
            print("  no xnu fingerprint found; is this a kernelcache?")
        }
    }

    /// Recover the `xnu-…/RELEASE_ARM64_…` build string from the image.
    private static func embeddedFingerprint(in image: BinaryImage) -> String? {
        for start in image.findAll(utf8: "xnu-") {
            let end = min(Int(start) + 128, image.count)
            let bytes = image.data[Int(start)..<end]
            guard let text = String(data: bytes, encoding: .ascii) else { continue }
            guard let terminator = text.firstIndex(where: { $0 == "\0" }) else { continue }
            let candidate = String(text[text.startIndex..<terminator])
            if candidate.contains("/RELEASE_") || candidate.contains("/DEVELOPMENT_") {
                return candidate
            }
        }
        return nil
    }

    /// One line per failure, trimmed to stay readable in a table.
    private static func reason(for error: Error) -> String {
        let text = (error as? PatchfinderError).map(String.init(describing:))
            ?? error.localizedDescription
        let single = text.replacingOccurrences(of: "\n", with: " ")
        return single.count > 90 ? String(single.prefix(87)) + "..." : single
    }

    private static func report(_ rows: [Row]) -> Int32 {
        // Size the plan column to the widest plan actually present. Plan names
        // grow as plans are added, and a hardcoded width silently ragged the
        // table the first time one exceeded it.
        let planWidth = max(4, rows.map(\.plan.count).max() ?? 4)
        let header = "COMPONENT".padded(9) + " " + "PLAN".padded(planWidth) + " RESULT"
        let rule = String(repeating: "-", count: header.count)

        print("")
        print(header)
        print(rule)
        var total = 0
        var failed = 0
        var skipped = 0
        for row in rows {
            let result: String
            if let count = row.count {
                total += count
                result = String(count)
            } else {
                let note = row.note ?? "failed"
                if note.hasPrefix("skipped") { skipped += 1 } else { failed += 1 }
                result = note
            }
            print("\(row.component.padded(9)) \(row.plan.padded(planWidth)) \(result)")
        }
        print(rule)
        print("\(rows.count - failed - skipped) resolved, \(failed) failed, "
            + "\(skipped) skipped, \(total) records")
        return failed == 0 ? 0 : 1
    }
}

private extension String {
    func padded(_ width: Int) -> String {
        count >= width ? self : self + String(repeating: " ", count: width - count)
    }
}
