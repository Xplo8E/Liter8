import Foundation
import Testing
@testable import Liter8Core

@Suite("FirmwareWorkflowContext")
struct FirmwareWorkflowContextTests {
    @Test func selectsNormalEraseIdentityAndExportsComponentPaths() throws {
        let profile = try #require(IPSWWorkflowRegistry.profiles.first)
        let source = try firmwareDirectory(identities: [
            identity(variant: "Research Developer Erase Install (IPSW)", ibss: "research/iBSS.im4p"),
            identity(variant: "Developer Erase Install (IPSW)", ibss: "release/iBSS.im4p"),
            identity(variant: "Developer Upgrade Install (IPSW)", ibss: "upgrade/iBSS.im4p"),
        ])
        defer { try? FileManager.default.removeItem(at: source) }

        let context = try FirmwareWorkflowContext.load(profile: profile, sourceRoot: source)

        #expect(context.variant == "Developer Erase Install (IPSW)")
        #expect(context.components["iBSS"] == "release/iBSS.im4p")
        #expect(context.components["RestoreKernelCache"] == "kernelcache.test")
        #expect(context.components["OS"] == "rootfs.dmg.aea")
    }

    @Test func rejectsTraversalInManifestComponent() throws {
        let profile = try #require(IPSWWorkflowRegistry.profiles.first)
        let source = try firmwareDirectory(identities: [
            identity(variant: "Developer Erase Install (IPSW)", ibss: "../iBSS.im4p"),
        ])
        defer { try? FileManager.default.removeItem(at: source) }

        #expect(throws: PatchfinderError.self) {
            try FirmwareWorkflowContext.load(profile: profile, sourceRoot: source)
        }
    }

    private func firmwareDirectory(identities: [[String: Any]]) throws -> URL {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("liter8-context-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let plist: [String: Any] = ["BuildIdentities": identities]
        let data = try PropertyListSerialization.data(
            fromPropertyList: plist,
            format: .binary,
            options: 0
        )
        try data.write(to: directory.appendingPathComponent("BuildManifest.plist"))
        return directory
    }

    private func identity(variant: String, ibss: String) -> [String: Any] {
        [
            "ApBoardID": "0x04",
            "ApChipID": "0x8030",
            "Info": ["DeviceClass": "n104ap", "Variant": variant],
            "Manifest": [
                "iBSS": entry(ibss),
                "iBEC": entry("Firmware/dfu/iBEC.test.im4p"),
                "RestoreDeviceTree": entry("Firmware/all_flash/DeviceTree.test.im4p"),
                "RestoreKernelCache": entry("kernelcache.test"),
                "RestoreRamDisk": entry("restore.dmg"),
                "OS": entry("rootfs.dmg.aea"),
            ],
        ]
    }

    private func entry(_ path: String) -> [String: Any] {
        ["Info": ["Path": path]]
    }
}
