import Foundation
import Testing
@testable import Liter8Core

@Suite("FirmwareWorkflowContext")
struct FirmwareWorkflowContextTests {
    @Test func selectsNormalEraseIdentityAndExportsComponentPaths() throws {
        let profile = try #require(DeviceWorkflowRegistry.profiles.first)
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
        #expect(context.schema == 3)
        #expect(context.bootPlan.normalIBSSAdditionalPlans == [.skipDisplayInitialization])
        #expect(context.bootPlan.restoreIBSSAdditionalPlans == [.skipDisplayInitialization])
        #expect(context.bootPlan.firmwareComponents == DeviceBootPlan.defaultFirmwareComponents)
        #expect(context.bootPlan.normalTrustCache == .restore)
    }

    @Test func ipad8PolicyRequiresExperimentalOptInAndStaticNormalTrustCache() throws {
        let profile = try #require(DeviceWorkflowRegistry.profiles.first {
            $0.id == "ipad11,6-j171aap-23H30"
        })
        let target = IPSWIdentity(
            productVersion: "26.7.1", build: "23H30", productTypes: ["iPad11,6", "iPad11,7"],
            buildIdentities: [.init(deviceClass: "j171aap", chipID: 0x8020, boardID: 0x24)]
        )
        #expect(DeviceWorkflowRegistry.profile(for: target) == nil)
        #expect(DeviceWorkflowRegistry.profile(for: target, includeExperimental: true) == profile)
        #expect(profile.validationState == .experimental)
        #expect(profile.bootPlan.firmwareComponents == [
            "RestoreLogo", "ANE", "AOP", "AVE", "GFX", "ISP", "SIO", "SEP",
        ])
        #expect(profile.bootPlan.normalTrustCache == .static)
        #expect(profile.bootPlan.normalIBSSAdditionalPlans.isEmpty)
        #expect(profile.bootPlan.restoreIBSSAdditionalPlans.isEmpty)

        var erase = identity(variant: "Customer Erase Install (IPSW)", ibss: "Firmware/iBSS.im4p")
        erase["ApChipID"] = "0x8020"
        erase["ApBoardID"] = "0x24"
        erase["Info"] = ["DeviceClass": "j171aap", "Variant": "Customer Erase Install (IPSW)"]
        let source = try firmwareDirectory(identities: [erase])
        defer { try? FileManager.default.removeItem(at: source) }
        let context = try FirmwareWorkflowContext.load(profile: profile, sourceRoot: source)
        let encoded = try JSONEncoder().encode(context)
        let decoded = try JSONDecoder().decode(FirmwareWorkflowContext.self, from: encoded)
        #expect(decoded.bootPlan == profile.bootPlan)
        #expect(decoded.schema == 3)
    }

    @Test func rejectsTraversalInManifestComponent() throws {
        let profile = try #require(DeviceWorkflowRegistry.profiles.first)
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
