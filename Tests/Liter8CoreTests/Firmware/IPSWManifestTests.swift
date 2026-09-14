import Foundation
import Testing
@testable import Liter8Core

struct IPSWManifestTests {
    @Test func parsesIdentityAndSelectsReviewedWorkflow() throws {
        let manifest: [String: Any] = [
            "ProductVersion": "27.0",
            "ProductBuildVersion": "24A5390f",
            "SupportedProductTypes": ["iPhone12,1"],
            "BuildIdentities": [[
                "ApBoardID": "0x04",
                "ApChipID": "0x8030",
                "Info": ["DeviceClass": "n104ap"],
            ]],
        ]
        let data = try PropertyListSerialization.data(
            fromPropertyList: manifest,
            format: .binary,
            options: 0
        )

        let identity = try IPSWManifestInspector.parse(data)
        #expect(identity.productVersion == "27.0")
        #expect(identity.build == "24A5390f")
        #expect(identity.productTypes == ["iPhone12,1"])
        #expect(identity.buildIdentities == [
            .init(deviceClass: "n104ap", chipID: 0x8030, boardID: 0x04),
        ])
        let profile = DeviceWorkflowRegistry.profile(for: identity)
        #expect(profile?.id == "iphone12,1-n104ap-24A5390f")
        #expect(
            profile?.launchdSHA256
                == "9ff28152483244a34cb43cd3541511f6989636e6814611c573b21b2ee43d70f7"
        )
    }

    @Test func releaseSelectsReviewedWorkflow() throws {
        let manifest: [String: Any] = [
            "ProductVersion": "27.0",
            "ProductBuildVersion": "24A435",
            "SupportedProductTypes": ["iPhone12,1"],
            "BuildIdentities": [[
                "ApBoardID": 4,
                "ApChipID": 0x8030,
                "Info": ["DeviceClass": "n104ap"],
            ]],
        ]
        let data = try PropertyListSerialization.data(
            fromPropertyList: manifest,
            format: .xml,
            options: 0
        )

        let identity = try IPSWManifestInspector.parse(data)
        let profile = DeviceWorkflowRegistry.profile(for: identity)
        #expect(profile?.id == "iphone12,1-n104ap-24A435")
        #expect(profile?.validationState == .reviewed)
        #expect(profile?.launchdCacheDaemonCount == 729)
        #expect(profile?.setupControllerMethodCount == 66)
    }
}
