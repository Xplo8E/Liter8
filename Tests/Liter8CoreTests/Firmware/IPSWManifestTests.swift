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

    @Test func d431SelectsExperimentalWorkflow() throws {
        let manifest: [String: Any] = [
            "ProductVersion": "27.0.1",
            "ProductBuildVersion": "24A446",
            "SupportedProductTypes": ["iPhone12,3", "iPhone12,5"],
            "BuildIdentities": [[
                "ApBoardID": "0x02",
                "ApChipID": "0x8030",
                "Info": ["DeviceClass": "d431ap"],
            ]],
        ]
        let data = try PropertyListSerialization.data(
            fromPropertyList: manifest,
            format: .binary,
            options: 0
        )

        let identity = try IPSWManifestInspector.parse(data)
        #expect(identity.buildIdentities == [
            .init(deviceClass: "d431ap", chipID: 0x8030, boardID: 0x02),
        ])
        let profile = DeviceWorkflowRegistry.profile(for: identity, includeExperimental: true)
        #expect(profile?.id == "iphone12,5-d431ap-24A446")
        #expect(profile?.validationState == .experimental)
    }

    /// 24A437 ships one IPSW for both Pro boards, so the board ID is the only
    /// thing separating them. Picking the wrong entry would hand a phone the
    /// other board's boot plan, which is why this asserts the id and not just
    /// that something matched.
    @Test(arguments: [
        ("0x06", "d421ap", "iPhone12,3", "iphone12,3-d421ap-24A437"),
        ("0x02", "d431ap", "iPhone12,5", "iphone12,5-d431ap-24A437"),
    ])
    func proBoardsSelectTheirOwnExperimentalWorkflow(
        board: String, deviceClass: String, productType: String, expectedID: String
    ) throws {
        let manifest: [String: Any] = [
            "ProductVersion": "27.0",
            "ProductBuildVersion": "24A437",
            "SupportedProductTypes": ["iPhone12,3", "iPhone12,5"],
            "BuildIdentities": [[
                "ApBoardID": board,
                "ApChipID": "0x8030",
                "Info": ["DeviceClass": deviceClass],
            ]],
        ]
        let data = try PropertyListSerialization.data(
            fromPropertyList: manifest,
            format: .binary,
            options: 0
        )
        let identity = try IPSWManifestInspector.parse(data)

        // Nothing on this build is device-validated, so the default lookup has
        // to refuse before the opt-in lookup is allowed to succeed.
        #expect(DeviceWorkflowRegistry.profile(for: identity) == nil)

        let profile = DeviceWorkflowRegistry.profile(for: identity, includeExperimental: true)
        #expect(profile?.id == expectedID)
        #expect(profile?.productType == productType)
        #expect(profile?.validationState == .experimental)
    }

    /// A dual-device IPSW lists both boards, so both profiles match it and the
    /// archive cannot say which phone is attached. Returning either one would
    /// hand a device the other board's boot plan and iBSS.
    @Test func aDualBoardIPSWIsAmbiguousUntilABoardIsNamed() throws {
        let identity = try proIdentity()

        let both = DeviceWorkflowRegistry.matchingProfiles(
            for: identity,
            includeExperimental: true
        )
        #expect(both.count == 2)
        #expect(DeviceWorkflowRegistry.profile(for: identity, includeExperimental: true) == nil)

        let message = DeviceWorkflowRegistry.ambiguityMessage(both)
        #expect(message.contains("d421ap"))
        #expect(message.contains("d431ap"))
        #expect(message.contains("--board"))

        for (board, expected) in [
            ("d421ap", "iphone12,3-d421ap-24A437"),
            ("d431ap", "iphone12,5-d431ap-24A437"),
        ] {
            let picked = DeviceWorkflowRegistry.profile(
                for: identity, includeExperimental: true, board: board
            )
            #expect(picked?.id == expected)
        }

        #expect(DeviceWorkflowRegistry.matchingProfiles(
            for: identity, includeExperimental: true, board: "n104ap"
        ).isEmpty)
    }

    /// The common case must not regress: one board in the manifest resolves
    /// with no `--board` at all.
    @Test func aSingleBoardIPSWNeedsNoBoardArgument() throws {
        let manifest: [String: Any] = [
            "ProductVersion": "27.0.1",
            "ProductBuildVersion": "24A446",
            "SupportedProductTypes": ["iPhone12,1"],
            "BuildIdentities": [[
                "ApBoardID": "0x04",
                "ApChipID": "0x8030",
                "Info": ["DeviceClass": "n104ap"],
            ]],
        ]
        let data = try PropertyListSerialization.data(
            fromPropertyList: manifest, format: .binary, options: 0
        )
        let identity = try IPSWManifestInspector.parse(data)
        let profile = DeviceWorkflowRegistry.profile(for: identity)
        #expect(profile?.id == "iphone12,1-n104ap-24A446")
        #expect(profile?.validationState == .reviewed)
    }

    private func proIdentity() throws -> IPSWIdentity {
        let manifest: [String: Any] = [
            "ProductVersion": "27.0",
            "ProductBuildVersion": "24A437",
            "SupportedProductTypes": ["iPhone12,3", "iPhone12,5"],
            "BuildIdentities": [
                ["ApBoardID": "0x06", "ApChipID": "0x8030",
                 "Info": ["DeviceClass": "d421ap"]],
                ["ApBoardID": "0x02", "ApChipID": "0x8030",
                 "Info": ["DeviceClass": "d431ap"]],
            ],
        ]
        let data = try PropertyListSerialization.data(
            fromPropertyList: manifest, format: .binary, options: 0
        )
        return try IPSWManifestInspector.parse(data)
    }

    /// Both Pro boards read their guards from the one root filesystem the
    /// 24A437 IPSW ships, so a change to either entry alone is a mistake.
    @Test(arguments: ["24A437", "24A446", "24B119"])
    func proBoardsShareTheirMeasuredGuards(build: String) {
        let pro = DeviceWorkflowRegistry.profiles.filter {
            $0.build == build && $0.deviceClass.hasPrefix("d4")
        }
        #expect(pro.count == 2)
        #expect(Set(pro.map(\.launchdSHA256)).count == 1)
        #expect(Set(pro.map(\.launchdCacheSHA256)).count == 1)
        #expect(Set(pro.map(\.launchdCacheDaemonCount)).count == 1)
        #expect(Set(pro.map(\.setupControllerMethodCount)).count == 1)
        #expect(Set(pro.map(\.extractedDirectoryName)).count == 1)
        #expect(Set(pro.map(\.boardID)) == [0x06, 0x02])
    }

    /// 27.2 on the Pro boards must behave exactly like 27.0 did: ambiguous
    /// until a board is named, refused without `--experimental`, and never
    /// answering with the iPhone 11 entry that shares this build ID.
    ///
    /// The identity here is the real one from
    /// `iPhone12,3,iPhone12,5_27.2_24B119_Restore.ipsw`.
    @Test func proBoardsOn272AreExperimentalAndBoardDisambiguated() throws {
        let manifest: [String: Any] = [
            "ProductVersion": "27.2",
            "ProductBuildVersion": "24B119",
            "SupportedProductTypes": ["iPhone12,3", "iPhone12,5"],
            "BuildIdentities": [
                ["ApBoardID": "0x06", "ApChipID": "0x8030",
                 "Info": ["DeviceClass": "d421ap"]],
                ["ApBoardID": "0x02", "ApChipID": "0x8030",
                 "Info": ["DeviceClass": "d431ap"]],
            ],
        ]
        let data = try PropertyListSerialization.data(
            fromPropertyList: manifest, format: .binary, options: 0
        )
        let identity = try IPSWManifestInspector.parse(data)

        // Neither board has a device run, so the default lookup must refuse
        // even though a reviewed n104 entry exists for this same build.
        #expect(DeviceWorkflowRegistry.matchingProfiles(for: identity).isEmpty)

        let both = DeviceWorkflowRegistry.matchingProfiles(
            for: identity, includeExperimental: true
        )
        #expect(both.count == 2)
        #expect(DeviceWorkflowRegistry.profile(for: identity, includeExperimental: true) == nil)

        for (board, expected) in [
            ("d421ap", "iphone12,3-d421ap-24B119"),
            ("d431ap", "iphone12,5-d431ap-24B119"),
        ] {
            let picked = DeviceWorkflowRegistry.profile(
                for: identity, includeExperimental: true, board: board
            )
            #expect(picked?.id == expected)
            #expect(picked?.validationState == .experimental)
        }

        // The reviewed iPhone 11 entry shares the build and the chip ID and
        // differs only in board ID, so it must not match this IPSW at all.
        #expect(!both.contains { $0.deviceClass == "n104ap" })
    }
}
