// swift-tools-version: 6.0

import PackageDescription

let package = Package(
    name: "Liter8",
    platforms: [.macOS(.v14)],
    products: [
        .library(name: "Liter8Core", targets: ["Liter8Core"]),
        .executable(name: "liter8", targets: ["Liter8CLI"]),
    ],
    dependencies: [
        // Keep IMG4/IM4P handling in Swift. This is the same pinned vendor
        // used by vphone-cli, rather than a Python or img4tool subprocess.
        .package(path: "vendor/libimg4-spm"),
        .package(
            url: "https://github.com/Lakr233/libcapstone-spm.git",
            revision: "ea98aa0a31693d7ea2930c4372f9b5858b0bc7a3"
        ),
    ],
    targets: [
        .target(
            name: "Liter8Core",
            dependencies: [
                .product(name: "Capstone", package: "libcapstone-spm"),
                .product(name: "Img4tool", package: "libimg4-spm"),
            ]
        ),
        .executableTarget(
            name: "Liter8CLI",
            dependencies: ["Liter8Core"]
        ),
        .testTarget(
            name: "Liter8CoreTests",
            dependencies: ["Liter8Core"]
        ),
    ]
)
