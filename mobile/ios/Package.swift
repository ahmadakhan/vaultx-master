// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "VaultXTransfer",
    platforms: [
        .iOS(.v15)
    ],
    products: [
        .library(name: "VaultXTransfer", targets: ["VaultXTransfer"])
    ],
    targets: [
        .target(
            name: "VaultXTransfer",
            path: "VaultXTransfer",
            linkerSettings: [
                .linkedFramework("Security"),
                .linkedFramework("Foundation")
            ]
        )
    ]
)
