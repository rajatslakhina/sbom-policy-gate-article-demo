// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "SBOMGate",
    platforms: [.iOS(.v17), .macOS(.v14)],
    products: [
        .library(name: "SBOMGate", targets: ["SBOMGate"])
    ],
    targets: [
        .target(name: "SBOMGate"),
        .testTarget(
            name: "SBOMGateTests",
            dependencies: ["SBOMGate"]
        )
    ]
)
