// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "CvedexMac",
    platforms: [.macOS(.v15)],
    products: [.executable(name: "CvedexMac", targets: ["CvedexMac"])],
    targets: [
        .target(name: "CvedexKit"),
        .executableTarget(name: "CvedexMac", dependencies: ["CvedexKit"]),
        .testTarget(name: "CvedexKitTests", dependencies: ["CvedexKit"]),
    ]
)
