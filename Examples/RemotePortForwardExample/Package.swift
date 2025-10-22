// swift-tools-version:5.5
import PackageDescription

let package = Package(
    name: "RemotePortForwardExample",
    platforms: [
        .macOS(.v12)
    ],
    dependencies: [
        .package(name: "Citadel", path: "../.."),
        .package(url: "https://github.com/apple/swift-argument-parser", from: "1.2.0")
    ],
    targets: [
        .executableTarget(
            name: "RemotePortForwardExample",
            dependencies: [
                "Citadel",
                .product(name: "ArgumentParser", package: "swift-argument-parser")
            ]
        )
    ]
)
