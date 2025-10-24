// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "RemotePortForwardExample",
    platforms: [
        .macOS(.v14),
        .iOS(.v17)
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
