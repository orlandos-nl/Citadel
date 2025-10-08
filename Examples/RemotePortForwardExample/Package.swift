// swift-tools-version:5.5
import PackageDescription

let package = Package(
    name: "RemotePortForwardExample",
    platforms: [
        .macOS(.v12)
    ],
    dependencies: [
        .package(name: "Citadel", path: "../..")
    ],
    targets: [
        .executableTarget(
            name: "RemotePortForwardExample",
            dependencies: ["Citadel"]
        )
    ]
)
