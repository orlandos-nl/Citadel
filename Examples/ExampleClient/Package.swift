// swift-tools-version: 5.9
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "ExampleClient",
    platforms: [
        .macOS(.v12),  
    ],
    dependencies: [
        .package(path: "../../"),
    ],
    targets: [
        // Targets are the basic building blocks of a package, defining a module or a test suite.
        // Targets can depend on other targets in this package and products from dependencies.
        .executableTarget(
            name: "ExampleClient",
            dependencies: [
                .product(name: "Citadel", package: "Citadel"),
            ]
        ),
    ]
)