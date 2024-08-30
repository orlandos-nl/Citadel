// swift-tools-version: 5.10
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "TerminalAppServer",
    platforms: [
        .macOS(.v12),
    ],
    dependencies: [
        .package(url: "https://github.com/joannis/SwiftTUI.git", branch: "jo/allow-use-with-concurrency"),
        .package(path: "../.."),
    ],
    targets: [
        // Targets are the basic building blocks of a package, defining a module or a test suite.
        // Targets can depend on other targets in this package and products from dependencies.
        .executableTarget(
            name: "TerminalAppServer",
            dependencies: [
                .product(name: "Citadel", package: "Citadel"),
                .product(name: "SwiftTUI", package: "SwiftTUI"),
            ]
        ),
    ]
)
