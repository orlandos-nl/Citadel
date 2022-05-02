// swift-tools-version:5.5
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "Citadel",
    platforms: [
        .macOS(.v12),
        .iOS(.v15)
    ],
    products: [
        // Products define the executables and libraries produced by a package, and make them visible to other packages.
        .library(
            name: "Citadel",
            targets: ["Citadel"]
        ),
    ],
    dependencies: [
        // Dependencies declare other packages that this package depends on.
        .package(name: "swift-nio-ssh", url: "https://github.com/Joannis/swift-nio-ssh.git", .revision("316c8d6282e43df82595e3d0f5d5bc9f10e9f856")),
        .package(url: "https://github.com/attaswift/BigInt.git", from: "5.2.0"),
    ],
    targets: [
        // Targets are the basic building blocks of a package. A target can define a module or a test suite.
        // Targets can depend on other targets in this package, and on products in packages which this package depends on.
        .target(
            name: "Citadel",
            dependencies: [
                .product(name: "NIOSSH", package: "swift-nio-ssh"),
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "_CryptoExtras", package: "swift-crypto"),
                .product(name: "BigInt", package: "BigInt"),
            ]
        ),
        .testTarget(
            name: "CitadelTests",
            dependencies: ["Citadel"]),
    ]
)
