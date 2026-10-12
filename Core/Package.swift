// swift-tools-version: 6.0
import PackageDescription

// TwotbitKit is the wallet engine of the Twotbit app: BIP39/BIP84 keys,
// the validated SPV header chain, BIP157/158 compact filters, the P2P peer
// pool and the wallet sync, storage and rates. The app target only adds the
// SwiftUI interface on top of it.
let package = Package(
    name: "TwotbitCore",
    platforms: [.macOS(.v15)],
    products: [
        .library(name: "TwotbitKit", targets: ["TwotbitKit"]),
    ],
    targets: [
        // libsecp256k1 v0.6.0 from bitcoin-core/secp256k1, vendored
        // unchanged: the ECDSA signing and key arithmetic Bitcoin Core uses.
        .target(
            name: "CSecp256k1",
            path: "Sources/CSecp256k1",
            exclude: ["COPYING"],
            sources: ["unity/secp256k1.c", "unity/precomputed_ecmult.c", "unity/precomputed_ecmult_gen.c"],
            publicHeadersPath: "include",
            cSettings: [.headerSearchPath("src")]
        ),
        .target(
            name: "TwotbitKit",
            dependencies: ["CSecp256k1"],
            path: "Sources/TwotbitKit",
            resources: [.copy("Resources/rates.csv")]
        ),
        .testTarget(
            name: "TwotbitKitTests",
            dependencies: ["TwotbitKit"],
            path: "Tests/TwotbitKitTests",
            resources: [.copy("Fixtures")]
        ),
    ]
)
