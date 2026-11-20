// swift-tools-version:5.9
// Module partagé iPhone + Mac : toute la logique de sécurité testable.
// AUCUNE dépendance externe : uniquement les frameworks Apple (CryptoKit, Security, LocalAuthentication).
import PackageDescription

let package = Package(
    name: "RobAirKit",
    platforms: [.iOS(.v17), .macOS(.v14)],
    products: [
        .library(name: "RobAirKit", targets: ["RobAirKit"])
    ],
    targets: [
        .target(name: "RobAirKit"),
        .testTarget(name: "RobAirKitTests", dependencies: ["RobAirKit"])
    ]
)
