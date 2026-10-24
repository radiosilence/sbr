// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "SbrKit",
    platforms: [.iOS(.v15), .macOS(.v12)],
    products: [.library(name: "SbrKit", targets: ["SbrKit"])],
    targets: [
        // Produced by ./build-xcframework.sh
        .binaryTarget(name: "SbrCore", path: "SbrCore.xcframework"),
        .target(name: "SbrKit", dependencies: ["SbrCore"]),
    ]
)
