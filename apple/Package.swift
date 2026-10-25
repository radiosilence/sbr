// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "SbrKit",
    platforms: [.iOS(.v15), .macOS(.v12), .tvOS(.v17), .macCatalyst(.v15)],
    products: [.library(name: "SbrKit", targets: ["SbrKit"])],
    targets: [
        // Static library + sbr.h, produced by ./build-xcframework.sh.
        .binaryTarget(name: "SbrCore", path: "SbrCore.xcframework"),
        .target(
            name: "SbrKit",
            dependencies: ["SbrCore"],
            // Rust's std links libiconv on Apple targets.
            linkerSettings: [.linkedLibrary("iconv")]
        ),
    ]
)
