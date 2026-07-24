// swift-tools-version: 5.7
import PackageDescription

let package = Package(
    name: "InjectionScanner",
    products: [
        .library(name: "InjectionScanner", targets: ["InjectionScanner"]),
    ],
    targets: [
        .target(name: "InjectionScanner"),
        .testTarget(
            name: "InjectionScannerTests",
            dependencies: ["InjectionScanner"]
        ),
    ]
)
