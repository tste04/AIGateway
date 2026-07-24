// swift-tools-version: 5.7
import PackageDescription

let package = Package(
    name: "AIGateway",
    platforms: [
        .macOS(.v12),
    ],
    products: [
        .library(name: "GatewayCore", targets: ["GatewayCore"]),
        .library(name: "InputFirewall", targets: ["InputFirewall"]),
    ],
    targets: [
        // Reine Typen und Vertraege. Keine Abhaengigkeiten, auch keine internen.
        .target(name: "GatewayCore"),
        // Firewall-Stufen. Heute: Injection. Folgend: PII, DLP, Malware.
        .target(name: "InputFirewall", dependencies: ["GatewayCore"]),

        .testTarget(name: "GatewayCoreTests", dependencies: ["GatewayCore"]),
        .testTarget(name: "InputFirewallTests", dependencies: ["InputFirewall", "GatewayCore"]),
    ]
)
