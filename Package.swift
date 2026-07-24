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
        .library(name: "GatewayServer", targets: ["GatewayServer"]),
    ],
    targets: [
        // Reine Typen und Vertraege. Keine Abhaengigkeiten, auch keine internen.
        .target(name: "GatewayCore"),
        // Firewall-Stufen. Heute: Injection, PII. Folgend: DLP, Malware.
        .target(name: "InputFirewall", dependencies: ["GatewayCore"]),
        // Transport, Provider-Adapter, Pipeline-Verdrahtung.
        .target(name: "GatewayServer", dependencies: ["GatewayCore", "InputFirewall"]),

        .testTarget(name: "GatewayCoreTests", dependencies: ["GatewayCore"]),
        .testTarget(name: "InputFirewallTests", dependencies: ["InputFirewall", "GatewayCore"]),
        .testTarget(name: "GatewayServerTests",
                    dependencies: ["GatewayServer", "GatewayCore", "InputFirewall"]),
    ]
)
