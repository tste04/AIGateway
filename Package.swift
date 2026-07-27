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
        .executable(name: "aigatewayd", targets: ["aigatewayd"]),
    ],
    targets: [
        // Reine Typen und Vertraege. Keine Abhaengigkeiten, auch keine internen.
        .target(name: "GatewayCore"),
        // Firewall-Stufen: Injection, PII, DLP, Malware.
        .target(name: "InputFirewall", dependencies: ["GatewayCore"]),
        // Transport, Provider-Adapter, Pipeline-Verdrahtung.
        .target(name: "GatewayServer", dependencies: ["GatewayCore", "InputFirewall"]),
        // Der Daemon. Bewusst duenn: Konfiguration lesen, Stufen stecken,
        // Signale abfangen. Jede Zeile Sicherheitslogik hier waere eine, die
        // die Bibliothek nicht hat und die niemand testet.
        .executableTarget(name: "aigatewayd", dependencies: ["GatewayServer", "GatewayCore"]),

        .testTarget(name: "GatewayCoreTests", dependencies: ["GatewayCore"]),
        .testTarget(name: "InputFirewallTests", dependencies: ["InputFirewall", "GatewayCore"]),
        .testTarget(name: "GatewayServerTests",
                    dependencies: ["GatewayServer", "GatewayCore", "InputFirewall"]),
    ]
)
