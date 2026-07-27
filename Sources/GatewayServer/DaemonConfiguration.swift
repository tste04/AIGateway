// Copyright (c) 2026 Tommy Stellmacher
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

import Foundation
import GatewayCore
import InputFirewall

// MARK: - Konfiguration aus einer Datei
//
// Bis hierhin war das Gateway eine Bibliothek: wer es betreiben wollte, schrieb
// ein Host-Programm und verdrahtete die Stufen im Code. Das ist fuer einen
// Einbau richtig und fuer einen Betrieb falsch — eine Schwelle zu aendern darf
// keinen Compiler brauchen.
//
// Diese Datei ist der uebersetzende Rand: JSON hinein, fertige Bausteine
// heraus. Sie liegt in `GatewayServer` und nicht im Daemon, damit auch ein
// Host-Programm sie nutzen kann — und damit sie testbar ist, ohne einen Prozess
// zu starten.
//
// ZWEI FESTLEGUNGEN, die nicht bequem sind:
//
// 1. **Der API-Schluessel steht NICHT in der Datei.** Er kommt aus der Umgebung
//    (`AIGATEWAY_UPSTREAM_API_KEY`). Konfigurationsdateien landen in der
//    Versionsverwaltung, in Backups und in Fehlerberichten; ein Schluessel
//    darin ist irgendwann veroeffentlicht. Ein Feld dafuer anzubieten hiesse,
//    genau das zu erlauben — deshalb gibt es keines.
// 2. **Unbekannte Schluessel sind ein Fehler, kein Achselzucken.** Ein
//    verschriebenes `similarityTreshold` still zu ignorieren heisst, mit einer
//    Einstellung zu laufen, die der Betreiber gesetzt zu haben glaubt. Bei
//    einer Sicherheitskomponente ist das die schlechtere Haelfte von
//    „tolerant lesen".

public struct DaemonConfiguration: Sendable {

    public var gateway: GatewayConfiguration
    public var policy: GatewayPolicy
    public var pii: Bool
    public var dlp: Bool
    public var malware: Bool
    public var cache: SemanticCachePolicy
    public var rateLimit: RateLimitPolicy
    public var quarantine: QuarantinePolicy
    public var maskingSessions: MaskingSessionPolicy?
    /// Endpunkt der naechsten Stufe. Gesetzt = Stufenbetrieb (`StageDownstream`),
    /// leer = Proxy-Betrieb auf den konfigurierten Provider.
    public var nextStageURL: URL?
    /// Wie lange beim Abschalten auf laufende Anfragen gewartet wird.
    public var drainSeconds: TimeInterval

    public init(gateway: GatewayConfiguration = GatewayConfiguration(),
                policy: GatewayPolicy = .standard,
                pii: Bool = true,
                dlp: Bool = false,
                malware: Bool = true,
                cache: SemanticCachePolicy = .standard,
                rateLimit: RateLimitPolicy = .standard,
                quarantine: QuarantinePolicy = QuarantinePolicy(),
                maskingSessions: MaskingSessionPolicy? = nil,
                nextStageURL: URL? = nil,
                drainSeconds: TimeInterval = 15) {
        self.gateway = gateway
        self.policy = policy
        self.pii = pii
        self.dlp = dlp
        self.malware = malware
        self.cache = cache
        self.rateLimit = rateLimit
        self.quarantine = quarantine
        self.maskingSessions = maskingSessions
        self.nextStageURL = nextStageURL
        self.drainSeconds = drainSeconds
    }

    // MARK: - Lesen

    public enum ConfigurationError: Error, Equatable, CustomStringConvertible {
        case unreadable(String)
        case malformed(String)
        case unknownKeys([String], section: String)
        case badValue(String, String)

        public var description: String {
            switch self {
            case .unreadable(let path): return "cannot read configuration at \(path)"
            case .malformed(let detail): return "malformed configuration: \(detail)"
            case .unknownKeys(let keys, let section):
                return "unknown keys in '\(section)': \(keys.sorted().joined(separator: ", "))"
            case .badValue(let key, let detail): return "bad value for '\(key)': \(detail)"
            }
        }
    }

    public static func load(contentsOf url: URL,
                            environment: [String: String] = ProcessInfo.processInfo.environment)
    throws -> DaemonConfiguration {
        guard let data = try? Data(contentsOf: url) else {
            throw ConfigurationError.unreadable(url.path)
        }
        return try parse(data, environment: environment)
    }

    public static func parse(_ data: Data,
                             environment: [String: String] = [:]) throws -> DaemonConfiguration {
        guard let root = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw ConfigurationError.malformed("top level is not a JSON object")
        }
        try reject(unknownIn: root, section: "root",
                   allowed: ["server", "policy", "stages", "cache", "rateLimit",
                             "quarantine", "maskingSessions", "nextStage", "drainSeconds"])

        var config = DaemonConfiguration()

        if let server = try section(root, "server") {
            try reject(unknownIn: server, section: "server",
                       allowed: ["port", "loopbackOnly", "upstream", "upstreamBaseURL",
                                 "maxBodyBytes", "debugErrorDetails"])
            if let port = server["port"] as? Int {
                guard (1...65_535).contains(port) else {
                    throw ConfigurationError.badValue("server.port", "outside 1...65535")
                }
                config.gateway.port = UInt16(port)
            }
            if let loopback = server["loopbackOnly"] as? Bool { config.gateway.loopbackOnly = loopback }
            if let name = server["upstream"] as? String {
                guard let kind = ProviderKind(rawValue: name) else {
                    throw ConfigurationError.badValue("server.upstream", "unknown provider '\(name)'")
                }
                config.gateway.upstream = kind
            }
            if let raw = server["upstreamBaseURL"] as? String {
                guard let url = URL(string: raw) else {
                    throw ConfigurationError.badValue("server.upstreamBaseURL", "not a URL")
                }
                config.gateway.upstreamBaseURL = url
            }
            if let bytes = server["maxBodyBytes"] as? Int { config.gateway.maxBodyBytes = bytes }
            if let debug = server["debugErrorDetails"] as? Bool {
                config.gateway.debugErrorDetails = debug
            }
        }

        // Der Schluessel kommt ausschliesslich aus der Umgebung — siehe
        // Kopfkommentar, Festlegung 1.
        config.gateway.apiKey = environment["AIGATEWAY_UPSTREAM_API_KEY"]

        if let policy = try section(root, "policy") {
            try reject(unknownIn: policy, section: "policy",
                       allowed: ["blockThreshold", "maxInputBytes", "maxMessages",
                                 "stageBudgetMilliseconds", "failClosed"])
            if let threshold = policy["blockThreshold"] as? Double {
                config.policy.blockThreshold = threshold
            }
            if let bytes = policy["maxInputBytes"] as? Int { config.policy.maxInputBytes = bytes }
            if let count = policy["maxMessages"] as? Int { config.policy.maxMessages = count }
            if let budget = policy["stageBudgetMilliseconds"] as? Double {
                config.policy.stageBudgetMilliseconds = budget
            }
            if let failClosed = policy["failClosed"] as? Bool {
                config.policy.failureMode = failClosed ? .failClosed : .failOpen
            }
        }

        if let stages = try section(root, "stages") {
            try reject(unknownIn: stages, section: "stages", allowed: ["pii", "dlp", "malware"])
            if let value = stages["pii"] as? Bool { config.pii = value }
            if let value = stages["dlp"] as? Bool { config.dlp = value }
            if let value = stages["malware"] as? Bool { config.malware = value }
        }

        if let cache = try section(root, "cache") {
            try reject(unknownIn: cache, section: "cache",
                       allowed: ["enabled", "timeToLive", "maxEntries", "maxEntriesPerPartition",
                                 "similarityThreshold", "maxTemperature"])
            if let value = cache["enabled"] as? Bool { config.cache.enabled = value }
            if let value = cache["timeToLive"] as? Double { config.cache.timeToLive = value }
            if let value = cache["maxEntries"] as? Int { config.cache.maxEntries = value }
            if let value = cache["maxEntriesPerPartition"] as? Int {
                config.cache.maxEntriesPerPartition = value
            }
            if let value = cache["similarityThreshold"] as? Double {
                config.cache.similarityThreshold = value
            }
            if let value = cache["maxTemperature"] as? Double { config.cache.maxTemperature = value }
        }

        if let limit = try section(root, "rateLimit") {
            try reject(unknownIn: limit, section: "rateLimit",
                       allowed: ["enabled", "requestsPerInterval", "interval", "burst",
                                 "maxTrackedSubjects"])
            if let value = limit["enabled"] as? Bool { config.rateLimit.enabled = value }
            if let value = limit["requestsPerInterval"] as? Int {
                config.rateLimit.requestsPerInterval = value
            }
            if let value = limit["interval"] as? Double { config.rateLimit.interval = value }
            if let value = limit["burst"] as? Int { config.rateLimit.burst = value }
            if let value = limit["maxTrackedSubjects"] as? Int {
                config.rateLimit.maxTrackedSubjects = value
            }
        }

        if let quarantine = try section(root, "quarantine") {
            try reject(unknownIn: quarantine, section: "quarantine",
                       allowed: ["enabled", "detail", "retention", "nearMissBand"])
            if let value = quarantine["enabled"] as? Bool { config.quarantine.enabled = value }
            if let raw = quarantine["detail"] as? String {
                guard let detail = QuarantineDetail(rawValue: raw) else {
                    throw ConfigurationError.badValue("quarantine.detail", "unknown level '\(raw)'")
                }
                config.quarantine.detail = detail
            }
            if let value = quarantine["retention"] as? Double { config.quarantine.retention = value }
            if let value = quarantine["nearMissBand"] as? Double {
                config.quarantine.nearMissBand = value
            }
        }

        if let sessions = try section(root, "maskingSessions") {
            try reject(unknownIn: sessions, section: "maskingSessions",
                       allowed: ["enabled", "timeToLive", "extendedTimeToLive", "maxSessions"])
            if sessions["enabled"] as? Bool == true {
                var policy = MaskingSessionPolicy()
                if let value = sessions["timeToLive"] as? Double { policy.timeToLive = value }
                if let value = sessions["extendedTimeToLive"] as? Double {
                    policy.extendedTimeToLive = value
                }
                if let value = sessions["maxSessions"] as? Int { policy.maxSessions = value }
                config.maskingSessions = policy
            }
        }

        if let raw = root["nextStage"] as? String {
            guard let url = URL(string: raw) else {
                throw ConfigurationError.badValue("nextStage", "not a URL")
            }
            config.nextStageURL = url
        }
        if let value = root["drainSeconds"] as? Double { config.drainSeconds = value }

        return config
    }

    private static func section(_ root: [String: Any], _ name: String) throws -> [String: Any]? {
        guard let value = root[name] else { return nil }
        guard let object = value as? [String: Any] else {
            throw ConfigurationError.malformed("'\(name)' is not an object")
        }
        return object
    }

    private static func reject(unknownIn object: [String: Any], section: String,
                               allowed: Set<String>) throws {
        let unknown = Set(object.keys).subtracting(allowed)
        guard unknown.isEmpty else {
            throw ConfigurationError.unknownKeys(Array(unknown), section: section)
        }
    }

    // MARK: - Zusammenbau

    /// Baut die Pipeline aus der Konfiguration.
    ///
    /// Die Reihenfolge der Stufen steckt in `GatewayPipeline`, nicht hier —
    /// eine Konfiguration darf Stufen an- und abschalten, aber niemals ihre
    /// Position bestimmen. Sonst waere die Sicherheitsordnung aus DECISIONS
    /// eine Einstellung.
    public func makePipeline(embedder: Embedder? = nil,
                             quarantineSink: QuarantineSink? = nil) -> GatewayPipeline {
        GatewayPipeline(
            // `baseDirectory: nil` — der Vault bleibt im Speicher. Er ordnet
            // Platzhaltern KLARDATEN zu; ihn auf Platte zu legen macht aus
            // einer Maskierung eine Datei mit genau den Personendaten, die sie
            // vom Provider fernhalten sollte. Wer stabile Tokens ueber
            // Neustarts braucht, trifft diese Entscheidung im Host-Programm
            // bewusst — eine Konfigurationszeile ist dafuer zu billig.
            pii: pii ? PIIGate(policy: .gatewayDefault, baseDirectory: nil) : nil,
            malware: malware ? StructuralPayloadScanner() : nil,
            dlp: dlp ? DLPScanner() : nil,
            policy: policy,
            cache: cache.enabled ? SemanticCache(policy: cache) : nil,
            embedder: embedder,
            sessions: maskingSessions.map { MaskingSessionStore(policy: $0) },
            quarantine: quarantineSink.map { Quarantine(sink: $0, policy: quarantine) })
    }

    public func makeRateGuard() -> RateGuard? {
        rateLimit.enabled ? RateGuard(policy: rateLimit) : nil
    }
}
