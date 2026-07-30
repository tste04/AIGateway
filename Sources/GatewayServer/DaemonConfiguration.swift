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
    /// HTTP-Embedder fuer die semantische Cache-Stufe. `nil` heisst: kein
    /// Embedder, der Cache arbeitet dann rein exakt. Der API-Schluessel kommt
    /// wie der Upstream-Schluessel NUR aus der Umgebung
    /// (`AIGATEWAY_EMBEDDER_API_KEY`), nie aus der Datei.
    public var embedderBaseURL: URL?
    public var embedderPath: String
    public var embedderModel: String
    public var embedderTimeout: TimeInterval
    public var embedderAPIKey: String?
    /// Mandanten-Identitaet ueber ein geteiltes Geheimnis. Aus = anonym (eine
    /// Partition). Das Geheimnis kommt NUR aus der Umgebung
    /// (`AIGATEWAY_IDENTITY_SECRET`), nie aus der Datei.
    public var identityEnabled: Bool
    /// Duerfen Anfragen ohne Identitaets-Header als anonym durchlaufen?
    public var identityAllowAnonymous: Bool
    public var identitySecret: String?

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
                drainSeconds: TimeInterval = 15,
                embedderBaseURL: URL? = nil,
                embedderPath: String = "api/embeddings",
                embedderModel: String = "nomic-embed-text",
                embedderTimeout: TimeInterval = 2,
                embedderAPIKey: String? = nil,
                identityEnabled: Bool = false,
                identityAllowAnonymous: Bool = true,
                identitySecret: String? = nil) {
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
        self.embedderBaseURL = embedderBaseURL
        self.embedderPath = embedderPath
        self.embedderModel = embedderModel
        self.embedderTimeout = embedderTimeout
        self.embedderAPIKey = embedderAPIKey
        self.identityEnabled = identityEnabled
        self.identityAllowAnonymous = identityAllowAnonymous
        self.identitySecret = identitySecret
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
        guard let rootObject = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw ConfigurationError.malformed("top level is not a JSON object")
        }
        var config = DaemonConfiguration()
        var root = Section(name: "root", values: rootObject)

        if var server = try root.subsection("server") {
            if let port = server.int("port") {
                guard (1...65_535).contains(port) else {
                    throw ConfigurationError.badValue("server.port", "outside 1...65535")
                }
                config.gateway.port = UInt16(port)
            }
            if let loopback = server.bool("loopbackOnly") { config.gateway.loopbackOnly = loopback }
            if let name = server.string("upstream") {
                guard let kind = ProviderKind(rawValue: name) else {
                    throw ConfigurationError.badValue("server.upstream", "unknown provider '\(name)'")
                }
                config.gateway.upstream = kind
            }
            if let raw = server.string("upstreamBaseURL") {
                guard let url = URL(string: raw) else {
                    throw ConfigurationError.badValue("server.upstreamBaseURL", "not a URL")
                }
                config.gateway.upstreamBaseURL = url
            }
            if let bytes = server.int("maxBodyBytes") { config.gateway.maxBodyBytes = bytes }
            if let debug = server.bool("debugErrorDetails") { config.gateway.debugErrorDetails = debug }
            if let value = server.int("readTimeoutSeconds") {
                config.gateway.readTimeoutSeconds = value
            }
            if let value = server.int("maxConcurrentConnections") {
                config.gateway.maxConcurrentConnections = value
            }
            if let value = server.double("upstreamTimeoutSeconds") {
                config.gateway.upstreamTimeoutSeconds = value
            }
            try server.finish()
        }

        // Der Schluessel kommt ausschliesslich aus der Umgebung — siehe
        // Kopfkommentar, Festlegung 1. Ein `apiKey` in der Datei faellt als
        // unbekannter Schluessel durch, wie jeder andere auch.
        config.gateway.apiKey = environment["AIGATEWAY_UPSTREAM_API_KEY"]

        if var policy = try root.subsection("policy") {
            if let value = policy.double("blockThreshold") { config.policy.blockThreshold = value }
            if let value = policy.int("maxInputBytes") { config.policy.maxInputBytes = value }
            if let value = policy.int("maxMessages") { config.policy.maxMessages = value }
            if let value = policy.double("stageBudgetMilliseconds") {
                config.policy.stageBudgetMilliseconds = value
            }
            if let value = policy.bool("failClosed") {
                config.policy.failureMode = value ? .failClosed : .failOpen
            }
            if let value = policy.bool("capClientSystemTrust") {
                config.policy.capClientSystemTrust = value
            }
            try policy.finish()
        }

        if var stages = try root.subsection("stages") {
            if let value = stages.bool("pii") { config.pii = value }
            if let value = stages.bool("dlp") { config.dlp = value }
            if let value = stages.bool("malware") { config.malware = value }
            try stages.finish()
        }

        if var cache = try root.subsection("cache") {
            if let value = cache.bool("enabled") { config.cache.enabled = value }
            if let value = cache.double("timeToLive") { config.cache.timeToLive = value }
            if let value = cache.int("maxEntries") { config.cache.maxEntries = value }
            if let value = cache.int("maxEntriesPerPartition") {
                config.cache.maxEntriesPerPartition = value
            }
            if let value = cache.double("similarityThreshold") {
                config.cache.similarityThreshold = value
            }
            if let value = cache.double("maxTemperature") { config.cache.maxTemperature = value }
            try cache.finish()
        }

        if var limit = try root.subsection("rateLimit") {
            if let value = limit.bool("enabled") { config.rateLimit.enabled = value }
            if let value = limit.int("requestsPerInterval") {
                config.rateLimit.requestsPerInterval = value
            }
            if let value = limit.double("interval") { config.rateLimit.interval = value }
            if let value = limit.int("burst") { config.rateLimit.burst = value }
            if let value = limit.int("maxTrackedSubjects") {
                config.rateLimit.maxTrackedSubjects = value
            }
            try limit.finish()
        }

        if var quarantine = try root.subsection("quarantine") {
            if let value = quarantine.bool("enabled") { config.quarantine.enabled = value }
            if let raw = quarantine.string("detail") {
                guard let detail = QuarantineDetail(rawValue: raw) else {
                    throw ConfigurationError.badValue("quarantine.detail", "unknown level '\(raw)'")
                }
                config.quarantine.detail = detail
            }
            if let value = quarantine.double("retention") { config.quarantine.retention = value }
            if let value = quarantine.double("nearMissBand") { config.quarantine.nearMissBand = value }
            try quarantine.finish()
        }

        if var sessions = try root.subsection("maskingSessions") {
            // Die Werte werden auch bei `enabled: false` gelesen: sie sind
            // dann wirkungslos, aber nicht unbekannt — eine vorbereitete
            // Konfiguration mit ausgeschaltetem Speicher ist kein Tippfehler.
            let enabled = sessions.bool("enabled") ?? false
            var policy = MaskingSessionPolicy()
            if let value = sessions.double("timeToLive") { policy.timeToLive = value }
            if let value = sessions.double("extendedTimeToLive") {
                policy.extendedTimeToLive = value
            }
            if let value = sessions.int("maxSessions") { policy.maxSessions = value }
            try sessions.finish()
            if enabled { config.maskingSessions = policy }
        }

        if var embedder = try root.subsection("embedder") {
            if let raw = embedder.string("baseURL") {
                guard let url = URL(string: raw) else {
                    throw ConfigurationError.badValue("embedder.baseURL", "not a URL")
                }
                config.embedderBaseURL = url
            }
            if let value = embedder.string("path") { config.embedderPath = value }
            if let value = embedder.string("model") { config.embedderModel = value }
            if let value = embedder.double("timeout") { config.embedderTimeout = value }
            try embedder.finish()
        }
        // Wie der Upstream-Schluessel: nur aus der Umgebung.
        config.embedderAPIKey = environment["AIGATEWAY_EMBEDDER_API_KEY"]

        if var identity = try root.subsection("identity") {
            if let value = identity.bool("enabled") { config.identityEnabled = value }
            if let value = identity.bool("allowAnonymous") { config.identityAllowAnonymous = value }
            try identity.finish()
        }
        config.identitySecret = environment["AIGATEWAY_IDENTITY_SECRET"]

        if let raw = root.string("nextStage") {
            guard let url = URL(string: raw) else {
                throw ConfigurationError.badValue("nextStage", "not a URL")
            }
            config.nextStageURL = url
        }
        if let value = root.double("drainSeconds") { config.drainSeconds = value }
        try root.finish()

        // Identitaet eingeschaltet, aber kein Geheimnis: fail-closed und LAUT.
        // Still auf anonym zurueckzufallen liesse den Betreiber glauben, er
        // trenne Mandanten, waehrend alle eine Partition teilen.
        if config.identityEnabled, (config.identitySecret ?? "").isEmpty {
            throw ConfigurationError.badValue(
                "identity", "enabled but AIGATEWAY_IDENTITY_SECRET is unset")
        }
        // Der gefaehrliche Dreiklang: der Cache spielt Antworten in einer
        // Partition aus, ein oeffentlicher Bind laesst beliebige Aufrufer an, und
        // ohne Identitaet teilen sich ALLE dieselbe Partition — der Cache wuerde
        // die Antwort eines Aufrufers an einen fremden ausspielen. Das ist keine
        // Betriebswahl, sondern eine falsch-sichere Konfiguration; abweisen.
        if config.cache.enabled, !config.gateway.loopbackOnly, !config.identityEnabled {
            throw ConfigurationError.badValue(
                "cache", "enabled with a non-loopback bind and no identity — the cache "
                    + "would serve answers across unseparated callers; enable identity "
                    + "or bind to loopback")
        }

        return config
    }

    /// Ein Abschnitt der Datei, der MITSCHREIBT, was gelesen wurde.
    ///
    /// Vorher standen die erlaubten Schluessel in einer separaten Liste, die
    /// von Hand mit den Lesungen synchron zu halten war — ein vergessener
    /// Listeneintrag machte aus einer gueltigen Einstellung einen Fehler, ein
    /// vergessenes Lesen aus einem gelisteten Schluessel eine stille
    /// Wirkungslosigkeit. Jetzt IST die Lesung die Liste: was am Ende nicht
    /// gelesen wurde, ist unbekannt. Der Fehlermodus aus dem Kopfkommentar
    /// bleibt derselbe; er laesst sich nur nicht mehr durch Vergessen umgehen.
    private struct Section {
        let name: String
        private let values: [String: Any]
        private var seen: Set<String> = []

        init(name: String, values: [String: Any]) {
            self.name = name
            self.values = values
        }

        mutating func int(_ key: String) -> Int? {
            seen.insert(key)
            return values[key] as? Int
        }

        mutating func double(_ key: String) -> Double? {
            seen.insert(key)
            return values[key] as? Double
        }

        mutating func bool(_ key: String) -> Bool? {
            seen.insert(key)
            return values[key] as? Bool
        }

        mutating func string(_ key: String) -> String? {
            seen.insert(key)
            return values[key] as? String
        }

        mutating func subsection(_ key: String) throws -> Section? {
            seen.insert(key)
            guard let value = values[key] else { return nil }
            guard let object = value as? [String: Any] else {
                throw ConfigurationError.malformed("'\(key)' is not an object")
            }
            return Section(name: key, values: object)
        }

        func finish() throws {
            let unknown = Set(values.keys).subtracting(seen)
            guard unknown.isEmpty else {
                throw ConfigurationError.unknownKeys(Array(unknown), section: name)
            }
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

    /// Der Beweismittelschrank fuer den Feedback Loop. `nil`, wenn die
    /// Quarantaene aus ist. Bewusst der In-Memory-Sink: eine persistente Senke
    /// haelt Nutzinhalt auf Platte und entscheidet ueber Ablageort und
    /// Loeschfrist des Betreibers mit — das ist Host-Programm-Sache, keine
    /// Konfigurationszeile (siehe QuarantineSink-Invariante).
    public func makeQuarantineSink() -> QuarantineSink? {
        quarantine.enabled ? MemoryQuarantineSink() : nil
    }

    /// Der Embedder fuer die semantische Cache-Stufe, oder `nil`. Ohne ihn
    /// arbeitet der Cache rein exakt — die zweite Stufe verliert Reichweite,
    /// nicht Funktion. Bricht keine harte Regel: ausgehende `URLSession` ist die
    /// erlaubte Netz-Ausnahme.
    public func makeEmbedder() -> Embedder? {
        guard let url = embedderBaseURL else { return nil }
        return HTTPEmbedder(baseURL: url, path: embedderPath, model: embedderModel,
                            apiKey: embedderAPIKey, timeout: embedderTimeout)
    }

    /// Stellt den Aufrufer fest. Ohne eingeschaltete Identitaet der anonyme
    /// Resolver — er IGNORIERT Identitaets-Header, statt ihnen zu folgen (eine
    /// Partition, niemand kann eine waehlen). Mit Identitaet der
    /// `SharedSecretPrincipalResolver`; dass das Geheimnis dann gesetzt ist,
    /// hat `parse` bereits fail-closed geprueft.
    public func makePrincipalResolver() -> PrincipalResolver {
        guard identityEnabled, let secret = identitySecret,
              let resolver = SharedSecretPrincipalResolver(
                secret: secret, allowAnonymous: identityAllowAnonymous)
        else { return AnonymousPrincipalResolver() }
        return resolver
    }
}
