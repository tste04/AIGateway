// Copyright (c) 2026 Tommy Stellmacher
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

import Foundation
import GatewayCore

// MARK: - Semantic Cache
//
// Die zweite Haelfte der Gateway-Box aus dem Zielbild. Position im Pfad ist
// verbindlich (DECISIONS): NACH der Firewall und NACH der Maskierung.
//
//   - Nach der Firewall, weil ein Cache davor mit vergifteten Prompts
//     befuellbar und an der Firewall vorbei ausspielbar waere.
//   - Nach der Maskierung, weil sonst Klardaten im Cache-Index laegen. Und
//     weil maskierte Anfragen, die sich nur in Namen unterscheiden, identisch
//     werden — die Pseudonymisierung HEBT die Trefferquote.
//
// DREI EIGENSCHAFTEN, die nicht verhandelbar sind:
//
// 1. **Der Schluessel traegt die Partition.** Ein Cache, der nur ueber den
//    Prompt schluesselt, spielt die Antwort eines Berechtigten an einen
//    Unberechtigten aus. Auch die semantische Suche laeuft ausschliesslich
//    innerhalb einer Partition.
// 2. **Abgelegt wird die MASKIERTE Antwort.** Sie enthaelt Platzhalter, keine
//    Klardaten. Ein spaeterer Aufrufer loest sie mit SEINER Zuordnung auf und
//    sieht seine eigenen Daten — nie die des Vorgaengers. Wuerde hier die
//    de-maskierte Antwort landen, waere der Cache ein PII-Leck zwischen
//    Nutzern derselben Partition.
// 3. **Entitaeten-Waechter vor Aehnlichkeit.** „Umsatz Q3" und „Umsatz Q4"
//    liegen im Einbettungsraum dicht beieinander und brauchen verschiedene
//    Antworten. Weichen Zahlen oder Platzhalter ab, gibt es keinen Treffer —
//    unabhaengig von der Kosinus-Aehnlichkeit.

// MARK: - Schluessel

/// Exakter Cache-Schluessel.
///
/// Traegt den kanonischen Text vollstaendig statt eines Hashes: ein Hash
/// koennte kollidieren, und eine Kollision hiesse, einem Aufrufer die Antwort
/// auf eine fremde Frage auszuliefern. Der Speicher ist ueber `maxEntries`
/// gedeckelt, der Text ist maskiert — der Preis ist tragbar.
public struct CacheKey: Hashable, Sendable {
    public let partition: String
    public let model: String
    public let prompt: String
    public let temperature: Double?
    public let maxTokens: Int?

    /// Baut den Schluessel aus der bereits maskierten Anfrage.
    ///
    /// Rollen gehen mit in den Text ein, getrennt durch Steuerzeichen: sonst
    /// ergaeben `system:"a" user:"b"` und `user:"a\nb"` denselben Schluessel.
    /// Die Trenner koennen im Inhalt nicht vorkommen — die Sanitisierung der
    /// Injection-Stufe entfernt alle C0-Steuerzeichen ausser Tab und Umbruch,
    /// und der Schluessel entsteht erst danach.
    public init(partition: String, request: ChatRequest) {
        self.partition = partition
        self.model = request.model
        self.temperature = request.temperature
        self.maxTokens = request.maxTokens
        self.prompt = request.messages
            .map { "\($0.role.rawValue)\u{1F}\($0.content)" }
            .joined(separator: "\u{1E}")
    }
}

// MARK: - Entitaeten

/// Zahlen und Platzhalter einer Anfrage — der Waechter gegen semantische
/// Beinahe-Treffer.
public struct EntitySignature: Hashable, Sendable {
    public let terms: Set<String>

    public init(terms: Set<String>) { self.terms = terms }

    /// Zieht alles heraus, was eine Ziffer enthaelt, sowie die gesetzten
    /// Platzhalter.
    ///
    /// Nach der Maskierung sind Eigennamen bereits Platzhalter — `[Person-1]`
    /// gegen `[Person-2]` ist damit ein Unterschied, den der Waechter sieht,
    /// ohne dass er Klarnamen kennen muesste.
    public static func of(_ text: String) -> EntitySignature {
        let range = NSRange(text.startIndex..., in: text)
        var terms = Set<String>()
        for match in entityRegex.matches(in: text, range: range) {
            guard let bounds = Range(match.range, in: text) else { continue }
            terms.insert(String(text[bounds]).lowercased())
        }
        return EntitySignature(terms: terms)
    }

    private static let entityRegex = try! NSRegularExpression(
        pattern: #"\[[A-Za-z]+-\d+\]|[\p{L}]*\d[\p{L}\d]*"#)
}

// MARK: - Betriebsparameter

public struct SemanticCachePolicy: Sendable, Equatable {
    /// Default AUS — wie jede Expositions-Entscheidung ein Opt-in.
    public var enabled: Bool
    /// Lebensdauer eines Eintrags.
    public var timeToLive: TimeInterval
    /// Obergrenze der Eintraege; darueber wird der aelteste Zugriff verdraengt.
    public var maxEntries: Int
    /// Ab dieser Kosinus-Aehnlichkeit gilt ein Eintrag als semantischer
    /// Treffer. Bewusst hoch: ein falscher Treffer ist eine falsche Antwort.
    public var similarityThreshold: Double
    /// Oberhalb dieser Temperatur wird nicht gecacht — wer Varianz anfordert,
    /// soll sie bekommen.
    public var maxTemperature: Double

    public init(enabled: Bool = false,
                timeToLive: TimeInterval = 3600,
                maxEntries: Int = 1000,
                similarityThreshold: Double = 0.95,
                maxTemperature: Double = 0.3) {
        self.enabled = enabled
        self.timeToLive = timeToLive
        self.maxEntries = maxEntries
        self.similarityThreshold = similarityThreshold
        self.maxTemperature = maxTemperature
    }

    public static let standard = SemanticCachePolicy()
    /// Eingeschaltet mit den Standardwerten.
    public static let on = SemanticCachePolicy(enabled: true)
}

// MARK: - Cachebarkeit

public enum CacheEligibility {

    /// Darf diese Anfrage ueberhaupt in den Cache?
    ///
    /// Drei Ausschluesse nach DECISIONS, jeder mit eigenem Grund:
    ///
    ///   - **Tool-Nachrichten**: der Inhalt stammt aus einem Werkzeuglauf und
    ///     gilt nur fuer diesen einen Vorgang.
    ///   - **Hohe Temperatur**: ausdruecklich angeforderte Varianz.
    ///     Fehlt die Angabe, gilt die Anfrage als cachebar — wer nichts sagt,
    ///     fordert keine Varianz an, sondern nimmt, was kommt.
    ///   - **Zeitbezug**: „was ist heute" hat morgen eine andere Antwort.
    public static func isCacheable(_ request: ChatRequest,
                                   policy: SemanticCachePolicy) -> Bool {
        guard policy.enabled else { return false }
        if request.messages.contains(where: { $0.role == .tool }) { return false }
        if let temperature = request.temperature, temperature > policy.maxTemperature {
            return false
        }
        if request.messages.contains(where: { hasTimeReference($0.content) }) { return false }
        return true
    }

    static func hasTimeReference(_ text: String) -> Bool {
        let range = NSRange(text.startIndex..., in: text)
        return timeRegex.firstMatch(in: text, range: range) != nil
    }

    /// Deutsche und englische Zeitbezuege. Wie beim Regelkatalog gilt: andere
    /// Sprachen brauchen eigene Muster.
    private static let timeRegex = try! NSRegularExpression(
        pattern: #"\b(heute|jetzt|gerade|aktuell|aktuelle[nrs]?|derzeit|momentan|"#
            + #"gestern|morgen|soeben|neueste[nrs]?|letzte[nrs]?\s+(woche|monat|jahr)|"#
            + #"diese[nrs]?\s+(woche|monat|jahr)|"#
            + #"today|now|currently|current|latest|recent|yesterday|tomorrow|"#
            + #"this\s+(week|month|year)|right\s+now)\b"#,
        options: [.caseInsensitive])
}

// MARK: - Der Cache

public actor SemanticCache {

    /// Was zu einer Anfrage abgelegt wird.
    struct Entry {
        let key: CacheKey
        /// MASKIERT. Siehe Kopfkommentar, Punkt 2.
        let response: ChatResponse
        let embedding: [Double]?
        let entities: EntitySignature
        let storedAt: Date
        var lastUsed: UInt64
    }

    /// Warum ein Treffer zustande kam — fuer Metrik und Tests.
    public enum HitKind: String, Sendable {
        case exact
        case semantic
    }

    public struct Hit: Sendable {
        /// Die maskierte Antwort. Der Aufrufer de-maskiert mit SEINER Session.
        public let response: ChatResponse
        public let kind: HitKind
    }

    private let policy: SemanticCachePolicy
    private var entries: [CacheKey: Entry] = [:]
    private var clock: UInt64 = 0

    public init(policy: SemanticCachePolicy = .on) {
        self.policy = policy
    }

    public var isEnabled: Bool { policy.enabled }

    public func count() -> Int { entries.count }

    /// Darf diese Anfrage in den Cache? Prueft gegen die eigene Policy, damit
    /// der Aufrufer sie nicht kennen muss.
    public func isCacheable(_ request: ChatRequest) -> Bool {
        CacheEligibility.isCacheable(request, policy: policy)
    }

    // MARK: Lookup

    /// Zweistufig: erst exakt, dann semantisch.
    ///
    /// - Parameters:
    ///   - embedding: Vektor der Anfrage, oder `nil`. Ohne Vektor entfaellt die
    ///     zweite Stufe — der Cache arbeitet dann rein exakt.
    ///   - entities: Signatur der Anfrage; muss bei semantischen Treffern
    ///     uebereinstimmen.
    public func lookup(key: CacheKey,
                       embedding: [Double]?,
                       entities: EntitySignature,
                       now: Date = Date()) -> Hit? {
        guard policy.enabled else { return nil }
        expire(now: now)

        // Stufe 1 — exakt. Der Schluessel enthaelt die Partition, damit kann
        // dieser Treffer die Grenze nicht verletzen.
        if let entry = entries[key] {
            clock += 1
            entries[key]?.lastUsed = clock
            return Hit(response: entry.response, kind: .exact)
        }

        // Stufe 2 — semantisch. NUR innerhalb derselben Partition und nur bei
        // gleichem Modell: ein anderes Modell antwortet anders, auch auf
        // dieselbe Frage.
        guard let embedding else { return nil }
        var best: (key: CacheKey, entry: Entry, score: Double)?
        for (candidateKey, entry) in entries
        where candidateKey.partition == key.partition && candidateKey.model == key.model {
            // Waechter VOR der Aehnlichkeit: abweichende Zahlen oder
            // Platzhalter schliessen den Treffer aus, egal wie nah der Vektor
            // liegt.
            guard entry.entities == entities else { continue }
            guard let candidateVector = entry.embedding,
                  let score = VectorMath.cosineSimilarity(embedding, candidateVector),
                  score >= policy.similarityThreshold else { continue }
            if best == nil || score > best!.score {
                best = (candidateKey, entry, score)
            }
        }
        guard let winner = best else { return nil }
        clock += 1
        entries[winner.key]?.lastUsed = clock
        return Hit(response: winner.entry.response, kind: .semantic)
    }

    // MARK: Store

    /// Legt eine MASKIERTE Antwort ab.
    ///
    /// Der Aufrufer ist dafuer verantwortlich, dass `response` noch Platzhalter
    /// traegt — de-maskiert abgelegt waere der Cache ein PII-Leck zwischen
    /// Nutzern derselben Partition.
    public func store(key: CacheKey,
                      maskedResponse: ChatResponse,
                      embedding: [Double]?,
                      entities: EntitySignature,
                      now: Date = Date()) {
        guard policy.enabled else { return }
        // Eine leere Antwort ist kein Ergebnis, sondern ein Fehlschlag.
        guard !maskedResponse.content.isEmpty else { return }

        expire(now: now)
        clock += 1
        entries[key] = Entry(key: key, response: maskedResponse, embedding: embedding,
                             entities: entities, storedAt: now, lastUsed: clock)
        evictIfNeeded()
    }

    public func removeAll() { entries.removeAll() }

    // MARK: Verdraengung

    private func expire(now: Date) {
        guard policy.timeToLive > 0 else { return }
        entries = entries.filter { now.timeIntervalSince($0.value.storedAt) <= policy.timeToLive }
    }

    /// Verdraengt den am laengsten nicht genutzten Eintrag, bis die Grenze
    /// haelt. Ohne Deckel waere der Cache ein Speicherleck mit Ansage.
    private func evictIfNeeded() {
        guard policy.maxEntries > 0 else { entries.removeAll(); return }
        while entries.count > policy.maxEntries {
            guard let oldest = entries.min(by: { $0.value.lastUsed < $1.value.lastUsed })?.key else {
                return
            }
            entries.removeValue(forKey: oldest)
        }
    }
}
