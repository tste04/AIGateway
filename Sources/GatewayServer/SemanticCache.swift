// Copyright (c) 2026 Tommy Stellmacher
// SPDX-License-Identifier: Apache-2.0

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

    /// Feldweise — fuer den Wiederanlauf aus einem Abzug, wo die Anfrage nicht
    /// mehr vorliegt, sondern nur noch ihr kanonischer Text.
    public init(partition: String, model: String, prompt: String,
                temperature: Double?, maxTokens: Int?) {
        self.partition = partition
        self.model = model
        self.prompt = prompt
        self.temperature = temperature
        self.maxTokens = maxTokens
    }
}

// MARK: - Entitaeten

/// Zahlen, Platzhalter und Eigennamen einer Anfrage — der Waechter gegen
/// semantische Beinahe-Treffer.
public struct EntitySignature: Hashable, Sendable {
    public let terms: Set<String>

    public init(terms: Set<String>) { self.terms = terms }

    /// Sammelt drei Arten von Begriffen:
    ///
    ///   1. gesetzte Platzhalter (`[Person-1]`),
    ///   2. alles mit einer Ziffer (Q3, 2026, 42),
    ///   3. grossgeschriebene Woerter, abzueglich Funktionswoerter.
    ///
    /// Punkt 3 kam nach: mit Ziffern allein hatten „Umsatz Nord" und
    /// „Umsatz Sued" dieselbe Signatur, lagen im Einbettungsraum dicht
    /// beieinander und haetten sich gegenseitig beantwortet — genau der
    /// Fehler, gegen den der Waechter steht. DECISIONS verlangt ausdruecklich
    /// auch Eigennamen.
    ///
    /// Im Deutschen ist jedes Substantiv grossgeschrieben, die Signatur ist
    /// damit ungefaehr die Menge der Inhaltswoerter. Das macht den Waechter
    /// streng: verschiedene Substantive heissen kein Treffer. Diese Richtung
    /// ist die richtige — ein verpasster Treffer kostet einen Modellaufruf,
    /// ein falscher liefert eine falsche Antwort. Die Umformulierungen, die
    /// die semantische Stufe fangen soll (Wortstellung, Hoeflichkeitsfloskeln,
    /// Fuellwoerter), lassen die Inhaltswoerter ohnehin stehen.
    public static func of(_ text: String) -> EntitySignature {
        let range = NSRange(text.startIndex..., in: text)
        var terms = Set<String>()
        for match in entityRegex.matches(in: text, range: range) {
            guard let bounds = Range(match.range, in: text) else { continue }
            let term = String(text[bounds]).lowercased()
            guard !functionWords.contains(term) else { continue }
            terms.insert(term)
        }
        return EntitySignature(terms: terms)
    }

    /// Reihenfolge zaehlt: die Ziffern-Alternative steht vor der
    /// Grossschreibungs-Alternative, sonst faenge letztere „Q" aus „Q3".
    private static let entityRegex = try! NSRegularExpression(
        pattern: #"\[[A-Za-z]+-\d+\]|[\p{L}]*\d[\p{L}\d]*|\p{Lu}[\p{L}]+"#)

    /// Woerter, die nur wegen des Satzanfangs grossgeschrieben sind und keine
    /// Entitaet bezeichnen. Ohne sie unterschieden sich „Was ist Routing?" und
    /// „Erklaere Routing" in der Signatur, und die semantische Stufe liefe leer.
    ///
    /// Wie beim Regelkatalog: Deutsch und Englisch: andere Sprachen brauchen
    /// eigene Listen.
    static let functionWords: Set<String> = [
        // Deutsch — Fragewoerter, Aufforderungen, Artikel, Pronomen
        "was", "wie", "warum", "wieso", "weshalb", "wer", "wen", "wem", "wann",
        "wo", "woher", "wohin", "welche", "welcher", "welches", "welchen", "welchem",
        "bitte", "erklaere", "erkläre", "erklaer", "erklär", "nenne", "nenn",
        "zeige", "zeig", "gib", "sage", "sag", "schreibe", "schreib", "fasse",
        "fass", "liste", "beschreibe", "beschreib", "vergleiche", "vergleich",
        "kann", "kannst", "koennen", "können", "koennte", "könnte", "soll",
        "sollst", "ist", "sind", "war", "waren", "hat", "haben", "gibt",
        "der", "die", "das", "den", "dem", "des", "ein", "eine", "einer",
        "eines", "einem", "einen", "und", "oder", "aber", "auch", "nicht",
        "kein", "keine", "ich", "du", "er", "sie", "es", "wir", "ihr", "mir",
        "mich", "dir", "dich", "uns", "euch", "man",
        "in", "an", "auf", "fuer", "für", "mit", "von", "zu", "bei", "aus",
        "ueber", "über", "unter", "nach", "vor", "ohne", "durch",
        // Englisch
        "what", "how", "why", "who", "whom", "when", "where", "which",
        "please", "explain", "tell", "show", "give", "describe", "list",
        "write", "summarize", "summarise", "compare",
        "can", "could", "would", "should", "do", "does", "did", "have", "has",
        "is", "are", "were", "be",
        "the", "a", "an", "and", "or", "but", "not", "no",
        "i", "you", "he", "she", "it", "we", "they", "me", "us", "them",
        "on", "at", "for", "with", "from", "to", "by", "about", "of",
    ]
}

// MARK: - Betriebsparameter

public struct SemanticCachePolicy: Sendable, Equatable {
    /// Default AUS — wie jede Expositions-Entscheidung ein Opt-in.
    public var enabled: Bool
    /// Lebensdauer eines Eintrags.
    public var timeToLive: TimeInterval
    /// Obergrenze der Eintraege; darueber wird der aelteste Zugriff verdraengt.
    public var maxEntries: Int
    /// Obergrenze JE PARTITION. `0` heisst: keine.
    ///
    /// Ohne sie ist der globale Deckel ein Hebel zwischen Mandanten: wer viel
    /// schreibt, verdraengt die Eintraege aller anderen und macht deren Cache
    /// wertlos, ohne je ihre Daten zu sehen. Das ist kein Datenleck, aber ein
    /// Verfuegbarkeitsproblem — und der Deckel je Partition ist die Antwort
    /// darauf, dieselbe Ueberlegung wie beim Rate-Guard.
    public var maxEntriesPerPartition: Int
    /// Ab dieser Kosinus-Aehnlichkeit gilt ein Eintrag als semantischer
    /// Treffer. Bewusst hoch: ein falscher Treffer ist eine falsche Antwort.
    public var similarityThreshold: Double
    /// Oberhalb dieser Temperatur wird nicht gecacht — wer Varianz anfordert,
    /// soll sie bekommen.
    public var maxTemperature: Double
    /// So viele Embedder-Fehlschlaege in Folge schalten die semantische Stufe
    /// ab. Der Embedder ist die einzige Netz-Abhaengigkeit im Anfragepfad:
    /// haengt er, statt zu sterben, zahlt sonst JEDE cachebare Anfrage sein
    /// Zeitlimit, bevor sie in den Fehltreffer faellt — der Cache macht das
    /// Gateway dann langsamer statt schneller.
    public var embedderFailureThreshold: Int
    /// So lange bleibt die semantische Stufe danach aus. Der exakte Treffer
    /// laeuft die ganze Zeit weiter — er braucht keinen Embedder.
    public var embedderCooldown: TimeInterval

    public init(enabled: Bool = false,
                timeToLive: TimeInterval = 3600,
                maxEntries: Int = 1000,
                maxEntriesPerPartition: Int = 200,
                similarityThreshold: Double = 0.95,
                maxTemperature: Double = 0.3,
                embedderFailureThreshold: Int = 3,
                embedderCooldown: TimeInterval = 30) {
        self.enabled = enabled
        self.timeToLive = timeToLive
        self.maxEntries = maxEntries
        self.maxEntriesPerPartition = maxEntriesPerPartition
        self.similarityThreshold = similarityThreshold
        self.maxTemperature = maxTemperature
        self.embedderFailureThreshold = embedderFailureThreshold
        self.embedderCooldown = embedderCooldown
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

    /// `nonisolated`, weil unveraenderlich: die Pipeline liest Schwellen und
    /// Cachebarkeit ohne Actor-Sprung, und der Actor bleibt fuer die Eintraege
    /// zustaendig.
    public nonisolated let policy: SemanticCachePolicy
    private var entries: [CacheKey: Entry] = [:]
    private var clock: UInt64 = 0
    private var stats = CacheStatistics()

    public init(policy: SemanticCachePolicy = .on) {
        self.policy = policy
    }

    public func count() -> Int { entries.count }

    /// Eintraege einer Partition — fuer Betrieb und Tests der Quote.
    public func count(partition: String) -> Int {
        entries.keys.filter { $0.partition == partition }.count
    }

    /// Darf diese Anfrage in den Cache? Prueft gegen die eigene Policy, damit
    /// der Aufrufer sie nicht kennen muss.
    public nonisolated func isCacheable(_ request: ChatRequest) -> Bool {
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
        stats.lookups += 1

        // Stufe 1 — exakt. Der Schluessel enthaelt die Partition, damit kann
        // dieser Treffer die Grenze nicht verletzen.
        if let entry = entries[key] {
            clock += 1
            entries[key]?.lastUsed = clock
            stats.exactHits += 1
            return Hit(response: entry.response, kind: .exact)
        }

        // Stufe 2 — semantisch. NUR innerhalb derselben Partition und nur bei
        // gleichem Modell: ein anderes Modell antwortet anders, auch auf
        // dieselbe Frage.
        guard let embedding else { stats.misses += 1; return nil }
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
        guard let winner = best else { stats.misses += 1; return nil }
        clock += 1
        entries[winner.key]?.lastUsed = clock
        stats.semanticHits += 1
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
        stats.stores += 1
        evictIfNeeded(partition: key.partition)
    }

    // MARK: - Invalidierung
    //
    // Der Cache haelt Antworten eines Modells zu einem Wissensstand. Aendert
    // sich einer von beiden — neues Modell, neu geladene Wissensbasis,
    // zurueckgezogene Freigabe eines Mandanten — sind die Eintraege nicht
    // abgelaufen, sondern FALSCH. Die Frist hilft dagegen nicht: sie ist ein
    // Zeitmass, kein Ereignis. Deshalb drei gezielte Griffe.

    public func removeAll() {
        stats.invalidations += entries.count
        entries.removeAll()
    }

    /// Wirft alles einer Partition weg — der Griff fuer „Mandant hat seine
    /// Berechtigung verloren" und fuer jeden Zweifel an der Abgrenzung.
    @discardableResult
    public func invalidate(partition: String) -> Int {
        remove { $0.partition == partition }
    }

    /// Wirft alles zu einem Modell weg — der Griff fuer „Modellversion
    /// gewechselt". Antworten eines abgeloesten Modells sind nicht alt,
    /// sondern von jemand anderem.
    @discardableResult
    public func invalidate(model: String) -> Int {
        remove { $0.model == model }
    }

    @discardableResult
    public func invalidate(partition: String, model: String) -> Int {
        remove { $0.partition == partition && $0.model == model }
    }

    private func remove(where predicate: (CacheKey) -> Bool) -> Int {
        let doomed = entries.keys.filter(predicate)
        for key in doomed { entries.removeValue(forKey: key) }
        stats.invalidations += doomed.count
        return doomed.count
    }

    // MARK: - Metrik

    /// Zaehlerstand. Die Trefferquote ist die einzige Zahl, an der sich
    /// entscheidet, ob der Cache seinen Preis wert ist — sie zu schaetzen
    /// hiesse, den Kostenhebel im Dunkeln zu betreiben.
    public func statistics() -> CacheStatistics { stats }

    public func resetStatistics() { stats = CacheStatistics() }

    // MARK: - Persistenz-Naht
    //
    // Der Cache haelt seine Eintraege im Speicher, und dabei bleibt es. Was
    // hier fehlt, ist bewusst nicht gebaut: eine Bibliothek, die selbst auf
    // Platte schreibt, entscheidet ueber Ablageort, Verschluesselung und
    // Loeschfristen des Betreibers mit — dieselbe Ueberlegung wie bei
    // `QuarantineSink` und `PayloadScanner`.
    //
    // ZU BEDENKEN, bevor jemand `snapshot()` auf Platte legt: der Inhalt ist
    // nur dann platzhalterbehaftet, wenn eine PII-Stufe konfiguriert ist. Ohne
    // sie stehen dort rohe Modellantworten. Ein Abzug ist damit ein
    // Daten-in-Ruhe-Problem und braucht dieselbe Behandlung wie die
    // Quarantaene: Frist, Zugriffsschutz, bewusste Entscheidung.

    /// Abzug des Bestands. Vektoren gehen mit, sonst faellt der Wiederanlauf
    /// auf die exakte Stufe zurueck, bis jeder Eintrag neu eingebettet ist.
    public func snapshot() -> CacheSnapshot {
        CacheSnapshot(entries: entries.values.map {
            CacheSnapshot.Item(partition: $0.key.partition, model: $0.key.model,
                               prompt: $0.key.prompt, temperature: $0.key.temperature,
                               maxTokens: $0.key.maxTokens, response: $0.response,
                               embedding: $0.embedding, entities: Array($0.entities.terms),
                               storedAt: $0.storedAt)
        })
    }

    /// Spielt einen Abzug ein. Abgelaufene Eintraege werden dabei fallen
    /// gelassen, nicht mit neuem Datum wiederbelebt — sonst verlaengerte ein
    /// Neustart jede Frist.
    ///
    /// - Returns: Anzahl der uebernommenen Eintraege.
    @discardableResult
    public func restore(_ snapshot: CacheSnapshot, now: Date = Date()) -> Int {
        var taken = 0
        for item in snapshot.entries {
            if policy.timeToLive > 0,
               now.timeIntervalSince(item.storedAt) > policy.timeToLive { continue }
            let key = CacheKey(partition: item.partition, model: item.model,
                               prompt: item.prompt, temperature: item.temperature,
                               maxTokens: item.maxTokens)
            clock += 1
            entries[key] = Entry(key: key, response: item.response, embedding: item.embedding,
                                 entities: EntitySignature(terms: Set(item.entities)),
                                 storedAt: item.storedAt, lastUsed: clock)
            taken += 1
        }
        evictIfNeeded(partition: nil)
        return taken
    }

    // MARK: Verdraengung

    private func expire(now: Date) {
        guard policy.timeToLive > 0 else { return }
        let before = entries.count
        entries = entries.filter { now.timeIntervalSince($0.value.storedAt) <= policy.timeToLive }
        stats.expirations += before - entries.count
    }

    /// Verdraengt den am laengsten nicht genutzten Eintrag, bis beide Grenzen
    /// halten. Ohne Deckel waere der Cache ein Speicherleck mit Ansage.
    ///
    /// Die Partition zuerst: waere es umgekehrt, koennte der globale Deckel
    /// fremde Eintraege wegwerfen, um Platz fuer eine Partition zu schaffen,
    /// die ihr eigenes Kontingent gerade ueberzieht — genau der
    /// Nachbarschaftsschaden, gegen den `maxEntriesPerPartition` steht.
    private func evictIfNeeded(partition: String?) {
        if let partition, policy.maxEntriesPerPartition > 0 {
            evict(limit: policy.maxEntriesPerPartition) { $0.partition == partition }
        }
        guard policy.maxEntries > 0 else {
            stats.evictions += entries.count
            entries.removeAll()
            return
        }
        evict(limit: policy.maxEntries) { _ in true }
    }

    private func evict(limit: Int, scope: (CacheKey) -> Bool) {
        var inScope = entries.filter { scope($0.key) }
        while inScope.count > limit {
            guard let oldest = inScope.min(by: { $0.value.lastUsed < $1.value.lastUsed })?.key else {
                return
            }
            inScope.removeValue(forKey: oldest)
            entries.removeValue(forKey: oldest)
            stats.evictions += 1
        }
    }
}

// MARK: - Zaehler

/// Betriebszahlen des Caches. Reine Zaehler, kein Inhalt — dieselbe Linie wie
/// beim `AuditEvent`: eine Metrik, die Prompts traegt, ist ein Leck mit
/// Dashboard.
public struct CacheStatistics: Sendable, Equatable, Codable {
    public var lookups = 0
    public var exactHits = 0
    public var semanticHits = 0
    public var misses = 0
    public var stores = 0
    public var evictions = 0
    public var expirations = 0
    public var invalidations = 0

    public init() {}

    public var hits: Int { exactHits + semanticHits }

    /// Anteil der Anfragen, die ohne Modellaufruf beantwortet wurden.
    /// `nil` bei null Abfragen — 0 % waere hier eine Behauptung ueber nichts.
    public var hitRate: Double? {
        guard lookups > 0 else { return nil }
        return Double(hits) / Double(lookups)
    }
}

// MARK: - Abzug

/// Serialisierbarer Bestand des Caches. Siehe die Warnung an `snapshot()`.
public struct CacheSnapshot: Sendable, Codable {
    public struct Item: Sendable, Codable {
        public let partition: String
        public let model: String
        public let prompt: String
        public let temperature: Double?
        public let maxTokens: Int?
        public let response: ChatResponse
        public let embedding: [Double]?
        public let entities: [String]
        public let storedAt: Date

        public init(partition: String, model: String, prompt: String, temperature: Double?,
                    maxTokens: Int?, response: ChatResponse, embedding: [Double]?,
                    entities: [String], storedAt: Date) {
            self.partition = partition
            self.model = model
            self.prompt = prompt
            self.temperature = temperature
            self.maxTokens = maxTokens
            self.response = response
            self.embedding = embedding
            self.entities = entities
            self.storedAt = storedAt
        }
    }

    public let entries: [Item]

    public init(entries: [Item]) { self.entries = entries }
}
