// Copyright (c) 2026 Tommy Stellmacher
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

import Foundation
import Dispatch
import GatewayCore
import InputFirewall

// MARK: - Die Pipeline
//
// Reihenfolge nach docs/DECISIONS.md:
//
//   Groessen-Guard -> Injection -> PII-Maskierung -> (DLP) -> (Cache) -> weiter
//
// Der TEXT fliesst durch die Stufen: jede Stufe arbeitet auf dem Ergebnis der
// vorigen, und weitergereicht wird, was hinten herauskommt. Eine Stufe, deren
// bereinigter Inhalt verworfen wird, erzeugt Befunde ohne Wirkung.
//
// DLP und Semantic Cache sind noch nicht gebaut; ihre Plaetze sind markiert,
// damit sie spaeter nicht an falscher Stelle eingehaengt werden.

public actor GatewayPipeline {

    /// Alles, was der Rueckweg braucht, um die Antwort abzulegen.
    public struct CacheTicket: Sendable {
        public let key: CacheKey
        public let embedding: [Double]?
        public let entities: EntitySignature
    }

    public struct Outcome: Sendable {
        public let decision: GatewayDecision
        public let audit: AuditEvent
        /// Die weiterzureichende Anfrage — `nil`, wenn geblockt wurde.
        public let forward: ChatRequest?
        /// Rueckuebersetzung fuer den Antwortpfad.
        public let session: MaskingSession
        /// Antwort aus dem Cache, noch MASKIERT. Ist sie gesetzt, entfaellt
        /// der Weg nach oben; de-maskiert wird sie mit `session`.
        public let cached: ChatResponse?
        /// Gesetzt, wenn die Antwort abgelegt werden soll. `nil` bei Treffer
        /// (liegt schon), bei nicht cachebaren Anfragen und ohne Cache.
        public let cacheTicket: CacheTicket?

        init(decision: GatewayDecision, audit: AuditEvent, forward: ChatRequest?,
             session: MaskingSession, cached: ChatResponse? = nil,
             cacheTicket: CacheTicket? = nil) {
            self.decision = decision
            self.audit = audit
            self.forward = forward
            self.session = session
            self.cached = cached
            self.cacheTicket = cacheTicket
        }
    }

    private let injection: InjectionScanner
    private let pii: PIIGate?
    private let policy: GatewayPolicy
    private let cache: SemanticCache?
    private let embedder: Embedder?
    /// Optionaler Ablageort fuer die Rueckuebersetzung. Ohne ihn traegt der
    /// Aufrufer die Session selbst — das reicht, solange die Antwort im selben
    /// Aufruf zurueckkommt. Wer sie ueber einen Agent Loop oder eine
    /// menschliche Freigabe hinweg braucht, konfiguriert einen Speicher.
    private let sessions: MaskingSessionStore?
    /// Zustand des Embedder-Sicherungsschalters. Liegt hier, weil er ueber
    /// Anfragen hinweg gelten muss — und die Pipeline ist der Actor, der sie
    /// alle sieht.
    private var embedderFailures = 0
    private var embedderOpenUntil: Date?

    public init(injection: InjectionScanner = InjectionScanner(),
                pii: PIIGate? = nil,
                policy: GatewayPolicy = .standard,
                cache: SemanticCache? = nil,
                embedder: Embedder? = nil,
                sessions: MaskingSessionStore? = nil) {
        self.injection = injection
        self.pii = pii
        self.policy = policy
        self.cache = cache
        self.embedder = embedder
        self.sessions = sessions
    }

    /// Vertrauensstufe aus der Nachrichtenrolle.
    ///
    /// Das ist die wichtigste Einzelfestlegung dieser Stufe: **Tool-Ausgaben
    /// gelten als fremd.** Im Agent Loop ist genau das der Hauptangriffsweg —
    /// ein Werkzeug liefert Fremdinhalt zurueck, der als Anweisung gelesen wird.
    /// Systemnachrichten stammen aus der Anwendung selbst und sind vertrauens-
    /// wuerdig; alles vom Nutzer liegt neutral dazwischen.
    public static func trust(for role: ChatMessage.Role) -> SourceTrust {
        switch role {
        case .system: return .trusted
        case .user, .assistant: return .neutral
        case .tool: return .untrusted
        }
    }

    public func process(_ request: ChatRequest,
                        principal: Principal,
                        correlationID: String = UUID().uuidString) async -> Outcome {
        var findings: [Finding] = []
        var timings: [StageTiming] = []
        var worstRisk = 0.0
        // Ob eine Stufe den Inhalt angefasst hat. Gefuehrt aus
        // `ScanResult.wasModified` und NICHT aus einem Vergleich der Nachrichten:
        // der Vergleich sieht nur das Ergebnis, nicht den Eingriff — und er
        // uebersieht jede Bereinigung, die zufaellig denselben Text erzeugt.
        var wasModified = false

        // Stufe 1 — harte Eingabegrenzen. VOR jedem Regelwerk, sonst laeuft es
        // ueber beliebig grosse Eingaben. Beide Achsen pruefen: die Byte-Grenze
        // deckelt die Textmenge, die Stueckzahl-Grenze die Anzahl der
        // Scanner-Laeufe — 100.000 Kleinst-Nachrichten reissen die Byte-Grenze
        // nicht, kosten aber 100.000 Regelwerks-Durchgaenge.
        let payloadBytes = request.scannableText.utf8.count
        if payloadBytes > policy.maxInputBytes {
            let finding = Finding(
                ruleID: Self.ruleOversizedInput, category: .anomaly, severity: .high, weight: 1.0,
                message: "request exceeds maxInputBytes (\(payloadBytes) > \(policy.maxInputBytes))")
            return blocked(correlationID: correlationID, principal: principal, model: request.model,
                           findings: [finding], risk: 1.0,
                           content: "", timings: [], bytes: payloadBytes)
        }
        if request.messages.count > policy.maxMessages {
            let finding = Finding(
                ruleID: Self.ruleTooManyMessages, category: .anomaly, severity: .high, weight: 1.0,
                message: "request exceeds maxMessages (\(request.messages.count) > \(policy.maxMessages))")
            return blocked(correlationID: correlationID, principal: principal, model: request.model,
                           findings: [finding], risk: 1.0,
                           content: "", timings: [], bytes: payloadBytes)
        }

        // Stufe 2 — Injection, je Nachricht mit rollenabhaengiger Provenienz.
        //
        // Der bereinigte Text der Stufe wird UEBERNOMMEN. Die Sanitisierung
        // entfernt genau die Zeichen, mit denen Anweisungen getarnt werden; sie
        // zu erkennen und anschliessend doch das Original weiterzureichen, waere
        // ein Befund ohne Wirkung.
        var sanitized = request
        var scanned: [ChatMessage] = []
        let injectionStart = DispatchTime.now().uptimeNanoseconds
        for message in request.messages {
            let result = injection.scan(message.content, trust: Self.trust(for: message.role))
            findings += result.findings
            worstRisk = max(worstRisk, policy.disposition(for: result).1)
            wasModified = wasModified || result.wasModified
            scanned.append(ChatMessage(role: message.role, content: result.content))
        }
        sanitized.messages = scanned
        timings.append(budgetTiming(injection.stageName, since: injectionStart))

        // Bei `.block` wandert das ORIGINAL in die Entscheidung — die Quarantaene
        // soll den Angriff so sehen, wie er ankam, nicht bereinigt.
        if worstRisk >= policy.blockThreshold {
            return blocked(correlationID: correlationID, principal: principal, model: request.model,
                           findings: findings, risk: worstRisk,
                           content: request.scannableText, timings: timings, bytes: payloadBytes)
        }
        if let timing = timings.last, timing.timedOut, policy.failureMode == .failClosed {
            findings.append(Self.budgetFinding(timing, budget: policy.stageBudgetMilliseconds))
            return blocked(correlationID: correlationID, principal: principal, model: request.model,
                           findings: findings, risk: 1.0,
                           content: request.scannableText, timings: timings, bytes: payloadBytes)
        }

        // Stufe 3 — PII maskieren. MUSS vor der Cache-Schluessel-Bildung liegen
        // (siehe DECISIONS): kein Klardatum im Cache-Index, und maskierte
        // Anfragen kollidieren oefter, was die Trefferquote hebt.
        var forwarded = sanitized
        var mapping: [String: String] = [:]
        if let pii {
            let piiStart = DispatchTime.now().uptimeNanoseconds
            // Maskiert wird der BEREINIGTE Text. Erkennung und Maskierung muessen
            // auf derselben Fassung laufen — sonst sucht die PII-Stufe Muster in
            // Zeichenfolgen, die so gar nicht mehr ausgeliefert werden, und ein
            // getarntes Zeichen mitten im Namen laesst sie danebengreifen.
            //
            // BEWUSST OHNE `sparingQuery`: `keepQueriedEntity` liesse Personen
            // aus der Nutzerfrage im Klartext. Im Gateway ist die Frage aber
            // Teil des maskierten Bestands — bei einer Ein-Nachrichten-Anfrage
            // WAERE sie der gesamte Bestand, und die Personen-Maskierung liefe
            // im haeufigsten Fall leer. In Mehr-Nachrichten-Anfragen staende
            // derselbe Name zudem einmal klar (Frage) und einmal als Token
            // (Kontext) im selben Prompt — der Provider koennte die Zuordnung
            // einfach ablesen. Die Schonung bleibt ein Feature der Bibliothek
            // (`PIIGate.mask(_:sparingQuery:)`), wo Frage und Bestand getrennte
            // Dinge sind.
            var masked: [ChatMessage] = []
            var piiRisk = 0.0
            for message in sanitized.messages {
                let outcome = await pii.mask(message.content)
                findings += outcome.scan.findings
                piiRisk = max(piiRisk, policy.disposition(for: outcome.scan).1)
                wasModified = wasModified || outcome.scan.wasModified
                // Zuordnungen vereinigen: derselbe Vault vergibt stabile Tokens,
                // Kollisionen sind daher konsistent und nicht verlustbehaftet.
                mapping.merge(outcome.session.mapping) { current, _ in current }
                masked.append(ChatMessage(role: message.role, content: outcome.maskedContent))
            }
            forwarded.messages = masked
            worstRisk = max(worstRisk, piiRisk)
            timings.append(budgetTiming(pii.stageName, since: piiStart))

            if worstRisk >= policy.blockThreshold {
                // Praktisch nur der Dichte-Waechter auf `abstain`.
                return blocked(correlationID: correlationID, principal: principal, model: request.model,
                               findings: findings, risk: worstRisk,
                               content: request.scannableText, timings: timings,
                               bytes: payloadBytes)
            }
            if let timing = timings.last, timing.timedOut, policy.failureMode == .failClosed {
                findings.append(Self.budgetFinding(timing, budget: policy.stageBudgetMilliseconds))
                return blocked(correlationID: correlationID, principal: principal, model: request.model,
                               findings: findings, risk: 1.0,
                               content: request.scannableText, timings: timings,
                               bytes: payloadBytes)
            }
        }

        // Platz fuer Stufe 4 (DLP-Policy).

        // Stufe 5 — Semantic-Cache-Lookup. HIER und nirgends sonst: nach der
        // Firewall (sonst waere der Cache mit vergifteten Prompts befuellbar
        // und an ihr vorbei ausspielbar) und nach der Maskierung (sonst laegen
        // Klardaten im Index).
        //
        // ZWEI ABWEICHUNGEN vom Verhalten der Firewall-Stufen, beide bewusst:
        //
        //   - Der Cache unterliegt NICHT dem Fail-closed-Budget. Er ist ein
        //     Kostenhebel, keine Schutzstufe; sein einziger legitimer
        //     Fehlerausgang ist der Fehltreffer. Ein langsamer Embedder darf
        //     eine Anfrage niemals blocken, und eine langsame Cache-Stufe darf
        //     die Entscheidung nicht als `degraded` markieren — das Wort ist
        //     fuer unvollstaendige SICHERHEITSBEWERTUNG reserviert.
        //   - Ein Ausfall des Embedders wird geschluckt. Ohne Vektor entfaellt
        //     die semantische Stufe, die exakte bleibt.
        var cached: ChatResponse?
        var ticket: CacheTicket?
        if let cache, cache.isCacheable(forwarded) {
            let cacheStart = DispatchTime.now().uptimeNanoseconds
            let key = CacheKey(partition: principal.cachePartition, request: forwarded)
            let entities = EntitySignature.of(key.prompt)
            // Einbettung ausserhalb des Cache-Actors holen: Netz-I/O gehoert
            // nicht hinter eine Sperre, die alle Treffer serialisieren wuerde.
            let vector = await embedding(for: key.prompt, policy: cache.policy)
            if let hit = await cache.lookup(key: key, embedding: vector, entities: entities) {
                cached = hit.response
            } else {
                ticket = CacheTicket(key: key, embedding: vector, entities: entities)
            }
            timings.append(StageTiming(stage: "cache",
                                       milliseconds: elapsed(since: cacheStart),
                                       timedOut: false))
        }

        let disposition: Disposition = wasModified ? .allowModified : .allow
        let decision = GatewayDecision(
            correlationID: correlationID, disposition: disposition, riskScore: worstRisk,
            findings: findings, content: forwarded.scannableText, timings: timings,
            degraded: Self.isDegraded(timings))

        // Die Zuordnung wird zusaetzlich geparkt, wenn ein Speicher da ist.
        // `Outcome.session` bleibt trotzdem gefuellt: der Proxy-Pfad braucht
        // sie sofort und soll dafuer nicht erst nachschlagen muessen.
        let session = MaskingSession(mapping: mapping)
        if let sessions {
            await sessions.park(session, correlationID: correlationID,
                                partition: principal.cachePartition)
        }

        return Outcome(decision: decision,
                       audit: AuditEvent(decision: decision, principal: principal,
                                         model: request.model),
                       forward: forwarded,
                       session: session,
                       cached: cached,
                       cacheTicket: ticket)
    }

    // MARK: - Geparkte Zuordnungen

    /// Holt die geparkte Rueckuebersetzung eines Vorgangs.
    ///
    /// `nil` heisst: unbekannt, abgelaufen oder fremde Partition. Der Aufrufer
    /// nimmt dann `MaskingSession.empty` — die Antwort geht mit Platzhaltern
    /// hinaus, statt dass geraten wird.
    public func session(correlationID: String, partition: String) async -> MaskingSession? {
        await sessions?.session(correlationID: correlationID, partition: partition)
    }

    /// Verlaengert auf die lange Frist, weil der Vorgang in die menschliche
    /// Freigabe geht.
    @discardableResult
    public func extendSession(correlationID: String, partition: String) async -> Bool {
        await sessions?.extend(correlationID: correlationID, partition: partition) ?? false
    }

    /// Gibt die Zuordnung frei. Der Antwortpfad ruft das, sobald die Antwort
    /// draussen ist — die Frist ist der Notnagel, nicht der Plan.
    public func closeSession(correlationID: String, partition: String) async {
        await sessions?.close(correlationID: correlationID, partition: partition)
    }

    /// Vektor zur Anfrage, oder `nil`.
    ///
    /// Schluckt jeden Fehler — der Embedder ist die einzige Netz-Abhaengigkeit
    /// im Anfragepfad, und sein Ausfall darf hoechstens einen Fehltreffer
    /// kosten. Dazu ein Sicherungsschalter: **ein haengender Embedder ist
    /// schlimmer als gar keiner.** Stirbt er, kostet jeder Versuch nur einen
    /// abgelehnten Verbindungsaufbau; antwortet er dagegen langsam, zahlt sonst
    /// jede cachebare Anfrage sein volles Zeitlimit, bevor sie in den
    /// Fehltreffer faellt. Nach `embedderFailureThreshold` Fehlschlaegen in
    /// Folge bleibt die semantische Stufe deshalb fuer `embedderCooldown` aus.
    ///
    /// Der exakte Treffer laeuft die ganze Zeit weiter; er braucht keinen
    /// Vektor. Der Cache verliert also Reichweite, nie Funktion.
    private func embedding(for prompt: String, policy cachePolicy: SemanticCachePolicy) async -> [Double]? {
        guard let embedder else { return nil }
        if let openUntil = embedderOpenUntil {
            guard Date() >= openUntil else { return nil }
            // Frist abgelaufen: EIN Probelauf entscheidet, ob wieder gefragt wird.
            embedderOpenUntil = nil
        }
        do {
            let vector = try await embedder.embed(prompt)
            embedderFailures = 0
            return vector
        } catch {
            embedderFailures += 1
            if embedderFailures >= cachePolicy.embedderFailureThreshold {
                embedderOpenUntil = Date().addingTimeInterval(cachePolicy.embedderCooldown)
                embedderFailures = 0
            }
            return nil
        }
    }

    /// Legt die Antwort zum Ticket ab.
    ///
    /// Die Pipeline besitzt den Cache; der Rueckweg reicht ihr nur das
    /// Ergebnis. `maskedResponse` MUSS noch Platzhalter tragen — siehe
    /// `SemanticCache`, Punkt 2.
    public func store(_ ticket: CacheTicket, maskedResponse: ChatResponse) async {
        await cache?.store(key: ticket.key, maskedResponse: maskedResponse,
                           embedding: ticket.embedding, entities: ticket.entities)
    }

    // MARK: - Stabile Regel-IDs dieser Stufe
    //
    // Aenderungen brechen Suppressions und SIEM-Regeln.

    public static let ruleOversizedInput: RuleID = "GW-001"
    public static let ruleStageBudgetExceeded: RuleID = "GW-002"
    public static let ruleTooManyMessages: RuleID = "GW-003"

    // MARK: - Hilfen

    private func blocked(correlationID: String, principal: Principal, model: String,
                         findings: [Finding], risk: Double, content: String,
                         timings: [StageTiming], bytes: Int) -> Outcome {
        let decision = GatewayDecision(
            correlationID: correlationID, disposition: .block, riskScore: risk,
            findings: findings, content: content, timings: timings,
            degraded: Self.isDegraded(timings))
        return Outcome(decision: decision,
                       audit: AuditEvent(decision: decision, principal: principal, model: model),
                       forward: nil,
                       session: .empty)
    }

    /// Misst eine abgeschlossene Stufe gegen ihr Budget.
    ///
    /// WICHTIG — das ist eine Bewertung, KEIN Abbruch. Beide Stufen sind reine
    /// Regex-Laeufe ohne Netz-I/O: ein durchdrehender Backtracking-Lauf laesst
    /// sich in Swift nicht von aussen unterbrechen, und ihn in einer Nebenaufgabe
    /// verhungern zu lassen wuerde unter genau der Last Threads stapeln, gegen
    /// die das Budget schuetzen soll. Die Laufzeitgrenze der Regeln ist der
    /// Groessen-Guard davor; das Budget entscheidet, ob das ERGEBNIS noch zaehlt.
    private func budgetTiming(_ stage: String, since start: UInt64) -> StageTiming {
        let milliseconds = elapsed(since: start)
        return StageTiming(stage: stage, milliseconds: milliseconds,
                           timedOut: milliseconds > policy.stageBudgetMilliseconds)
    }

    /// Befund einer Stufe, die ihr Zeitbudget gerissen hat.
    private static func budgetFinding(_ timing: StageTiming, budget: Double) -> Finding {
        Finding(
            ruleID: ruleStageBudgetExceeded, category: .anomaly, severity: .high, weight: 1.0,
            message: "stage '\(timing.stage)' exceeded budget "
                + "(\(String(format: "%.1f", timing.milliseconds)) ms > \(budget) ms)")
    }

    /// Stammt die Entscheidung aus dem Fehlerpfad? Gilt fuer BEIDE Fehlermodi:
    /// bei `failOpen` ist gerade das Durchlassen die ungeprueft getroffene
    /// Entscheidung, und das muss im Audit sichtbar sein.
    private static func isDegraded(_ timings: [StageTiming]) -> Bool {
        timings.contains { $0.timedOut }
    }

    private func elapsed(since start: UInt64) -> Double {
        Double(DispatchTime.now().uptimeNanoseconds &- start) / 1_000_000
    }
}
