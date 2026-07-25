// Copyright (c) 2026 Tommy Stellmacher
// SPDX-License-Identifier: Apache-2.0

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

    public struct Outcome: Sendable {
        public let decision: GatewayDecision
        public let audit: AuditEvent
        /// Die weiterzureichende Anfrage — `nil`, wenn geblockt wurde.
        public let forward: ChatRequest?
        /// Rueckuebersetzung fuer den Antwortpfad.
        public let session: MaskingSession
    }

    private let injection: InjectionScanner
    private let pii: PIIGate?
    private let policy: GatewayPolicy

    public init(injection: InjectionScanner = InjectionScanner(),
                pii: PIIGate? = nil,
                policy: GatewayPolicy = .standard) {
        self.injection = injection
        self.pii = pii
        self.policy = policy
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

        // Stufe 1 — harte Eingabegrenze. VOR jedem Regelwerk, sonst laeuft es
        // ueber beliebig grosse Eingaben.
        let payloadBytes = request.scannableText.utf8.count
        if payloadBytes > policy.maxInputBytes {
            let finding = Finding(
                ruleID: Self.ruleOversizedInput, category: .anomaly, severity: .high, weight: 1.0,
                message: "request exceeds maxInputBytes (\(payloadBytes) > \(policy.maxInputBytes))")
            return blocked(correlationID: correlationID, principal: principal,
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
            return blocked(correlationID: correlationID, principal: principal,
                           findings: findings, risk: worstRisk,
                           content: request.scannableText, timings: timings, bytes: payloadBytes)
        }
        if let timing = timings.last, timing.timedOut, policy.failureMode == .failClosed {
            findings.append(Self.budgetFinding(timing, budget: policy.stageBudgetMilliseconds))
            return blocked(correlationID: correlationID, principal: principal,
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
            let query = sanitized.lastUserMessage
            var masked: [ChatMessage] = []
            var piiRisk = 0.0
            for message in sanitized.messages {
                let outcome = await pii.mask(message.content, sparingQuery: query)
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
                return blocked(correlationID: correlationID, principal: principal,
                               findings: findings, risk: worstRisk,
                               content: request.scannableText, timings: timings,
                               bytes: payloadBytes)
            }
            if let timing = timings.last, timing.timedOut, policy.failureMode == .failClosed {
                findings.append(Self.budgetFinding(timing, budget: policy.stageBudgetMilliseconds))
                return blocked(correlationID: correlationID, principal: principal,
                               findings: findings, risk: 1.0,
                               content: request.scannableText, timings: timings,
                               bytes: payloadBytes)
            }
        }

        // Platz fuer Stufe 4 (DLP-Policy) und Stufe 5 (Semantic-Cache-Lookup).
        // Der Cache gehoert HIERHIN — nach der Firewall, mit
        // `principal.cachePartition` im Schluessel.

        let disposition: Disposition = wasModified ? .allowModified : .allow
        let decision = GatewayDecision(
            correlationID: correlationID, disposition: disposition, riskScore: worstRisk,
            findings: findings, content: forwarded.scannableText, timings: timings,
            degraded: Self.isDegraded(timings))
        return Outcome(decision: decision,
                       audit: AuditEvent(decision: decision, principal: principal),
                       forward: forwarded,
                       session: MaskingSession(mapping: mapping))
    }

    // MARK: - Stabile Regel-IDs dieser Stufe
    //
    // Aenderungen brechen Suppressions und SIEM-Regeln.

    public static let ruleOversizedInput: RuleID = "GW-001"
    public static let ruleStageBudgetExceeded: RuleID = "GW-002"

    // MARK: - Hilfen

    private func blocked(correlationID: String, principal: Principal,
                         findings: [Finding], risk: Double, content: String,
                         timings: [StageTiming], bytes: Int) -> Outcome {
        let decision = GatewayDecision(
            correlationID: correlationID, disposition: .block, riskScore: risk,
            findings: findings, content: content, timings: timings,
            degraded: Self.isDegraded(timings))
        return Outcome(decision: decision,
                       audit: AuditEvent(decision: decision, principal: principal),
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
