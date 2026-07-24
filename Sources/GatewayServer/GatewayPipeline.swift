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

        // Stufe 1 — harte Eingabegrenze. VOR jedem Regelwerk, sonst laeuft es
        // ueber beliebig grosse Eingaben.
        let payloadBytes = request.scannableText.utf8.count
        if payloadBytes > policy.maxInputBytes {
            let finding = Finding(
                ruleID: "GW-001", category: .anomaly, severity: .high, weight: 1.0,
                message: "request exceeds maxInputBytes (\(payloadBytes) > \(policy.maxInputBytes))")
            return blocked(correlationID: correlationID, principal: principal,
                           findings: [finding], risk: 1.0,
                           content: "", timings: [], bytes: payloadBytes)
        }

        // Stufe 2 — Injection, je Nachricht mit rollenabhaengiger Provenienz.
        let injectionStart = DispatchTime.now().uptimeNanoseconds
        for message in request.messages {
            let result = injection.scan(message.content, trust: Self.trust(for: message.role))
            findings += result.findings
            worstRisk = max(worstRisk, policy.disposition(for: result).1)
        }
        timings.append(StageTiming(stage: injection.stageName,
                                   milliseconds: elapsed(since: injectionStart)))

        if worstRisk >= policy.blockThreshold {
            return blocked(correlationID: correlationID, principal: principal,
                           findings: findings, risk: worstRisk,
                           content: request.scannableText, timings: timings, bytes: payloadBytes)
        }

        // Stufe 3 — PII maskieren. MUSS vor der Cache-Schluessel-Bildung liegen
        // (siehe DECISIONS): kein Klardatum im Cache-Index, und maskierte
        // Anfragen kollidieren oefter, was die Trefferquote hebt.
        var forwarded = request
        var mapping: [String: String] = [:]
        if let pii {
            let piiStart = DispatchTime.now().uptimeNanoseconds
            let query = request.lastUserMessage
            var masked: [ChatMessage] = []
            var piiRisk = 0.0
            for message in request.messages {
                let outcome = await pii.mask(message.content, sparingQuery: query)
                findings += outcome.scan.findings
                piiRisk = max(piiRisk, policy.disposition(for: outcome.scan).1)
                // Zuordnungen vereinigen: derselbe Vault vergibt stabile Tokens,
                // Kollisionen sind daher konsistent und nicht verlustbehaftet.
                mapping.merge(outcome.session.mapping) { current, _ in current }
                masked.append(ChatMessage(role: message.role, content: outcome.maskedContent))
            }
            forwarded.messages = masked
            worstRisk = max(worstRisk, piiRisk)
            timings.append(StageTiming(stage: pii.stageName,
                                       milliseconds: elapsed(since: piiStart)))

            if worstRisk >= policy.blockThreshold {
                // Praktisch nur der Dichte-Waechter auf `abstain`.
                return blocked(correlationID: correlationID, principal: principal,
                               findings: findings, risk: worstRisk,
                               content: request.scannableText, timings: timings,
                               bytes: payloadBytes)
            }
        }

        // Platz fuer Stufe 4 (DLP-Policy) und Stufe 5 (Semantic-Cache-Lookup).
        // Der Cache gehoert HIERHIN — nach der Firewall, mit
        // `principal.cachePartition` im Schluessel.

        let disposition: Disposition = forwarded.messages != request.messages
            ? .allowModified : .allow
        let decision = GatewayDecision(
            correlationID: correlationID, disposition: disposition, riskScore: worstRisk,
            findings: findings, content: forwarded.scannableText, timings: timings)
        return Outcome(decision: decision,
                       audit: AuditEvent(decision: decision, principal: principal),
                       forward: forwarded,
                       session: MaskingSession(mapping: mapping))
    }

    // MARK: - Hilfen

    private func blocked(correlationID: String, principal: Principal,
                         findings: [Finding], risk: Double, content: String,
                         timings: [StageTiming], bytes: Int) -> Outcome {
        let decision = GatewayDecision(
            correlationID: correlationID, disposition: .block, riskScore: risk,
            findings: findings, content: content, timings: timings)
        return Outcome(decision: decision,
                       audit: AuditEvent(decision: decision, principal: principal),
                       forward: nil,
                       session: .empty)
    }

    private func elapsed(since start: UInt64) -> Double {
        Double(DispatchTime.now().uptimeNanoseconds &- start) / 1_000_000
    }
}
