// Copyright (c) 2026 Tommy Stellmacher
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

import Foundation

// MARK: - Audit-Eintrag
//
// Speist die Audit-Box des Zielbilds. Zentrale Entwurfsregel:
//
//   EIN AUDIT-EINTRAG ENTHAELT NIEMALS NUTZINHALT.
//
// Ein Audit-Log ist langlebig, breit lesbar und wird exportiert. Wuerde es den
// Prompt oder Treffer-Auszuege mitschreiben, waere ausgerechnet die Komponente,
// die PII und Secrets fernhalten soll, deren dauerhafter Speicher. Protokolliert
// werden Regel-IDs, Kategorien, Groessen und Zeiten — genug fuer Forensik,
// Dashboards und SIEM-Korrelation, zu wenig fuer ein Datenleck.

/// Payload-freier, serialisierbarer Audit-Eintrag einer Gateway-Entscheidung.
public struct AuditEvent: Sendable, Codable, Equatable {
    public let eventID: String
    public let timestamp: Date
    public let correlationID: String

    // Wer
    public let subject: String
    public let tenant: String?

    // Was
    /// Das angefragte Modell. Kein Nutzinhalt, sondern ein Policy-Fakt — auch
    /// bei `.block` ist interessant, worauf die Anfrage gezielt hat.
    public let model: String?
    public let disposition: Disposition
    public let riskScore: Double
    public let ruleIDs: [RuleID]
    public let categories: [FindingCategory]
    public let maxSeverity: Severity?

    // Wieviel / wie lange
    public let contentBytes: Int
    public let totalMilliseconds: Double
    public let degraded: Bool

    public init(
        eventID: String,
        timestamp: Date,
        correlationID: String,
        subject: String,
        tenant: String?,
        model: String? = nil,
        disposition: Disposition,
        riskScore: Double,
        ruleIDs: [RuleID],
        categories: [FindingCategory],
        maxSeverity: Severity?,
        contentBytes: Int,
        totalMilliseconds: Double,
        degraded: Bool
    ) {
        self.eventID = eventID
        self.timestamp = timestamp
        self.correlationID = correlationID
        self.subject = subject
        self.tenant = tenant
        self.model = model
        self.disposition = disposition
        self.riskScore = riskScore
        self.ruleIDs = ruleIDs
        self.categories = categories
        self.maxSeverity = maxSeverity
        self.contentBytes = contentBytes
        self.totalMilliseconds = totalMilliseconds
        self.degraded = degraded
    }

    /// Leitet den Eintrag aus einer Entscheidung ab und laesst den Payload
    /// dabei bewusst fallen. Das ist der EINZIGE vorgesehene Weg, aus einer
    /// `GatewayDecision` einen Audit-Eintrag zu machen.
    ///
    /// `eventID` und `timestamp` sind injizierbar, damit Tests deterministisch
    /// bleiben und der Aufrufer seine eigene ID-Quelle behalten kann.
    public init(
        decision: GatewayDecision,
        principal: Principal,
        model: String? = nil,
        eventID: String = UUID().uuidString,
        timestamp: Date = Date()
    ) {
        self.eventID = eventID
        self.timestamp = timestamp
        self.correlationID = decision.correlationID
        self.subject = principal.subject
        self.tenant = principal.tenant
        self.model = model
        self.disposition = decision.disposition
        self.riskScore = decision.riskScore
        self.ruleIDs = decision.findings.map(\.ruleID)
        // Reihenfolge stabil halten (Set waere ungeordnet -> unstetige Logs).
        var seen = Set<FindingCategory>()
        self.categories = decision.findings.map(\.category).filter { seen.insert($0).inserted }
        self.maxSeverity = decision.maxSeverity
        self.contentBytes = decision.content.utf8.count
        self.totalMilliseconds = decision.totalMilliseconds
        self.degraded = decision.degraded
    }
}
