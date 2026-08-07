// Copyright (c) 2026 Tommy Stellmacher
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

import Foundation

// MARK: - Abschluss-Eintrag
//
// Das Gegenstueck zu `AuditEvent` auf dem Rueckweg. ZWEI Ereignisse statt
// einem, und zwar mit Absicht:
//
// `AuditEvent` feuert sofort nach der Firewall-Entscheidung. Stirbt der Prozess
// waehrend des Modellaufrufs, existiert die Entscheidung trotzdem im Log — ein
// einziges Ereignis am Ende verloere ausgerechnet die sicherheitsrelevante
// Aufzeichnung. Was erst der Rueckweg weiss (Verbrauch, Latenz, Ausgang),
// kommt deshalb hier, verknuepft ueber `correlationID`.
//
// Das Gateway ist die einzige Stelle im Zielbild, die Anfrage UND Antwort sieht.
// Laesst es die Zahlen fallen, kann die FinOps-Box sie nirgends mehr einsammeln.
//
// Wie `AuditEvent` traegt dieser Eintrag KEINEN Nutzinhalt.

/// Was der Weg nach oben gekostet hat.
public struct CompletionEvent: Sendable, Codable, Equatable {
    public let correlationID: String

    // Wer
    public let subject: String
    public let tenant: String?

    // Was
    /// Das angefragte Modell. Kein Nutzinhalt — ein Routing- und Kostenfakt.
    public let model: String
    /// Was der Provider gemeldet hat. `nil`, wenn er nichts gemeldet hat.
    public let usage: TokenUsage?

    // Wie lange / wie ausgegangen
    public let upstreamMilliseconds: Double
    public let streamed: Bool
    /// HTTP-Status, mit dem das Gateway geantwortet hat.
    public let status: Int
    /// Aus dem Semantic Cache bedient. Heute immer `false` — Rang 5 fuellt es.
    public let cacheHit: Bool

    public init(correlationID: String,
                principal: Principal,
                model: String,
                usage: TokenUsage?,
                upstreamMilliseconds: Double,
                streamed: Bool,
                status: Int,
                cacheHit: Bool = false) {
        self.correlationID = correlationID
        self.subject = principal.subject
        self.tenant = principal.tenant
        self.model = model
        self.usage = usage
        self.upstreamMilliseconds = upstreamMilliseconds
        self.streamed = streamed
        self.status = status
        self.cacheHit = cacheHit
    }
}
