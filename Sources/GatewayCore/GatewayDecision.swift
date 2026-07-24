// Copyright (c) 2026 Tommy Stellmacher
// SPDX-License-Identifier: Apache-2.0

import Foundation

// MARK: - Entscheidung
//
// Das Uebergabeobjekt des Gateways an die naechste Stufe (Policy Engine).
// Traegt den Payload — es bleibt im Prozess. Was ins Audit wandert, ist die
// abgeleitete, payload-freie `AuditEvent` (siehe AuditEvent.swift).

/// Was mit der Anfrage geschieht.
public enum Disposition: String, Sendable, Codable {
    /// Unveraendert weiterreichen.
    case allow
    /// Weiterreichen, aber mit veraendertem Inhalt (bereinigt/maskiert).
    case allowModified
    /// Nicht weiterreichen.
    case block
}

/// Laufzeit einer einzelnen Pipeline-Stufe. Grundlage fuer Latenz-Budgets
/// und die Metrik-Box des Zielbilds.
public struct StageTiming: Sendable, Codable, Equatable {
    public let stage: String
    public let milliseconds: Double
    /// Stufe hat ihr Budget gerissen und wurde abgebrochen.
    public let timedOut: Bool

    public init(stage: String, milliseconds: Double, timedOut: Bool = false) {
        self.stage = stage
        self.milliseconds = milliseconds
        self.timedOut = timedOut
    }
}

/// Gebuendeltes Ergebnis des Gateways fuer eine Anfrage.
public struct GatewayDecision: Sendable, Codable, Equatable {
    /// Verknuepft Anfrage, Entscheidung, Audit-Eintrag und Antwort.
    public let correlationID: String
    public let disposition: Disposition
    public let riskScore: Double
    public let findings: [Finding]
    /// Der Inhalt, mit dem weitergearbeitet wird (bereinigt/maskiert).
    /// Bei `.block` der Original-Inhalt fuer die Quarantaene-Ablage.
    public let content: String
    public let timings: [StageTiming]
    /// Gesetzt, wenn die Entscheidung aus dem Fehlerpfad stammt
    /// (Scanner-Ausfall/Timeout + `FailureMode`), nicht aus einer Bewertung.
    public let degraded: Bool

    public init(
        correlationID: String,
        disposition: Disposition,
        riskScore: Double,
        findings: [Finding],
        content: String,
        timings: [StageTiming] = [],
        degraded: Bool = false
    ) {
        self.correlationID = correlationID
        self.disposition = disposition
        self.riskScore = riskScore
        self.findings = findings
        self.content = content
        self.timings = timings
        self.degraded = degraded
    }

    public var totalMilliseconds: Double {
        timings.reduce(0) { $0 + $1.milliseconds }
    }

    /// Hoechster aufgetretener Schweregrad, `nil` wenn befundfrei.
    public var maxSeverity: Severity? {
        findings.map(\.severity).max()
    }
}
