// Copyright (c) 2026 Tommy Stellmacher
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

import Foundation

// MARK: - Policy
//
// Scanner erkennen, die Policy entscheidet. Diese Trennung ist Absicht:
// Schwellen und Fehlerverhalten sind Betriebsparameter und muessen aenderbar
// sein, ohne eine Erkennungsregel anzufassen.

/// Verhalten, wenn eine Stufe ausfaellt oder ihr Zeitbudget reisst.
public enum FailureMode: String, Sendable, Codable {
    /// Durchlassen. Verfuegbarkeit vor Schutz — nur bewusst waehlen.
    case failOpen
    /// Blocken. Schutz vor Verfuegbarkeit (Default).
    case failClosed
}

/// Betriebsparameter des Gateways.
public struct GatewayPolicy: Sendable, Codable, Equatable {
    /// Ab diesem Risiko wird geblockt.
    public var blockThreshold: Double
    /// Verhalten bei Stufen-Ausfall/Timeout.
    public var failureMode: FailureMode
    /// Zeitbudget je Stufe. Wer laenger braucht, gilt als unzuverlaessig: das
    /// Ergebnis wird nach `failureMode` behandelt und die Entscheidung als
    /// `degraded` markiert (Befund `GW-002`).
    ///
    /// Das ist eine Bewertung NACH der Stufe, kein Abbruch. Die Stufen sind
    /// reine Regex-Laeufe ohne Netz-I/O; ein durchdrehender Backtracking-Lauf
    /// laesst sich nicht von aussen unterbrechen, und ihn in einer Nebenaufgabe
    /// verhungern zu lassen wuerde unter Last Threads stapeln. Die harte
    /// Laufzeitgrenze der Regeln ist `maxInputBytes`, nicht dieses Budget.
    public var stageBudgetMilliseconds: Double
    /// Harte Obergrenze der Eingabe. Wird VOR jedem Scan geprueft und fuehrt
    /// zum sofortigen Abbruch — nicht bloss zu einem Risiko-Aufschlag.
    /// Ohne diese Grenze laeuft jedes Regelwerk ueber beliebig grosse Eingaben.
    public var maxInputBytes: Int
    /// Harte Obergrenze der Nachrichtenzahl je Anfrage. `maxInputBytes` deckelt
    /// die Textmenge, nicht die Stueckzahl — sehr viele Kleinst-Nachrichten
    /// wuerden sonst je Nachricht volle Scanner-Laeufe ausloesen, ohne die
    /// Byte-Grenze zu reissen.
    public var maxMessages: Int
    /// Regel-IDs, die nicht zum Risiko beitragen (bleiben im Audit sichtbar).
    /// Die Escape-Luke fuer Fehlalarme — z. B. Sicherheits-Dokumentation, die
    /// Angriffsmuster zitiert und sonst dauerhaft blockiert wuerde.
    public var suppressedRules: Set<RuleID>
    /// Deckelt den Vertrauensrabatt einer vom Client als `system` deklarierten
    /// Nachricht auf `neutral`.
    ///
    /// Hintergrund: `system` → `trusted` gibt den staerksten Rabatt (0.55). Im
    /// Gateway kommt das Rollen-Label aber VERBATIM aus dem Client-Request;
    /// nichts belegt, dass eine `system`-Nachricht anwendungserzeugt ist. Ein
    /// Angreifer, der seine Injection als `system` deklariert, drueckt sie so
    /// unter die Schwelle. Wer vor dem Gateway keine belegte Identitaet hat (der
    /// Default-Resolver ist anonym), sollte diesen Deckel setzen — dann zaehlt
    /// eine Client-`system`-Nachricht wie `user` (neutral).
    ///
    /// Default `false`: die dokumentierte Provenienz-Bewertung (DECISIONS) bleibt
    /// unveraendert, wo `system` aus einer vertrauenswuerdigen, identitaets-
    /// belegten Anwendung stammt. Es ist eine bewusste Betreiber-Entscheidung,
    /// keine stille Voreinstellung.
    public var capClientSystemTrust: Bool

    public init(
        blockThreshold: Double = 0.7,
        failureMode: FailureMode = .failClosed,
        stageBudgetMilliseconds: Double = 50,
        maxInputBytes: Int = 1_000_000,
        maxMessages: Int = 1_000,
        suppressedRules: Set<RuleID> = [],
        capClientSystemTrust: Bool = false
    ) {
        self.blockThreshold = blockThreshold
        self.failureMode = failureMode
        self.stageBudgetMilliseconds = stageBudgetMilliseconds
        self.maxInputBytes = maxInputBytes
        self.maxMessages = maxMessages
        self.suppressedRules = suppressedRules
        self.capClientSystemTrust = capClientSystemTrust
    }

    public static let standard = GatewayPolicy()

    /// Wendet die Policy auf ein Scan-Ergebnis an und bestimmt die Disposition.
    ///
    /// Unterdrueckte Regeln werden aus der Risiko-Summe herausgerechnet, ihre
    /// Befunde aber BEHALTEN — Sichtbarkeit im Audit bleibt, die Blockwirkung
    /// entfaellt. Ein stilles Verschwinden waere die schlechtere Voreinstellung.
    public func disposition(for result: ScanResult) -> (Disposition, Double) {
        var risk = result.riskScore
        if !suppressedRules.isEmpty {
            let suppressedWeight = result.findings
                .filter { suppressedRules.contains($0.ruleID) }
                .reduce(0.0) { $0 + $1.weight }
            // Exakt herausrechnen: erst von der ROH-Summe abziehen, dann die
            // Provenienz-Gewichtung anwenden — in dieser Reihenfolge, sonst
            // stimmt der Abzug bei trusted/untrusted Quellen nicht.
            risk = min(1.0, max(0, result.rawScore - suppressedWeight) * result.trustMultiplier)
        }
        if risk >= blockThreshold { return (.block, risk) }
        if result.wasModified { return (.allowModified, risk) }
        return (.allow, risk)
    }
}
