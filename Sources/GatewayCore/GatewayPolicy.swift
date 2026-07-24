// Copyright (c) 2026 Tommy Stellmacher
// SPDX-License-Identifier: Apache-2.0

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
    /// Zeitbudget je Stufe. Das Gateway liegt im synchronen Pfad —
    /// eine haengende Stufe darf nicht die ganze Anfrage haengen lassen.
    public var stageBudgetMilliseconds: Double
    /// Harte Obergrenze der Eingabe. Wird VOR jedem Scan geprueft und fuehrt
    /// zum sofortigen Abbruch — nicht bloss zu einem Risiko-Aufschlag.
    /// Ohne diese Grenze laeuft jedes Regelwerk ueber beliebig grosse Eingaben.
    public var maxInputBytes: Int
    /// Regel-IDs, die nicht zum Risiko beitragen (bleiben im Audit sichtbar).
    /// Die Escape-Luke fuer Fehlalarme — z. B. Sicherheits-Dokumentation, die
    /// Angriffsmuster zitiert und sonst dauerhaft blockiert wuerde.
    public var suppressedRules: Set<RuleID>

    public init(
        blockThreshold: Double = 0.7,
        failureMode: FailureMode = .failClosed,
        stageBudgetMilliseconds: Double = 50,
        maxInputBytes: Int = 1_000_000,
        suppressedRules: Set<RuleID> = []
    ) {
        self.blockThreshold = blockThreshold
        self.failureMode = failureMode
        self.stageBudgetMilliseconds = stageBudgetMilliseconds
        self.maxInputBytes = maxInputBytes
        self.suppressedRules = suppressedRules
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
