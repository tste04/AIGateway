// Copyright (c) 2026 Tommy Stellmacher
// SPDX-License-Identifier: Apache-2.0

import Foundation

// MARK: - Befund
//
// Ein einzelner Treffer eines Scanners. Bewusst OHNE Auszug aus dem Inhalt:
// ein Befund wandert bis ins Audit, und Rohtext im Audit-Log ist genau der
// Leak-Kanal, den die Firewall verhindern soll. Wer den Kontext braucht,
// nimmt die Position (`occurrences`) und den Original-Payload im Prozess.

/// Ein Treffer einer Erkennungsregel.
public struct Finding: Sendable, Codable, Equatable {
    /// Stabile Regel-ID — der Ankerpunkt fuer Suppressions und SIEM.
    public let ruleID: RuleID
    public let category: FindingCategory
    public let severity: Severity
    /// Beitrag zum Risiko-Score (0...1, wird additiv verrechnet).
    public let weight: Double
    /// Anzeigetext. Darf sich aendern — niemals maschinell auswerten.
    public let message: String
    /// Wie oft die Regel im Inhalt getroffen hat.
    public let occurrences: Int

    public init(
        ruleID: RuleID,
        category: FindingCategory,
        severity: Severity,
        weight: Double,
        message: String,
        occurrences: Int = 1
    ) {
        self.ruleID = ruleID
        self.category = category
        self.severity = severity
        self.weight = weight
        self.message = message
        self.occurrences = occurrences
    }
}

/// Ergebnis eines Scanner-Laufs.
///
/// Ein Scanner ERKENNT und BEREINIGT — er entscheidet nicht. Ob daraus ein
/// Block wird, bestimmt allein die `GatewayPolicy`. Diese Trennung erlaubt,
/// Schwellen zu aendern, ohne Scanner anzufassen.
public struct ScanResult: Sendable, Codable, Equatable {
    public let findings: [Finding]
    /// Der (ggf. bereinigte/maskierte) Inhalt, mit dem weitergearbeitet wird.
    public let content: String
    /// Summe der Regel-Gewichte VOR Provenienz-Gewichtung.
    /// Wird mitgefuehrt, damit die Policy Regeln exakt herausrechnen kann.
    public let rawScore: Double
    /// Angewandter Provenienz-Multiplikator (`SourceTrust.riskMultiplier`).
    public let trustMultiplier: Double
    /// Wurde `content` gegenueber der Eingabe veraendert?
    public let wasModified: Bool

    /// Normalisiertes Risiko 0...1 — das Ergebnis, auf das Schwellen wirken.
    public var riskScore: Double { min(1.0, rawScore * trustMultiplier) }

    public init(
        findings: [Finding],
        content: String,
        rawScore: Double,
        trustMultiplier: Double,
        wasModified: Bool
    ) {
        self.findings = findings
        self.content = content
        self.rawScore = rawScore
        self.trustMultiplier = trustMultiplier
        self.wasModified = wasModified
    }

    /// Unauffaelliger Durchlauf.
    public static func clean(_ content: String) -> ScanResult {
        ScanResult(findings: [], content: content, rawScore: 0, trustMultiplier: 1, wasModified: false)
    }
}

/// Naht fuer alle textbasierten Firewall-Stufen (Injection, PII, DLP).
///
/// Malware arbeitet auf Bytes und hat eine eigene Naht (`PayloadScanner`) —
/// ein `String` waere dort das falsche Modell.
public protocol ContentScanner: Sendable {
    /// Stabiler Name der Stufe, erscheint in `StageTiming`.
    var stageName: String { get }

    /// `async`, weil spaetere Stufen es sein muessen (Vault-Actor, ClamAV-Socket).
    /// Rein synchrone Scanner erfuellen die Anforderung unveraendert — Swift laesst
    /// eine sync-Funktion eine async-Anforderung bezeugen.
    func scan(_ content: String, trust: SourceTrust) async -> ScanResult
}

/// Naht fuer Stufen, die auf BYTES arbeiten — heute Malware.
///
/// Getrennt von `ContentScanner`, weil ein `String` das falsche Modell waere:
/// ein Anhang ist nicht notwendig Text, und ihn dafuer zu dekodieren hiesse,
/// ihn zu parsen, bevor er geprueft wurde. Genau das soll die Stufe
/// verhindern — sie steht im Ablauf VOR allem anderen.
///
/// Das Ergebnis ist bewusst wieder `ScanResult`, damit `GatewayPolicy` nur
/// EINEN Entscheidungsweg kennt. `content` bleibt dabei leer und `wasModified`
/// falsch: ein Byte-Scanner erkennt und bereinigt nicht — er kann einen Anhang
/// nur ganz durchlassen oder die Anfrage kippen.
public protocol PayloadScanner: Sendable {
    var stageName: String { get }

    /// - Parameters:
    ///   - name: Dateiname, falls bekannt. Nur ein Hinweis — er ist
    ///     Angreifer-kontrolliert und darf nie allein entscheiden.
    ///   - mediaType: der BEHAUPTETE Typ. Ebenfalls Angreifer-kontrolliert;
    ///     sein Wert liegt darin, ihn gegen den tatsaechlichen Inhalt zu
    ///     pruefen.
    func scan(_ bytes: Data, name: String?, mediaType: String?) async -> ScanResult
}
