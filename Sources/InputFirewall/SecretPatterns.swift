// Copyright (c) 2026 Tommy Stellmacher
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

import Foundation
import GatewayCore

// MARK: - Secret-Formate an EINER Stelle
//
// Zwei Stufen brauchen dieselben Muster, aber fuer Verschiedenes: die
// Injection-Stufe GEWICHTET einen Secret-Fund (Erkennung, damit er im Audit
// steht und zum Risiko beitraegt), die DLP-Stufe REDIGIERT ihn (Handlung,
// damit die Zugangsdaten die Box nicht verlassen). Zwei Kopien derselben
// Regexe wuerden auseinanderdriften — ein hier geschaerftes Muster bliebe dort
// stumpf. Deshalb die eine Quelle.
//
// WARUM Erkennung UND Redaktion noetig sind: ein einzelnes Secret in einer
// user-Nachricht (neutral 1.0) scort unter der Blockschwelle und wuerde sonst
// verbatim zum Drittanbieter geschickt — und, weil der Cache-Schluessel aus dem
// (maskierten, aber secret-tragenden) Text entsteht, zusaetzlich in den
// Cache-Index gelegt. Eine Erkennung ohne Handlung ist ein Leck mit Logzeile.

/// Ein Zugangsdaten-Format mit seinen beiden Regel-IDs.
public struct SecretPattern: Sendable {
    /// ID der Injection-Regel (Erkennung/Gewichtung). Stabil.
    public let injectionID: RuleID
    /// ID der DLP-Regel (Redaktion). Stabil.
    public let dlpID: RuleID
    public let label: String
    public let pattern: String
    public let caseSensitive: Bool
    public let severity: Severity
    /// Gewicht in der Injection-Stufe.
    public let weight: Double

    public init(injectionID: RuleID, dlpID: RuleID, label: String, pattern: String,
                caseSensitive: Bool, severity: Severity, weight: Double) {
        self.injectionID = injectionID
        self.dlpID = dlpID
        self.label = label
        self.pattern = pattern
        self.caseSensitive = caseSensitive
        self.severity = severity
        self.weight = weight
    }
}

/// Die mitgelieferten Secret-Formate. `SEC-00x` in der Injection-Stufe,
/// `DLP-01x` in der DLP-Stufe — dieselben Muster, verschiedene Handlung.
public let defaultSecretPatterns: [SecretPattern] = [
    SecretPattern(injectionID: "SEC-001", dlpID: "DLP-010", label: "private-key block",
                  pattern: #"-----BEGIN [A-Z ]*PRIVATE KEY-----"#,
                  caseSensitive: true, severity: .critical, weight: 0.45),
    SecretPattern(injectionID: "SEC-002", dlpID: "DLP-011", label: "AWS access key id",
                  pattern: #"\bAKIA[0-9A-Z]{16}\b"#,
                  caseSensitive: true, severity: .high, weight: 0.40),
    SecretPattern(injectionID: "SEC-003", dlpID: "DLP-012", label: "GitHub token",
                  pattern: #"\bgh[pousr]_[A-Za-z0-9]{36,}\b"#,
                  caseSensitive: true, severity: .high, weight: 0.40),
    SecretPattern(injectionID: "SEC-004", dlpID: "DLP-013", label: "Slack token",
                  pattern: #"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"#,
                  caseSensitive: true, severity: .high, weight: 0.40),
    SecretPattern(injectionID: "SEC-005", dlpID: "DLP-014", label: "JWT",
                  pattern: #"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"#,
                  caseSensitive: true, severity: .medium, weight: 0.35),
    SecretPattern(injectionID: "SEC-006", dlpID: "DLP-015", label: "api key (sk-...)",
                  pattern: #"\bsk-[A-Za-z0-9_-]{20,}\b"#,
                  caseSensitive: false, severity: .medium, weight: 0.35),
    SecretPattern(injectionID: "SEC-007", dlpID: "DLP-016", label: "credential assignment",
                  pattern: #"(api[_-]?key|client[_-]?secret|access[_-]?token)\s*[:=]\s*['"][A-Za-z0-9_\-/+]{16,}['"]"#,
                  caseSensitive: false, severity: .medium, weight: 0.35),
    // Google-Schluessel haben feste Laenge (AIza + 35), das Muster darf
    // deshalb exakt sein — kein {n,} noetig.
    SecretPattern(injectionID: "SEC-008", dlpID: "DLP-017", label: "Google API key",
                  pattern: #"\bAIza[0-9A-Za-z_-]{35}\b"#,
                  caseSensitive: true, severity: .high, weight: 0.40),
    // Nur live-Schluessel: sk_test/rk_test sind absichtlich wertlos und
    // tauchen legitim in Doku und Beispielen auf — sie zu redigieren waere
    // Fehlalarm ohne Schutzwirkung. Ein live-Schluessel dagegen bewegt Geld.
    SecretPattern(injectionID: "SEC-009", dlpID: "DLP-018", label: "Stripe live key",
                  pattern: #"\b[sr]k_live_[A-Za-z0-9]{16,}\b"#,
                  caseSensitive: true, severity: .critical, weight: 0.45),
]

/// Die Secret-Regeln fuer die DLP-Stufe: `redact`, einweg. Ersetzt die
/// Fundstelle durch `[SECRET]`. Anders als DLP-003 (interne URL) gibt es hier
/// keinen Rueckweg — ein Secret DARF die Box nicht verlassen, auch nicht als
/// Platzhalter, der zurueckuebersetzt wuerde.
public let defaultSecretDLPRules: [DLPRule] = defaultSecretPatterns.compactMap {
    DLPRule(id: $0.dlpID, action: .redact, severity: $0.severity,
            message: "secret: \($0.label)", pattern: $0.pattern,
            replacement: "[SECRET]", caseSensitive: $0.caseSensitive)
}
