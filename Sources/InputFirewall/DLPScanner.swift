// Copyright (c) 2026 Tommy Stellmacher
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

import Foundation
import GatewayCore

// MARK: - DLP (Data Loss Prevention)
//
// Was diese Stufe von einer weiteren Injection-Regelliste unterscheidet, ist
// nicht das Regelwerk, sondern die HANDLUNG: block / redact / allow.
//
// **`redact` ist der eigentliche Punkt.** Ein DLP-Treffer muss nicht die
// Anfrage kippen — er muss die Stelle entfernen. Wer nur blocken kann, zwingt
// jede Organisation zu „ganz oder gar nicht" und bekommt deshalb Regeln, die
// niemand scharf schaltet.
//
// UNTERSCHIED ZUR PII-MASKIERUNG, der leicht uebersehen wird: Maskierung ist
// eine KLAMMER — hin ersetzt, zurueck eingesetzt. Redaktion ist EINWEG. Was
// hier entfernt wird, kommt auf dem Rueckweg nicht wieder, und das ist Absicht:
// bei PII geht es um Datensparsamkeit gegenueber dem Provider, bei DLP um
// Inhalte, die das Haus gar nicht verlassen duerfen. Ein Rueckweg waere hier
// ein Leck mit Extraschritt.
//
// Provenienz gewichtet NICHT (Multiplikator 1.0) — dieselbe Begruendung wie
// bei PII: ein Geschaeftsgeheimnis ist in einer Systemnachricht so
// schutzbeduerftig wie in einer Tool-Ausgabe. Anders als bei Injection, wo die
// Herkunft die Gefaehrlichkeit bestimmt.

/// Was bei einem Treffer geschieht.
public enum DLPAction: String, Sendable, Codable, CaseIterable {
    /// Nur protokollieren. Der Befund steht im Audit, aendert aber nichts —
    /// der Weg, eine Regel scharf zu beobachten, bevor man sie scharf stellt.
    case allow
    /// Die Fundstelle entfernen und weiterreichen. **Unumkehrbar.**
    case redact
    /// Die Anfrage abweisen.
    case block
}

/// Eine DLP-Regel: Muster plus Handlung.
///
/// `@unchecked Sendable` aus demselben Grund wie bei `InjectionRule`:
/// `NSRegularExpression` ist immutable und laut Dokumentation threadsicher.
public struct DLPRule: @unchecked Sendable {
    public let id: RuleID
    public let action: DLPAction
    public let severity: Severity
    public let message: String
    /// Was bei `redact` an die Fundstelle tritt.
    public let replacement: String

    private let regex: NSRegularExpression

    public init?(id: RuleID,
                 action: DLPAction,
                 severity: Severity = .high,
                 message: String,
                 pattern: String,
                 replacement: String = "[REDACTED]",
                 caseSensitive: Bool = false) {
        var options: NSRegularExpression.Options = [.dotMatchesLineSeparators]
        if !caseSensitive { options.insert(.caseInsensitive) }
        guard let regex = try? NSRegularExpression(pattern: pattern, options: options) else {
            return nil
        }
        self.regex = regex
        self.id = id
        self.action = action
        self.severity = severity
        self.message = message
        self.replacement = replacement
    }

    func occurrences(in text: String) -> Int {
        regex.numberOfMatches(in: text, range: NSRange(text.startIndex..., in: text))
    }

    /// Ersetzt alle Fundstellen. `escapedTemplate`, damit ein `$` im Ersatz
    /// nicht als Gruppenverweis gelesen wird.
    func redacting(_ text: String) -> String {
        regex.stringByReplacingMatches(
            in: text, range: NSRange(text.startIndex..., in: text),
            withTemplate: NSRegularExpression.escapedTemplate(for: replacement))
    }
}

public struct DLPScanner: ContentScanner {

    public let stageName = "dlp"

    private let rules: [DLPRule]

    /// - Parameter rules: Default ist der mitgelieferte Katalog. Er ist
    ///   bewusst klein: echte DLP-Regeln sind organisationsspezifisch
    ///   (Projektnamen, Vertragsnummern, Kundenkennungen) und gehoeren in die
    ///   Konfiguration, nicht in die Bibliothek.
    public init(rules: [DLPRule] = DLPScanner.defaultRules) {
        self.rules = rules
    }

    public func scan(_ content: String, trust: SourceTrust) -> ScanResult {
        var findings: [Finding] = []
        var raw = 0.0
        var text = content
        var redacted = false

        for rule in rules {
            let hits = rule.occurrences(in: text)
            guard hits > 0 else { continue }

            switch rule.action {
            case .allow:
                break
            case .redact:
                text = rule.redacting(text)
                redacted = true
            case .block:
                // Gewicht 1.0: eine DLP-Blockregel ist kein Risikobeitrag, den
                // man gegen andere aufrechnet — sie ist eine Betreiber-Ansage.
                raw += 1.0
            }

            findings.append(Finding(
                ruleID: rule.id,
                category: .dlp,
                severity: rule.severity,
                // `allow` und `redact` tragen NICHT zum Risiko bei: der eine
                // beobachtet nur, der andere hat das Problem bereits behoben.
                weight: rule.action == .block ? 1.0 : 0,
                message: "dlp \(rule.action.rawValue): \(rule.message)",
                occurrences: hits))
        }

        return ScanResult(
            findings: findings,
            content: text,
            rawScore: raw,
            // Siehe Kopfkommentar: Herkunft aendert die Schutzbeduerftigkeit
            // eines Geschaeftsgeheimnisses nicht.
            trustMultiplier: 1.0,
            wasModified: redacted)
    }

    // MARK: - Katalog

    /// Der mitgelieferte Katalog. Zwei Regelklassen, und sie haben aus gutem
    /// Grund UNTERSCHIEDLICHE Default-Handlungen.
    ///
    /// **Klassifizierungs-Vermerke (DLP-001/002) beobachten nur.** Der Vermerk
    /// ist nicht das Geheimnis — das Dokument ist es. Ihn wegzuredigieren
    /// entfernt genau das Wort, das den Betreiber gewarnt haette, und laesst
    /// den Inhalt unveraendert ziehen; das waere Redaktionstheater. Ihn zu
    /// blocken waere umgekehrt eine Zumutung, weil „vertraulich" auch in
    /// harmlosen Saetzen steht. Also `allow`: der Befund steht im Audit, und
    /// wer sieht, dass in seiner Organisation markierte Dokumente ans Modell
    /// gehen, stellt die Regel selbst auf `block`.
    ///
    /// **Interne Adressen (DLP-003) werden redigiert**, denn dort IST die
    /// Fundstelle der Verlust: ein Hostname verraet interne Topologie, und
    /// entfernt man ihn, ist der Schaden tatsaechlich behoben.
    ///
    /// Der Katalog ist bewusst klein: echte DLP-Regeln sind
    /// organisationsspezifisch und gehoeren in die Konfiguration.
    public static let defaultRules: [DLPRule] = [
        DLPRule(id: "DLP-001", action: .allow, severity: .high,
                message: "classification marker (de)",
                pattern: #"\b(streng\s+geheim|vertraulich|nur\s+f(ue|ü)r\s+den\s+internen\s+gebrauch|"#
                    + #"betriebsgeheimnis|verschlusssache)\b"#),
        DLPRule(id: "DLP-002", action: .allow, severity: .high,
                message: "classification marker (en)",
                pattern: #"\b(strictly\s+confidential|confidential|internal\s+use\s+only|"#
                    + #"trade\s+secret|proprietary\s+and\s+confidential)\b"#),
        DLPRule(id: "DLP-003", action: .redact, severity: .medium,
                message: "internal URL or host",
                pattern: #"\bhttps?://[A-Za-z0-9.-]*\.(intern|internal|local|lan|corp)\b[^\s]*"#,
                replacement: "[INTERNAL-URL]"),
    ].compactMap { $0 } + defaultSecretDLPRules
    // Secret-Formate (DLP-01x) werden redigiert, nicht nur gemeldet: die
    // Injection-Stufe erkennt sie (SEC-00x, Gewicht), aber ein einzelnes Secret
    // scort unter der Blockschwelle. DLP laeuft nach der Maskierung und VOR dem
    // Cache-Schluessel, entfernt das Secret also, bevor es den Provider oder den
    // Cache-Index erreicht. Einweg: kein Rueckweg fuer Zugangsdaten.
}
