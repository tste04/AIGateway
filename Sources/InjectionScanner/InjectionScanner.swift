// Copyright (c) 2026 Tommy Stellmacher
// SPDX-License-Identifier: Apache-2.0

import Foundation

// MARK: - InjectionScanner (reiner, abhängigkeitsfreier Prompt-Injection-Wächter)
//
// Eine KI-Pipeline ist nur so vertrauenswürdig wie der Fremdinhalt, den sie verarbeitet.
// Der gefährlichste Angriff auf eine RAG-/Memory-Schicht ist **Content-Poisoning**: ein
// fremder Inhalt (E-Mail, Web-Snippet, Tool-Output, retrieved document) trägt eine
// versteckte Prompt-Injection und wird später in ein Host-LLM gespielt — das die Injection
// dann als legitime Anweisung ausführt (Daten-Exfiltration, Tool-Missbrauch).
//
// `InjectionScanner` bewertet JEDEN Inhalt, bevor er weitergereicht/indexiert wird:
//   • **Sanitisierung**  — unsichtbare/bidirektionale/Steuerzeichen entfernen (klassische
//     Tarn-Vektoren für versteckte Anweisungen) — zerstörungsfrei.
//   • **Injection-Heuristik** — bekannte Override-/Exfiltrations-Muster erkennen.
//   • **Secret-Erkennung** — erkennbare Zugangsdaten-Formate (OWASP-ASI06).
//   • **Provenance-Gewichtung** — vertrauenswürdige Quellen (eigene Notizen) milder,
//     externe Quellen (Web/E-Mail/Tool) strenger bewerten.
//
// Verdikt: `clean` (durchlassen), `sanitized` (gesäuberten Inhalt verwenden) oder
// `quarantined` (über der Risikoschwelle — nicht weitergeben, nur für Audit/Review halten).
//
// Deterministisch, netzfrei, keine externen Abhängigkeiten außer Foundation.

public struct InjectionScanner: Sendable {

    public enum Verdict: Sendable, Equatable {
        /// Unauffällig — unverändert verwenden.
        case clean
        /// Auffällig, aber säuberbar — gesäuberten Inhalt verwenden (Gründe protokolliert).
        case sanitized(reasons: [String])
        /// Über der Risikoschwelle — NICHT weitergeben, nicht teilen, nur für Review halten.
        case quarantined(reasons: [String])
    }

    public struct Assessment: Sendable, Equatable {
        public let verdict: Verdict
        /// Gesäuberter Inhalt (== Original, falls nichts entfernt wurde).
        public let sanitizedContent: String
        /// Normalisiertes Risiko 0..1.
        public let riskScore: Double
        public let reasons: [String]
    }

    /// Quellen, deren Inhalt der Nutzer bewusst selbst erzeugt hat → mildere Gewichtung.
    private let trustedSourceTypes: Set<String>
    /// Quellen, die per Definition fremdbestimmt sind → strengere Gewichtung.
    private let untrustedSourceTypes: Set<String>
    /// Ab diesem Risiko wird quarantänisiert statt nur gesäubert.
    private let quarantineThreshold: Double

    public init(
        quarantineThreshold: Double = 0.7,
        trustedSourceTypes: Set<String> = ["note", "manual", "transcript", "user", "journal"],
        untrustedSourceTypes: Set<String> = ["web", "email", "tool", "tool_output", "external",
                                             "import", "rss", "webhook", "attachment", "clipboard"]
    ) {
        self.quarantineThreshold = quarantineThreshold
        self.trustedSourceTypes = trustedSourceTypes
        self.untrustedSourceTypes = untrustedSourceTypes
    }

    // MARK: - Bewertung

    /// Bewertet einen Inhalt im Kontext seiner Quelle. Reine Funktion, keine Seiteneffekte.
    public func assess(content: String, sourceType: String, isUserCreated: Bool = false) -> Assessment {
        var reasons: [String] = []
        var risk = 0.0

        // 1. Unsichtbare / bidirektionale / Steuerzeichen entfernen (Tarn-Vektoren).
        let (cleaned, removed, hadBidi) = Self.stripHiddenCharacters(content)
        if removed > 0 {
            risk += hadBidi ? 0.35 : 0.15
            reasons.append("entfernte \(removed) unsichtbare/Steuer-Zeichen\(hadBidi ? " (inkl. Bidi-Override)" : "")")
        }

        // 2. Injection-/Exfiltrations-Muster auf dem GESÄUBERTEN Text (gegen Split-Tricks).
        let lower = cleaned.lowercased()
        for rule in Self.injectionRules where rule.matches(lower) {
            risk += rule.weight
            reasons.append(rule.label)
        }

        // 3. Secret-Erkennung (OWASP-ASI06-Abgleich): Zugangsdaten im weitergereichten
        //    Inhalt sind ein Leak-Kanal. Auf dem ORIGINAL-Casing prüfen (Token-Formate sind
        //    case-sensitiv). Eigene Notizen (Provenance) bleiben milder gewichtet — wer
        //    bewusst ein Passwort notiert, wird nicht blockiert, aber der Fund steht in den
        //    Gründen/im Audit.
        for rule in Self.secretRules where rule.matches(cleaned) {
            risk += rule.weight
            reasons.append(rule.label)
        }

        // 4. Größen-Anomalie (OWASP-ASI06-Abgleich): absurd große Einzel-Inhalte sind
        //    ein Stuffing-Vektor (Kontext fluten, Detektoren verdünnen).
        if cleaned.unicodeScalars.count > Self.sizeAnomalyThreshold {
            risk += 0.2
            reasons.append("size anomaly: \(cleaned.unicodeScalars.count) Zeichen in EINEM Inhalt")
        }

        // 5. Provenance-Gewichtung.
        let multiplier: Double
        if isUserCreated || trustedSourceTypes.contains(sourceType) {
            multiplier = 0.55
        } else if untrustedSourceTypes.contains(sourceType) {
            multiplier = 1.35
        } else {
            multiplier = 1.0
        }
        risk = min(1.0, risk * multiplier)

        let verdict: Verdict
        if risk >= quarantineThreshold {
            verdict = .quarantined(reasons: reasons)
        } else if removed > 0 || !reasons.isEmpty {
            verdict = .sanitized(reasons: reasons)
        } else {
            verdict = .clean
        }
        return Assessment(verdict: verdict, sanitizedContent: cleaned, riskScore: risk, reasons: reasons)
    }

    // MARK: - Sanitisierung

    /// Entfernt unsichtbare/format-/steuerzeichen, die zur Tarnung von Anweisungen dienen.
    /// Erlaubt bleiben gängige Whitespaces (`\t`, `\n`, `\r`). Gibt den gesäuberten String,
    /// die Anzahl entfernter Skalare und ob ein Bidi-Override entfernt wurde zurück.
    static func stripHiddenCharacters(_ text: String) -> (cleaned: String, removed: Int, hadBidi: Bool) {
        var out = String.UnicodeScalarView()
        out.reserveCapacity(text.unicodeScalars.count)
        var removed = 0
        var hadBidi = false

        for scalar in text.unicodeScalars {
            let v = scalar.value
            let isAllowedWhitespace = (v == 0x09 || v == 0x0A || v == 0x0D)
            // Generisch über die Unicode-Kategorie strippen: `Cf` (Format) deckt
            // zero-width, Bidi, Word-Joiner, den Tags-Block, Soft-Hyphen, BOM und
            // Interlinear-Annotation ab; `Cc` (Steuer) die C0/C1/DEL-Bereiche — außer dem
            // erlaubten Whitespace. Damit fallen auch bislang übersehene Skalare weg.
            let category = scalar.properties.generalCategory
            let isFormatOrControl = category == .format
                || (category == .control && !isAllowedWhitespace)
            // Nicht-Cf-Unsichtbare, die dennoch zur Tarnung taugen, explizit ergänzen:
            let isVariationSelector = (0xFE00...0xFE0F).contains(v) || (0xE0100...0xE01EF).contains(v)
            let isInvisibleLetterLike = v == 0x115F || v == 0x1160 || v == 0x3164 || v == 0xFFA0  // Hangul-Filler
                || v == 0x2800 || v == 0x034F || v == 0x180E   // Braille-Blank, CGJ, Mongolian Vowel Separator
            let isLineParaSeparator = v == 0x2028 || v == 0x2029
            // Für die Gewichtung: Bidi-Overrides und der Tags-Block sind starke Injektionssignale.
            let isBidi = (0x202A...0x202E).contains(v) || (0x2066...0x2069).contains(v)
            let isTagChar = (0xE0000...0xE007F).contains(v)

            if isFormatOrControl || isVariationSelector || isInvisibleLetterLike || isLineParaSeparator {
                removed += 1
                if isBidi || isTagChar { hadBidi = true }   // starkes Signal → wie Bidi gewichten
                continue
            }
            out.append(scalar)
        }
        return (String(out), removed, hadBidi)
    }

    // MARK: - Regelwerk

    /// Vorkompilierte Regel. `NSRegularExpression` ist immutable und laut Dokumentation
    /// threadsicher — daher ist `@unchecked Sendable` hier gedeckt. Die Muster sind
    /// statisch; einmal kompilieren statt bei jedem `assess()`-Aufruf erneut.
    private struct Rule: @unchecked Sendable {
        let regex: NSRegularExpression
        let weight: Double
        let label: String

        init?(pattern: String, weight: Double, label: String,
              options: NSRegularExpression.Options = [.caseInsensitive, .dotMatchesLineSeparators]) {
            guard let regex = try? NSRegularExpression(pattern: pattern, options: options) else {
                return nil
            }
            self.regex = regex
            self.weight = weight
            self.label = label
        }

        func matches(_ text: String) -> Bool {
            let range = NSRange(text.startIndex..<text.endIndex, in: text)
            return regex.firstMatch(in: text, options: [], range: range) != nil
        }
    }

    /// Kuratierte, case-insensitive Muster bekannter Prompt-Injection-/Exfiltrations-Vektoren.
    private static let injectionRules: [Rule] = compactRules([
        Rule(pattern: #"ignore\s+(all\s+|the\s+|any\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|messages?|context)"#,
             weight: 0.55, label: "override: 'ignore previous instructions'"),
        Rule(pattern: #"disregard\s+(the\s+|all\s+|any\s+)?(previous|prior|above|system|earlier)"#,
             weight: 0.45, label: "override: 'disregard above/system'"),
        Rule(pattern: #"(reveal|print|show|repeat|output|dump)\s+(your|the|all\s+your)\s+(system\s+|initial\s+)?(prompt|instructions?|rules)"#,
             weight: 0.55, label: "exfil: 'reveal your system prompt'"),
        Rule(pattern: #"you\s+are\s+now\s+(a|an|the|in)\b"#,
             weight: 0.30, label: "role-override: 'you are now ...'"),
        Rule(pattern: #"</?(system|assistant|user|tool|im_start|im_end|instructions?)\b[^>]*>"#,
             weight: 0.40, label: "fake chat/role markup"),
        Rule(pattern: #"\b(developer|admin|root|god|dan)\s+mode\b"#,
             weight: 0.30, label: "privilege-escalation mode"),
        Rule(pattern: #"do\s+anything\s+now\b"#,
             weight: 0.30, label: "jailbreak: DAN"),
        Rule(pattern: #"\bjailbreak\b|\bjail\s*break\b"#,
             weight: 0.25, label: "jailbreak keyword"),
        Rule(pattern: #"(begin|end|start)\s+(of\s+)?(system|admin)\s+(prompt|message|instructions?)"#,
             weight: 0.40, label: "fake system-prompt delimiter"),
        Rule(pattern: #"new\s+(instructions?|rules?|task)\s*:\s*"#,
             weight: 0.30, label: "instruction injection: 'new instructions:'"),
        Rule(pattern: #"!\[[^\]]*\]\(\s*https?://[^)]*[?&][^)]*\)"#,
             weight: 0.45, label: "markdown image with query-string (exfil channel)"),
        Rule(pattern: #"\b(curl|wget|fetch|xhr|navigator\.sendbeacon)\b[^\n]{0,80}https?://"#,
             weight: 0.30, label: "embedded network call (exfil)"),
        Rule(pattern: #"(send|post|exfiltrate|leak|forward)\s+[^\n]{0,40}(api[_\s-]?key|secret|token|password|credential)"#,
             weight: 0.50, label: "credential-exfiltration request"),
    ])

    /// Ab dieser Zeichenzahl gilt ein EINZELNER Inhalt als Größen-Anomalie.
    static let sizeAnomalyThreshold = 200_000

    /// Secret-Formate (case-sensitiv geprüft): erkennbare Zugangsdaten-Muster,
    /// keine Heuristik über Entropie (zu viele Falschtreffer in Prosa).
    private static let secretRules: [Rule] = compactRules([
        Rule(pattern: #"-----BEGIN [A-Z ]*PRIVATE KEY-----"#,
             weight: 0.45, label: "secret: private-key block", options: []),
        Rule(pattern: #"\bAKIA[0-9A-Z]{16}\b"#,
             weight: 0.40, label: "secret: AWS access key id", options: []),
        Rule(pattern: #"\bgh[pousr]_[A-Za-z0-9]{36,}\b"#,
             weight: 0.40, label: "secret: GitHub token", options: []),
        Rule(pattern: #"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"#,
             weight: 0.40, label: "secret: Slack token", options: []),
        Rule(pattern: #"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"#,
             weight: 0.35, label: "secret: JWT", options: []),
        Rule(pattern: #"\bsk-[A-Za-z0-9_-]{20,}\b"#,
             weight: 0.35, label: "secret: api key (sk-…)"),
        Rule(pattern: #"(api[_-]?key|client[_-]?secret|access[_-]?token)\s*[:=]\s*['"][A-Za-z0-9_\-/+]{16,}['"]"#,
             weight: 0.35, label: "secret: credential assignment"),
    ])

    private static func compactRules(_ rules: [Rule?]) -> [Rule] { rules.compactMap { $0 } }
}
