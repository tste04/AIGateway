// Copyright (c) 2026 Tommy Stellmacher
// SPDX-License-Identifier: Apache-2.0

import Foundation
import GatewayCore

// MARK: - InjectionScanner (Input-Firewall-Stufe „Injection")
//
// Bewertet Fremdinhalt, bevor er ein Modell erreicht — als Prompt, als
// retrieved content aus dem Context Orchestrator oder als Tool-Ausgabe im
// Agent Loop. Deterministisch, netzfrei, ohne externe Abhaengigkeiten.
//
//   • Sanitisierung  — unsichtbare/bidirektionale/Steuerzeichen entfernen.
//   • Injection-Heuristik — bekannte Override-/Exfiltrations-Muster.
//   • Secret-Erkennung — erkennbare Zugangsdaten-Formate.
//   • Groessen-Anomalie — Context-Stuffing.
//
// Der Scanner ENTSCHEIDET NICHT. Er liefert Befunde und einen Score;
// die Disposition bestimmt `GatewayPolicy`.
//
// Gegen Verschleierung laeuft der Vergleich zusaetzlich auf einer normalisierten
// Erkennungs-Oberflaeche (`TextNormalizer`): Homoglyphen, Buchstaben-Sperrung,
// Trennzeichen und base64-Nutzlast. Diese Oberflaeche wird NIE ausgeliefert.
//
// BEWUSSTE GRENZEN (nicht ueberlesen): Muster-Erkennung bleibt wortnah. Der
// Katalog deckt Englisch und Deutsch ab — andere Sprachen brauchen eigene
// Regeln. Semantische Umschreibungen ('tu so, als haettest du keine Vorgaben')
// erkennt keine Regex. Der Scanner ist eine billige erste Schicht, kein Ersatz
// fuer Least-Privilege-Tool-Design und Output-Guardrails.

public struct InjectionScanner: ContentScanner {

    public let stageName = "injection"

    private let rules: [InjectionRule]
    private let sizeAnomalyThreshold: Int

    /// - Parameters:
    ///   - rules: Regelwerk. Default ist der mitgelieferte Katalog; eigene
    ///     Regeln koennen ergaenzt oder das Set komplett ersetzt werden.
    ///   - sizeAnomalyThreshold: Ab dieser Zeichenzahl gilt EIN Inhalt als
    ///     Anomalie. Das ist ein Risikosignal — die harte Eingabegrenze liegt
    ///     in `GatewayPolicy.maxInputBytes`.
    public init(
        rules: [InjectionRule] = InjectionScanner.defaultRules,
        sizeAnomalyThreshold: Int = 200_000
    ) {
        self.rules = rules
        self.sizeAnomalyThreshold = sizeAnomalyThreshold
    }

    // MARK: - Scan

    public func scan(_ content: String, trust: SourceTrust) -> ScanResult {
        var findings: [Finding] = []
        var raw = 0.0

        // 1. Tarnzeichen entfernen. Zuerst, damit die Muster auf dem
        //    gesaeuberten Text greifen (gegen Zero-Width-Split-Tricks).
        let (cleaned, removed, strongSignal) = Self.stripHiddenCharacters(content)
        if removed > 0 {
            let id: RuleID = strongSignal ? Self.ruleBidiOverride : Self.ruleInvisibleChars
            let severity: Severity = strongSignal ? .high : .low
            let weight = strongSignal ? 0.35 : 0.15
            let message = strongSignal
                ? "sanitization: removed bidi-override or tag characters"
                : "sanitization: removed invisible or control characters"
            raw += weight
            findings.append(Finding(
                ruleID: id, category: .sanitization, severity: severity,
                weight: weight, message: message, occurrences: removed))
        }

        // 2. Erkennungs-Oberflaeche aufbauen (NFKC, Homoglyphen, Sperrung, base64).
        //    Sie wird NIE ausgeliefert — nur verglichen. Unterscheidet sie sich
        //    nicht vom gesaeuberten Text, entfaellt der zweite Durchgang komplett;
        //    das ist der Normalfall und kostet dann nichts.
        let normalized = TextNormalizer.normalize(cleaned)
        var evadedRules = 0

        // 3. Regelwerk. Secret-Formate laufen NUR auf dem Original: ihre Muster
        //    sind case-sensitiv und wuerden auf der gefalteten Oberflaeche
        //    reihenweise falsch anschlagen.
        for rule in rules {
            var hits = rule.occurrences(in: cleaned)
            var onlyOnSurface = false
            if hits == 0, rule.category != .secret {
                if normalized.didChange {
                    hits = rule.occurrences(in: normalized.surface)
                }
                // Letzte Stufe: durchgehend gesperrter Text faellt zu EINEM Wort
                // zusammen — dort greift nur das gelockerte Muster.
                if hits == 0, let compact = normalized.compact {
                    hits = rule.occurrencesRelaxed(in: compact)
                }
                onlyOnSurface = hits > 0
            }
            guard hits > 0 else { continue }
            raw += rule.weight
            findings.append(rule.finding(occurrences: hits))
            if onlyOnSurface { evadedRules += 1 }
        }

        // 4. Verschleierung ist ein eigenes Signal: wer eine Regel erst nach
        //    Normalisierung trifft, hat sie aktiv zu umgehen versucht. Das wiegt
        //    schwerer als derselbe Text im Klartext.
        if evadedRules > 0 {
            raw += 0.25
            findings.append(Finding(
                ruleID: Self.ruleObfuscation, category: .injection, severity: .high,
                weight: 0.25,
                message: "evasion: rule matched only after normalization",
                occurrences: evadedRules))
        }

        // 5. Groessen-Anomalie.
        if cleaned.unicodeScalars.count > sizeAnomalyThreshold {
            raw += 0.2
            findings.append(Finding(
                ruleID: Self.ruleSizeAnomaly, category: .anomaly, severity: .low,
                weight: 0.2,
                message: "anomaly: oversized single payload",
                occurrences: 1))
        }

        return ScanResult(
            findings: findings,
            content: cleaned,
            rawScore: raw,
            trustMultiplier: trust.riskMultiplier,
            wasModified: removed > 0
        )
    }

    // MARK: - Sanitisierung

    /// Entfernt unsichtbare/Format-/Steuerzeichen, die Anweisungen tarnen.
    /// Erlaubt bleiben `\t`, `\n`, `\r`. Liefert den gesaeuberten Text, die
    /// Anzahl entfernter Skalare und ob ein starkes Signal (Bidi/Tag) dabei war.
    static func stripHiddenCharacters(_ text: String) -> (cleaned: String, removed: Int, strongSignal: Bool) {
        var out = String.UnicodeScalarView()
        out.reserveCapacity(text.unicodeScalars.count)
        var removed = 0
        var strongSignal = false

        for scalar in text.unicodeScalars {
            let v = scalar.value
            let isAllowedWhitespace = (v == 0x09 || v == 0x0A || v == 0x0D)
            // Generisch ueber die Unicode-Kategorie: `Cf` (Format) deckt
            // zero-width, Bidi, Word-Joiner, Tags-Block, Soft-Hyphen, BOM und
            // Interlinear-Annotation ab; `Cc` (Steuer) die C0/C1/DEL-Bereiche.
            let category = scalar.properties.generalCategory
            let isFormatOrControl = category == .format
                || (category == .control && !isAllowedWhitespace)
            // Nicht-Cf-Unsichtbare, die dennoch zur Tarnung taugen:
            let isVariationSelector = (0xFE00...0xFE0F).contains(v) || (0xE0100...0xE01EF).contains(v)
            let isInvisibleLetterLike = v == 0x115F || v == 0x1160 || v == 0x3164 || v == 0xFFA0  // Hangul-Filler
                || v == 0x2800 || v == 0x034F || v == 0x180E   // Braille-Blank, CGJ, Mongolian Vowel Separator
            let isLineParaSeparator = v == 0x2028 || v == 0x2029
            // Starke Injektionssignale: Bidi-Overrides und der Tags-Block.
            let isBidi = (0x202A...0x202E).contains(v) || (0x2066...0x2069).contains(v)
            let isTagChar = (0xE0000...0xE007F).contains(v)

            if isFormatOrControl || isVariationSelector || isInvisibleLetterLike || isLineParaSeparator {
                removed += 1
                if isBidi || isTagChar { strongSignal = true }
                continue
            }
            out.append(scalar)
        }
        return (String(out), removed, strongSignal)
    }

    // MARK: - Regel-IDs der eingebauten Stufen
    //
    // Stabil. Aenderungen hier brechen Suppressions und SIEM-Regeln.

    public static let ruleInvisibleChars: RuleID = "SAN-001"
    public static let ruleBidiOverride: RuleID = "SAN-002"
    public static let ruleObfuscation: RuleID = "SAN-003"
    public static let ruleSizeAnomaly: RuleID = "ANO-001"

    // MARK: - Katalog

    /// Mitgelieferter Regelkatalog: Prompt-Injection englisch (INJ-0xx) und
    /// deutsch (INJ-1xx) plus Secret-Formate (SEC).
    public static let defaultRules: [InjectionRule] =
        [defaultInjectionRules, defaultGermanInjectionRules, defaultSecretRules].flatMap { $0 }

    /// Kuratierte Muster bekannter Prompt-Injection-/Exfiltrations-Vektoren.
    public static let defaultInjectionRules: [InjectionRule] = [
        InjectionRule(id: "INJ-001", category: .injection, severity: .critical, weight: 0.55,
                      message: "override: 'ignore previous instructions'",
                      pattern: #"ignore\s+(all\s+|the\s+|any\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|messages?|context)"#),
        InjectionRule(id: "INJ-002", category: .injection, severity: .high, weight: 0.45,
                      message: "override: 'disregard above/system'",
                      pattern: #"disregard\s+(the\s+|all\s+|any\s+)?(previous|prior|above|system|earlier)"#),
        InjectionRule(id: "INJ-003", category: .injection, severity: .critical, weight: 0.55,
                      message: "exfil: 'reveal your system prompt'",
                      pattern: #"(reveal|print|show|repeat|output|dump)\s+(your|the|all\s+your)\s+(system\s+|initial\s+)?(prompt|instructions?|rules)"#),
        InjectionRule(id: "INJ-004", category: .injection, severity: .medium, weight: 0.30,
                      message: "role-override: 'you are now ...'",
                      pattern: #"you\s+are\s+now\s+(a|an|the|in)\b"#),
        InjectionRule(id: "INJ-005", category: .injection, severity: .high, weight: 0.40,
                      message: "fake chat/role markup",
                      pattern: #"</?(system|assistant|user|tool|im_start|im_end|instructions?)\b[^>]*>"#),
        InjectionRule(id: "INJ-006", category: .injection, severity: .medium, weight: 0.30,
                      message: "privilege-escalation mode",
                      pattern: #"\b(developer|admin|root|god|dan)\s+mode\b"#),
        InjectionRule(id: "INJ-007", category: .injection, severity: .medium, weight: 0.30,
                      message: "jailbreak: DAN",
                      pattern: #"do\s+anything\s+now\b"#),
        InjectionRule(id: "INJ-008", category: .injection, severity: .low, weight: 0.25,
                      message: "jailbreak keyword",
                      pattern: #"\bjailbreak\b|\bjail\s*break\b"#),
        InjectionRule(id: "INJ-009", category: .injection, severity: .high, weight: 0.40,
                      message: "fake system-prompt delimiter",
                      pattern: #"(begin|end|start)\s+(of\s+)?(system|admin)\s+(prompt|message|instructions?)"#),
        InjectionRule(id: "INJ-010", category: .injection, severity: .medium, weight: 0.30,
                      message: "instruction injection: 'new instructions:'",
                      pattern: #"new\s+(instructions?|rules?|task)\s*:\s*"#),
        InjectionRule(id: "INJ-011", category: .injection, severity: .high, weight: 0.45,
                      message: "markdown image with query-string (exfil channel)",
                      pattern: #"!\[[^\]]*\]\(\s*https?://[^)]*[?&][^)]*\)"#),
        InjectionRule(id: "INJ-012", category: .injection, severity: .medium, weight: 0.30,
                      message: "embedded network call (exfil)",
                      pattern: #"\b(curl|wget|fetch|xhr|navigator\.sendbeacon)\b[^\n]{0,80}https?://"#),
        InjectionRule(id: "INJ-013", category: .injection, severity: .critical, weight: 0.50,
                      message: "credential-exfiltration request",
                      pattern: #"(send|post|exfiltrate|leak|forward)\s+[^\n]{0,40}(api[_\s-]?key|secret|token|password|credential)"#),
    ].compactMap { $0 }

    /// Deutschsprachige Muster. Ein Modell befolgt 'Ignoriere alle vorherigen
    /// Anweisungen' genauso zuverlaessig wie die englische Fassung — ein rein
    /// englischer Katalog ist im deutschsprachigen Betrieb praktisch blind.
    ///
    /// Umlaute sind jeweils in beiden Schreibweisen abgedeckt (ue/ü), weil
    /// Transliteration ein trivialer Bypass waere.
    public static let defaultGermanInjectionRules: [InjectionRule] = [
        InjectionRule(id: "INJ-101", category: .injection, severity: .critical, weight: 0.55,
                      message: "override (de): 'ignoriere vorherige Anweisungen'",
                      pattern: #"ignorier(?:e|en|st)?\s+(?:alle[nrs]?\s+|die\s+|jegliche\s+)?(?:vorherigen|bisherigen|obigen|vorangegangenen|frueheren|früheren)\s+(?:anweisungen|anleitungen|regeln|befehle|instruktionen|vorgaben)"#),
        InjectionRule(id: "INJ-102", category: .injection, severity: .high, weight: 0.50,
                      message: "override (de): 'vergiss alle Regeln'",
                      pattern: #"vergiss\s+(?:alle[sn]?\s+|die\s+)?(?:bisherigen\s+|vorherigen\s+|obigen\s+)?(?:anweisungen|regeln|befehle|vorgaben|kontext)"#),
        InjectionRule(id: "INJ-103", category: .injection, severity: .critical, weight: 0.55,
                      message: "exfil (de): 'zeige deinen System-Prompt'",
                      pattern: #"(?:zeig|zeige|nenne|gib|verrate|drucke|wiederhole|nenn)\s+(?:mir\s+)?(?:deine[nr]?|den|die|das|alle)\s+(?:system[\s-]?)?(?:prompt|anweisungen|instruktionen|regeln|vorgaben)"#),
        InjectionRule(id: "INJ-104", category: .injection, severity: .medium, weight: 0.30,
                      message: "role-override (de): 'du bist jetzt ...'",
                      pattern: #"du\s+bist\s+(?:jetzt|nun|ab\s+(?:jetzt|sofort))\b"#),
        InjectionRule(id: "INJ-105", category: .injection, severity: .medium, weight: 0.30,
                      message: "instruction injection (de): 'neue Anweisungen:'",
                      pattern: #"neue[nrs]?\s+(?:anweisungen?|regeln?|aufgabe|instruktionen?)\s*:"#),
        InjectionRule(id: "INJ-106", category: .injection, severity: .high, weight: 0.45,
                      message: "override (de): 'missachte die obigen Anweisungen'",
                      pattern: #"(?:missachte|ignoriere|uebergehe|übergehe)\s+(?:alle\s+|die\s+)?(?:vorherigen|obigen|bisherigen|system)"#),
        InjectionRule(id: "INJ-107", category: .injection, severity: .medium, weight: 0.30,
                      message: "privilege-escalation (de): Entwicklermodus",
                      pattern: #"\b(?:entwickler|admin|administrator|root|gott)[\s-]?modus\b"#),
        InjectionRule(id: "INJ-108", category: .injection, severity: .critical, weight: 0.50,
                      message: "credential exfiltration (de)",
                      pattern: #"(?:sende|schicke|leite|uebermittle|übermittle|verrate)\s+[^\n]{0,40}(?:passwort|passwoerter|passwörter|zugangsdaten|api[\s-]?(?:schluessel|schlüssel|key)|geheimnis|token|anmeldedaten)"#),
        InjectionRule(id: "INJ-109", category: .injection, severity: .high, weight: 0.40,
                      message: "fake system-prompt delimiter (de)",
                      pattern: #"\b(?:anfang|beginn|ende)\s+(?:der\s+|des\s+)?(?:system|admin)[\s-]?(?:prompt|nachricht|anweisung|anweisungen)"#),
        InjectionRule(id: "INJ-110", category: .injection, severity: .high, weight: 0.40,
                      message: "role-override (de): 'ab jetzt handelst du als'",
                      pattern: #"ab\s+(?:jetzt|sofort|nun)\s+(?:handelst|agierst|verhaeltst|verhältst|antwortest)\s+du"#),
    ].compactMap { $0 }

    /// Secret-Formate. Ueberwiegend case-sensitiv geprueft — Token-Formate
    /// sind es auch, und Kleinschreibung erzeugt sonst Falschtreffer in Prosa.
    public static let defaultSecretRules: [InjectionRule] = [
        InjectionRule(id: "SEC-001", category: .secret, severity: .critical, weight: 0.45,
                      message: "secret: private-key block",
                      pattern: #"-----BEGIN [A-Z ]*PRIVATE KEY-----"#, caseSensitive: true),
        InjectionRule(id: "SEC-002", category: .secret, severity: .high, weight: 0.40,
                      message: "secret: AWS access key id",
                      pattern: #"\bAKIA[0-9A-Z]{16}\b"#, caseSensitive: true),
        InjectionRule(id: "SEC-003", category: .secret, severity: .high, weight: 0.40,
                      message: "secret: GitHub token",
                      pattern: #"\bgh[pousr]_[A-Za-z0-9]{36,}\b"#, caseSensitive: true),
        InjectionRule(id: "SEC-004", category: .secret, severity: .high, weight: 0.40,
                      message: "secret: Slack token",
                      pattern: #"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"#, caseSensitive: true),
        InjectionRule(id: "SEC-005", category: .secret, severity: .medium, weight: 0.35,
                      message: "secret: JWT",
                      pattern: #"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"#,
                      caseSensitive: true),
        InjectionRule(id: "SEC-006", category: .secret, severity: .medium, weight: 0.35,
                      message: "secret: api key (sk-...)",
                      pattern: #"\bsk-[A-Za-z0-9_-]{20,}\b"#),
        InjectionRule(id: "SEC-007", category: .secret, severity: .medium, weight: 0.35,
                      message: "secret: credential assignment",
                      pattern: #"(api[_-]?key|client[_-]?secret|access[_-]?token)\s*[:=]\s*['"][A-Za-z0-9_\-/+]{16,}['"]"#),
    ].compactMap { $0 }
}
