// Copyright (c) 2026 Tommy Stellmacher
// SPDX-License-Identifier: Apache-2.0

import Foundation

// MARK: - Erkennungs-Oberflaeche
//
// Muster-Erkennung scheitert an trivialer Verschleierung: 'Ign\u{043E}re' mit
// kyrillischem o, 'I g n o r e' mit Leerzeichen, 'ignore-all-previous' mit
// Bindestrichen, oder eine base64-kodierte Nutzlast. Dagegen hilft nur
// Normalisierung VOR dem Vergleich.
//
// KERNREGEL: Die Oberflaeche wird NIE ausgeliefert.
//
// Wer Homoglyphen im Nutztext faltet, zerstoert legitimen kyrillischen oder
// griechischen Inhalt — aus 'Москва' wuerde Buchstabensalat. Die Oberflaeche
// ist ein Schatten allein fuer den Mustervergleich; weitergereicht wird immer
// der bloss sanitisierte Text.

/// Ergebnis der Normalisierung.
public struct NormalizedText: Sendable, Equatable {
    /// Gefaltete, kollabierte Vergleichsfassung.
    public let surface: String
    /// Vollstaendig entleerte Fassung (ohne jeden Whitespace) — **nur gesetzt**,
    /// wenn Buchstaben-Sperrung erkannt wurde.
    ///
    /// Grund: Bei durchgehender Sperrung ('i g n o r e a l l ...') gibt es keine
    /// Wortgrenzen mehr zu retten — alles faellt zu EINEM Wort zusammen, und
    /// Regeln mit `\s+` greifen nicht mehr. Dafuer laeuft ein zweiter Vergleich
    /// mit gelockerten Mustern. Weil das die Fehlalarm-Gefahr erhoeht, wird die
    /// Fassung NUR bei tatsaechlich beobachteter Sperrung erzeugt — auf normaler
    /// Prosa entsteht sie nie.
    public let compact: String?
    /// Unterscheidet sich die Oberflaeche vom bloss kleingeschriebenen Original?
    public let didChange: Bool

    public init(surface: String, compact: String?, didChange: Bool) {
        self.surface = surface
        self.compact = compact
        self.didChange = didChange
    }
}

public enum TextNormalizer {

    /// Vollstaendige Normalisierung inklusive der Sonderfassung fuer Sperrung.
    public static func normalize(_ text: String) -> NormalizedText {
        let surface = detectionSurface(text)
        let spaced = hasLetterSpacing(text)
        return NormalizedText(
            surface: surface,
            compact: spaced ? surface.filter { !$0.isWhitespace } : nil,
            didChange: differs(surface, from: text))
    }

    /// Baut die Vergleichs-Oberflaeche: NFKC, Kleinschreibung, Homoglyphen-Faltung,
    /// Kollaps von Buchstaben-Sperrung und Trennzeichen, dekodierte base64-Nutzlast.
    public static func detectionSurface(_ text: String) -> String {
        // 1. NFKC — faltet Fullwidth-Formen, mathematische Alphabete
        //    (\u{1D422}\u{1D420}\u{1D427}... = 'ign...'), Ligaturen und roemische Ziffern.
        var s = text.precomposedStringWithCompatibilityMapping.lowercased()

        // 2. Homoglyphen auf Latein falten.
        s = foldConfusables(s)

        // 3. Trennzeichen zwischen Buchstaben zu Leerzeichen —
        //    schlaegt 'ignore-all-previous-instructions'.
        s = separatorRegex.stringByReplacingMatches(
            in: s, range: NSRange(s.startIndex..., in: s), withTemplate: " ")

        // 4. Buchstaben-Sperrung zusammenziehen — schlaegt 'i g n o r e'.
        s = collapseLetterSpacing(s)

        // 5. Kodierte Nutzlast anhaengen (nicht ersetzen — das Original bleibt
        //    vergleichbar, die Klartext-Fassung kommt zusaetzlich dazu).
        if let decoded = decodedBase64Payloads(in: text), !decoded.isEmpty {
            s += " " + foldConfusables(decoded.lowercased())
        }
        return s
    }

    /// Wurde ueberhaupt etwas veraendert? Wenn nicht, spart der Aufrufer den
    /// zweiten Regex-Durchgang — der Normalfall.
    public static func differs(_ surface: String, from cleaned: String) -> Bool {
        surface != cleaned.lowercased()
    }

    /// Enthaelt der Text eine Kette gesperrter Einzelbuchstaben?
    static func hasLetterSpacing(_ text: String) -> Bool {
        let ns = text as NSString
        return spacedLettersRegex.firstMatch(
            in: text, range: NSRange(location: 0, length: ns.length)) != nil
    }

    // MARK: - Homoglyphen

    /// Kyrillische und griechische Buchstaben, die lateinischen zum Verwechseln
    /// aehnlich sehen. Bewusst kuratiert statt vollstaendige UTS-#39-Tabelle:
    /// diese Handvoll deckt praktisch jeden real gesehenen Bypass ab.
    private static let confusables: [Character: Character] = [
        // Kyrillisch
        "\u{0430}": "a", "\u{0435}": "e", "\u{043E}": "o", "\u{0440}": "p",
        "\u{0441}": "c", "\u{0443}": "y", "\u{0445}": "x", "\u{0456}": "i",
        "\u{0455}": "s", "\u{0458}": "j", "\u{043A}": "k", "\u{043C}": "m",
        "\u{043D}": "h", "\u{0442}": "t", "\u{0432}": "b", "\u{0433}": "r",
        "\u{0451}": "e", "\u{04CF}": "l",
        // Griechisch
        "\u{03B1}": "a", "\u{03B5}": "e", "\u{03BF}": "o", "\u{03C1}": "p",
        "\u{03B9}": "i", "\u{03BA}": "k", "\u{03BD}": "v", "\u{03C4}": "t",
        "\u{03C5}": "u", "\u{03C7}": "x", "\u{03B3}": "y", "\u{03C3}": "o",
        "\u{03B2}": "b", "\u{03B7}": "n",
        // Armenisch / Cherokee — seltener, aber gaengige Lookalikes
        "\u{0585}": "o", "\u{13A0}": "a", "\u{13C0}": "g",
    ]

    private static func foldConfusables(_ text: String) -> String {
        // Schnellpfad: reines ASCII kann keine Homoglyphen enthalten.
        guard text.unicodeScalars.contains(where: { $0.value > 127 }) else { return text }
        var out = String()
        out.reserveCapacity(text.count)
        for ch in text { out.append(confusables[ch] ?? ch) }
        return out
    }

    // MARK: - Sperrung

    /// Zieht 'i g n o r e' zu 'ignore' zusammen. Nur Ketten ab vier Einzel-
    /// buchstaben werden angefasst — kuerzere Folgen sind zu oft echte Sprache
    /// ('a b c' in einer Aufzaehlung).
    private static func collapseLetterSpacing(_ text: String) -> String {
        let ns = text as NSString
        let matches = spacedLettersRegex.matches(
            in: text, range: NSRange(location: 0, length: ns.length))
        guard !matches.isEmpty else { return text }
        var out = ""
        var cursor = 0
        for m in matches {
            out += ns.substring(with: NSRange(location: cursor, length: m.range.location - cursor))
            let run = ns.substring(with: m.range)
            out += run.filter { !$0.isWhitespace }
            cursor = m.range.location + m.range.length
        }
        out += ns.substring(from: cursor)
        return out
    }

    // MARK: - Kodierte Nutzlast

    /// Dekodiert base64-verdaechtige Laeufe, wenn dabei lesbarer Text herauskommt.
    /// Binaermuell wird verworfen — sonst floetet zufaelliger Bytesalat die Regeln.
    private static func decodedBase64Payloads(in text: String) -> String? {
        let ns = text as NSString
        let matches = base64Regex.matches(
            in: text, range: NSRange(location: 0, length: ns.length))
        guard !matches.isEmpty else { return nil }
        var parts: [String] = []
        for m in matches.prefix(maxBase64Candidates) {
            var raw = ns.substring(with: m.range)
            // Auf ein Vielfaches von 4 auffuellen, sonst lehnt der Decoder ab.
            let pad = raw.count % 4
            if pad != 0 { raw += String(repeating: "=", count: 4 - pad) }
            guard let data = Data(base64Encoded: raw, options: [.ignoreUnknownCharacters]),
                  data.count >= 8,
                  let decoded = String(data: data, encoding: .utf8) else { continue }
            let printable = decoded.unicodeScalars.filter {
                $0.value == 9 || $0.value == 10 || $0.value == 13 || (32...126).contains($0.value)
            }.count
            // Mindestens 80 Prozent druckbar -> als Text behandeln.
            guard Double(printable) / Double(max(1, decoded.unicodeScalars.count)) >= 0.8 else { continue }
            parts.append(decoded)
        }
        return parts.isEmpty ? nil : parts.joined(separator: " ")
    }

    /// Deckel gegen Rechenlast: mehr als so viele Kandidaten werden ignoriert.
    private static let maxBase64Candidates = 16

    // MARK: - Muster

    private static let separatorRegex = try! NSRegularExpression(
        pattern: #"(?<=\p{L})[-_.·•]+(?=\p{L})"#)

    private static let spacedLettersRegex = try! NSRegularExpression(
        pattern: #"(?<!\p{L})(?:\p{L}[ \t]){3,}\p{L}(?!\p{L})"#)

    private static let base64Regex = try! NSRegularExpression(
        pattern: #"[A-Za-z0-9+/]{24,}={0,2}"#)
}
