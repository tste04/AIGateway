// Copyright (c) 2026 Tommy Stellmacher
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

import Foundation
import GatewayCore

// MARK: - Regel
//
// Oeffentlich und erweiterbar: jede Organisation hat eigene Muster (Codenamen,
// interne Werkzeuge, Mandatsbezeichner). Ein versiegeltes Regelwerk zwingt
// solche Faelle in einen Fork.

/// Eine musterbasierte Erkennungsregel.
///
/// `NSRegularExpression` ist immutable und laut Dokumentation threadsicher —
/// `@unchecked Sendable` ist damit gedeckt. Muster werden einmal kompiliert,
/// nicht bei jedem Scan.
public struct InjectionRule: @unchecked Sendable {
    public let id: RuleID
    public let category: FindingCategory
    public let severity: Severity
    public let weight: Double
    public let message: String

    private let regex: NSRegularExpression
    /// Gelockerte Fassung fuer die entleerte Vergleichsform (siehe unten).
    private let relaxedRegex: NSRegularExpression?

    /// Schlaegt fehl (`nil`), wenn das Muster nicht kompiliert — eine kaputte
    /// Regel darf den Scanner nicht zur Laufzeit ueberraschen.
    public init?(
        id: RuleID,
        category: FindingCategory,
        severity: Severity,
        weight: Double,
        message: String,
        pattern: String,
        caseSensitive: Bool = false
    ) {
        var options: NSRegularExpression.Options = [.dotMatchesLineSeparators]
        if !caseSensitive { options.insert(.caseInsensitive) }
        guard let regex = try? NSRegularExpression(pattern: pattern, options: options) else {
            return nil
        }
        self.regex = regex
        // Nur die Sequenz `\s+` wird zu `\s*` — NICHT ein einzelnes `\s`, denn
        // das steht in Mustern auch innerhalb von Zeichenklassen (`[\s-]?`),
        // wo die Ersetzung die Klasse zerstoeren wuerde (`[\s*-]?`).
        let relaxedPattern = pattern.replacingOccurrences(of: #"\s+"#, with: #"\s*"#)
        self.relaxedRegex = relaxedPattern == pattern
            ? nil
            : try? NSRegularExpression(pattern: relaxedPattern, options: options)
        self.id = id
        self.category = category
        self.severity = severity
        self.weight = weight
        self.message = message
    }

    /// Trefferanzahl im Text.
    public func occurrences(in text: String) -> Int {
        let range = NSRange(text.startIndex..<text.endIndex, in: text)
        return regex.numberOfMatches(in: text, options: [], range: range)
    }

    /// Trefferanzahl in der entleerten Vergleichsform ('ignoreallprevious...').
    /// Nutzt das gelockerte Muster; ohne Wortabstaende im Muster gibt es keine
    /// gelockerte Fassung und damit auch keinen Treffer.
    public func occurrencesRelaxed(in text: String) -> Int {
        guard let relaxedRegex else { return 0 }
        let range = NSRange(text.startIndex..<text.endIndex, in: text)
        return relaxedRegex.numberOfMatches(in: text, options: [], range: range)
    }

    /// Baut den Befund. Das Gewicht zaehlt EINMAL, unabhaengig von der
    /// Trefferzahl — sonst kippt ein einziges wiederholtes Muster jeden Score.
    public func finding(occurrences: Int) -> Finding {
        Finding(
            ruleID: id,
            category: category,
            severity: severity,
            weight: weight,
            message: message,
            occurrences: occurrences
        )
    }
}
