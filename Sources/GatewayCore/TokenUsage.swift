// Copyright (c) 2026 Tommy Stellmacher
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

import Foundation

// MARK: - Token-Verbrauch
//
// Liegt im Kern, nicht im Transport: die Zahlen entstehen im Provider-Adapter
// und wandern bis in die FinOps-Box. Beide Enden sollen denselben Typ kennen,
// ohne dass der Kern vom Transport abhaengt.

/// Gemeldeter Token-Verbrauch einer Anfrage.
///
/// Beide Werte sind das, was der Provider GEMELDET hat. Es wird nie geschaetzt —
/// eine erfundene Zahl in einer Kostenrechnung ist schlimmer als eine fehlende.
public struct TokenUsage: Sendable, Codable, Equatable {
    public var promptTokens: Int
    public var completionTokens: Int

    public init(promptTokens: Int, completionTokens: Int) {
        self.promptTokens = promptTokens
        self.completionTokens = completionTokens
    }

    public var totalTokens: Int { promptTokens + completionTokens }

    /// Vereinigt zwei Teilmeldungen.
    ///
    /// Noetig, weil manche Dialekte Eingabe- und Ausgabe-Verbrauch in
    /// VERSCHIEDENEN Stromereignissen melden (Anthropic: `message_start` traegt
    /// die Eingabe, `message_delta` die Ausgabe). Feldweise das Maximum, weil
    /// die Zaehler monoton wachsen: die Reihenfolge der Ereignisse wird damit
    /// egal, und eine spaetere Teilmeldung loescht keine fruehere Zahl.
    public func merging(_ other: TokenUsage) -> TokenUsage {
        TokenUsage(promptTokens: max(promptTokens, other.promptTokens),
                   completionTokens: max(completionTokens, other.completionTokens))
    }
}
