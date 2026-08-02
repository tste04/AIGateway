// Copyright (c) 2026 Tommy Stellmacher
// SPDX-License-Identifier: Apache-2.0

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

    /// Liest eine `usage`-Meldung im verbreiteten prompt/completion-Format
    /// (snake_case wie camelCase).
    ///
    /// Liegt hier, weil drei Raender dieselbe Lesung brauchen (OpenAI-Antwort,
    /// OpenAI-Strom, Stufen-Naht) — eine vierte Abschrift waere die naechste
    /// Drift-Quelle. `nil`, wenn KEINES der Felder da ist: eine leere Meldung
    /// ist keine Meldung, und geschaetzt wird nie. Dialekte mit eigenen
    /// Feldnamen (Anthropic: `input_tokens`/`output_tokens`) lesen weiterhin
    /// selbst.
    public init?(json: [String: Any]) {
        let prompt = json["prompt_tokens"] as? Int ?? json["promptTokens"] as? Int
        let completion = json["completion_tokens"] as? Int ?? json["completionTokens"] as? Int
        guard prompt != nil || completion != nil else { return nil }
        self.init(promptTokens: prompt ?? 0, completionTokens: completion ?? 0)
    }

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
