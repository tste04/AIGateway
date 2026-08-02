// Copyright (c) 2026 Tommy Stellmacher
// SPDX-License-Identifier: Apache-2.0

import Foundation

// MARK: - Stabile Regel-Identitaet
//
// Jeder Befund traegt eine ID, die sich NIE aendert. Prosa-Texte sind
// Anzeige-Material und duerfen umformuliert werden; Suppressions, SIEM-Regeln
// und Dashboards binden ausschliesslich an die ID.

/// Stabiler Bezeichner einer Erkennungsregel, z. B. `INJ-001`.
///
/// Wird als blanker String serialisiert (`"INJ-001"`), nicht als Objekt.
public struct RuleID: Hashable, Sendable, Codable, CustomStringConvertible, ExpressibleByStringLiteral {
    public let rawValue: String

    public init(_ rawValue: String) { self.rawValue = rawValue }
    public init(stringLiteral value: String) { self.rawValue = value }

    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        self.rawValue = try container.decode(String.self)
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(rawValue)
    }

    public var description: String { rawValue }
}

/// Fachliche Einordnung eines Befunds. Entspricht den Boxen der Input Firewall.
public enum FindingCategory: String, Sendable, Codable, CaseIterable {
    /// Prompt-Injection / Instruction-Override.
    case injection
    /// Erkannte Zugangsdaten-Formate (Schluessel, Token).
    case secret
    /// Personenbezogene Daten.
    case pii
    /// Verstoss gegen eine Data-Loss-Prevention-Richtlinie.
    case dlp
    /// Schadcode-Verdacht in Anhaengen/Payloads.
    case malware
    /// Struktur-Anomalie (Groesse, Entropie, Wiederholung).
    case anomaly
    /// Der Inhalt wurde bereinigt (unsichtbare/Steuerzeichen entfernt).
    case sanitization
}

/// Schweregrad eines Befunds — unabhaengig vom numerischen Risikobeitrag.
public enum Severity: String, Sendable, Codable, CaseIterable, Comparable {
    case info
    case low
    case medium
    case high
    case critical

    private var rank: Int {
        switch self {
        case .info: return 0
        case .low: return 1
        case .medium: return 2
        case .high: return 3
        case .critical: return 4
        }
    }

    public static func < (lhs: Severity, rhs: Severity) -> Bool { lhs.rank < rhs.rank }
}
