// Copyright (c) 2026 Tommy Stellmacher
// SPDX-License-Identifier: Apache-2.0

import Foundation

// MARK: - Provenienz
//
// Dieselbe Zeichenfolge ist in einer eigenen Notiz harmlos und in einer fremden
// E-Mail ein Angriff. Die Herkunft ist daher ein Multiplikator auf das Risiko.
//
// WICHTIG (Sicherheits-Default): Eine UNBEKANNTE Quelle gilt als `untrusted`,
// nicht als `neutral`. Andernfalls waere jeder nicht katalogisierte Quelltyp
// — `sharepoint`, `confluence`, `jira`, `rag_chunk` — automatisch der mildeste
// Pfad, und genau dort kommt Fremdinhalt herein. Fail-closed by default.

/// Vertrauensstufe der Inhaltsquelle.
public enum SourceTrust: String, Sendable, Codable, CaseIterable {
    /// Vom Nutzer selbst erzeugt (Notiz, Diktat).
    case trusted
    /// Herkunft bekannt, aber weder eigen noch offensichtlich fremd.
    case neutral
    /// Fremdbestimmt (Web, Mail, Tool-Output, Retrieval).
    case untrusted

    /// Multiplikator auf den aufsummierten Risiko-Score.
    public var riskMultiplier: Double {
        switch self {
        case .trusted: return 0.55
        case .neutral: return 1.0
        case .untrusted: return 1.35
        }
    }
}

/// Bildet einen Quelltyp-String auf eine Vertrauensstufe ab.
///
/// Die Listen sind bewusst offen konfigurierbar — jede Organisation hat eigene
/// Konnektoren. Was in keiner Liste steht, faellt auf `unknownTrust`.
public struct SourceTrustResolver: Sendable {
    public let trustedTypes: Set<String>
    public let untrustedTypes: Set<String>
    /// Default `.untrusted` — siehe Kopfkommentar.
    public let unknownTrust: SourceTrust

    public static let defaultTrusted: Set<String> = [
        "note", "manual", "transcript", "user", "journal",
    ]

    public static let defaultUntrusted: Set<String> = [
        "web", "email", "tool", "tool_output", "external", "import",
        "rss", "webhook", "attachment", "clipboard",
        // Retrieval-Quellen aus dem Context Orchestrator: fremder Inhalt,
        // der als Kontext in den Prompt wandert.
        "rag", "rag_chunk", "retrieval", "confluence", "sharepoint",
        "jira", "gitlab", "github", "wiki", "crawl",
    ]

    public init(
        trustedTypes: Set<String> = SourceTrustResolver.defaultTrusted,
        untrustedTypes: Set<String> = SourceTrustResolver.defaultUntrusted,
        unknownTrust: SourceTrust = .untrusted
    ) {
        self.trustedTypes = trustedTypes
        self.untrustedTypes = untrustedTypes
        self.unknownTrust = unknownTrust
    }

    public func trust(for sourceType: String, isUserCreated: Bool = false) -> SourceTrust {
        if isUserCreated { return .trusted }
        let key = sourceType.lowercased()
        if trustedTypes.contains(key) { return .trusted }
        if untrustedTypes.contains(key) { return .untrusted }
        return unknownTrust
    }
}
