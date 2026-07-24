// Copyright (c) 2026 Tommy Stellmacher
// SPDX-License-Identifier: Apache-2.0

import Foundation
import GatewayCore

// MARK: - Regeln der Pseudonymisierung
//
// Schutz und Antwortqualitaet sind ein Zielkonflikt. Deshalb ist das Gate
// stufenlos einstellbar und die Qualitaet wird MITGEMESSEN (Dichte-Waechter).

/// Erkennungs-Kategorien mit ihren Token-Praefixen.
public enum PseudonymCategory: String, CaseIterable, Sendable, Codable {
    case person, mail, tel, iban, adresse, ort
    /// Nutzer-kuratierte Denylist-Begriffe (Codenamen, Mandate) — immer ersetzen.
    case custom = "begriff"

    var tokenPrefix: String {
        switch self {
        case .person: return "Person"
        case .mail: return "Mail"
        case .tel: return "Tel"
        case .iban: return "IBAN"
        case .adresse: return "Adresse"
        case .ort: return "Ort"
        case .custom: return "Begriff"
        }
    }

    /// Stabile Regel-ID fuer Audit und Suppression.
    public var ruleID: RuleID {
        switch self {
        case .person: return "PII-001"
        case .mail: return "PII-002"
        case .tel: return "PII-003"
        case .iban: return "PII-004"
        case .adresse: return "PII-005"
        case .ort: return "PII-006"
        case .custom: return "PII-007"
        }
    }

    public var severity: Severity {
        switch self {
        case .person, .iban, .custom: return .high
        case .mail, .tel, .adresse: return .medium
        case .ort: return .low
        }
    }
}

/// Konfigurierbare Pseudonymisierungs-Regeln.
public struct PseudonymizationPolicy: Codable, Sendable, Equatable {
    /// Standard AUS (Opt-in wie jede Expositions-Entscheidung).
    public var enabled: Bool
    /// Kategorien, die nicht ersetzt werden (== Modus off).
    public var disabledCategories: [String]?
    /// Preset: "minimal" (nur mail/tel/iban) · "standard" (alles, Default) ·
    /// "streng" (zusaetzlich ALLE grossgeschriebenen Namens-Ketten — Privatsphaere
    /// vor Praezision; der Dichte-Waechter meldet die Kosten).
    public var profile: String?
    /// Feinsteuerung pro Kategorie: "off" | "token" | "alias" (alias nur fuer person;
    /// andere Kategorien behandeln alias wie token). Ueberschreibt das Profil.
    public var categoryModes: [String: String]?
    /// Nie ersetzen (exakter Wert, case-insensitiv) — z. B. "Amtsgericht Koeln".
    public var allowlist: [String]?
    /// Immer ersetzen, auch ohne Heuristik-Treffer — Codenamen, Mandate.
    public var denylist: [String]?
    /// Die in der Anfrage selbst genannte Person bleibt Klartext (Default an).
    public var keepQueriedEntity: Bool?
    /// Dichte-Schwelle: Anteil Token pro Inhaltswort, ab dem ein Treffer als
    /// semantisch entkernt gilt (Default 0.35).
    public var maxTokenDensity: Double?
    /// Reaktion auf zu dichte Treffer:
    /// "warn" (nur Befund, Default) · "trim" · "abstain" (blockt).
    public var onDensityExceeded: String?

    public init(enabled: Bool = false, disabledCategories: [String]? = nil,
                profile: String? = nil, categoryModes: [String: String]? = nil,
                allowlist: [String]? = nil, denylist: [String]? = nil,
                keepQueriedEntity: Bool? = nil, maxTokenDensity: Double? = nil,
                onDensityExceeded: String? = nil) {
        self.enabled = enabled
        self.disabledCategories = disabledCategories
        self.profile = profile
        self.categoryModes = categoryModes
        self.allowlist = allowlist
        self.denylist = denylist
        self.keepQueriedEntity = keepQueriedEntity
        self.maxTokenDensity = maxTokenDensity
        self.onDensityExceeded = onDensityExceeded
    }

    public static let standard = PseudonymizationPolicy()
    /// Im Gateway sinnvolle Voreinstellung: an, Standardprofil.
    public static let gatewayDefault = PseudonymizationPolicy(enabled: true, profile: "standard")

    // MARK: Aufloesung

    public enum Mode: String, Sendable { case off, token, alias }
    public enum DensityAction: String, Sendable { case warn, trim, abstain }

    /// Wirksamer Modus einer Kategorie: explizite Feinsteuerung > disabled >
    /// Denylist-Sonderfall > Profil.
    public func mode(for category: PseudonymCategory) -> Mode {
        if let raw = categoryModes?[category.rawValue], let m = Mode(rawValue: raw) { return m }
        if let disabled = disabledCategories,
           disabled.contains(where: { $0.lowercased() == category.rawValue }) { return .off }
        // Denylist-Begriffe sind EXPLIZITER Nutzerwille — sie greifen in jedem Profil.
        if category == .custom { return .token }
        switch profile?.lowercased() {
        case "minimal":
            return [.mail, .tel, .iban].contains(category) ? .token : .off
        default:
            return .token   // "standard", "streng", nil — alles ersetzen
        }
    }

    /// "streng": zusaetzlich generische Namens-Ketten ohne Lexikon/Anrede erkennen.
    public var strictNameChains: Bool { profile?.lowercased() == "streng" }

    public var effectiveKeepQueriedEntity: Bool { keepQueriedEntity ?? true }
    public var effectiveMaxDensity: Double { maxTokenDensity ?? 0.35 }
    public var densityAction: DensityAction {
        DensityAction(rawValue: onDensityExceeded?.lowercased() ?? "") ?? .warn
    }
}
