// Copyright (c) 2026 Tommy Stellmacher
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

import Foundation

// MARK: - Aufrufer-Identitaet
//
// Kommt aus der Identity/SSO-Stufe und wird durch die gesamte Pipeline
// gereicht. Traegt drei Aufgaben: Audit-Zuordnung, Policy-Eingang und —
// sicherheitskritisch — die Partitionierung des Semantic Cache.

/// Authentifizierter Aufrufer.
public struct Principal: Sendable, Codable, Equatable {
    /// Subject aus dem Identity-Token (z. B. OIDC `sub`).
    public let subject: String
    /// Mandant. `nil` = Einzelmandant-Betrieb.
    public let tenant: String?
    /// Autorisierungs-Scopes, die den Datenzugriff begrenzen.
    public let scopes: Set<String>

    public init(subject: String, tenant: String? = nil, scopes: Set<String> = []) {
        self.subject = subject
        self.tenant = tenant
        self.scopes = scopes
    }

    /// Partitionsschluessel fuer den Semantic Cache.
    ///
    /// ACHTUNG — hier entscheidet sich, ob der Cache ein Kostenhebel oder ein
    /// Datenleck ist. Ein Cache, der nur ueber den Prompt schluesselt, spielt
    /// die Antwort eines berechtigten Nutzers an einen unberechtigten aus.
    ///
    /// Geschluesselt wird ueber Mandant + SCOPES, bewusst NICHT ueber `subject`:
    /// zwei Nutzer mit identischer Berechtigung duerfen dieselben Daten sehen,
    /// also duerfen sie sich Treffer teilen. Das haelt die Trefferquote hoch,
    /// ohne die Zugriffsgrenze zu verletzen. Pro-Nutzer-Schluesselung waere
    /// sicher, aber wirtschaftlich wertlos.
    ///
    /// Der Wert ist ein kanonischer Klartext-Schluessel, kein Hash — Hashing
    /// (falls Opazitaet gewuenscht) gehoert in die Speicherschicht, nicht hierhin.
    public var cachePartition: String {
        let scopePart = scopes.sorted().joined(separator: ",")
        return "\(tenant ?? "-")|\(scopePart)"
    }

    /// Technischer Aufrufer ohne Identity-Kontext (lokale Werkzeuge, Tests).
    public static let anonymous = Principal(subject: "anonymous")
}
