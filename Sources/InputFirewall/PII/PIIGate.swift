// Copyright (c) 2026 Tommy Stellmacher
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

import Foundation
import GatewayCore

// MARK: - PII-Stufe der Input Firewall
//
// Das Gateway ist eine KLAMMER, kein Durchgangsknoten: auf dem Hinweg werden
// Klardaten maskiert, auf dem Rueckweg wieder eingesetzt. Der Provider sieht
// durchgehend nur Platzhalter; der Nutzer sieht durchgehend seine echten Daten.
//
// Reihenfolge im Pfad: NACH dem Injection-Scan, VOR der Cache-Schluessel-Bildung.
// Das ist kein Detail — der Cache-Schluessel darf keine Klardaten enthalten, und
// nach der Maskierung werden Anfragen, die sich nur in Namen unterscheiden,
// identisch. Datenschutz und Trefferquote ziehen hier in dieselbe Richtung.

/// Die Rueckuebersetzung EINER Anfrage.
///
/// Bewusst anfragegebunden statt aus dem Vault gelesen: die Antwort wird mit
/// exakt der Zuordnung zurueckuebersetzt, die den Prompt maskiert hat — auch
/// wenn der Vault sich nebenlaeufig weiterentwickelt. Das macht den Rueckweg
/// unabhaengig vom globalen Zustand und mehrmandantensicher.
public struct MaskingSession: Sendable, Codable, Equatable {
    /// Ersatzform (Token ODER Alias) -> Klarwert.
    public let mapping: [String: String]

    public init(mapping: [String: String]) { self.mapping = mapping }

    public static let empty = MaskingSession(mapping: [:])

    public var isEmpty: Bool { mapping.isEmpty }

    /// Setzt Klardaten in einer Modell-Antwort wieder ein.
    ///
    /// Laengste Ersatzform zuerst — sonst zerlegt eine kuerzere Form eine
    /// laengere (relevant bei Alias-Namen, die einander praefixen koennen).
    public func unmask(_ text: String) -> String {
        guard !mapping.isEmpty, !text.isEmpty else { return text }
        var out = text
        for key in mapping.keys.sorted(by: { $0.count > $1.count }) {
            guard let value = mapping[key] else { continue }
            out = out.replacingOccurrences(of: key, with: value)
        }
        return out
    }
}

/// Ergebnis des Hinwegs: was weitergereicht wird und wie es zurueckuebersetzt wird.
public struct PIIOutcome: Sendable {
    public let scan: ScanResult
    public let session: MaskingSession
    /// Anteil Tokens an den Inhaltswoertern nach der Maskierung.
    public let density: Double

    /// Der maskierte Inhalt — das, was den Provider erreichen darf.
    public var maskedContent: String { scan.content }
}

public actor PIIGate: ContentScanner {

    /// Befund-ID des Dichte-Waechters.
    public static let ruleDensityExceeded: RuleID = "PII-900"

    public nonisolated let stageName = "pii"

    private let pseudonymizer: Pseudonymizer

    public init(pseudonymizer: Pseudonymizer) {
        self.pseudonymizer = pseudonymizer
    }

    /// Bequemer Weg: baut Vault und Gate aus einer Policy.
    /// `baseDirectory == nil` -> reiner In-Memory-Betrieb (zustandslose Knoten).
    public init(policy: PseudonymizationPolicy, baseDirectory: URL?, partition: String = "default") {
        let url = baseDirectory.map { PseudonymVault.url(baseDirectory: $0, partition: partition) }
        self.pseudonymizer = Pseudonymizer(vault: PseudonymVault(fileURL: url), policy: policy)
    }

    // MARK: - Hinweg

    /// Maskiert und liefert die Rueckuebersetzung mit. **Das ist der Weg fuer den
    /// Anfragepfad** — `scan(_:trust:)` verwirft die Session und taugt nur, wo
    /// keine Antwort zurueckkommt.
    ///
    /// - Parameter sparingQuery: die Nutzerfrage. Wer darin selbst genannt ist,
    ///   bleibt Klartext (der Empfaenger kennt den Namen ohnehin) — maskiert wird
    ///   die Masse der anderen. Voller Qualitaetsgewinn ohne echten Mehr-Leak.
    public func mask(_ content: String, sparingQuery: String? = nil) async -> PIIOutcome {
        let policy = pseudonymizer.policy
        guard policy.enabled else {
            return PIIOutcome(scan: .clean(content), session: .empty, density: 0)
        }

        let outcome = await pseudonymizer.mask(content, sparingQuery: sparingQuery)
        var findings: [Finding] = []
        var raw = 0.0

        // Ein PII-Treffer ist KEIN Verstoss — er wird behoben, indem maskiert wird.
        // Deshalb Gewicht 0: der Befund steht im Audit, blockt aber nicht. Wer auf
        // PII blocken will, setzt eine eigene Regel in der Policy.
        for (category, count) in outcome.counts.sorted(by: { $0.key.rawValue < $1.key.rawValue }) {
            findings.append(Finding(
                ruleID: category.ruleID,
                category: .pii,
                severity: category.severity,
                weight: 0,
                message: "pii: masked \(category.rawValue)",
                occurrences: count))
        }

        // Dichte-Waechter: zu stark entkernter Text liefert schlechte Antworten.
        // Nur `abstain` blockt — warn/trim bleiben sichtbar, aber folgenlos.
        if outcome.density > policy.effectiveMaxDensity {
            let blocks = policy.densityAction == .abstain
            if blocks { raw += 1.0 }
            findings.append(Finding(
                ruleID: Self.ruleDensityExceeded,
                category: .pii,
                severity: blocks ? .high : .low,
                weight: blocks ? 1.0 : 0,
                message: "pii: token density \(String(format: "%.2f", outcome.density)) exceeds limit (action: \(policy.densityAction.rawValue))",
                occurrences: 1))
        }

        let scan = ScanResult(
            findings: findings,
            content: outcome.content,
            rawScore: raw,
            // Provenienz gewichtet PII NICHT: eine IBAN ist in eigenen Notizen so
            // schutzbeduerftig wie in fremder Post. Der Multiplikator bleibt neutral.
            trustMultiplier: 1.0,
            wasModified: outcome.content != content)

        return PIIOutcome(scan: scan, session: MaskingSession(mapping: outcome.mapping),
                          density: outcome.density)
    }

    // MARK: - ContentScanner

    /// Konformitaet fuer die generische Pipeline. **Verwirft die Session** —
    /// im Anfragepfad `mask(_:sparingQuery:)` verwenden, sonst laesst sich die
    /// Antwort nicht mehr zurueckuebersetzen.
    public func scan(_ content: String, trust: SourceTrust) async -> ScanResult {
        await mask(content).scan
    }

    // MARK: - Betrieb

    /// Rueckuebersetzung aus dem Vault-Wissen (CLI/Report). Fuer den Antwortpfad
    /// ist `MaskingSession.unmask` vorzuziehen.
    public func restore(_ text: String) async -> String {
        await pseudonymizer.restore(text)
    }

    public func mappings() async -> [(token: String, value: String, category: String)] {
        await pseudonymizer.mappings()
    }
}
