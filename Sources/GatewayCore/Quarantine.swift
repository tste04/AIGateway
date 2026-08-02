// Copyright (c) 2026 Tommy Stellmacher
// SPDX-License-Identifier: Apache-2.0

import Foundation

// MARK: - Quarantaene fuer den Feedback Loop
//
// Der Zielkonflikt, der diese Naht erzwingt: Der Feedback Loop tunt Router und
// Guardrails mit BEISPIELEN, also mit Text. `AuditEvent` enthaelt per
// Invariante niemals Nutzinhalt. Beides ist richtig, und beides zusammen heisst:
// **der Feedback Loop kann nicht aus dem Audit-Log gespeist werden.**
//
// Ohne eine ausdrueckliche Festlegung endet das damit, dass jemand Prompts ins
// Audit schreibt und die Invariante bricht. Deshalb ein GETRENNTER Pfad, mit
// eigenem Schalter, eigener Stufe und eigener Frist — und mit Default AUS, wie
// jede Expositions-Entscheidung in diesem Projekt.
//
// Was hier landet, ist kein Log. Es ist ein befristeter Beweismittelschrank.

/// Wieviel von einem Vorfall aufbewahrt wird.
public enum QuarantineDetail: String, Sendable, Codable, CaseIterable, Comparable {
    /// Nur Regel-IDs, Kategorien und Zahlen. Kein Text. Der sichere Default,
    /// wenn die Quarantaene ueberhaupt eingeschaltet wird.
    case counts
    /// PII-maskierter Text. **Die Arbeitsstufe.**
    ///
    /// Das ist keine Notloesung: Injection-Muster sind STRUKTURELL, nicht
    /// namensabhaengig. „ignore all previous instructions", Homoglyphen und
    /// Buchstaben-Sperrung ueberstehen die Maskierung unbeschadet — man kann
    /// den Injection-Katalog daran vollstaendig nachschaerfen.
    case masked
    /// Rohtext. Nur mit ausdruecklicher Betreiber-Entscheidung, und praktisch
    /// nur noetig, wenn die PII-REGELN SELBST getunt werden sollen.
    case raw

    private var rank: Int {
        switch self {
        case .counts: return 0
        case .masked: return 1
        case .raw: return 2
        }
    }

    public static func < (lhs: QuarantineDetail, rhs: QuarantineDetail) -> Bool {
        lhs.rank < rhs.rank
    }
}

public struct QuarantinePolicy: Sendable, Equatable {
    /// Default AUS.
    public var enabled: Bool
    /// Hoechste Stufe, die abgelegt werden darf. Was tatsaechlich abgelegt
    /// wurde, steht in `QuarantineSample.detail` — die beiden koennen
    /// abweichen, wenn die hoehere Stufe nicht erreichbar war.
    public var detail: QuarantineDetail
    /// Harte Aufbewahrungsfrist. Ein Beweismittelschrank ohne Frist ist ein
    /// Archiv, und ein Archiv voller Prompts ist genau das, was die
    /// Audit-Invariante verhindern soll.
    public var retention: TimeInterval
    /// Breite des Fensters UNTERHALB der Blockschwelle, aus dem zusaetzlich
    /// aufbewahrt wird.
    ///
    /// Die wertvollsten Beispiele liegen nicht bei den klaren Blocks, sondern
    /// knapp darunter: dort sitzen die Fehlalarme, gegen die man Schwellen
    /// senkt, und die knapp durchgerutschten Angriffe, gegen die man Regeln
    /// ergaenzt. Ein Wert von 0 schaltet das Fenster ab.
    public var nearMissBand: Double

    public init(enabled: Bool = false,
                detail: QuarantineDetail = .counts,
                retention: TimeInterval = 7 * 24 * 3600,
                nearMissBand: Double = 0.15) {
        self.enabled = enabled
        self.detail = detail
        self.retention = retention
        self.nearMissBand = nearMissBand
    }

    public static let standard = QuarantinePolicy()
    /// Eingeschaltet auf der Arbeitsstufe.
    public static let masked = QuarantinePolicy(enabled: true, detail: .masked)

    /// Gehoert dieser Vorfall in die Quarantaene?
    ///
    /// Blocks immer; darunter alles im Fenster. Bewusst OHNE Zufall: eine
    /// zufaellig ziehende Stichprobe machte Vorfaelle unreproduzierbar und
    /// brachte eine Nichtdeterminismus-Quelle in eine Sicherheitskomponente.
    /// Das Fenster IST die Auswahl.
    public func collects(disposition: Disposition,
                         riskScore: Double,
                         blockThreshold: Double) -> Bool {
        guard enabled else { return false }
        if disposition == .block { return true }
        guard nearMissBand > 0 else { return false }
        return riskScore >= blockThreshold - nearMissBand
    }
}

/// Ein aufbewahrter Vorfall.
public struct QuarantineSample: Sendable, Codable, Equatable {
    public let correlationID: String
    public let timestamp: Date
    public let subject: String
    public let tenant: String?
    public let model: String?

    public let disposition: Disposition
    public let riskScore: Double
    public let ruleIDs: [RuleID]
    public let categories: [FindingCategory]

    /// Was TATSAECHLICH aufbewahrt wurde — nicht, was die Policy erlaubt haette.
    public let detail: QuarantineDetail
    /// Der aufbewahrte Text. `nil` auf Stufe `counts`.
    public let content: String?
    /// Ab hier ist der Eintrag zu loeschen.
    public let expiresAt: Date

    public init(correlationID: String,
                timestamp: Date,
                principal: Principal,
                model: String?,
                disposition: Disposition,
                riskScore: Double,
                ruleIDs: [RuleID],
                categories: [FindingCategory],
                detail: QuarantineDetail,
                content: String?,
                expiresAt: Date) {
        self.correlationID = correlationID
        self.timestamp = timestamp
        self.subject = principal.subject
        self.tenant = principal.tenant
        self.model = model
        self.disposition = disposition
        self.riskScore = riskScore
        self.ruleIDs = ruleIDs
        self.categories = categories
        self.detail = detail
        self.content = content
        self.expiresAt = expiresAt
    }
}

/// Wohin Vorfaelle gehen. Die Implementierung ist Betreibersache — sie
/// entscheidet ueber Ablageort und Zugriffsschutz, und sie MUSS
/// `expiresAt` durchsetzen.
public protocol QuarantineSink: Sendable {
    func store(_ sample: QuarantineSample) async
}

/// Senke und Regeln zusammen. Ohne beides passiert nichts.
public struct Quarantine: Sendable {
    public let sink: QuarantineSink
    public let policy: QuarantinePolicy

    public init(sink: QuarantineSink, policy: QuarantinePolicy = .masked) {
        self.sink = sink
        self.policy = policy
    }
}

// MARK: - Referenz-Implementierung

/// Haelt Vorfaelle im Speicher und setzt die Frist tatsaechlich durch.
///
/// Gedacht als Ausgangspunkt und als Beleg, dass die Frist keine Empfehlung
/// ist. Wer die Beispiele ueber einen Neustart hinaus braucht, schreibt eine
/// eigene Senke — und trifft damit ausdruecklich die Entscheidung, Nutzinhalt
/// dauerhaft abzulegen.
public actor MemoryQuarantineSink: QuarantineSink {

    private var stored: [QuarantineSample] = []
    private let maxSamples: Int

    public init(maxSamples: Int = 1000) {
        self.maxSamples = maxSamples
    }

    public func store(_ sample: QuarantineSample) async {
        sweep(now: sample.timestamp)
        stored.append(sample)
        if stored.count > maxSamples {
            stored.removeFirst(stored.count - maxSamples)
        }
    }

    /// Die noch gueltigen Vorfaelle. Abgelaufene werden dabei entfernt — ein
    /// Leser bekommt nie etwas zu sehen, das laengst haette geloescht sein
    /// muessen.
    public func samples(now: Date = Date()) -> [QuarantineSample] {
        sweep(now: now)
        return stored
    }

    public func removeAll() { stored.removeAll() }

    private func sweep(now: Date) {
        stored.removeAll { $0.expiresAt <= now }
    }
}
