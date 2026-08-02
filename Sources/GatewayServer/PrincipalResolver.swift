// Copyright (c) 2026 Tommy Stellmacher
// SPDX-License-Identifier: Apache-2.0

import Foundation
import GatewayCore

// MARK: - Woher die Identitaet kommt
//
// Bis hierher hat das Gateway `x-gateway-subject`, `-tenant` und `-scopes`
// ungeprueft uebernommen. Das war solange folgenlos, wie der `Principal` nur
// im Audit landete — mit dem Semantic Cache wird er zur ZUGRIFFSGRENZE:
// `Principal.cachePartition` entsteht aus Mandant und Scopes, also haette ein
// Aufrufer seine Cache-Partition frei gewaehlt und damit fremde Antworten
// abgeholt. Genau der Bypass, gegen den partitioniert wird.
//
// Deshalb diese Naht, und deshalb ihr Default: **eine unbelegte Behauptung
// wird nicht geglaubt.** Ohne konfigurierten Resolver werden die Header
// IGNORIERT (nicht etwa geglaubt), und alles laeuft unter `Principal.anonymous`
// in einer einzigen Partition. Das ist der Einzelnutzer-Betrieb hinter
// Loopback — sicher, weil niemand eine Identitaet behaupten kann.
//
// Wer Mandanten trennen will, konfiguriert einen Resolver. Der mitgelieferte
// `SharedSecretPrincipalResolver` deckt den Fall ab, den DECISIONS als
// Vorbedingung nennt: ein Transportweg, den nur die Identity-Stufe erreicht.
// Wer signierte Token pruefen will, implementiert das Protokoll mit einer
// echten Krypto-Bibliothek — hier wird bewusst keine gebaut.

/// Ergebnis der Identitaetsfeststellung.
public enum PrincipalResolution: Sendable, Equatable {
    /// Identitaet festgestellt und belegt.
    case identified(Principal)
    /// Keine Identitaet behauptet — Einzelnutzer-Betrieb.
    case anonymous
    /// Identitaet behauptet, aber nicht belegt. Fuehrt zu 401.
    case rejected(String)
}

public protocol PrincipalResolver: Sendable {
    func resolve(_ request: HTTPRequest) -> PrincipalResolution
}

// MARK: - Default: Behauptungen werden ignoriert

/// Ignoriert jede Identitaets-Behauptung und liefert immer `.anonymous`.
///
/// Der sichere Default. Wichtig ist, was er NICHT tut: er weist nicht ab,
/// sondern uebergeht. Ein Aufrufer kann damit keine Partition waehlen — es
/// gibt nur eine.
public struct AnonymousPrincipalResolver: PrincipalResolver {
    public init() {}
    public func resolve(_ request: HTTPRequest) -> PrincipalResolution { .anonymous }
}

// MARK: - Gemeinsames Geheimnis

/// Glaubt die Identitaets-Header nur, wenn die Anfrage ein vereinbartes
/// Geheimnis mitbringt.
///
/// Gedacht fuer den Aufbau aus DECISIONS: die Identity-Stufe sitzt davor und
/// ist die einzige Instanz, die das Geheimnis kennt. Das Gateway prueft damit
/// nicht die Identitaet selbst — es prueft, dass die Behauptung von der Stufe
/// stammt, die sie pruefen durfte.
///
/// Bewusste Grenze: ein statisches Geheimnis ist kein Token-Format. Es kann
/// nicht ablaufen und bindet nicht an die konkrete Anfrage. Wer das braucht,
/// implementiert `PrincipalResolver` mit signierten Token.
public struct SharedSecretPrincipalResolver: PrincipalResolver {

    /// Header, in dem das Geheimnis erwartet wird.
    public static let secretHeader = "x-gateway-auth"

    private let secret: String
    /// Duerfen Anfragen ohne jede Behauptung als anonym durchlaufen?
    private let allowAnonymous: Bool

    /// - Parameters:
    ///   - secret: das vereinbarte Geheimnis. Leer ist nicht erlaubt — sonst
    ///     wuerde jede Anfrage ohne Header als belegt gelten.
    ///   - allowAnonymous: `true` (Default) laesst Anfragen ohne Identitaets-
    ///     Header als `.anonymous` durch; `false` verlangt fuer JEDE Anfrage
    ///     ein gueltiges Geheimnis.
    public init?(secret: String, allowAnonymous: Bool = true) {
        guard !secret.isEmpty else { return nil }
        self.secret = secret
        self.allowAnonymous = allowAnonymous
    }

    public func resolve(_ request: HTTPRequest) -> PrincipalResolution {
        let claimsIdentity = request.header(Self.subjectHeader) != nil
            || request.header(Self.tenantHeader) != nil
            || request.header(Self.scopesHeader) != nil

        let presented = request.header(Self.secretHeader)
        let authenticated = presented.map { Self.constantTimeEquals($0, secret) } ?? false

        guard authenticated else {
            // Eine Behauptung ohne Beleg ist ein Fehler, kein stiller Abstieg
            // auf anonym: sonst bekaeme ein Angreifer fuer denselben Aufruf
            // einmal die fremde und einmal die eigene Partition, je nachdem ob
            // er das Geheimnis errat. Abweisen macht das Scheitern sichtbar.
            if claimsIdentity { return .rejected("identity claimed without valid credential") }
            return allowAnonymous ? .anonymous : .rejected("missing credential")
        }
        guard claimsIdentity else { return .anonymous }

        return .identified(Principal(
            subject: request.header(Self.subjectHeader) ?? Principal.anonymous.subject,
            tenant: request.header(Self.tenantHeader),
            scopes: Self.scopes(from: request.header(Self.scopesHeader))))
    }

    // MARK: - Header-Namen

    public static let subjectHeader = "x-gateway-subject"
    public static let tenantHeader = "x-gateway-tenant"
    public static let scopesHeader = "x-gateway-scopes"

    static func scopes(from raw: String?) -> Set<String> {
        Set((raw ?? "")
            .split(separator: ",")
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty })
    }

    /// Vergleicht ueber die volle Laenge, ohne fruehen Abbruch.
    ///
    /// Kein Krypto-Eigenbau — ein Vergleich ist keine Primitive. Aber ein
    /// Abbruch beim ersten Unterschied verraet ueber die Laufzeit, wie viele
    /// Zeichen stimmen, und macht das Geheimnis Zeichen fuer Zeichen erratbar.
    static func constantTimeEquals(_ lhs: String, _ rhs: String) -> Bool {
        let a = Array(lhs.utf8)
        let b = Array(rhs.utf8)
        // Die Laenge selbst ist kein Geheimnis; sie fliesst trotzdem in das
        // Ergebnis ein, damit ein Praefix nicht als Treffer durchgeht.
        var difference = a.count ^ b.count
        for index in 0..<max(a.count, b.count) {
            let left = index < a.count ? Int(a[index]) : 0
            let right = index < b.count ? Int(b[index]) : 0
            difference |= left ^ right
        }
        return difference == 0
    }
}
