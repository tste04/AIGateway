// Copyright (c) 2026 Tommy Stellmacher
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

import Foundation
import GatewayCore

// MARK: - Rate-Guard
//
// Die dritte Aufgabe der Gateway-Box neben Firewall und Cache: verhindern, dass
// ein einzelner Aufrufer die Kosten oder die Verfuegbarkeit aller anderen
// bestimmt.
//
// **Er steht VOR der Pipeline, nicht darin.** Das ist der ganze Punkt: die
// Arbeit IST die Kosten. Ein Rate-Guard, der erst nach Injection-, PII- und
// DLP-Lauf greift, hat die Rechenzeit bereits ausgegeben, die er sparen
// sollte. Deshalb liegt er in `GatewayService` zwischen Identitaet und
// Firewall — frueher geht nicht, denn ohne festgestellte Identitaet gibt es
// niemanden zu deckeln.
//
// GESCHLUESSELT WIRD UEBER DAS SUBJECT, nicht ueber `cachePartition`. Die
// Partition ist absichtlich GETEILT: zwei Nutzer mit gleicher Berechtigung
// sollen sich Cache-Treffer teilen. Ein geteiltes Rate-Budget waere daraus die
// falsche Folgerung — dann hungerte ein Vielnutzer seine Kollegen aus, obwohl
// er ihnen nichts wegnimmt ausser dem Kontingent, das er selbst verbraucht.
//
// EHRLICH DAZUGESAGT: mit dem Default-`AnonymousPrincipalResolver` heisst jeder
// Aufrufer „anonymous". Der Guard ist dann eine Gesamtbremse fuer das Gateway,
// keine Pro-Aufrufer-Grenze — nuetzlich gegen Ausreisser, wertlos gegen einen
// gezielten Nachbarn. Wer pro Aufrufer deckeln will, braucht einen echten
// `PrincipalResolver`. Das ist dieselbe Vorbedingung wie beim Cache und kein
// Zufall: beide haengen daran, dass Identitaet BELEGT ist.

/// Betriebsparameter des Rate-Guards.
public struct RateLimitPolicy: Sendable, Equatable {
    /// Default AUS. Wie jede Grenze, die Anfragen abweisen kann, ein Opt-in —
    /// eine Bibliothek, die ungefragt drosselt, wird einmal eingebaut und
    /// danach ausgebaut.
    public var enabled: Bool
    /// Nachfuellrate: so viele Anfragen je `interval`.
    public var requestsPerInterval: Int
    public var interval: TimeInterval
    /// Wie viele Anfragen auf einmal zulaessig sind. Ein Eimer ohne Spielraum
    /// bestraft die normale Stossform echter Clients (eine Seite laedt, fuenf
    /// Anfragen gehen gleichzeitig raus).
    public var burst: Int
    /// Obergrenze der beobachteten Subjekte. Ohne sie waere die Buchhaltung
    /// ein Speicherleck mit fremdgesteuertem Schluessel: wer beliebige
    /// Subject-Namen erzeugen kann, laesst das Woerterbuch wachsen.
    public var maxTrackedSubjects: Int

    public init(enabled: Bool = false,
                requestsPerInterval: Int = 60,
                interval: TimeInterval = 60,
                burst: Int = 10,
                maxTrackedSubjects: Int = 10_000) {
        self.enabled = enabled
        self.requestsPerInterval = requestsPerInterval
        self.interval = interval
        self.burst = burst
        self.maxTrackedSubjects = maxTrackedSubjects
    }

    public static let standard = RateLimitPolicy()
    /// Eingeschaltet mit den Standardwerten.
    public static let on = RateLimitPolicy(enabled: true)

    /// Nachgefuellte Anfragen je Sekunde.
    var refillPerSecond: Double {
        guard interval > 0 else { return 0 }
        return Double(requestsPerInterval) / interval
    }
}

/// Was der Guard entscheidet.
public enum RateVerdict: Sendable, Equatable {
    case allowed
    /// Abgewiesen. `retryAfter` ist die Wartezeit bis zum naechsten Token —
    /// eine gerechnete Zahl, keine geratene Konstante, damit ein gutwilliger
    /// Client nicht blind pollt.
    case limited(retryAfter: TimeInterval)
}

/// Token-Eimer je Aufrufer.
public actor RateGuard {

    /// Ein Eimer. `tokens` ist fraktional, damit die Nachfuellung nicht auf
    /// ganze Anfragen rundet — sonst bekaeme ein knapp unter der Rate
    /// liegender Client nie wieder ein Token.
    private struct Bucket {
        var tokens: Double
        var updatedAt: Date
    }

    /// `nonisolated`, weil unveraenderlich — der Aufrufer liest `enabled`,
    /// ohne den Actor zu betreten.
    public nonisolated let policy: RateLimitPolicy
    private var buckets: [String: Bucket] = [:]

    public init(policy: RateLimitPolicy = .on) {
        self.policy = policy
    }

    public func count() -> Int { buckets.count }

    /// Schluessel eines Aufrufers. Mandant davor, weil zwei Mandanten
    /// dasselbe Subject vergeben duerfen.
    public static func key(for principal: Principal) -> String {
        "\(principal.tenant ?? "-")|\(principal.subject)"
    }

    /// Darf diese Anfrage laufen? Ein `.allowed` VERBRAUCHT ein Token —
    /// die Methode ist bewusst keine Abfrage, sondern die Buchung selbst.
    public func admit(_ principal: Principal, now: Date = Date()) -> RateVerdict {
        guard policy.enabled else { return .allowed }
        let id = Self.key(for: principal)
        let capacity = Double(max(policy.burst, 1))

        var bucket = buckets[id] ?? Bucket(tokens: capacity, updatedAt: now)
        // Nachfuellen fuer die verstrichene Zeit, gedeckelt auf die Kapazitaet.
        let elapsed = max(0, now.timeIntervalSince(bucket.updatedAt))
        bucket.tokens = min(capacity, bucket.tokens + elapsed * policy.refillPerSecond)
        bucket.updatedAt = now

        guard bucket.tokens >= 1 else {
            buckets[id] = bucket
            return .limited(retryAfter: retryAfter(missing: 1 - bucket.tokens))
        }

        // Neuer Aufrufer und die Buchhaltung ist voll: erst aufraeumen, und
        // wenn das nichts bringt, abweisen — siehe `makeRoom`.
        if buckets[id] == nil, buckets.count >= policy.maxTrackedSubjects, !makeRoom(capacity: capacity) {
            return .limited(retryAfter: policy.interval)
        }

        bucket.tokens -= 1
        buckets[id] = bucket
        return .allowed
    }

    /// Vergisst einen Aufrufer (Test- und Betriebshilfe).
    public func forget(_ principal: Principal) {
        buckets.removeValue(forKey: Self.key(for: principal))
    }

    public func removeAll() { buckets.removeAll() }

    /// Schafft Platz, ohne ein Schlupfloch zu oeffnen.
    ///
    /// Verdraengt wird ausschliesslich, was VOLL ist. Ein voller Eimer ist
    /// informationsgleich mit gar keinem Eimer — sein Besitzer hat sein
    /// Kontingent nicht angetastet, ihn zu vergessen aendert keine
    /// Entscheidung. Ein angebrochener Eimer dagegen IST das Gedaechtnis der
    /// Drosselung; wer ihn verdraengt, baut die Umgehung ein: genug fremde
    /// Subject-Namen erzeugen, bis der eigene Eimer hinausfliegt und voll
    /// zurueckkommt.
    ///
    /// Bleibt danach kein Platz, sind alle beobachteten Aufrufer gerade
    /// gedrosselt. Dann wird abgewiesen statt zugelassen: unter genau dieser
    /// Last ist Fail-closed die einzige Richtung, die noch schuetzt.
    private func makeRoom(capacity: Double) -> Bool {
        let full = buckets.filter { $0.value.tokens >= capacity }.map(\.key)
        guard !full.isEmpty else { return false }
        for key in full { buckets.removeValue(forKey: key) }
        return true
    }

    private func retryAfter(missing tokens: Double) -> TimeInterval {
        let rate = policy.refillPerSecond
        guard rate > 0 else { return policy.interval }
        // Aufgerundet auf ganze Sekunden: `Retry-After` traegt in HTTP keine
        // Bruchteile, und abrunden hiesse den Client in eine erneute Absage
        // zu schicken.
        return max(1, (tokens / rate).rounded(.up))
    }

    // MARK: - Stabile Regel-ID
    //
    // Reiht sich in die GW-Familie ein: das sind die Guards, die nicht auf
    // Inhalt schauen, sondern auf die Form der Anfrage. Aendern bricht
    // Suppressions und SIEM-Regeln.

    public static let ruleRateLimited: RuleID = "GW-004"

    /// Befund fuer die abgewiesene Anfrage. Gewicht 1.0 — der Guard bewertet
    /// kein Risiko, er hat entschieden. Der Befund existiert, damit die
    /// Absage denselben payload-freien Audit-Weg nimmt wie jede andere: eine
    /// Drosselung, die im Log fehlt, ist als Angriffsspur unsichtbar.
    public static func finding(retryAfter: TimeInterval) -> Finding {
        Finding(ruleID: ruleRateLimited, category: .anomaly, severity: .medium, weight: 1.0,
                message: "rate limit exceeded, retry after \(Int(retryAfter))s")
    }
}
