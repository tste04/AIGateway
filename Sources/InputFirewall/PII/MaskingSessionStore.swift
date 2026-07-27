// Copyright (c) 2026 Tommy Stellmacher
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

import Foundation

// MARK: - Die Klammer ueber laengere Vorgaenge
//
// `MaskingSession` traegt die Rueckuebersetzung EINER Anfrage. Im Proxy-Betrieb
// lebt sie auf dem Stapel: maskieren, Modell fragen, de-maskieren, fertig —
// Millisekunden.
//
// Im Zielbild liegen zwischen Maskierung und De-Maskierung aber Router,
// Context Orchestrator, n Iterationen Agent Loop, Output Guardrails und bei
// hohem Risiko eine MENSCHLICHE FREIGABE. Das sind Minuten bis Stunden. Eine
// lokale Variable traegt das nicht; ein selbstgebautes Dictionary traegt es
// auch nicht, weil ihm Frist, Deckel und Partitionsbindung fehlen.
//
// VIER FESTLEGUNGEN (docs/DECISIONS.md), die den Entwurf bestimmen:
//
// 1. **Nur im Speicher, niemals persistiert.** Die Zuordnung ist Klartext-PII.
//    Sie auf Platte zu schreiben machte ausgerechnet die Komponente, die PII
//    vom Provider fernhaelt, zu deren dauerhaftem Speicher — dasselbe
//    Argument, das `AuditEvent` payload-frei haelt. Diese Datei fasst deshalb
//    kein Dateisystem an, und das ist kein Versaeumnis.
// 2. **Verlust ist sichtbar, nicht still.** Fehlt die Zuordnung, liefert der
//    Speicher `nil`. Der Aufrufer nimmt dann `MaskingSession.empty`, und die
//    Antwort geht MIT Platzhaltern hinaus. Nicht raten, und nicht ersatzweise
//    aus dem globalen Vault aufloesen — das waere der mehrmandantenunsichere
//    Rueckweg, den `MaskingSession` gerade vermeidet. Der Nutzer sieht
//    `[Person-1]` und meldet es.
// 3. **Der Zugriff ist an die Partition gebunden**, nicht nur an die
//    `correlationID`. Eine UUID zu raten ist unwahrscheinlich; die Bindung
//    kostet nichts und schliesst die Klasse aus.
// 4. **Zwei Fristen.** Der Default ist kurz und deckt den Auto-Execute-Pfad.
//    Wer in die menschliche Freigabe geht, verlaengert ausdruecklich. Eine
//    einzige Frist, die beides abdeckt, hielte Klardaten stundenlang fuer JEDE
//    Anfrage vor.

public struct MaskingSessionPolicy: Sendable, Equatable {
    /// Regelfall: der Vorgang laeuft durch, niemand wartet auf einen Menschen.
    public var timeToLive: TimeInterval
    /// Nach ausdruecklicher Verlaengerung — der Freigabe-Pfad.
    public var extendedTimeToLive: TimeInterval
    /// Obergrenze. Wird sie erreicht, laeuft etwas falsch: im Normalbetrieb
    /// gibt der Antwortpfad jede Zuordnung wieder frei, lange bevor die Frist
    /// greift. Der Deckel ist der Schutz davor, dass ein vergessenes
    /// `close` zum Speicherleck mit Klardaten wird.
    public var maxSessions: Int

    public init(timeToLive: TimeInterval = 900,
                extendedTimeToLive: TimeInterval = 4 * 3600,
                maxSessions: Int = 10_000) {
        self.timeToLive = timeToLive
        self.extendedTimeToLive = extendedTimeToLive
        self.maxSessions = maxSessions
    }

    public static let standard = MaskingSessionPolicy()
}

public actor MaskingSessionStore {

    private struct Entry {
        let session: MaskingSession
        let partition: String
        var expiresAt: Date
    }

    public nonisolated let policy: MaskingSessionPolicy
    private var entries: [String: Entry] = [:]

    public init(policy: MaskingSessionPolicy = .standard) {
        self.policy = policy
    }

    public func count() -> Int { entries.count }

    // MARK: Ablegen

    /// Parkt die Zuordnung einer Anfrage.
    ///
    /// Eine leere Zuordnung wird nicht abgelegt: es gibt nichts
    /// zurueckzuuebersetzen, und `MaskingSession.empty` ist ohnehin die
    /// Identitaet. Das haelt den Speicher frei von Eintraegen ohne Zweck.
    public func park(_ session: MaskingSession,
                     correlationID: String,
                     partition: String,
                     now: Date = Date()) {
        guard !session.isEmpty else { return }
        expire(now: now)
        entries[correlationID] = Entry(session: session, partition: partition,
                                       expiresAt: now.addingTimeInterval(policy.timeToLive))
        evictIfNeeded()
    }

    // MARK: Holen

    /// Liefert die Zuordnung, oder `nil`.
    ///
    /// Nicht verbrauchend: ein Antwortstrom braucht sie ueber seine ganze
    /// Laufzeit. Freigegeben wird ausdruecklich mit `close`.
    ///
    /// `nil` bedeutet immer dasselbe — unbekannt, abgelaufen oder fremde
    /// Partition. Die Faelle werden bewusst nicht unterschieden: ein Aufrufer
    /// soll aus der Antwort nicht ablesen koennen, ob es eine `correlationID`
    /// gibt, die ihm nicht gehoert.
    public func session(correlationID: String,
                        partition: String,
                        now: Date = Date()) -> MaskingSession? {
        guard let entry = entries[correlationID],
              entry.partition == partition,
              entry.expiresAt > now else { return nil }
        return entry.session
    }

    /// Verlaengert auf die lange Frist — der Vorgang geht in die menschliche
    /// Freigabe. Liefert `false`, wenn nichts (mehr) zu verlaengern war.
    ///
    /// Ausdruecklich und nicht automatisch: wer Klardaten stundenlang vorhalten
    /// laesst, soll das an einer Stelle im Code tun, die man findet.
    @discardableResult
    public func extend(correlationID: String,
                       partition: String,
                       now: Date = Date()) -> Bool {
        guard let entry = entries[correlationID],
              entry.partition == partition,
              entry.expiresAt > now else { return false }
        entries[correlationID]?.expiresAt = now.addingTimeInterval(policy.extendedTimeToLive)
        return true
    }

    /// Gibt die Zuordnung frei. Der Regelweg, sobald die Antwort draussen ist —
    /// die Frist ist der Notnagel, nicht der Plan.
    public func close(correlationID: String, partition: String) {
        guard let entry = entries[correlationID], entry.partition == partition else { return }
        entries.removeValue(forKey: correlationID)
    }

    public func removeAll() { entries.removeAll() }

    // MARK: Fristen und Deckel

    private func expire(now: Date) {
        entries = entries.filter { $0.value.expiresAt > now }
    }

    /// Verdraengt die Eintraege, deren Frist am naechsten liegt.
    ///
    /// Verdraengung ist hier schmerzhafter als beim Cache: ein verlorener
    /// Eintrag heisst Platzhalter beim Nutzer. Sie bleibt trotzdem richtig —
    /// unbegrenztes Wachstum mit Klardaten waere schlimmer als eine sichtbar
    /// unvollstaendige Antwort.
    private func evictIfNeeded() {
        guard policy.maxSessions > 0 else { entries.removeAll(); return }
        while entries.count > policy.maxSessions {
            guard let soonest = entries.min(by: { $0.value.expiresAt < $1.value.expiresAt })?.key
            else { return }
            entries.removeValue(forKey: soonest)
        }
    }
}
