// Copyright (c) 2026 Tommy Stellmacher
// SPDX-License-Identifier: Apache-2.0

import XCTest
import GatewayCore
@testable import InputFirewall

// MARK: - Die Klammer ueber laengere Vorgaenge
//
// Geprueft wird vor allem, was NICHT passiert: keine fremde Partition, kein
// Raten bei fehlender Zuordnung, kein unbegrenztes Wachstum.

final class MaskingSessionStoreTests: XCTestCase {

    private let session = MaskingSession(mapping: ["[Person-1]": "Anna Schmidt"])
    private let t0 = Date(timeIntervalSince1970: 1_000_000)

    private func store(_ policy: MaskingSessionPolicy = .standard) -> MaskingSessionStore {
        MaskingSessionStore(policy: policy)
    }

    // MARK: Ablegen und Holen

    func testParkedSessionComesBackAndUnmasks() async {
        let store = store()
        await store.park(session, correlationID: "c1", partition: "acme|", now: t0)

        let found = await store.session(correlationID: "c1", partition: "acme|", now: t0)
        XCTAssertEqual(found?.unmask("Notiert fuer [Person-1]."), "Notiert fuer Anna Schmidt.")
    }

    func testUnknownCorrelationIDYieldsNothing() async {
        let store = store()
        await store.park(session, correlationID: "c1", partition: "acme|", now: t0)
        let found = await store.session(correlationID: "c2", partition: "acme|", now: t0)
        XCTAssertNil(found)
    }

    func testForeignPartitionCannotFetchTheSession() async {
        // Die tragende Zusicherung: die correlationID allein oeffnet nichts.
        let store = store()
        await store.park(session, correlationID: "c1", partition: "acme|", now: t0)
        let found = await store.session(correlationID: "c1", partition: "fremd-ag|", now: t0)
        XCTAssertNil(found)
    }

    func testEmptySessionIsNotParked() async {
        let store = store()
        await store.park(.empty, correlationID: "c1", partition: "acme|", now: t0)
        let count = await store.count()
        XCTAssertEqual(count, 0, "eine leere Zuordnung hat nichts zurueckzuuebersetzen")
    }

    // MARK: Verlust ist sichtbar

    func testMissingSessionLeavesPlaceholdersStanding() async {
        // Was der Aufrufer tun soll, wenn nichts (mehr) da ist: `.empty`
        // nehmen. Die Antwort geht mit Platzhaltern hinaus — sichtbar falsch
        // statt still falsch aufgeloest.
        let store = store()
        let missing = await store.session(correlationID: "weg", partition: "acme|", now: t0)
        XCTAssertNil(missing)

        let fallback = missing ?? .empty
        XCTAssertEqual(fallback.unmask("Notiert fuer [Person-1]."), "Notiert fuer [Person-1].")
    }

    // MARK: Zwei Fristen

    func testSessionExpiresAfterTheShortDeadline() async {
        let store = store(MaskingSessionPolicy(timeToLive: 900))
        await store.park(session, correlationID: "c1", partition: "acme|", now: t0)

        let inTime = await store.session(correlationID: "c1", partition: "acme|",
                                         now: t0.addingTimeInterval(899))
        XCTAssertNotNil(inTime)
        let late = await store.session(correlationID: "c1", partition: "acme|",
                                       now: t0.addingTimeInterval(901))
        XCTAssertNil(late)
    }

    func testExtendingMovesTheDeadlineToTheLongOne() async {
        // Der Freigabe-Pfad: der Vorgang wartet auf einen Menschen.
        let store = store(MaskingSessionPolicy(timeToLive: 900, extendedTimeToLive: 4 * 3600))
        await store.park(session, correlationID: "c1", partition: "acme|", now: t0)

        let extended = await store.extend(correlationID: "c1", partition: "acme|", now: t0)
        XCTAssertTrue(extended)

        // Weit hinter der kurzen Frist, aber innerhalb der langen.
        let found = await store.session(correlationID: "c1", partition: "acme|",
                                        now: t0.addingTimeInterval(3600))
        XCTAssertNotNil(found)
        let tooLate = await store.session(correlationID: "c1", partition: "acme|",
                                          now: t0.addingTimeInterval(4 * 3600 + 1))
        XCTAssertNil(tooLate)
    }

    func testExtendingRefusesForeignPartitionAndUnknownID() async {
        let store = store()
        await store.park(session, correlationID: "c1", partition: "acme|", now: t0)

        let foreign = await store.extend(correlationID: "c1", partition: "fremd-ag|", now: t0)
        let unknown = await store.extend(correlationID: "c2", partition: "acme|", now: t0)
        XCTAssertFalse(foreign)
        XCTAssertFalse(unknown)
    }

    func testExtendingAnExpiredSessionFails() async {
        let store = store(MaskingSessionPolicy(timeToLive: 60))
        await store.park(session, correlationID: "c1", partition: "acme|", now: t0)
        let revived = await store.extend(correlationID: "c1", partition: "acme|",
                                         now: t0.addingTimeInterval(120))
        XCTAssertFalse(revived, "eine abgelaufene Zuordnung darf nicht wiederbelebt werden")
    }

    // MARK: Freigeben

    func testCloseRemovesTheSession() async {
        let store = store()
        await store.park(session, correlationID: "c1", partition: "acme|", now: t0)
        await store.close(correlationID: "c1", partition: "acme|")

        let found = await store.session(correlationID: "c1", partition: "acme|", now: t0)
        let count = await store.count()
        XCTAssertNil(found)
        XCTAssertEqual(count, 0)
    }

    func testForeignPartitionCannotCloseTheSession() async {
        let store = store()
        await store.park(session, correlationID: "c1", partition: "acme|", now: t0)
        await store.close(correlationID: "c1", partition: "fremd-ag|")

        let stillThere = await store.session(correlationID: "c1", partition: "acme|", now: t0)
        XCTAssertNotNil(stillThere, "fremde Partition darf auch nicht loeschen")
    }

    // MARK: Deckel

    func testCapEvictsTheSoonestToExpire() async {
        let store = store(MaskingSessionPolicy(timeToLive: 900, maxSessions: 2))
        // Zeitlich gestaffelt ablegen, damit die Fristen auseinanderliegen.
        await store.park(session, correlationID: "alt", partition: "p", now: t0)
        await store.park(session, correlationID: "mittel", partition: "p",
                         now: t0.addingTimeInterval(10))
        await store.park(session, correlationID: "neu", partition: "p",
                         now: t0.addingTimeInterval(20))

        let count = await store.count()
        XCTAssertEqual(count, 2)
        let oldest = await store.session(correlationID: "alt", partition: "p",
                                         now: t0.addingTimeInterval(20))
        let newest = await store.session(correlationID: "neu", partition: "p",
                                         now: t0.addingTimeInterval(20))
        XCTAssertNil(oldest)
        XCTAssertNotNil(newest)
    }

    func testExpiredEntriesAreSweptOnPark() async {
        let store = store(MaskingSessionPolicy(timeToLive: 60))
        await store.park(session, correlationID: "c1", partition: "p", now: t0)
        await store.park(session, correlationID: "c2", partition: "p",
                         now: t0.addingTimeInterval(120))

        let count = await store.count()
        XCTAssertEqual(count, 1, "der abgelaufene Eintrag darf nicht liegen bleiben")
    }
}
