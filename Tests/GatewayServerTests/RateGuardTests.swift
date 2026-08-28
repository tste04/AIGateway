// Copyright (c) 2026 Tommy Stellmacher
// SPDX-License-Identifier: Apache-2.0

import XCTest
import GatewayCore
@testable import GatewayServer

// MARK: - Rate-Guard
//
// `await` steht hier durchgehend in einer lokalen Bindung und nie direkt in
// einem `XCTAssert…`: dessen Argument ist eine Autoclosure ohne
// Nebenlaeufigkeit.

final class RateGuardTests: XCTestCase {

    private let alice = Principal(subject: "alice", tenant: "acme")
    private let bob = Principal(subject: "bob", tenant: "acme")

    private func guardWith(_ changes: (inout RateLimitPolicy) -> Void) -> RateGuard {
        var policy = RateLimitPolicy.on
        changes(&policy)
        return RateGuard(policy: policy)
    }

    private func isLimited(_ verdict: RateVerdict) -> Bool {
        if case .limited = verdict { return true }
        return false
    }

    func testDisabledGuardAdmitsEverything() async {
        let rate = RateGuard(policy: RateLimitPolicy(enabled: false, burst: 1))
        for _ in 0..<50 {
            let verdict = await rate.admit(alice)
            XCTAssertEqual(verdict, .allowed)
        }
    }

    func testBurstIsSpentThenRefused() async {
        let rate = guardWith { $0.burst = 3; $0.requestsPerInterval = 0 }
        let now = Date()
        for _ in 0..<3 {
            let verdict = await rate.admit(alice, now: now)
            XCTAssertEqual(verdict, .allowed)
        }
        let fourth = await rate.admit(alice, now: now)
        XCTAssertTrue(isLimited(fourth), "der vierte Aufruf muss abgewiesen werden")
    }

    func testSubjectsDoNotShareABudget() async {
        // Der Punkt der Subject-Schluesselung: die Partition ist absichtlich
        // geteilt, das Kontingent darf es nicht sein.
        let rate = guardWith { $0.burst = 1; $0.requestsPerInterval = 0 }
        let now = Date()
        let forAlice = await rate.admit(alice, now: now)
        let forBob = await rate.admit(bob, now: now)

        XCTAssertEqual(forAlice, .allowed)
        XCTAssertEqual(forBob, .allowed, "Bob zahlt nicht fuer Alices Verbrauch")
        XCTAssertEqual(alice.cachePartition, bob.cachePartition,
                       "beide teilen sich die Cache-Partition — genau darum geht es")
    }

    func testSameSubjectInDifferentTenantsIsADifferentCaller() async {
        let rate = guardWith { $0.burst = 1; $0.requestsPerInterval = 0 }
        let now = Date()
        let one = await rate.admit(Principal(subject: "a", tenant: "one"), now: now)
        let two = await rate.admit(Principal(subject: "a", tenant: "two"), now: now)
        XCTAssertEqual(one, .allowed)
        XCTAssertEqual(two, .allowed)
    }

    func testTokensRefillOverTime() async {
        let rate = guardWith { $0.burst = 1; $0.requestsPerInterval = 60; $0.interval = 60 }
        let start = Date()

        let first = await rate.admit(alice, now: start)
        let second = await rate.admit(alice, now: start)
        // Eine Sekunde spaeter ist genau ein Token nachgefuellt.
        let third = await rate.admit(alice, now: start.addingTimeInterval(1))

        XCTAssertEqual(first, .allowed)
        XCTAssertTrue(isLimited(second), "sofort danach ist der Eimer leer")
        XCTAssertEqual(third, .allowed)
    }

    func testRefillIsCappedAtBurst() async {
        let rate = guardWith { $0.burst = 2; $0.requestsPerInterval = 60; $0.interval = 60 }
        // Eine Stunde Pause fuellt nicht mehr als den Eimer.
        let later = Date().addingTimeInterval(3600)
        let first = await rate.admit(alice, now: later)
        let second = await rate.admit(alice, now: later)
        let third = await rate.admit(alice, now: later)

        XCTAssertEqual(first, .allowed)
        XCTAssertEqual(second, .allowed)
        XCTAssertTrue(isLimited(third), "mehr als burst darf nicht angespart werden")
    }

    func testRetryAfterIsComputedNotGuessed() async {
        let rate = guardWith { $0.burst = 1; $0.requestsPerInterval = 1; $0.interval = 10 }
        let now = Date()
        _ = await rate.admit(alice, now: now)
        let verdict = await rate.admit(alice, now: now)

        guard case .limited(let retryAfter) = verdict else {
            return XCTFail("erwartet abgewiesen")
        }
        // Ein Token je 10 Sekunden, der Eimer ist bei 0 — also 10 Sekunden.
        XCTAssertEqual(retryAfter, 10, accuracy: 0.001)
    }

    func testRetryAfterIsNeverZero() async {
        // Abrunden wuerde den Client in die naechste Absage schicken.
        let rate = guardWith { $0.burst = 1; $0.requestsPerInterval = 1000; $0.interval = 1 }
        let now = Date()
        _ = await rate.admit(alice, now: now)
        let verdict = await rate.admit(alice, now: now)

        guard case .limited(let retryAfter) = verdict else {
            return XCTFail("erwartet abgewiesen")
        }
        XCTAssertGreaterThanOrEqual(retryAfter, 1)
    }

    func testChurnCannotResetAThrottledBucket() async {
        // Der Angriff, gegen den `makeRoom` steht: genug fremde Subjects
        // erzeugen, bis der eigene, leergelaufene Eimer verdraengt wird und
        // voll zurueckkommt.
        let rate = guardWith { $0.burst = 1; $0.requestsPerInterval = 0; $0.maxTrackedSubjects = 4 }
        let now = Date()
        let first = await rate.admit(alice, now: now)
        let throttled = await rate.admit(alice, now: now)
        XCTAssertEqual(first, .allowed)
        XCTAssertTrue(isLimited(throttled), "Alice ist gedrosselt")

        // Die Buchhaltung mit fremden Namen fluten.
        for index in 0..<40 {
            _ = await rate.admit(Principal(subject: "flood-\(index)", tenant: "acme"), now: now)
        }

        let stillThrottled = await rate.admit(alice, now: now)
        let tracked = await rate.count()
        XCTAssertTrue(isLimited(stillThrottled),
                      "Alice muss gedrosselt BLEIBEN — sonst ist die Verdraengung das Schlupfloch")
        XCTAssertLessThanOrEqual(tracked, 5, "die Buchhaltung bleibt gedeckelt")
    }

    func testFullBucketsAreTheOnesEvicted() async {
        // Ein voller Eimer ist informationsgleich mit keinem Eimer. Sind alle
        // angebrochen, wird abgewiesen statt zugelassen — fail-closed.
        let rate = guardWith { $0.burst = 2; $0.requestsPerInterval = 0; $0.maxTrackedSubjects = 2 }
        let now = Date()
        _ = await rate.admit(Principal(subject: "one"), now: now)
        _ = await rate.admit(Principal(subject: "two"), now: now)
        _ = await rate.admit(Principal(subject: "two"), now: now)

        let tracked = await rate.count()
        let third = await rate.admit(Principal(subject: "three"), now: now)
        XCTAssertEqual(tracked, 2)
        XCTAssertTrue(isLimited(third))
    }

    func testForgetClearsABucket() async {
        let rate = guardWith { $0.burst = 1; $0.requestsPerInterval = 0 }
        let now = Date()
        _ = await rate.admit(alice, now: now)
        await rate.forget(alice)
        let again = await rate.admit(alice, now: now)
        XCTAssertEqual(again, .allowed)
    }

    func testFindingCarriesTheStableRuleID() {
        let finding = RateGuard.finding(retryAfter: 12)
        XCTAssertEqual(finding.ruleID, "GW-004")
        XCTAssertEqual(finding.category, .anomaly)
        XCTAssertEqual(finding.weight, 1.0, accuracy: 0.0001)
    }
}
