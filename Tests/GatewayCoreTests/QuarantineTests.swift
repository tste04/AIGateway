// Copyright (c) 2026 Tommy Stellmacher
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

import XCTest
@testable import GatewayCore

// MARK: - Auswahl: was ueberhaupt aufbewahrt wird

final class QuarantinePolicyTests: XCTestCase {

    func testDisabledCollectsNothingNotEvenBlocks() {
        // Default AUS heisst AUS — auch fuer den klaren Verstoss.
        let policy = QuarantinePolicy()
        XCTAssertFalse(policy.enabled)
        XCTAssertFalse(policy.collects(disposition: .block, riskScore: 1.0, blockThreshold: 0.7))
    }

    func testEnabledCollectsEveryBlock() {
        let policy = QuarantinePolicy.masked
        XCTAssertTrue(policy.collects(disposition: .block, riskScore: 0.9, blockThreshold: 0.7))
    }

    func testNearMissesInsideTheBandAreCollected() {
        // Schwelle 0.7, Fenster 0.15 -> ab 0.55 wird aufbewahrt.
        let policy = QuarantinePolicy(enabled: true, nearMissBand: 0.15)
        XCTAssertTrue(policy.collects(disposition: .allow, riskScore: 0.60, blockThreshold: 0.7))
        XCTAssertTrue(policy.collects(disposition: .allowModified, riskScore: 0.55,
                                      blockThreshold: 0.7))
    }

    func testQuietRequestsAreNotCollected() {
        let policy = QuarantinePolicy(enabled: true, nearMissBand: 0.15)
        XCTAssertFalse(policy.collects(disposition: .allow, riskScore: 0.2, blockThreshold: 0.7))
        XCTAssertFalse(policy.collects(disposition: .allow, riskScore: 0, blockThreshold: 0.7))
    }

    func testZeroBandKeepsOnlyBlocks() {
        let policy = QuarantinePolicy(enabled: true, nearMissBand: 0)
        XCTAssertTrue(policy.collects(disposition: .block, riskScore: 0.9, blockThreshold: 0.7))
        XCTAssertFalse(policy.collects(disposition: .allow, riskScore: 0.69, blockThreshold: 0.7))
    }

    func testDetailLevelsAreOrdered() {
        // `masked` ist mehr Exposition als `counts`, `raw` mehr als `masked`.
        XCTAssertLessThan(QuarantineDetail.counts, QuarantineDetail.masked)
        XCTAssertLessThan(QuarantineDetail.masked, QuarantineDetail.raw)
    }
}

// MARK: - Die Frist ist keine Empfehlung

final class MemoryQuarantineSinkTests: XCTestCase {

    private let t0 = Date(timeIntervalSince1970: 2_000_000)

    private func sample(_ id: String, at when: Date, retention: TimeInterval = 60,
                        detail: QuarantineDetail = .counts,
                        content: String? = nil) -> QuarantineSample {
        QuarantineSample(
            correlationID: id, timestamp: when, principal: .anonymous, model: "m",
            disposition: .block, riskScore: 0.9, ruleIDs: ["INJ-001"], categories: [.injection],
            detail: detail, content: content,
            expiresAt: when.addingTimeInterval(retention))
    }

    func testStoredSampleComesBack() async {
        let sink = MemoryQuarantineSink()
        await sink.store(sample("c1", at: t0))
        let found = await sink.samples(now: t0)
        XCTAssertEqual(found.map(\.correlationID), ["c1"])
    }

    func testExpiredSamplesAreNeverHandedOut() async {
        let sink = MemoryQuarantineSink()
        await sink.store(sample("c1", at: t0, retention: 60))

        let fresh = await sink.samples(now: t0.addingTimeInterval(30))
        XCTAssertEqual(fresh.count, 1)
        let stale = await sink.samples(now: t0.addingTimeInterval(90))
        XCTAssertTrue(stale.isEmpty, "abgelaufene Vorfaelle duerfen nicht mehr lesbar sein")
    }

    func testCapDropsTheOldest() async {
        let sink = MemoryQuarantineSink(maxSamples: 2)
        for (n, id) in ["a", "b", "c"].enumerated() {
            await sink.store(sample(id, at: t0.addingTimeInterval(Double(n)), retention: 3600))
        }
        let found = await sink.samples(now: t0)
        XCTAssertEqual(found.map(\.correlationID), ["b", "c"])
    }

    func testSampleSurvivesEncoding() throws {
        // Eine Senke wird die Vorfaelle serialisieren wollen.
        let original = sample("c1", at: t0, detail: .masked, content: "Frau [Person-1]")
        let data = try JSONEncoder().encode(original)
        let decoded = try JSONDecoder().decode(QuarantineSample.self, from: data)
        XCTAssertEqual(decoded, original)
    }
}
