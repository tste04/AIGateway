// Copyright (c) 2026 Tommy Stellmacher
// SPDX-License-Identifier: Apache-2.0

import XCTest
import GatewayCore
@testable import GatewayServer

// MARK: - Betrieb des Caches: Quote, Verdraengung, Invalidierung, Abzug
//
// `await` steht durchgehend in einer lokalen Bindung und nie direkt in einem
// `XCTAssert…`: dessen Argument ist eine Autoclosure ohne Nebenlaeufigkeit.

final class CacheOperationsTests: XCTestCase {

    private func key(_ partition: String, _ prompt: String,
                     model: String = "m") -> CacheKey {
        CacheKey(partition: partition, model: model, prompt: prompt,
                 temperature: nil, maxTokens: nil)
    }

    private func fill(_ cache: SemanticCache, _ key: CacheKey, content: String = "antwort") async {
        await cache.store(key: key, maskedResponse: ChatResponse(model: key.model, content: content),
                          embedding: nil, entities: EntitySignature(terms: []))
    }

    private func lookup(_ cache: SemanticCache, _ key: CacheKey) async -> SemanticCache.Hit? {
        await cache.lookup(key: key, embedding: nil, entities: EntitySignature(terms: []))
    }

    // MARK: Trefferquote

    func testHitRateCountsWhatItSays() async {
        let cache = SemanticCache(policy: .on)
        await fill(cache, key("p", "eins"))

        _ = await lookup(cache, key("p", "eins"))     // Treffer
        _ = await lookup(cache, key("p", "zwei"))     // Fehltreffer
        _ = await lookup(cache, key("p", "eins"))     // Treffer

        let stats = await cache.statistics()
        XCTAssertEqual(stats.lookups, 3)
        XCTAssertEqual(stats.exactHits, 2)
        XCTAssertEqual(stats.misses, 1)
        XCTAssertEqual(stats.stores, 1)
        XCTAssertEqual(stats.hitRate ?? 0, 2.0 / 3.0, accuracy: 0.0001)
    }

    func testHitRateIsNilWithoutLookups() {
        // 0 % waere hier eine Behauptung ueber nichts.
        XCTAssertNil(CacheStatistics().hitRate)
    }

    func testStatisticsCarryNoContent() async {
        // Eine Metrik, die Prompts traegt, ist ein Leck mit Dashboard. Der Typ
        // hat schlicht kein Feld dafuer — nachgewiesen ueber die Kodierung.
        let cache = SemanticCache(policy: .on)
        await fill(cache, key("p", "geheime frage"), content: "geheime antwort")
        _ = await lookup(cache, key("p", "geheime frage"))

        let stats = await cache.statistics()
        let data = try! JSONEncoder().encode(stats)
        let text = String(data: data, encoding: .utf8) ?? ""
        XCTAssertFalse(text.contains("geheime"))
    }

    // MARK: Verdraengung je Partition

    func testOnePartitionCannotEvictAnother() async {
        // Der Nachbarschaftsschaden: viel schreiben und damit die Eintraege
        // aller anderen wertlos machen.
        let cache = SemanticCache(policy: SemanticCachePolicy(
            enabled: true, maxEntries: 100, maxEntriesPerPartition: 2))

        await fill(cache, key("ruhig", "frage"))
        for index in 0..<50 {
            await fill(cache, key("laut", "frage-\(index)"))
        }

        let quiet = await lookup(cache, key("ruhig", "frage"))
        let loud = await cache.count(partition: "laut")
        XCTAssertNotNil(quiet, "der leise Mandant behaelt seinen Eintrag")
        XCTAssertEqual(loud, 2, "der laute bleibt in seinem Kontingent")
    }

    func testGlobalCapStillHolds() async {
        let cache = SemanticCache(policy: SemanticCachePolicy(
            enabled: true, maxEntries: 3, maxEntriesPerPartition: 0))
        for index in 0..<10 {
            await fill(cache, key("p-\(index)", "frage"))
        }
        let total = await cache.count()
        XCTAssertEqual(total, 3)
    }

    func testEvictionIsCounted() async {
        let cache = SemanticCache(policy: SemanticCachePolicy(
            enabled: true, maxEntries: 2, maxEntriesPerPartition: 0))
        for index in 0..<5 { await fill(cache, key("p", "frage-\(index)")) }
        let stats = await cache.statistics()
        XCTAssertEqual(stats.evictions, 3)
    }

    // MARK: Invalidierung

    func testInvalidatingAPartitionLeavesOthersAlone() async {
        // Der Griff fuer „Mandant hat seine Berechtigung verloren". Die Frist
        // hilft dort nicht: sie ist ein Zeitmass, kein Ereignis.
        let cache = SemanticCache(policy: .on)
        await fill(cache, key("a", "frage"))
        await fill(cache, key("b", "frage"))

        let removed = await cache.invalidate(partition: "a")
        let gone = await lookup(cache, key("a", "frage"))
        let kept = await lookup(cache, key("b", "frage"))

        XCTAssertEqual(removed, 1)
        XCTAssertNil(gone)
        XCTAssertNotNil(kept)
    }

    func testInvalidatingAModelLeavesOthersAlone() async {
        // Antworten eines abgeloesten Modells sind nicht alt, sondern von
        // jemand anderem.
        let cache = SemanticCache(policy: .on)
        await fill(cache, key("p", "frage", model: "alt"))
        await fill(cache, key("p", "frage", model: "neu"))

        let removed = await cache.invalidate(model: "alt")
        let gone = await lookup(cache, key("p", "frage", model: "alt"))
        let kept = await lookup(cache, key("p", "frage", model: "neu"))

        XCTAssertEqual(removed, 1)
        XCTAssertNil(gone)
        XCTAssertNotNil(kept)
    }

    func testInvalidatingBothNarrowsFurther() async {
        let cache = SemanticCache(policy: .on)
        await fill(cache, key("a", "frage", model: "x"))
        await fill(cache, key("a", "frage", model: "y"))
        await fill(cache, key("b", "frage", model: "x"))

        let removed = await cache.invalidate(partition: "a", model: "x")
        let remaining = await cache.count()
        XCTAssertEqual(removed, 1)
        XCTAssertEqual(remaining, 2)
    }

    // MARK: Abzug

    func testSnapshotRoundTripsIncludingVectors() async {
        let cache = SemanticCache(policy: .on)
        await cache.store(key: key("p", "frage"),
                          maskedResponse: ChatResponse(model: "m", content: "[Person-1] ok"),
                          embedding: [0.1, 0.9],
                          entities: EntitySignature(terms: ["q3"]))

        // Ueber JSON, weil genau das der Zweck des Abzugs ist.
        let snapshot = await cache.snapshot()
        let coded = try! JSONDecoder().decode(
            CacheSnapshot.self, from: try! JSONEncoder().encode(snapshot))

        let restored = SemanticCache(policy: .on)
        let taken = await restored.restore(coded)
        let hit = await lookup(restored, key("p", "frage"))

        XCTAssertEqual(taken, 1)
        XCTAssertEqual(hit?.response.content, "[Person-1] ok")
        XCTAssertEqual(hit?.kind, .exact)
    }

    func testRestoreDropsExpiredEntriesInsteadOfReviving() async {
        // Sonst verlaengerte jeder Neustart jede Frist.
        let stale = CacheSnapshot(entries: [CacheSnapshot.Item(
            partition: "p", model: "m", prompt: "frage", temperature: nil, maxTokens: nil,
            response: ChatResponse(model: "m", content: "alt"), embedding: nil,
            entities: [], storedAt: Date(timeIntervalSinceNow: -7200))])

        let cache = SemanticCache(policy: SemanticCachePolicy(enabled: true, timeToLive: 3600))
        let taken = await cache.restore(stale)
        let count = await cache.count()
        XCTAssertEqual(taken, 0)
        XCTAssertEqual(count, 0)
    }

    func testRestoreRespectsTheCap() async {
        let items = (0..<10).map { index in
            CacheSnapshot.Item(partition: "p", model: "m", prompt: "frage-\(index)",
                               temperature: nil, maxTokens: nil,
                               response: ChatResponse(model: "m", content: "x"),
                               embedding: nil, entities: [], storedAt: Date())
        }
        let cache = SemanticCache(policy: SemanticCachePolicy(
            enabled: true, maxEntries: 4, maxEntriesPerPartition: 0))
        _ = await cache.restore(CacheSnapshot(entries: items))
        let count = await cache.count()
        XCTAssertEqual(count, 4)
    }
}

// MARK: - Die Pipeline reicht Metrik und Invalidierung durch

final class PipelineCacheControlTests: XCTestCase {

    func testStatisticsAreNilWithoutACache() async {
        // Kein Cache und ein Cache ohne Treffer sind verschiedene Aussagen.
        let pipeline = GatewayPipeline(policy: .standard)
        let stats = await pipeline.cacheStatistics()
        XCTAssertNil(stats)
    }

    func testInvalidationReachesTheCache() async {
        let cache = SemanticCache(policy: .on)
        await cache.store(key: CacheKey(partition: "-|", model: "m", prompt: "x",
                                        temperature: nil, maxTokens: nil),
                          maskedResponse: ChatResponse(model: "m", content: "a"),
                          embedding: nil, entities: EntitySignature(terms: []))

        var policy = GatewayPolicy.standard
        policy.stageBudgetMilliseconds = 10_000
        let pipeline = GatewayPipeline(policy: policy, cache: cache)

        let removed = await pipeline.invalidateCache(partition: "-|")
        let remaining = await cache.count()
        XCTAssertEqual(removed, 1)
        XCTAssertEqual(remaining, 0)
    }
}
