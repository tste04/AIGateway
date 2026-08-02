// Copyright (c) 2026 Tommy Stellmacher
// SPDX-License-Identifier: Apache-2.0

import XCTest
import GatewayCore
import InputFirewall
@testable import GatewayServer

// MARK: - Charakterisierung: die Stufenfolge als Vertrag
//
// Diese Tests beschreiben, was IST — als Sicherungsseil fuer den Umbau des
// Stufen-Abschlusses. Nach dem Refactoring muss exakt dieselbe Folge
// herauskommen, Zeichen fuer Zeichen.

final class PipelineCharacterizationTests: XCTestCase {

    private func pipeline(malware: Bool = false, pii: Bool = false, dlp: Bool = false,
                          cache: SemanticCache? = nil,
                          budget: Double = 10_000,
                          failureMode: FailureMode = .failClosed) -> GatewayPipeline {
        var policy = GatewayPolicy.standard
        policy.stageBudgetMilliseconds = budget
        policy.failureMode = failureMode
        return GatewayPipeline(
            pii: pii ? PIIGate(policy: .gatewayDefault, baseDirectory: nil) : nil,
            malware: malware ? StructuralPayloadScanner() : nil,
            dlp: dlp ? DLPScanner() : nil,
            policy: policy,
            cache: cache)
    }

    private func request(_ content: String = "Wie funktioniert Routing?",
                         attachment: Bool = false) -> ChatRequest {
        ChatRequest(model: "m",
                    messages: [ChatMessage(role: .user, content: content)],
                    attachments: attachment
                        ? [Attachment(name: "bild.png", mediaType: "image/png",
                                      bytes: Data([0x89, 0x50, 0x4E, 0x47] + Array(repeating: 0x41, count: 12)))]
                        : [])
    }

    func testFullStackRunsInTheBindingOrder() async {
        // Alle Stufen aktiv: die Reihenfolge aus DECISIONS, vollstaendig.
        let outcome = await pipeline(malware: true, pii: true, dlp: true,
                                     cache: SemanticCache(policy: .on))
            .process(request(attachment: true), principal: .anonymous)
        XCTAssertEqual(outcome.decision.timings.map(\.stage),
                       ["malware", "injection", "pii", "dlp", "cache"])
        XCTAssertEqual(outcome.decision.disposition, .allow)
    }

    func testEachOptionalStageDropsOutCleanly() async {
        // Jede Teilmenge behaelt die relative Ordnung der verbleibenden Stufen.
        let combinations: [(malware: Bool, pii: Bool, dlp: Bool, expected: [String])] = [
            (false, false, false, ["injection"]),
            (true, false, false, ["malware", "injection"]),
            (false, true, false, ["injection", "pii"]),
            (false, false, true, ["injection", "dlp"]),
            (true, true, true, ["malware", "injection", "pii", "dlp"]),
        ]
        for combo in combinations {
            let outcome = await pipeline(malware: combo.malware, pii: combo.pii, dlp: combo.dlp)
                .process(request(attachment: combo.malware), principal: .anonymous)
            XCTAssertEqual(outcome.decision.timings.map(\.stage), combo.expected,
                           "Kombination \(combo)")
        }
    }

    func testMalwareStageIsSkippedWithoutAttachments() async {
        // Konfiguriert, aber ohne Anhang: die Stufe laeuft nicht und taucht
        // auch nicht in den Zeiten auf.
        let outcome = await pipeline(malware: true).process(request(), principal: .anonymous)
        XCTAssertEqual(outcome.decision.timings.map(\.stage), ["injection"])
    }

    // MARK: Budget je Stufe

    func testFailOpenLetsThroughButMarksEveryStageAndTheDecision() async {
        // Budget 0: jede Stufe reisst es. failOpen laesst durch — aber das
        // Durchlassen ist eine ungeprueft getroffene Entscheidung und muss als
        // `degraded` im Audit stehen, je Stufe und im Ganzen.
        let outcome = await pipeline(malware: true, pii: true, dlp: true,
                                     budget: 0, failureMode: .failOpen)
            .process(request(attachment: true), principal: .anonymous)

        XCTAssertNotNil(outcome.forward, "failOpen blockt nicht")
        XCTAssertTrue(outcome.decision.degraded)
        XCTAssertEqual(outcome.decision.timings.count, 4)
        for timing in outcome.decision.timings {
            XCTAssertTrue(timing.timedOut, "Stufe \(timing.stage) muss ihr Budget gerissen haben")
        }
        XCTAssertFalse(outcome.decision.findings.contains { $0.ruleID == "GW-002" },
                       "failOpen erzeugt keinen Block-Befund")
    }

    func testFailClosedStopsAtTheFirstStageOverBudget() async {
        // failClosed: die ERSTE Stufe ueber Budget beendet den Lauf — spaetere
        // Stufen laufen gar nicht erst. Ohne Anhang ist das die Injection.
        let outcome = await pipeline(pii: true, dlp: true, budget: 0)
            .process(request(), principal: .anonymous)

        XCTAssertEqual(outcome.decision.disposition, .block)
        XCTAssertTrue(outcome.decision.findings.contains { $0.ruleID == "GW-002" })
        XCTAssertEqual(outcome.decision.timings.map(\.stage), ["injection"],
                       "nach dem Budget-Block darf keine weitere Stufe laufen")
        XCTAssertNil(outcome.forward)
    }

    func testFailClosedStopsAtMalwareWhenAttachmentsArePresent() async {
        // Mit Anhang ist die Malware-Stufe die erste — und damit die, an der
        // der Budget-Block greift.
        let outcome = await pipeline(malware: true, pii: true, budget: 0)
            .process(request(attachment: true), principal: .anonymous)

        XCTAssertEqual(outcome.decision.disposition, .block)
        XCTAssertTrue(outcome.decision.findings.contains { $0.ruleID == "GW-002" })
        XCTAssertEqual(outcome.decision.timings.map(\.stage), ["malware"])
    }
}

// MARK: - Provider-Strom-Zustand ueber Chunk-Grenzen

final class ProviderStreamCollectorTests: XCTestCase {

    func testDeltasAreAssembledAcrossChunkBoundaries() {
        let state = ProviderDownstream.collector(for: OpenAIAdapter())

        let whole = state.consume(Data("data: {\"choices\":[{\"delta\":{\"content\":\"Hal\"}}]}\n\n".utf8))
        // Eine ueber zwei Chunks zerrissene Ereigniszeile liefert erst beim
        // zweiten Chunk — und dann genau einmal.
        let half = state.consume(Data("data: {\"choices\":[{\"delta\":{\"con".utf8))
        let rest = state.consume(Data("tent\":\"lo\"}}]}\n\n".utf8))

        XCTAssertEqual(whole, ["Hal"])
        XCTAssertEqual(half, [])
        XCTAssertEqual(rest, ["lo"])
    }

    func testSplitUsageReportsAreMerged() {
        // Manche Dialekte melden Eingabe- und Ausgabe-Verbrauch in
        // verschiedenen Ereignissen; der Zustand vereinigt sie feldweise.
        let state = ProviderDownstream.collector(for: OpenAIAdapter())
        _ = state.consume(Data("data: {\"usage\":{\"prompt_tokens\":7}}\n\n".utf8))
        _ = state.consume(Data("data: {\"usage\":{\"completion_tokens\":9}}\n\n".utf8))
        XCTAssertEqual(state.reportedUsage(), TokenUsage(promptTokens: 7, completionTokens: 9))
    }

    func testTerminatorYieldsNoDelta() {
        let state = ProviderDownstream.collector(for: OpenAIAdapter())
        XCTAssertEqual(state.consume(Data("data: [DONE]\n\n".utf8)), [])
    }
}

// MARK: - Bibliotheksoberflaeche ohne interne Verwendung
//
// Diese Symbole benutzt das Gateway selbst nicht — sie sind fuer Einbetter da.
// Ohne Test braechen sie unbemerkt; genau deshalb steht hier je einer.

final class LibrarySurfaceTests: XCTestCase {

    func testMappingContentsTransformsEveryMessage() {
        let request = ChatRequest(model: "m", messages: [
            ChatMessage(role: .system, content: "a"),
            ChatMessage(role: .user, content: "b"),
        ])
        let upper = request.mappingContents { $0.uppercased() }
        XCTAssertEqual(upper.messages.map(\.content), ["A", "B"])
        XCTAssertEqual(upper.messages.map(\.role), [.system, .user], "Rollen bleiben stehen")
    }

    func testLastUserMessageSkipsTrailingAssistantTurns() {
        let request = ChatRequest(model: "m", messages: [
            ChatMessage(role: .user, content: "erste Frage"),
            ChatMessage(role: .assistant, content: "Antwort"),
            ChatMessage(role: .user, content: "zweite Frage"),
            ChatMessage(role: .assistant, content: "noch eine Antwort"),
        ])
        XCTAssertEqual(request.lastUserMessage, "zweite Frage")
        XCTAssertNil(ChatRequest(model: "m", messages: []).lastUserMessage)
    }

    func testResetStatisticsStartsANewCountingPeriod() async {
        let cache = SemanticCache(policy: .on)
        _ = await cache.lookup(key: CacheKey(partition: "p", model: "m", prompt: "x",
                                             temperature: nil, maxTokens: nil),
                               embedding: nil, entities: EntitySignature(terms: []))
        await cache.resetStatistics()
        let stats = await cache.statistics()
        XCTAssertEqual(stats, CacheStatistics())
    }

    func testRateGuardRemoveAllForgetsEveryBucket() async {
        let rate = RateGuard(policy: RateLimitPolicy(enabled: true, requestsPerInterval: 0, burst: 1))
        let caller = Principal(subject: "s")
        _ = await rate.admit(caller)
        await rate.removeAll()
        let count = await rate.count()
        let verdict = await rate.admit(caller)
        XCTAssertEqual(count, 0)
        XCTAssertEqual(verdict, .allowed)
    }

    func testExtendSessionReachesTheStore() async {
        var policy = GatewayPolicy.standard
        policy.stageBudgetMilliseconds = 10_000
        let pipeline = GatewayPipeline(
            pii: PIIGate(policy: .gatewayDefault, baseDirectory: nil),
            policy: policy,
            sessions: MaskingSessionStore())
        _ = await pipeline.process(
            ChatRequest(model: "m", messages: [ChatMessage(role: .user, content: "Frau Anna Schmidt")]),
            principal: .anonymous, correlationID: "c-extend")

        let extended = await pipeline.extendSession(correlationID: "c-extend", partition: "-|")
        let foreign = await pipeline.extendSession(correlationID: "c-extend", partition: "andere|")
        XCTAssertTrue(extended)
        XCTAssertFalse(foreign, "fremde Partition verlaengert nicht")
    }
}
