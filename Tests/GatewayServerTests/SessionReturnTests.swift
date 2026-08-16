// Copyright (c) 2026 Tommy Stellmacher
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

import XCTest
import GatewayCore
import InputFirewall
@testable import GatewayServer

// MARK: - Rueckweg der Stufen-Variante
//
// Die naechste Box bringt den fertigen Text zurueck und holt sich die
// Klardaten ueber /v1/session/unmask; extend und close steuern die Frist.
// Getestet gegen `GatewayService.handle` mit aufzeichnendem Responder —
// derselbe Schnitt wie in GatewayServiceTests.

private final class RecordingResponder: HTTPResponder, @unchecked Sendable {
    private let lock = NSLock()
    private(set) var status: Int?
    private(set) var body: Data?

    func respond(status: Int, contentType: String, body: Data, extraHeaders: [String: String]) {
        lock.lock(); defer { lock.unlock() }
        self.status = status
        self.body = body
    }
    func beginStream(contentType: String, extraHeaders: [String: String]) {}
    @discardableResult func writeChunk(_ text: String) -> Bool { true }
    func endStream() {}

    var bodyJSON: [String: Any] {
        body.flatMap { try? JSONSerialization.jsonObject(with: $0) as? [String: Any] } ?? [:]
    }
}

private struct StubDownstream: Downstream {
    func send(_ handoff: GatewayHandoff) async throws -> ChatResponse {
        ChatResponse(model: "fake", content: "ok")
    }
    @discardableResult
    func stream(_ handoff: GatewayHandoff,
                onDelta: @escaping @Sendable (String) -> Void) async throws -> TokenUsage? { nil }
}

final class SessionReturnTests: XCTestCase {

    private var store: MaskingSessionStore!
    private var service: GatewayService!

    override func setUp() {
        store = MaskingSessionStore()
        var policy = GatewayPolicy.standard
        policy.stageBudgetMilliseconds = 10_000
        let pipeline = GatewayPipeline(policy: policy, sessions: store)
        service = GatewayService(configuration: GatewayConfiguration(),
                                 pipeline: pipeline,
                                 downstream: StubDownstream())
    }

    private var partition: String { Principal.anonymous.cachePartition }

    private func park(_ mapping: [String: String], correlationID: String = "corr-1",
                      partition: String? = nil) async {
        await store.park(MaskingSession(mapping: mapping),
                         correlationID: correlationID,
                         partition: partition ?? self.partition)
    }

    private func post(_ path: String, _ json: [String: Any]) async -> RecordingResponder {
        let responder = RecordingResponder()
        await service.handle(
            HTTPRequest(method: "POST", path: path, headers: [:],
                        body: try! JSONSerialization.data(withJSONObject: json)),
            responder)
        return responder
    }

    func testUnmaskReturnsCleartextAndClosesByDefault() async {
        await park(["[Person-1]": "Alice Meier"])
        let first = await post("/v1/session/unmask",
                               ["correlation_id": "corr-1",
                                "content": "Antwort fuer [Person-1]."])
        XCTAssertEqual(first.status, 200)
        XCTAssertEqual(first.bodyJSON["content"] as? String, "Antwort fuer Alice Meier.")
        XCTAssertEqual(first.bodyJSON["restored"] as? Bool, true)

        // De-Maskierung ist der letzte Schritt: die Zuordnung ist danach weg.
        let second = await post("/v1/session/unmask",
                                ["correlation_id": "corr-1",
                                 "content": "[Person-1]"])
        XCTAssertEqual(second.bodyJSON["restored"] as? Bool, false)
        XCTAssertEqual(second.bodyJSON["content"] as? String, "[Person-1]",
                       "ohne Zuordnung bleiben die Platzhalter sichtbar stehen")
    }

    func testKeepLeavesTheSessionForAPreview() async {
        await park(["[Person-1]": "Alice"])
        _ = await post("/v1/session/unmask",
                       ["correlation_id": "corr-1", "content": "[Person-1]",
                        "keep": true])
        let again = await post("/v1/session/unmask",
                               ["correlation_id": "corr-1", "content": "[Person-1]"])
        XCTAssertEqual(again.bodyJSON["restored"] as? Bool, true,
                       "keep laesst die Zuordnung fuer die Freigabe-Vorschau stehen")
    }

    func testForeignPartitionGetsPlaceholdersNotData() async {
        // Die correlationID zu kennen reicht nicht: die Zuordnung gehoert
        // einer anderen Partition, der Text kommt unaufgeloest zurueck.
        await park(["[Person-1]": "Geheim"], partition: "tenant-b|scope")
        let response = await post("/v1/session/unmask",
                                  ["correlation_id": "corr-1", "content": "[Person-1]"])
        XCTAssertEqual(response.bodyJSON["restored"] as? Bool, false)
        XCTAssertEqual(response.bodyJSON["content"] as? String, "[Person-1]")
    }

    func testExtendThenCloseLifecycle() async {
        await park(["[Person-1]": "Alice"])
        let extended = await post("/v1/session/extend", ["correlation_id": "corr-1"])
        XCTAssertEqual(extended.status, 200)
        XCTAssertEqual(extended.bodyJSON["extended"] as? Bool, true)

        let closed = await post("/v1/session/close", ["correlation_id": "corr-1"])
        XCTAssertEqual(closed.status, 200)

        let afterwards = await post("/v1/session/unmask",
                                    ["correlation_id": "corr-1", "content": "[Person-1]"])
        XCTAssertEqual(afterwards.bodyJSON["restored"] as? Bool, false)
    }

    func testExtendingAnUnknownSessionSaysSo() async {
        let response = await post("/v1/session/extend", ["correlation_id": "niemand"])
        XCTAssertEqual(response.status, 404)
        XCTAssertEqual(response.bodyJSON["extended"] as? Bool, false)
    }

    func testMissingFieldsAreRejected() async {
        let noID = await post("/v1/session/unmask", ["content": "x"])
        XCTAssertEqual(noID.status, 400)
        let noContent = await post("/v1/session/unmask", ["correlation_id": "c"])
        XCTAssertEqual(noContent.status, 400)
    }

    func testUnknownSessionRouteIs404() async {
        let response = await post("/v1/session/steal", ["correlation_id": "c"])
        XCTAssertEqual(response.status, 404)
    }

    // MARK: Die Klammer je Betriebsart

    private func chat() -> [String: Any] {
        ["model": "m", "stream": false,
         "messages": [["role": "user", "content": "Hallo"]]]
    }

    func testProxyModeClosesTheParkedSessionAfterTheAnswer() async {
        // Alleinbetrieb: mit der Antwort ist die Klammer zu — niemand kommt
        // spaeter noch einmal vorbei.
        let responder = await post("/v1/chat/completions", chat())
        XCTAssertEqual(responder.status, 200)
        let remaining = await store.count()
        XCTAssertEqual(remaining, 0)
    }

    func testStageModeKeepsTheParkedSessionForTheReturnPath() async {
        // Stufenbetrieb: die naechste Box (hier ein toter Port, der Fehlschlag
        // ist egal) arbeitet weiter — die Zuordnung muss den Rueckweg erleben.
        var policy = GatewayPolicy.standard
        policy.stageBudgetMilliseconds = 10_000
        let staged = GatewayService(
            configuration: GatewayConfiguration(),
            pipeline: GatewayPipeline(policy: policy, sessions: store),
            downstream: StageDownstream(url: URL(string: "http://127.0.0.1:9/v1/decide")!))

        let responder = RecordingResponder()
        await staged.handle(
            HTTPRequest(method: "POST", path: "/v1/chat/completions", headers: [:],
                        body: try! JSONSerialization.data(withJSONObject: chat())),
            responder)

        let remaining = await store.count()
        XCTAssertEqual(remaining, 1, "die Klammer bleibt fuer den Rueckweg offen")
    }
}
