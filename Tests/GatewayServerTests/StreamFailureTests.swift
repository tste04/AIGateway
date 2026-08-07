// Copyright (c) 2026 Tommy Stellmacher
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

import XCTest
import GatewayCore
@testable import GatewayServer

// MARK: - In-Band-Stream-Fehler werden sichtbar (M1)
//
// Ein Provider kann auf eine Stream-Anfrage mit HTTP 200 antworten und den
// Fehler dann als Ereignis schicken ({"error": …}). Vorher wurde das doppelt
// verschluckt: der Provider-Collector setzte `failure` nie, und
// ProviderDownstream.stream rief `pendingFailure()` nicht. Ergebnis war eine
// leere, scheinbar vollstaendige 200-Antwort samt falschem Audit.

final class ProviderStreamFailureTests: XCTestCase {

    private func surfacesError(_ dialect: ProviderAdapter, _ raw: String) -> Bool {
        let collector = ProviderDownstream.collector(for: dialect)
        _ = collector.consume(Data(raw.utf8))
        return collector.pendingFailure() != nil
    }

    func testOpenAIInStreamErrorIsSurfaced() {
        XCTAssertTrue(surfacesError(OpenAIAdapter(),
                                    "data: {\"error\":{\"message\":\"rate limit\"}}\n\n"))
    }

    func testAnthropicInStreamErrorIsSurfaced() {
        XCTAssertTrue(surfacesError(AnthropicAdapter(),
                                    "data: {\"type\":\"error\",\"error\":{\"message\":\"overloaded\"}}\n\n"))
    }

    func testOllamaInStreamErrorIsSurfaced() {
        XCTAssertTrue(surfacesError(OllamaAdapter(), "{\"error\":\"model not found\"}\n"))
    }

    func testNormalDeltaIsNotMistakenForError() {
        // Kein Fehlalarm: ein gewoehnlicher Text-Delta hat keinen error-Schluessel.
        let collector = ProviderDownstream.collector(for: OpenAIAdapter())
        let deltas = collector.consume(Data("data: {\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}\n\n".utf8))
        XCTAssertEqual(deltas, ["hi"])
        XCTAssertNil(collector.pendingFailure())
    }

    func testFailureCarriesTheProviderMessage() {
        let collector = ProviderDownstream.collector(for: OllamaAdapter())
        _ = collector.consume(Data("{\"error\":\"boom\"}\n".utf8))
        guard case .upstream(let status, let body)? = collector.pendingFailure() else {
            return XCTFail("erwartet .upstream")
        }
        XCTAssertEqual(status, 0, "In-Band-Fehler: HTTP-Status war 200, hier unbekannt")
        XCTAssertEqual(body, "boom")
    }
}
