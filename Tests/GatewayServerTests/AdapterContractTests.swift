// Copyright (c) 2026 Tommy Stellmacher
// SPDX-License-Identifier: Apache-2.0

import XCTest
import GatewayCore
@testable import GatewayServer

// MARK: - Adapter-Vertraege: Ausgabepfade und Ablehnungen
//
// Die Encode-Seiten und die Ablehnung semantik-aendernder Felder liefen je
// Dialekt bisher ungeprueft. Diese Tests nageln sie fest, bevor spaetere
// Bausteine (Secret-Redaktion, Trust-Deckel) die Adapter beruehren.

final class AdapterRejectionTests: XCTestCase {

    private func decode(_ adapter: ProviderAdapter, _ json: [String: Any]) throws -> ChatRequest {
        try adapter.decodeRequest(try JSONSerialization.data(withJSONObject: json))
    }

    private func minimal(_ extra: [String: Any]) -> [String: Any] {
        var d: [String: Any] = ["model": "m", "messages": [["role": "user", "content": "hi"]]]
        for (k, v) in extra { d[k] = v }
        return d
    }

    // Ein still verworfenes semantik-aenderndes Feld liefert eine Antwort auf
    // eine ANDERE Anfrage als die gestellte — deshalb Ablehnung, nicht Ignorieren.
    func testOpenAIRejectsEachSemanticField() throws {
        for field in ["tools", "tool_choice", "functions", "function_call", "response_format"] {
            XCTAssertThrowsError(try decode(OpenAIAdapter(), minimal([field: ["x"]])),
                                 "OpenAI muss '\(field)' abweisen")
        }
    }

    func testAnthropicRejectsToolFields() throws {
        for field in ["tools", "tool_choice"] {
            XCTAssertThrowsError(try decode(AnthropicAdapter(), minimal([field: ["x"]])),
                                 "Anthropic muss '\(field)' abweisen")
        }
    }

    func testOllamaRejectsToolsAndFormat() throws {
        for field in ["tools", "format"] {
            XCTAssertThrowsError(try decode(OllamaAdapter(), minimal([field: "json"])),
                                 "Ollama muss '\(field)' abweisen")
        }
    }

    func testHarmlessFieldsAreAccepted() throws {
        // Gegenprobe: was die Semantik NICHT aendert, darf nicht abgewiesen werden.
        let request = try decode(OpenAIAdapter(), minimal(["user": "abc", "temperature": 0.2]))
        XCTAssertEqual(request.temperature, 0.2)
    }

    // Binaere Inhaltsbloecke: heute Ablehnung (die Box traegt nur Text). Das ist
    // eine fail-closed Naht wie das abgewiesene `tools` — nicht still verwerfen.
    func testBinaryContentBlockIsRejectedNotDropped() throws {
        let block: [String: Any] = [
            "role": "user",
            "content": [
                ["type": "text", "text": "was ist auf dem Bild?"],
                ["type": "image_url", "image_url": ["url": "data:image/png;base64,AAAA"]],
            ],
        ]
        XCTAssertThrowsError(
            try decode(OpenAIAdapter(), ["model": "m", "messages": [block]]),
            "ein Bildblock ohne text-Feld muss abgewiesen werden, nicht stillschweigend verschwinden"
        ) { error in
            guard case GatewayServerError.unsupported = error else {
                return XCTFail("erwartet .unsupported, bekommen: \(error)")
            }
        }
    }

    func testBlockWithBothTextAndBinaryIsStillRejected() throws {
        // Der eigentliche M9-Fall: ein Bildblock, der zusaetzlich ein text-Feld
        // traegt, rutschte an der alten "hat kein text"-Pruefung vorbei und das
        // Binaere wurde still verworfen. Positive Erkennung faengt ihn.
        let block: [String: Any] = [
            "role": "user",
            "content": [
                ["type": "image_url", "text": "tarnung", "image_url": ["url": "data:image/png;base64,AAAA"]],
            ],
        ]
        XCTAssertThrowsError(try decode(OpenAIAdapter(), ["model": "m", "messages": [block]]),
                             "ein Binaerblock mit text-Feld darf nicht durchrutschen")
    }

    func testTextOnlyBlockArrayIsAccepted() throws {
        let block: [String: Any] = [
            "role": "user",
            "content": [["type": "text", "text": "Teil 1"], ["type": "text", "text": "Teil 2"]],
        ]
        let request = try decode(OpenAIAdapter(), ["model": "m", "messages": [block]])
        XCTAssertTrue(request.messages.first?.content.contains("Teil 1") ?? false)
        XCTAssertTrue(request.messages.first?.content.contains("Teil 2") ?? false)
    }
}

final class AdapterEncodeRoundTripTests: XCTestCase {

    // encodeResponse -> decodeResponse muss Inhalt, Modell und Usage tragen.
    // Geantwortet wird im Dialekt der Frage; der Round-Trip beweist, dass der
    // ausgehende Rahmen wieder lesbar ist.
    private func roundTrip(_ adapter: ProviderAdapter) throws -> ChatResponse {
        let original = ChatResponse(model: "m-1", content: "Hallo Welt",
                                    usage: TokenUsage(promptTokens: 11, completionTokens: 22))
        return try adapter.decodeResponse(try adapter.encodeResponse(original))
    }

    func testOpenAIResponseRoundTrips() throws {
        let r = try roundTrip(OpenAIAdapter())
        XCTAssertEqual(r.content, "Hallo Welt")
        XCTAssertEqual(r.usage, TokenUsage(promptTokens: 11, completionTokens: 22))
    }

    func testAnthropicResponseRoundTrips() throws {
        let r = try roundTrip(AnthropicAdapter())
        XCTAssertEqual(r.content, "Hallo Welt")
        XCTAssertEqual(r.usage, TokenUsage(promptTokens: 11, completionTokens: 22))
    }

    func testOllamaResponseRoundTrips() throws {
        let r = try roundTrip(OllamaAdapter())
        XCTAssertEqual(r.content, "Hallo Welt")
        XCTAssertEqual(r.usage, TokenUsage(promptTokens: 11, completionTokens: 22))
    }

    // Der ausgehende Stream-Delta muss vom eigenen streamDelta wieder als Text
    // gelesen werden koennen — sonst zerfaellt der Cache-Wiedergabe-Pfad.
    func testStreamDeltaIsReadableBackPerDialect() {
        for adapter in [OpenAIAdapter() as ProviderAdapter, AnthropicAdapter(), OllamaAdapter()] {
            let framed = adapter.encodeStreamDelta("Stueck", model: "m")
            // Die Rahmung (data:-Praefix bzw. Zeilen) wird vom Parser entfernt;
            // hier reicht die reine Nutzlast durch streamDelta.
            let payload = framed
                .replacingOccurrences(of: "data: ", with: "")
                .trimmingCharacters(in: .whitespacesAndNewlines)
            XCTAssertEqual(adapter.streamDelta(fromEventPayload: payload), "Stueck",
                           "\(type(of: adapter)) liest den eigenen Delta nicht zurueck")
        }
    }
}
