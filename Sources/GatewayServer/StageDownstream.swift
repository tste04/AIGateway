// Copyright (c) 2026 Tommy Stellmacher
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

import Foundation
import GatewayCore

// MARK: - Ziel: die naechste Stufe
//
// Im Zielbild liegt unter dem Gateway nicht der Modellanbieter, sondern die
// Policy Engine — und darunter erst Router, Orchestrator, Agent Loop. Der
// `ProviderDownstream` daneben ist die Abkuerzung fuer den Alleinbetrieb; DIES
// hier ist die Betriebsart, die ins Zielbild passt.
//
// Der Unterschied ist nicht die Adresse, sondern WAS uebergeben wird. Ein
// Provider bekommt eine Anfrage. Die naechste Stufe bekommt eine Anfrage PLUS
// das Urteil der Firewall — sonst muesste sie die Bewertung wiederholen, die
// hier bereits stattgefunden hat, und zwei Stellen entschieden ueber dieselbe
// Frage. Deshalb ist das Format kanonisch und providerfrei: `GatewayHandoff`
// als JSON, nicht der Dialekt irgendeines Anbieters.
//
// WAS NICHT MITGEHT: der `message`-Text der Befunde. Er ist Anzeigetext und
// darf laut Konvention frei umformuliert werden — eine Gegenstelle, die darauf
// prueft, bricht beim naechsten Textlauf. Uebergeben werden `rule`, `category`,
// `severity`, `weight` und `occurrences`: die maschinell auswertbaren Felder,
// dieselbe Linie wie beim `AuditEvent`.

/// Reicht die geprueften Anfragen an die naechste Stufe der Kette weiter.
public struct StageDownstream: Downstream {

    private let url: URL
    private let headers: [String: String]
    private let client: UpstreamClient

    /// - Parameters:
    ///   - url: Endpunkt der naechsten Stufe. Ein Pfad, beide Betriebsarten —
    ///     `stream` im Rumpf sagt, welche gemeint ist.
    ///   - headers: Zusaetzliche Kopfzeilen, etwa ein Dienst-Token. Der
    ///     Aufrufer setzt sie; diese Naht kennt kein Authentifizierungsschema,
    ///     weil sie keines erfinden soll.
    public init(url: URL, headers: [String: String] = [:],
                client: UpstreamClient = UpstreamClient()) {
        self.url = url
        self.headers = headers
        self.client = client
    }

    public func send(_ handoff: GatewayHandoff) async throws -> ChatResponse {
        let data = try await client.send(url: url, headers: headers,
                                         body: try Self.encode(handoff, stream: false))
        return try Self.decodeResponse(data)
    }

    @discardableResult
    public func stream(_ handoff: GatewayHandoff,
                       onDelta: @escaping @Sendable (String) -> Void) async throws -> TokenUsage? {
        let events = Self.collector()
        try await client.stream(url: url, headers: headers,
                                body: try Self.encode(handoff, stream: true)) { data in
            for text in events.consume(data) { onDelta(text) }
        }
        if let failure = events.pendingFailure() { throw failure }
        return events.reportedUsage()
    }

    /// Der Leser der Stufen-Seite: NDJSON statt SSE, weil die Gegenstelle ein
    /// Dienst ist, kein Browser — eine Zeile ist ein JSON-Objekt, das genuegt
    /// und spart die Rahmung. Unlesbare Zeilen werden uebersprungen, ein
    /// `{"error": ...}` wird gemerkt statt verschluckt.
    static func collector() -> StreamCollector {
        StreamCollector(framing: .newlineDelimitedJSON) { payload in
            guard let object = try? JSONSerialization.jsonObject(with: Data(payload.utf8))
                    as? [String: Any] else { return StreamCollector.Event() }
            if let message = object["error"] as? String {
                return StreamCollector.Event(failure: .upstream(status: 502, body: message))
            }
            return StreamCollector.Event(delta: object["delta"] as? String,
                                         usage: StageDownstream.usage(from: object["usage"]))
        }
    }

    // MARK: - Kanonische Form

    static func encode(_ handoff: GatewayHandoff, stream: Bool) throws -> Data {
        var request = handoff.request
        request.stream = stream

        var principal: [String: Any] = ["subject": handoff.principal.subject]
        if let tenant = handoff.principal.tenant { principal["tenant"] = tenant }
        if !handoff.principal.scopes.isEmpty {
            // Sortiert, damit derselbe Aufrufer dieselbe Zeile erzeugt — eine
            // Gegenstelle, die mitschreibt, soll nicht ueber Set-Reihenfolge
            // stolpern.
            principal["scopes"] = handoff.principal.scopes.sorted()
        }

        let findings: [[String: Any]] = handoff.findings.map { finding in
            [
                "rule": finding.ruleID.rawValue,
                "category": finding.category.rawValue,
                "severity": finding.severity.rawValue,
                "weight": finding.weight,
                "occurrences": finding.occurrences,
            ]
        }
        let verdict: [String: Any] = [
            "disposition": handoff.disposition.rawValue,
            "risk_score": handoff.riskScore,
            "findings": findings,
        ]

        // Maskiert und bereinigt — das ist der Stand, den die naechste Stufe
        // sehen darf, und der einzige, den sie bekommt.
        var payload: [String: Any] = [
            "model": request.model,
            "stream": request.stream,
            "messages": request.messages.map {
                ["role": $0.role.rawValue, "content": $0.content]
            },
        ]
        if let temperature = request.temperature { payload["temperature"] = temperature }
        if let maxTokens = request.maxTokens { payload["max_tokens"] = maxTokens }

        let body: [String: Any] = [
            "correlation_id": handoff.correlationID,
            "principal": principal,
            "verdict": verdict,
            "request": payload,
        ]
        return try JSONSerialization.data(withJSONObject: body, options: [.sortedKeys])
    }

    /// Liest die Antwort der naechsten Stufe.
    ///
    /// Tolerant wie die Provider-Adapter und aus demselben Grund: die Formate
    /// am Rand sind unregelmaessig, und ein strenger Decoder scheitert an
    /// einem zusaetzlichen Feld, statt die Antwort zu lesen, die da ist.
    static func decodeResponse(_ data: Data) throws -> ChatResponse {
        guard let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw GatewayServerError.malformedRequest("stage response is not a JSON object")
        }
        guard let content = object["content"] as? String else {
            throw GatewayServerError.malformedRequest("stage response has no 'content'")
        }
        return ChatResponse(model: object["model"] as? String ?? "",
                            content: content,
                            usage: usage(from: object["usage"]),
                            finishReason: object["finish_reason"] as? String)
    }

    static func usage(from value: Any?) -> TokenUsage? {
        (value as? [String: Any]).flatMap(TokenUsage.init(json:))
    }
}
