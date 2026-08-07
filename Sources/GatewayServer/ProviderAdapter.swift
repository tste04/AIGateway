// Copyright (c) 2026 Tommy Stellmacher
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

import Foundation
import GatewayCore

// MARK: - Provider-Naht
//
// Ein Adapter uebersetzt zwischen dem kanonischen Modell und genau einem
// Provider-Dialekt — in BEIDE Richtungen. Damit kann ein Client im
// OpenAI-Dialekt sprechen, waehrend das Gateway nach Anthropic weiterreicht,
// oder umgekehrt.
//
// JSON wird bewusst ueber `JSONSerialization` verarbeitet statt ueber je ein
// Codable-Modell pro Provider: die Formate sind unregelmaessig (Anthropic
// erlaubt String ODER Array als content, Ollama liefert NDJSON statt SSE), und
// tolerantes Lesen ist hier mehr wert als strenge Typisierung.

public enum ProviderKind: String, Sendable, Codable, CaseIterable {
    case openai, anthropic, ollama
}

/// Rahmung des Antwortstroms — nicht jeder Provider spricht SSE.
public enum StreamFraming: Sendable, Equatable {
    /// `data: {...}` je Ereignis, Abschluss mit `data: [DONE]`.
    case serverSentEvents
    /// Eine JSON-Zeile je Ereignis (Ollama).
    case newlineDelimitedJSON
}

public protocol ProviderAdapter: Sendable {
    var kind: ProviderKind { get }
    /// Eingehende Route, unter der dieser Dialekt bedient wird.
    var inboundPath: String { get }
    var framing: StreamFraming { get }

    func decodeRequest(_ data: Data) throws -> ChatRequest
    func encodeRequest(_ request: ChatRequest) throws -> Data
    func upstreamURL(base: URL) -> URL
    func authHeaders(apiKey: String?) -> [String: String]

    func decodeResponse(_ data: Data) throws -> ChatResponse
    func encodeResponse(_ response: ChatResponse) throws -> Data

    /// Zieht den Text-Zuwachs aus einer Ereignis-Nutzlast. `nil` = kein Text
    /// (Steuer-Ereignis, Abschluss, Heartbeat).
    func streamDelta(fromEventPayload payload: String) -> String?
    /// Baut eine Ereignis-Nutzlast fuer den ausgehenden Strom.
    func encodeStreamDelta(_ text: String, model: String) -> String
    /// Abschluss-Nutzlast des ausgehenden Stroms, falls der Dialekt eine kennt.
    func streamTerminator(model: String) -> String?

    /// Zieht gemeldeten Token-Verbrauch aus einer Ereignis-Nutzlast.
    ///
    /// Getrennt von `streamDelta`, weil beides in verschiedenen Ereignissen
    /// steht: Text kommt laufend, der Verbrauch erst am Ende — bei Anthropic
    /// sogar auf zwei Ereignisse verteilt. Teilmeldungen sind erlaubt, der
    /// Aufrufer vereinigt sie ueber `TokenUsage.merging`.
    func streamUsage(fromEventPayload payload: String) -> TokenUsage?

    /// Baut ein Fehler-Ereignis fuer den AUSGEHENDEN Strom.
    ///
    /// Noetig, weil ein Upstream-Fehler nach `beginStream` nicht mehr als
    /// HTTP-Status ausdrueckbar ist — der Client muss den Fehler im Strom
    /// selbst erfahren, sonst sieht ein Abbruch wie eine vollstaendige
    /// Antwort aus.
    func encodeStreamError(_ message: String) -> String

    /// Erkennt ein FEHLER-Ereignis im EINGEHENDEN Upstream-Strom.
    ///
    /// Ein Provider kann auf eine Stream-Anfrage mit HTTP 200 antworten und den
    /// Fehler dann als In-Band-Ereignis schicken (`{"error": …}`). Ohne diese
    /// Erkennung liefe der Strom leer aus und der Abbruch saehe fuer den Client
    /// wie eine vollstaendige Antwort aus — samt falschem `status: 200` im
    /// Audit. `nil` = kein Fehler in dieser Nutzlast.
    func streamFailure(fromEventPayload payload: String) -> GatewayServerError?
}

public extension ProviderAdapter {
    /// Nicht jeder Dialekt meldet Verbrauch im Strom. Wer nichts meldet,
    /// liefert `nil` — geschaetzt wird nie.
    func streamUsage(fromEventPayload payload: String) -> TokenUsage? { nil }

    /// Generische Form fuer Dialekte ohne eigenes Fehlerformat.
    func encodeStreamError(_ message: String) -> String {
        JSONHelper.compactJSONLine(["error": message])
    }

    /// Deckt alle drei mitgelieferten Dialekte ab: OpenAI und Anthropic tragen
    /// den Fehler als Objekt (`{"error":{"message":…}}` bzw.
    /// `{"type":"error","error":{"message":…}}`), Ollama als String
    /// (`{"error":"…"}`). Der HTTP-Status ist hier nicht bekannt (die Antwort
    /// WAR 200), deshalb `status: 0`; der Antwortpfad macht daraus einen 502.
    func streamFailure(fromEventPayload payload: String) -> GatewayServerError? {
        guard let data = payload.data(using: .utf8),
              let dict = try? JSONHelper.object(data) else { return nil }
        if let message = dict["error"] as? String {
            return .upstream(status: 0, body: message)
        }
        if let error = dict["error"] as? [String: Any] {
            return .upstream(status: 0, body: error["message"] as? String ?? "upstream stream error")
        }
        return nil
    }
}

// MARK: - Hilfen

enum JSONHelper {
    static func object(_ data: Data) throws -> [String: Any] {
        guard let any = try? JSONSerialization.jsonObject(with: data),
              let dict = any as? [String: Any] else {
            throw GatewayServerError.malformedRequest("body is not a JSON object")
        }
        return dict
    }

    /// Fail-closed statt still veraendern: Felder, deren Verlust die Semantik
    /// der Anfrage aendert (Tool-Definitionen, erzwungene Antwortformate),
    /// werden ABGEWIESEN. Das kanonische Modell traegt sie nicht — ein
    /// Gateway, das sie kommentarlos entfernt, wuerde aus einem Agent-Request
    /// einen Chat-Request machen und die Antwort saehe trotzdem gueltig aus.
    /// Kosmetische Extras (z. B. `user`, `stream_options`) bleiben erlaubt.
    static func rejectSemanticFields(_ dict: [String: Any], _ fields: [String]) throws {
        if let present = fields.first(where: { dict[$0] != nil }) {
            throw GatewayServerError.unsupported(
                "field '\(present)' is not supported: this gateway forwards chat text only "
                + "and refuses to silently strip semantics-changing fields")
        }
    }

    static func data(_ object: [String: Any]) throws -> Data {
        try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
    }

    static func compactJSONLine(_ object: [String: Any]) -> String {
        (try? String(data: JSONSerialization.data(withJSONObject: object, options: [.sortedKeys]),
                     encoding: .utf8)) as? String ?? "{}"
    }

    /// Anthropic erlaubt `content` als String ODER als Block-Array. Beides lesen.
    static func flattenContent(_ value: Any?) -> String {
        if let s = value as? String { return s }
        if let blocks = value as? [[String: Any]] {
            return blocks.compactMap { $0["text"] as? String }.joined()
        }
        return ""
    }

    /// Traegt der Inhalt Bloecke, die `flattenContent` nicht abbildet?
    ///
    /// Bilder und andere Binaerbloecke sind genau der Fall: sie verschwaenden
    /// beim Flachklopfen spurlos. Ein still verworfener Bildanhang ist
    /// dieselbe Fehlerklasse wie ein still entferntes `tools` — der Aufrufer
    /// bekaeme eine Antwort auf eine ANDERE Anfrage als die gestellte.
    /// Bekannte Binaer-Blocktypen der drei Dialekte. Erweitern ist ungefaehrlich
    /// (fail-closed), Weglassen liesse einen Anhang still verschwinden.
    static let binaryBlockTypes: Set<String> = [
        "image", "image_url", "input_image", "file", "input_file",
        "audio", "input_audio", "document", "video",
    ]

    /// Erkennt Binaerbloecke POSITIV an ihrem Typ oder ihren Containern — nicht
    /// negativ am fehlenden `text`. Der Unterschied ist der Angriff: ein Block
    /// mit BEIDEM (`{"type":"image_url","text":"…","image_url":{…}}`) traegt ein
    /// `text`-Feld und rutschte an einer „hat kein text"-Pruefung vorbei; das
    /// Binaere wuerde still verworfen, und der Aufrufer bekaeme eine Antwort auf
    /// eine andere Anfrage als die gestellte.
    static func carriesNonTextBlocks(_ value: Any?) -> Bool {
        guard let blocks = value as? [[String: Any]] else { return false }
        return blocks.contains { block in
            if let type = block["type"] as? String, binaryBlockTypes.contains(type) { return true }
            // Auch ohne bekannten `type`: die verraeterischen Container.
            return block["image_url"] != nil || block["source"] != nil
                || block["input_image"] != nil || block["file"] != nil
                || block["audio"] != nil || block["data"] != nil
        }
    }

    static func messages(from raw: Any?) throws -> [ChatMessage] {
        guard let array = raw as? [[String: Any]] else { return [] }
        return try array.compactMap { entry in
            guard let roleRaw = entry["role"] as? String else { return nil }
            guard !carriesNonTextBlocks(entry["content"]) else {
                throw GatewayServerError.unsupported(
                    "this gateway forwards text only; it does not yet carry binary content "
                    + "blocks and refuses to silently drop them")
            }
            let role = ChatMessage.Role(rawValue: roleRaw) ?? .user
            return ChatMessage(role: role, content: flattenContent(entry["content"]))
        }
    }
}

// MARK: - OpenAI

public struct OpenAIAdapter: ProviderAdapter {
    public let kind = ProviderKind.openai
    public let inboundPath = "/v1/chat/completions"
    public let framing = StreamFraming.serverSentEvents

    public init() {}

    public func decodeRequest(_ data: Data) throws -> ChatRequest {
        let dict = try JSONHelper.object(data)
        try JSONHelper.rejectSemanticFields(
            dict, ["tools", "tool_choice", "functions", "function_call", "response_format"])
        guard let model = dict["model"] as? String else {
            throw GatewayServerError.malformedRequest("missing 'model'")
        }
        let messages = try JSONHelper.messages(from: dict["messages"])
        guard !messages.isEmpty else {
            throw GatewayServerError.malformedRequest("missing 'messages'")
        }
        return ChatRequest(model: model, messages: messages,
                           stream: dict["stream"] as? Bool ?? false,
                           temperature: dict["temperature"] as? Double,
                           maxTokens: dict["max_tokens"] as? Int)
    }

    public func encodeRequest(_ request: ChatRequest) throws -> Data {
        var dict: [String: Any] = [
            "model": request.model,
            "messages": request.messages.map { ["role": $0.role.rawValue, "content": $0.content] },
            "stream": request.stream,
        ]
        if let t = request.temperature { dict["temperature"] = t }
        if let m = request.maxTokens { dict["max_tokens"] = m }
        return try JSONHelper.data(dict)
    }

    public func upstreamURL(base: URL) -> URL {
        base.appendingPathComponent("v1/chat/completions")
    }

    public func authHeaders(apiKey: String?) -> [String: String] {
        guard let apiKey else { return [:] }
        return ["Authorization": "Bearer \(apiKey)"]
    }

    public func decodeResponse(_ data: Data) throws -> ChatResponse {
        let dict = try JSONHelper.object(data)
        let choices = dict["choices"] as? [[String: Any]] ?? []
        let message = choices.first?["message"] as? [String: Any]
        return ChatResponse(
            model: dict["model"] as? String ?? "",
            content: JSONHelper.flattenContent(message?["content"]),
            usage: (dict["usage"] as? [String: Any]).flatMap(TokenUsage.init(json:)),
            finishReason: choices.first?["finish_reason"] as? String)
    }

    public func encodeResponse(_ response: ChatResponse) throws -> Data {
        var dict: [String: Any] = [
            "id": "chatcmpl-gateway",
            "object": "chat.completion",
            "model": response.model,
            "choices": [[
                "index": 0,
                "message": ["role": "assistant", "content": response.content],
                "finish_reason": response.finishReason ?? "stop",
            ]],
        ]
        if let u = response.usage {
            dict["usage"] = [
                "prompt_tokens": u.promptTokens,
                "completion_tokens": u.completionTokens,
                "total_tokens": u.promptTokens + u.completionTokens,
            ]
        }
        return try JSONHelper.data(dict)
    }

    public func streamDelta(fromEventPayload payload: String) -> String? {
        guard payload != "[DONE]", let data = payload.data(using: .utf8),
              let dict = try? JSONHelper.object(data),
              let choices = dict["choices"] as? [[String: Any]],
              let delta = choices.first?["delta"] as? [String: Any] else { return nil }
        let text = JSONHelper.flattenContent(delta["content"])
        return text.isEmpty ? nil : text
    }

    public func encodeStreamDelta(_ text: String, model: String) -> String {
        JSONHelper.compactJSONLine([
            "id": "chatcmpl-gateway",
            "object": "chat.completion.chunk",
            "model": model,
            "choices": [["index": 0, "delta": ["content": text]]],
        ])
    }

    public func streamTerminator(model: String) -> String? { "[DONE]" }

    /// OpenAI haengt den Verbrauch an den letzten Chunk (nur mit
    /// `stream_options.include_usage`); dessen `choices` sind dann leer.
    public func streamUsage(fromEventPayload payload: String) -> TokenUsage? {
        guard payload != "[DONE]", let data = payload.data(using: .utf8),
              let dict = try? JSONHelper.object(data),
              let usage = dict["usage"] as? [String: Any] else { return nil }
        return TokenUsage(json: usage)
    }

    public func encodeStreamError(_ message: String) -> String {
        JSONHelper.compactJSONLine(["error": ["message": message, "type": "upstream_error"]])
    }
}

// MARK: - Anthropic

public struct AnthropicAdapter: ProviderAdapter {
    public let kind = ProviderKind.anthropic
    public let inboundPath = "/v1/messages"
    public let framing = StreamFraming.serverSentEvents

    /// Anthropic verlangt `max_tokens`. Fehlt es, muss das Gateway etwas setzen.
    public let defaultMaxTokens: Int

    public init(defaultMaxTokens: Int = 4096) {
        self.defaultMaxTokens = defaultMaxTokens
    }

    public func decodeRequest(_ data: Data) throws -> ChatRequest {
        let dict = try JSONHelper.object(data)
        try JSONHelper.rejectSemanticFields(dict, ["tools", "tool_choice"])
        guard let model = dict["model"] as? String else {
            throw GatewayServerError.malformedRequest("missing 'model'")
        }
        var messages: [ChatMessage] = []
        // Anthropic fuehrt die Systemanweisung getrennt — kanonisch wird sie
        // zur ersten Nachricht, damit die Firewall sie ueberhaupt sieht.
        let system = JSONHelper.flattenContent(dict["system"])
        if !system.isEmpty { messages.append(ChatMessage(role: .system, content: system)) }
        messages += try JSONHelper.messages(from: dict["messages"])
        guard messages.contains(where: { $0.role != .system }) else {
            throw GatewayServerError.malformedRequest("missing 'messages'")
        }
        return ChatRequest(model: model, messages: messages,
                           stream: dict["stream"] as? Bool ?? false,
                           temperature: dict["temperature"] as? Double,
                           maxTokens: dict["max_tokens"] as? Int)
    }

    public func encodeRequest(_ request: ChatRequest) throws -> Data {
        let system = request.messages.filter { $0.role == .system }.map(\.content).joined(separator: "\n")
        let rest = request.messages.filter { $0.role != .system }
        var dict: [String: Any] = [
            "model": request.model,
            "max_tokens": request.maxTokens ?? defaultMaxTokens,
            "messages": rest.map { ["role": $0.role == .assistant ? "assistant" : "user",
                                    "content": $0.content] },
            "stream": request.stream,
        ]
        if !system.isEmpty { dict["system"] = system }
        if let t = request.temperature { dict["temperature"] = t }
        return try JSONHelper.data(dict)
    }

    public func upstreamURL(base: URL) -> URL {
        base.appendingPathComponent("v1/messages")
    }

    public func authHeaders(apiKey: String?) -> [String: String] {
        var headers = ["anthropic-version": "2023-06-01"]
        if let apiKey { headers["x-api-key"] = apiKey }
        return headers
    }

    public func decodeResponse(_ data: Data) throws -> ChatResponse {
        let dict = try JSONHelper.object(data)
        let usage = dict["usage"] as? [String: Any]
        return ChatResponse(
            model: dict["model"] as? String ?? "",
            content: JSONHelper.flattenContent(dict["content"]),
            usage: usage.map {
                TokenUsage(promptTokens: $0["input_tokens"] as? Int ?? 0,
                           completionTokens: $0["output_tokens"] as? Int ?? 0)
            },
            finishReason: dict["stop_reason"] as? String)
    }

    public func encodeResponse(_ response: ChatResponse) throws -> Data {
        var dict: [String: Any] = [
            "id": "msg_gateway",
            "type": "message",
            "role": "assistant",
            "model": response.model,
            "content": [["type": "text", "text": response.content]],
            "stop_reason": response.finishReason ?? "end_turn",
        ]
        if let u = response.usage {
            dict["usage"] = ["input_tokens": u.promptTokens, "output_tokens": u.completionTokens]
        }
        return try JSONHelper.data(dict)
    }

    public func streamDelta(fromEventPayload payload: String) -> String? {
        guard let data = payload.data(using: .utf8),
              let dict = try? JSONHelper.object(data),
              dict["type"] as? String == "content_block_delta",
              let delta = dict["delta"] as? [String: Any],
              let text = delta["text"] as? String, !text.isEmpty else { return nil }
        return text
    }

    public func encodeStreamDelta(_ text: String, model: String) -> String {
        JSONHelper.compactJSONLine([
            "type": "content_block_delta",
            "index": 0,
            "delta": ["type": "text_delta", "text": text],
        ])
    }

    public func streamTerminator(model: String) -> String? {
        JSONHelper.compactJSONLine(["type": "message_stop"])
    }

    /// Anthropic meldet den Verbrauch auf ZWEI Ereignisse verteilt: die Eingabe
    /// im `message_start`, die Ausgabe im abschliessenden `message_delta`.
    /// Beides sind Teilmeldungen — der Aufrufer vereinigt sie.
    public func streamUsage(fromEventPayload payload: String) -> TokenUsage? {
        guard let data = payload.data(using: .utf8),
              let dict = try? JSONHelper.object(data) else { return nil }
        let reported: [String: Any]?
        switch dict["type"] as? String {
        case "message_start":
            reported = (dict["message"] as? [String: Any])?["usage"] as? [String: Any]
        case "message_delta":
            reported = dict["usage"] as? [String: Any]
        default:
            reported = nil
        }
        guard let usage = reported else { return nil }
        return TokenUsage(promptTokens: usage["input_tokens"] as? Int ?? 0,
                          completionTokens: usage["output_tokens"] as? Int ?? 0)
    }

    public func encodeStreamError(_ message: String) -> String {
        JSONHelper.compactJSONLine([
            "type": "error",
            "error": ["type": "api_error", "message": message],
        ])
    }
}

// MARK: - Ollama

public struct OllamaAdapter: ProviderAdapter {
    public let kind = ProviderKind.ollama
    public let inboundPath = "/api/chat"
    /// Ollama sendet zeilengetrenntes JSON, KEIN SSE.
    public let framing = StreamFraming.newlineDelimitedJSON

    public init() {}

    public func decodeRequest(_ data: Data) throws -> ChatRequest {
        let dict = try JSONHelper.object(data)
        try JSONHelper.rejectSemanticFields(dict, ["tools", "format"])
        guard let model = dict["model"] as? String else {
            throw GatewayServerError.malformedRequest("missing 'model'")
        }
        let messages = try JSONHelper.messages(from: dict["messages"])
        guard !messages.isEmpty else {
            throw GatewayServerError.malformedRequest("missing 'messages'")
        }
        let options = dict["options"] as? [String: Any]
        return ChatRequest(model: model, messages: messages,
                           stream: dict["stream"] as? Bool ?? true,   // Ollama streamt per Default
                           temperature: options?["temperature"] as? Double,
                           maxTokens: options?["num_predict"] as? Int)
    }

    public func encodeRequest(_ request: ChatRequest) throws -> Data {
        var dict: [String: Any] = [
            "model": request.model,
            "messages": request.messages.map { ["role": $0.role.rawValue, "content": $0.content] },
            "stream": request.stream,
        ]
        var options: [String: Any] = [:]
        if let t = request.temperature { options["temperature"] = t }
        if let m = request.maxTokens { options["num_predict"] = m }
        if !options.isEmpty { dict["options"] = options }
        return try JSONHelper.data(dict)
    }

    public func upstreamURL(base: URL) -> URL {
        base.appendingPathComponent("api/chat")
    }

    /// Lokal, kein Schluessel. Wer Ollama hinter einem Proxy betreibt, ergaenzt
    /// den Header selbst.
    public func authHeaders(apiKey: String?) -> [String: String] {
        guard let apiKey else { return [:] }
        return ["Authorization": "Bearer \(apiKey)"]
    }

    public func decodeResponse(_ data: Data) throws -> ChatResponse {
        let dict = try JSONHelper.object(data)
        let message = dict["message"] as? [String: Any]
        let prompt = dict["prompt_eval_count"] as? Int
        let completion = dict["eval_count"] as? Int
        return ChatResponse(
            model: dict["model"] as? String ?? "",
            content: JSONHelper.flattenContent(message?["content"]),
            usage: (prompt != nil || completion != nil)
                ? TokenUsage(promptTokens: prompt ?? 0, completionTokens: completion ?? 0)
                : nil,
            finishReason: dict["done_reason"] as? String)
    }

    public func encodeResponse(_ response: ChatResponse) throws -> Data {
        var dict: [String: Any] = [
            "model": response.model,
            "message": ["role": "assistant", "content": response.content],
            "done": true,
        ]
        if let u = response.usage {
            dict["prompt_eval_count"] = u.promptTokens
            dict["eval_count"] = u.completionTokens
        }
        return try JSONHelper.data(dict)
    }

    public func streamDelta(fromEventPayload payload: String) -> String? {
        guard let data = payload.data(using: .utf8),
              let dict = try? JSONHelper.object(data),
              let message = dict["message"] as? [String: Any] else { return nil }
        let text = JSONHelper.flattenContent(message["content"])
        return text.isEmpty ? nil : text
    }

    public func encodeStreamDelta(_ text: String, model: String) -> String {
        JSONHelper.compactJSONLine([
            "model": model,
            "message": ["role": "assistant", "content": text],
            "done": false,
        ])
    }

    public func streamTerminator(model: String) -> String? {
        JSONHelper.compactJSONLine(["model": model, "done": true])
    }

    /// Ollama meldet den Verbrauch im abschliessenden Objekt (`done: true`).
    public func streamUsage(fromEventPayload payload: String) -> TokenUsage? {
        guard let data = payload.data(using: .utf8),
              let dict = try? JSONHelper.object(data),
              dict["done"] as? Bool == true else { return nil }
        let prompt = dict["prompt_eval_count"] as? Int
        let completion = dict["eval_count"] as? Int
        guard prompt != nil || completion != nil else { return nil }
        return TokenUsage(promptTokens: prompt ?? 0, completionTokens: completion ?? 0)
    }

    public func encodeStreamError(_ message: String) -> String {
        JSONHelper.compactJSONLine(["error": message, "done": true])
    }
}

// MARK: - Registrierung

public enum Providers {
    public static let all: [ProviderAdapter] = [
        OpenAIAdapter(), AnthropicAdapter(), OllamaAdapter(),
    ]

    public static func adapter(for kind: ProviderKind) -> ProviderAdapter {
        switch kind {
        case .openai: return OpenAIAdapter()
        case .anthropic: return AnthropicAdapter()
        case .ollama: return OllamaAdapter()
        }
    }

    /// Adapter zu einer eingehenden Route.
    public static func adapter(forPath path: String) -> ProviderAdapter? {
        all.first { $0.inboundPath == path }
    }
}
