// Copyright (c) 2026 Tommy Stellmacher
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

import Foundation

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

    static func messages(from raw: Any?) -> [ChatMessage] {
        guard let array = raw as? [[String: Any]] else { return [] }
        return array.compactMap { entry in
            guard let roleRaw = entry["role"] as? String else { return nil }
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
        guard let model = dict["model"] as? String else {
            throw GatewayServerError.malformedRequest("missing 'model'")
        }
        let messages = JSONHelper.messages(from: dict["messages"])
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
        let usage = dict["usage"] as? [String: Any]
        return ChatResponse(
            model: dict["model"] as? String ?? "",
            content: JSONHelper.flattenContent(message?["content"]),
            usage: usage.map {
                TokenUsage(promptTokens: $0["prompt_tokens"] as? Int ?? 0,
                           completionTokens: $0["completion_tokens"] as? Int ?? 0)
            },
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
        guard let model = dict["model"] as? String else {
            throw GatewayServerError.malformedRequest("missing 'model'")
        }
        var messages: [ChatMessage] = []
        // Anthropic fuehrt die Systemanweisung getrennt — kanonisch wird sie
        // zur ersten Nachricht, damit die Firewall sie ueberhaupt sieht.
        let system = JSONHelper.flattenContent(dict["system"])
        if !system.isEmpty { messages.append(ChatMessage(role: .system, content: system)) }
        messages += JSONHelper.messages(from: dict["messages"])
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
        guard let model = dict["model"] as? String else {
            throw GatewayServerError.malformedRequest("missing 'model'")
        }
        let messages = JSONHelper.messages(from: dict["messages"])
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
