// Copyright (c) 2026 Tommy Stellmacher
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

import Foundation
import GatewayCore

// MARK: - Kanonisches Modell
//
// Drei Provider-Dialekte, eine interne Form. Ohne diese Zwischenschicht muesste
// jede Firewall-Stufe drei JSON-Formate kennen — und jeder neue Provider
// brauchte einen Eingriff in die Sicherheitslogik. Adapter uebersetzen an den
// Raendern, die Mitte bleibt neutral.

public struct ChatMessage: Sendable, Codable, Equatable {
    public enum Role: String, Sendable, Codable {
        case system, user, assistant, tool
    }

    public var role: Role
    public var content: String

    public init(role: Role, content: String) {
        self.role = role
        self.content = content
    }
}

/// Ein binaerer Anhang.
///
/// Die Angriffsflaeche der Malware-Stufe. `mediaType` und `name` sind
/// BEHAUPTUNGEN des Aufrufers und werden nie geglaubt — ihr Wert liegt darin,
/// sie gegen den tatsaechlichen Inhalt zu pruefen.
public struct Attachment: Sendable, Codable, Equatable {
    public var name: String?
    public var mediaType: String?
    public var bytes: Data

    public init(name: String? = nil, mediaType: String? = nil, bytes: Data) {
        self.name = name
        self.mediaType = mediaType
        self.bytes = bytes
    }
}

public struct ChatRequest: Sendable, Codable, Equatable {
    public var model: String
    public var messages: [ChatMessage]
    public var stream: Bool
    public var temperature: Double?
    public var maxTokens: Int?
    /// Binaere Anhaenge. Werden von den HTTP-Adaptern derzeit NICHT befuellt:
    /// die Dialekte tragen Bilder in Inhaltsblöcken, und die weiterzureichen
    /// waere echte Multimodalitaet, die dieses Repo noch nicht baut. Statt sie
    /// still fallen zu lassen, weisen die Adapter solche Anfragen ab. Wer die
    /// Bibliothek direkt benutzt, fuellt das Feld selbst — und bekommt damit
    /// die Malware-Stufe.
    public var attachments: [Attachment]

    public init(model: String, messages: [ChatMessage], stream: Bool = false,
                temperature: Double? = nil, maxTokens: Int? = nil,
                attachments: [Attachment] = []) {
        self.model = model
        self.messages = messages
        self.stream = stream
        self.temperature = temperature
        self.maxTokens = maxTokens
        self.attachments = attachments
    }

    /// Der Text, den die Firewall pruefen muss: alles, was ein Modell als
    /// Anweisung lesen koennte. Systemnachrichten gehoeren dazu — gerade sie
    /// sind das Ziel einer Injection.
    public var scannableText: String {
        messages.map(\.content).joined(separator: "\n")
    }

    /// Die letzte Nutzerfrage. Fuer Bibliotheks-Aufrufer, die `PIIGate` mit
    /// `sparingQuery` betreiben (Frage und Bestand getrennt). Die Pipeline
    /// selbst maskiert OHNE Schonung — siehe Begruendung in `GatewayPipeline`.
    public var lastUserMessage: String? {
        messages.last { $0.role == .user }?.content
    }

    /// Wendet eine Transformation auf jeden Nachrichteninhalt an (Maskierung).
    public func mappingContents(_ transform: (String) -> String) -> ChatRequest {
        var copy = self
        copy.messages = messages.map { ChatMessage(role: $0.role, content: transform($0.content)) }
        return copy
    }
}

public struct ChatResponse: Sendable, Codable, Equatable {
    public var model: String
    public var content: String
    public var usage: TokenUsage?
    public var finishReason: String?

    public init(model: String, content: String, usage: TokenUsage? = nil,
                finishReason: String? = nil) {
        self.model = model
        self.content = content
        self.usage = usage
        self.finishReason = finishReason
    }
}

public enum GatewayServerError: Error, Sendable, Equatable {
    case malformedRequest(String)
    case upstream(status: Int, body: String)
    case unsupported(String)
}
