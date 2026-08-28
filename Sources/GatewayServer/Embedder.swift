// Copyright (c) 2026 Tommy Stellmacher
// SPDX-License-Identifier: Apache-2.0

import Foundation
import GatewayCore

// MARK: - Einbettung fuer die zweite Cache-Stufe
//
// Nach DECISIONS (Grundentscheidung 3): API-foermig und lokal lauffaehig. Eine
// HTTP-Implementierung mit konfigurierbarer Basis-URL — Ollama auf derselben
// Maschine oder eine Cloud-API, das ist Betreiberwahl. Kein Modell im Prozess:
// das waere eine Abhaengigkeit, und der Kern bleibt netzfrei.
//
// Der Embedder ist OPTIONAL. Ohne ihn arbeitet der Cache nur mit exakten
// Treffern — das ist der wertvollere Teil und kostet nichts. Die semantische
// Stufe ist der Aufschlag, nicht die Grundlage.

public protocol Embedder: Sendable {
    /// Vektor zu einem Text. Wirft, wenn der Dienst nicht erreichbar ist —
    /// der Aufrufer faellt dann auf exakte Treffer zurueck.
    func embed(_ text: String) async throws -> [Double]
}

/// Holt Vektoren ueber HTTP.
///
/// Liest die drei gaengigen Antwortformen tolerant, aus demselben Grund wie
/// die Provider-Adapter: die Formate sind unregelmaessig, und ein neuer
/// Dienst soll keinen Eingriff erzwingen.
///
///   Ollama (aelter):  `{"embedding": [...]}`
///   Ollama (neuer):   `{"embeddings": [[...]]}`
///   OpenAI-foermig:   `{"data": [{"embedding": [...]}]}`
public struct HTTPEmbedder: Embedder {

    private let url: URL
    private let model: String
    private let apiKey: String?
    private let client: UpstreamClient

    /// - Parameters:
    ///   - baseURL: Basis des Dienstes, z. B. `http://127.0.0.1:11434`.
    ///   - path: Endpunkt unterhalb der Basis. Default ist Ollamas Pfad.
    ///   - model: Einbettungs-Modell.
    ///   - timeout: knapp gehalten — der Cache liegt im synchronen Pfad, und
    ///     ein langsamer Embedder darf die Anfrage nicht teurer machen als der
    ///     Modellaufruf, den er einspart.
    public init(baseURL: URL,
                path: String = "api/embeddings",
                model: String = "nomic-embed-text",
                apiKey: String? = nil,
                timeout: TimeInterval = 2) {
        self.url = baseURL.appendingPathComponent(path)
        self.model = model
        self.apiKey = apiKey
        self.client = UpstreamClient(timeout: timeout)
    }

    public func embed(_ text: String) async throws -> [Double] {
        // `prompt` bedient Ollama, `input` die OpenAI-foermigen Dienste. Beide
        // zu senden ist harmlos: jeder liest das Feld, das er kennt.
        let body = try JSONHelper.data(["model": model, "prompt": text, "input": text])
        var headers: [String: String] = [:]
        if let apiKey { headers["Authorization"] = "Bearer \(apiKey)" }

        let data = try await client.send(url: url, headers: headers, body: body)
        guard let vector = Self.vector(from: try JSONHelper.object(data)) else {
            throw GatewayServerError.upstream(status: 0, body: "embedding response has no vector")
        }
        return vector
    }

    static func vector(from dict: [String: Any]) -> [Double]? {
        if let flat = doubles(from: dict["embedding"]) { return flat }
        if let nested = (dict["embeddings"] as? [Any])?.first, let v = doubles(from: nested) { return v }
        if let entry = (dict["data"] as? [[String: Any]])?.first,
           let v = doubles(from: entry["embedding"]) {
            return v
        }
        return nil
    }

    /// Liest ein Zahlen-Array, egal ob JSONSerialization es als `[Double]` oder
    /// — auf Linux haeufig — als `[NSNumber]` geliefert hat. `nil` bei leer oder
    /// Nicht-Array. Frueher deckte der NSNumber-Fallback nur den flachen
    /// `embedding`-Zweig ab; die neueren `embeddings`- und `data`-Formen fielen
    /// auf Linux durch, der Sicherungsschalter feuerte, obwohl der Dienst
    /// korrekt geantwortet hatte.
    static func doubles(from value: Any?) -> [Double]? {
        if let d = value as? [Double], !d.isEmpty { return d }
        if let n = value as? [NSNumber], !n.isEmpty { return n.map(\.doubleValue) }
        return nil
    }
}

// MARK: - Aehnlichkeit

enum VectorMath {

    /// Kosinus-Aehnlichkeit. `nil`, wenn die Vektoren nicht vergleichbar sind
    /// (verschiedene Laenge, Nullvektor) — dann gibt es keinen Treffer, statt
    /// einer erfundenen Zahl.
    static func cosineSimilarity(_ a: [Double], _ b: [Double]) -> Double? {
        guard a.count == b.count, !a.isEmpty else { return nil }
        var dot = 0.0, normA = 0.0, normB = 0.0
        for index in 0..<a.count {
            dot += a[index] * b[index]
            normA += a[index] * a[index]
            normB += b[index] * b[index]
        }
        guard normA > 0, normB > 0 else { return nil }
        return dot / (normA.squareRoot() * normB.squareRoot())
    }
}
