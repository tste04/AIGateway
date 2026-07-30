// Copyright (c) 2026 Tommy Stellmacher
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

// MARK: - Weg nach oben
//
// Ausgehend darf `URLSession` verwendet werden: sie gehoert zur Toolchain und
// ist keine externe Abhaengigkeit. Nur EINGEHEND wird selbst gebaut, weil dort
// TLS-Terminierung und Protokoll-Details sonst zu Fremdcode zwingen wuerden.
//
// Streaming laeuft ueber die Delegate-Schnittstelle statt ueber
// `URLSession.bytes(for:)` — letztere ist auf aelteren Linux-Foundation-
// Versionen nicht verfuegbar, die Delegate-Form ueberall.

public struct UpstreamClient: Sendable {

    public let timeout: TimeInterval

    public init(timeout: TimeInterval = 120) {
        self.timeout = timeout
    }

    private func request(url: URL, headers: [String: String], body: Data) -> URLRequest {
        var req = URLRequest(url: url)
        req.httpMethod = "POST"
        req.httpBody = body
        req.timeoutInterval = timeout
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        for (key, value) in headers { req.setValue(value, forHTTPHeaderField: key) }
        return req
    }

    /// Einmalige Antwort.
    public func send(url: URL, headers: [String: String], body: Data) async throws -> Data {
        let (data, response) = try await dataTask(request(url: url, headers: headers, body: body))
        let status = (response as? HTTPURLResponse)?.statusCode ?? 0
        guard (200...299).contains(status) else {
            throw GatewayServerError.upstream(
                status: status, body: String(data: data, encoding: .utf8) ?? "")
        }
        return data
    }

    /// Antwortstrom. `onChunk` wird auf einem Hintergrund-Thread aufgerufen.
    public func stream(url: URL, headers: [String: String], body: Data,
                       onChunk: @escaping @Sendable (Data) -> Void) async throws {
        let req = request(url: url, headers: headers, body: body)
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            let delegate = StreamDelegate(onChunk: onChunk) { error in
                if let error { continuation.resume(throwing: error) }
                else { continuation.resume() }
            }
            let session = URLSession(configuration: .default, delegate: delegate, delegateQueue: nil)
            session.dataTask(with: req).resume()
        }
    }

    private func dataTask(_ request: URLRequest) async throws -> (Data, URLResponse) {
        try await withCheckedThrowingContinuation { continuation in
            URLSession.shared.dataTask(with: request) { data, response, error in
                if let error { return continuation.resume(throwing: error) }
                guard let data, let response else {
                    return continuation.resume(
                        throwing: GatewayServerError.upstream(status: 0, body: "empty response"))
                }
                continuation.resume(returning: (data, response))
            }.resume()
        }
    }
}

/// Reicht eintreffende Bruchstuecke sofort weiter, statt sie zu sammeln.
private final class StreamDelegate: NSObject, URLSessionDataDelegate, @unchecked Sendable {
    private let onChunk: @Sendable (Data) -> Void
    private let onFinish: @Sendable (Error?) -> Void
    private var finished = false
    private let lock = NSLock()

    init(onChunk: @escaping @Sendable (Data) -> Void,
         onFinish: @escaping @Sendable (Error?) -> Void) {
        self.onChunk = onChunk
        self.onFinish = onFinish
    }

    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive data: Data) {
        onChunk(data)
    }

    func urlSession(_ session: URLSession, task: URLSessionTask, didCompleteWithError error: Error?) {
        // Genau einmal aufloesen — sonst bricht die Continuation.
        lock.lock(); defer { lock.unlock() }
        guard !finished else { return }
        finished = true
        onFinish(error)
        session.finishTasksAndInvalidate()
    }
}

// MARK: - Ereignis-Zerlegung

/// Zerlegt einen Byte-Strom in Ereignis-Nutzlasten. Beherrscht beide Rahmungen:
/// SSE (`data: {...}`) und zeilengetrenntes JSON (Ollama).
///
/// Puffert unvollstaendige Zeilen — ein Ereignis darf ueber Chunk-Grenzen
/// zerfallen, genau wie ein Platzhalter im `StreamRewriter`.
///
/// Gepuffert wird auf BYTES, nicht auf einem String. `String(decoding: data,
/// as: UTF8.self)` je Netz-Chunk waere ein Datenfehler: URLSession liefert die
/// Bruchstuecke an beliebigen TCP-Grenzen, und endet ein Chunk mitten in einer
/// Mehrbyte-Sequenz (Umlaut, Emoji), ersetzte das Dekodieren sie durch U+FFFD
/// — die Fortsetzungsbytes des naechsten Chunks ebenso. Erst an der
/// Zeilengrenze (0x0A, immer ein einzelnes ASCII-Byte, das keine Sequenz
/// zerschneidet) wird dekodiert; die angebrochene Sequenz bleibt im
/// Byte-Puffer, bis ihre restlichen Bytes ankommen.
public struct EventStreamParser {

    private let framing: StreamFraming
    private var buffer = Data()

    public init(framing: StreamFraming) {
        self.framing = framing
    }

    public mutating func consume(_ data: Data) -> [String] {
        buffer.append(data)
        var payloads: [String] = []

        while let newline = buffer.firstIndex(of: 0x0A) {
            let lineBytes = buffer[buffer.startIndex..<newline]
            // `Data(...)` rebasiert die Indizes des Restes auf 0 — sonst
            // driftete `startIndex` mit jeder Zeile weiter.
            buffer = Data(buffer[buffer.index(after: newline)...])
            let line = String(decoding: lineBytes, as: UTF8.self)
                .trimmingCharacters(in: .whitespacesAndNewlines)
            guard !line.isEmpty else { continue }

            switch framing {
            case .serverSentEvents:
                // Nur Datenzeilen tragen Nutzlast; `event:`/`id:`/Kommentare nicht.
                guard line.hasPrefix("data:") else { continue }
                let payload = String(line.dropFirst(5)).trimmingCharacters(in: .whitespaces)
                if !payload.isEmpty { payloads.append(payload) }
            case .newlineDelimitedJSON:
                payloads.append(line)
            }
        }
        return payloads
    }
}
