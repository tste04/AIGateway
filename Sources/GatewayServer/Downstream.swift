// Copyright (c) 2026 Tommy Stellmacher
// SPDX-License-Identifier: Apache-2.0

import Foundation
import GatewayCore

// MARK: - Abwaerts-Naht
//
// Im Zielbild liegt unter dem Gateway die Policy Engine. Beide Betriebsarten
// existieren: `ProviderDownstream` reicht direkt an einen Modellanbieter
// weiter (Alleinbetrieb), `StageDownstream` an die naechste Stufe der Kette.
// Der Antwortpfad kennt den Unterschied nicht — genau dafuer ist diese Naht da.
//
// Der Strom liefert bewusst nur TEXT-Zuwaechse. Rahmung und Dialekt des Ziels
// gehoeren der Implementierung, De-Maskierung und ausgehende Rahmung bleiben
// beim Aufrufer — sonst muesste jede Implementierung die Maskierung kennen,
// und die Klammer waere nicht mehr an einer Stelle geschlossen.

/// Was das Gateway nach unten reicht.
///
/// Traegt die MASKIERTE Anfrage plus das Ergebnis der Firewall — nie den
/// Rohtext. Dasselbe Prinzip wie bei `AuditEvent`: die naechste Stufe braucht
/// die Bewertung, nicht das Beweisstueck.
public struct GatewayHandoff: Sendable {
    public let correlationID: String
    public let principal: Principal
    /// Maskiert und bereinigt — das, was ein Modell sehen darf.
    public let request: ChatRequest
    public let disposition: Disposition
    public let riskScore: Double
    public let findings: [Finding]

    public init(correlationID: String, principal: Principal, request: ChatRequest,
                disposition: Disposition, riskScore: Double, findings: [Finding]) {
        self.correlationID = correlationID
        self.principal = principal
        self.request = request
        self.disposition = disposition
        self.riskScore = riskScore
        self.findings = findings
    }
}

public protocol Downstream: Sendable {
    /// Einmalige Antwort.
    func send(_ handoff: GatewayHandoff) async throws -> ChatResponse

    /// Antwortstrom. `onDelta` bekommt Text-Zuwaechse, bereits aus der Rahmung
    /// des Ziels geloest — und wird aus einem Hintergrund-Thread aufgerufen.
    ///
    /// Liefert den gemeldeten Token-Verbrauch, sofern das Ziel einen meldet.
    /// Bei der Einmal-Antwort steckt er in `ChatResponse.usage`; im Strom
    /// kommt er verstreut und muss eingesammelt werden.
    @discardableResult
    func stream(_ handoff: GatewayHandoff,
                onDelta: @escaping @Sendable (String) -> Void) async throws -> TokenUsage?
}

// MARK: - Ziel: ein Modellanbieter

/// Reicht direkt an einen Provider weiter — der Alleinbetrieb.
public struct ProviderDownstream: Downstream {

    private let dialect: ProviderAdapter
    private let baseURL: URL
    private let apiKey: String?
    private let client: UpstreamClient

    public init(dialect: ProviderAdapter, baseURL: URL, apiKey: String? = nil,
                client: UpstreamClient = UpstreamClient()) {
        self.dialect = dialect
        self.baseURL = baseURL
        self.apiKey = apiKey
        self.client = client
    }

    public func send(_ handoff: GatewayHandoff) async throws -> ChatResponse {
        var request = handoff.request
        request.stream = false
        let body = try dialect.encodeRequest(request)
        let data = try await client.send(
            url: dialect.upstreamURL(base: baseURL),
            headers: dialect.authHeaders(apiKey: apiKey),
            body: body)
        return try dialect.decodeResponse(data)
    }

    @discardableResult
    public func stream(_ handoff: GatewayHandoff,
                       onDelta: @escaping @Sendable (String) -> Void) async throws -> TokenUsage? {
        var request = handoff.request
        request.stream = true

        // Eigener Name statt `self.dialect` im Rueckruf: der Strom-Callback ist
        // `@Sendable`, und was er anfasst, soll hier sichtbar gebunden sein.
        let target = dialect
        let body = try target.encodeRequest(request)
        let events = Self.collector(for: target)

        try await client.stream(
            url: target.upstreamURL(base: baseURL),
            headers: target.authHeaders(apiKey: apiKey),
            body: body
        ) { data in
            for text in events.consume(data) { onDelta(text) }
        }
        // Ein In-Band-Fehler des Providers ({"error":…} bei HTTP 200) wird
        // nach dem Strom-Ende geworfen — dieselbe Linie wie StageDownstream.
        // Ohne das saehe der leere Strom wie eine vollstaendige Antwort aus.
        if let failure = events.pendingFailure() { throw failure }
        return events.reportedUsage()
    }

    /// Der Leser der Provider-Seite: was ein Ereignis bedeutet, weiss der
    /// Dialekt. `internal`, damit die Chunk-Grenzen-Tests genau den Leser
    /// fahren, der im Betrieb laeuft.
    static func collector(for dialect: ProviderAdapter) -> StreamCollector {
        StreamCollector(framing: dialect.framing) { payload in
            StreamCollector.Event(
                delta: dialect.streamDelta(fromEventPayload: payload),
                usage: dialect.streamUsage(fromEventPayload: payload),
                failure: dialect.streamFailure(fromEventPayload: payload))
        }
    }
}

/// Ereignis-Zerlegung ueber Chunk-Grenzen hinweg, gemeinsam fuer beide
/// Abwaerts-Ziele. Der Rueckruf kommt aus einem Hintergrund-Thread und
/// `EventStreamParser` ist ein mutierender Wert — deshalb gekapselt und
/// gesperrt.
///
/// Was eine Nutzlast BEDEUTET, entscheidet der mitgegebene Leser: die
/// Provider-Seite fragt ihren Dialekt, die Stufen-Seite liest das kanonische
/// NDJSON. Vorher waren das zwei fast identische Klassen, die nur in dieser
/// einen Frage auseinandergingen — und die Streaming-Fehler dieser Schicht
/// haetten in beiden gefixt werden muessen.
final class StreamCollector: @unchecked Sendable {

    /// Was ein Leser aus einer Nutzlast zieht. Ein Ereignis kann Text tragen,
    /// Verbrauch, einen Fehler — oder nichts von alledem.
    struct Event {
        var delta: String?
        var usage: TokenUsage?
        var failure: GatewayServerError?

        init(delta: String? = nil, usage: TokenUsage? = nil,
             failure: GatewayServerError? = nil) {
            self.delta = delta
            self.usage = usage
            self.failure = failure
        }
    }

    private var parser: EventStreamParser
    private let read: (String) -> Event
    private var usage: TokenUsage?
    private var failure: GatewayServerError?
    private let lock = NSLock()

    init(framing: StreamFraming, read: @escaping (String) -> Event) {
        self.parser = EventStreamParser(framing: framing)
        self.read = read
    }

    func consume(_ data: Data) -> [String] {
        lock.lock(); defer { lock.unlock() }
        var deltas: [String] = []
        for payload in parser.consume(data) {
            let event = read(payload)
            if let reported = event.usage {
                usage = usage.map { $0.merging(reported) } ?? reported
            }
            if let raised = event.failure {
                failure = raised
            }
            if let text = event.delta, !text.isEmpty {
                deltas.append(text)
            }
        }
        return deltas
    }

    func reportedUsage() -> TokenUsage? {
        lock.lock(); defer { lock.unlock() }
        return usage
    }

    /// Ein im Strom gemeldeter Fehler. Wird gemerkt statt geworfen, weil der
    /// Rueckruf nicht werfen kann — der Aufrufer prueft nach dem Strom-Ende
    /// und wirft dann; still verschluckt saehe der Abbruch fuer den Client
    /// wie eine vollstaendige Antwort aus.
    func pendingFailure() -> GatewayServerError? {
        lock.lock(); defer { lock.unlock() }
        return failure
    }
}
