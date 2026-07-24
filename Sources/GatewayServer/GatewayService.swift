// Copyright (c) 2026 Tommy Stellmacher
// SPDX-License-Identifier: Apache-2.0

import Foundation
import GatewayCore
import InputFirewall

// MARK: - Der Dienst
//
// Verbindet Server, Pipeline, Adapter und Weg nach oben. Der Client spricht
// einen der drei Dialekte; das Gateway prueft, maskiert, reicht an den
// konfigurierten Provider weiter und uebersetzt die Antwort in den Dialekt
// zurueck, in dem gefragt wurde.

public struct GatewayConfiguration: Sendable {
    public var port: UInt16
    /// Default an: TLS-Terminierung ist Betreibersache (siehe DECISIONS).
    public var loopbackOnly: Bool
    public var upstream: ProviderKind
    public var upstreamBaseURL: URL
    public var apiKey: String?
    public var maxBodyBytes: Int

    public init(port: UInt16 = 8080, loopbackOnly: Bool = true,
                upstream: ProviderKind = .ollama,
                upstreamBaseURL: URL = URL(string: "http://127.0.0.1:11434")!,
                apiKey: String? = nil, maxBodyBytes: Int = 1_000_000) {
        self.port = port
        self.loopbackOnly = loopbackOnly
        self.upstream = upstream
        self.upstreamBaseURL = upstreamBaseURL
        self.apiKey = apiKey
        self.maxBodyBytes = maxBodyBytes
    }
}

public final class GatewayService: @unchecked Sendable {

    private let configuration: GatewayConfiguration
    private let pipeline: GatewayPipeline
    private let client: UpstreamClient
    private let onAudit: (@Sendable (AuditEvent) -> Void)?
    private var server: HTTPServer?

    public init(configuration: GatewayConfiguration,
                pipeline: GatewayPipeline,
                client: UpstreamClient = UpstreamClient(),
                onAudit: (@Sendable (AuditEvent) -> Void)? = nil) {
        self.configuration = configuration
        self.pipeline = pipeline
        self.client = client
        self.onAudit = onAudit
    }

    public func start() throws {
        let server = HTTPServer(port: configuration.port,
                                loopbackOnly: configuration.loopbackOnly,
                                maxBodyBytes: configuration.maxBodyBytes) { [weak self] request, connection in
            await self?.handle(request, connection)
        }
        self.server = server
        try server.start()
    }

    public func stop() {
        server?.stop()
        server = nil
    }

    // MARK: - Bearbeitung

    private func handle(_ request: HTTPRequest, _ connection: HTTPConnection) async {
        if request.path == "/healthz" {
            return connection.respond(status: 200, json: ["status": "ok"])
        }
        guard request.method == "POST", let inbound = Providers.adapter(forPath: request.path) else {
            return connection.respond(status: 404, json: ["error": "unknown route \(request.path)"])
        }

        let chat: ChatRequest
        do {
            chat = try inbound.decodeRequest(request.body)
        } catch {
            return connection.respond(status: 400, json: ["error": "\(error)"])
        }

        // Identitaet kommt von der Identity-Stufe davor. Ohne Header laeuft das
        // Gateway im Einzelnutzer-Betrieb — bewusst kein stiller Ausfall, aber
        // auch kein erfundener Nutzer.
        let principal = Principal(
            subject: request.header("x-gateway-subject") ?? Principal.anonymous.subject,
            tenant: request.header("x-gateway-tenant"),
            scopes: Set((request.header("x-gateway-scopes") ?? "")
                .split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }
                .filter { !$0.isEmpty }))

        let outcome = await pipeline.process(chat, principal: principal)
        onAudit?(outcome.audit)

        guard let forward = outcome.forward else {
            return connection.respond(status: 403, json: [
                "error": "blocked by input firewall",
                "correlation_id": outcome.decision.correlationID,
                "rules": outcome.decision.findings.map { $0.ruleID.rawValue },
            ])
        }

        let upstreamAdapter = Providers.adapter(for: configuration.upstream)
        do {
            if forward.stream {
                try await relayStream(forward, inbound: inbound, upstream: upstreamAdapter,
                                      session: outcome.session, connection: connection)
            } else {
                try await relayOnce(forward, inbound: inbound, upstream: upstreamAdapter,
                                    session: outcome.session, connection: connection)
            }
        } catch {
            connection.respond(status: 502, json: ["error": "upstream failure", "detail": "\(error)"])
        }
    }

    private func relayOnce(_ request: ChatRequest, inbound: ProviderAdapter,
                           upstream: ProviderAdapter, session: MaskingSession,
                           connection: HTTPConnection) async throws {
        var forwarded = request
        forwarded.stream = false
        let body = try upstream.encodeRequest(forwarded)
        let data = try await client.send(
            url: upstream.upstreamURL(base: configuration.upstreamBaseURL),
            headers: upstream.authHeaders(apiKey: configuration.apiKey),
            body: body)

        var response = try upstream.decodeResponse(data)
        // Rueckweg: Klardaten wieder einsetzen.
        response.content = session.unmask(response.content)
        connection.respond(status: 200, body: try inbound.encodeResponse(response))
    }

    private func relayStream(_ request: ChatRequest, inbound: ProviderAdapter,
                             upstream: ProviderAdapter, session: MaskingSession,
                             connection: HTTPConnection) async throws {
        var forwarded = request
        forwarded.stream = true
        let body = try upstream.encodeRequest(forwarded)
        let model = request.model

        connection.beginStream(contentType: inbound.framing == .serverSentEvents
                               ? "text/event-stream" : "application/x-ndjson")

        // Zustand ueber Chunk-Grenzen: Ereignis-Zerlegung UND De-Maskierung
        // muessen beide puffern. Der Callback kommt aus einem Hintergrund-Thread,
        // deshalb gekapselt und gesperrt.
        let state = StreamState(framing: upstream.framing, session: session)

        try await client.stream(
            url: upstream.upstreamURL(base: configuration.upstreamBaseURL),
            headers: upstream.authHeaders(apiKey: configuration.apiKey),
            body: body
        ) { data in
            for text in state.consume(data, using: upstream) {
                let payload = inbound.encodeStreamDelta(text, model: model)
                connection.writeChunk(Self.frame(payload, as: inbound.framing))
            }
        }

        // Rest freigeben — nach dem Strom kann kein Platzhalter mehr wachsen.
        let tail = state.flush()
        if !tail.isEmpty {
            connection.writeChunk(Self.frame(inbound.encodeStreamDelta(tail, model: model),
                                             as: inbound.framing))
        }
        if let terminator = inbound.streamTerminator(model: model) {
            connection.writeChunk(Self.frame(terminator, as: inbound.framing))
        }
        connection.endStream()
    }

    private static func frame(_ payload: String, as framing: StreamFraming) -> String {
        switch framing {
        case .serverSentEvents: return "data: \(payload)\n\n"
        case .newlineDelimitedJSON: return payload + "\n"
        }
    }
}

/// Gekapselter Strom-Zustand: Ereignis-Puffer plus De-Maskierungs-Puffer.
private final class StreamState: @unchecked Sendable {
    private var parser: EventStreamParser
    private var rewriter: StreamRewriter
    private let lock = NSLock()

    init(framing: StreamFraming, session: MaskingSession) {
        self.parser = EventStreamParser(framing: framing)
        self.rewriter = StreamRewriter(session: session)
    }

    func consume(_ data: Data, using adapter: ProviderAdapter) -> [String] {
        lock.lock(); defer { lock.unlock() }
        var out: [String] = []
        for payload in parser.consume(data) {
            guard let delta = adapter.streamDelta(fromEventPayload: payload) else { continue }
            let emittable = rewriter.push(delta)
            if !emittable.isEmpty { out.append(emittable) }
        }
        return out
    }

    func flush() -> String {
        lock.lock(); defer { lock.unlock() }
        return rewriter.flush()
    }
}
