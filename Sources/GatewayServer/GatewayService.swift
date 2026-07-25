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
    private let downstream: Downstream
    private let onAudit: (@Sendable (AuditEvent) -> Void)?
    private var server: HTTPServer?

    /// Betriebsart „Proxy": das Ziel ist der in der Konfiguration genannte
    /// Provider.
    public convenience init(configuration: GatewayConfiguration,
                           pipeline: GatewayPipeline,
                           client: UpstreamClient = UpstreamClient(),
                           onAudit: (@Sendable (AuditEvent) -> Void)? = nil) {
        self.init(configuration: configuration,
                  pipeline: pipeline,
                  downstream: ProviderDownstream(
                    dialect: Providers.adapter(for: configuration.upstream),
                    baseURL: configuration.upstreamBaseURL,
                    apiKey: configuration.apiKey,
                    client: client),
                  onAudit: onAudit)
    }

    /// Betriebsart „Stufe": das Ziel wird gesetzt. `configuration.upstream` und
    /// `upstreamBaseURL` bleiben dann ungenutzt.
    public init(configuration: GatewayConfiguration,
                pipeline: GatewayPipeline,
                downstream: Downstream,
                onAudit: (@Sendable (AuditEvent) -> Void)? = nil) {
        self.configuration = configuration
        self.pipeline = pipeline
        self.downstream = downstream
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

        let handoff = GatewayHandoff(
            correlationID: outcome.decision.correlationID,
            principal: principal,
            request: forward,
            disposition: outcome.decision.disposition,
            riskScore: outcome.decision.riskScore,
            findings: outcome.decision.findings)

        do {
            if forward.stream {
                try await relayStream(handoff, inbound: inbound,
                                      session: outcome.session, connection: connection)
            } else {
                try await relayOnce(handoff, inbound: inbound,
                                    session: outcome.session, connection: connection)
            }
        } catch {
            connection.respond(status: 502, json: ["error": "upstream failure", "detail": "\(error)"])
        }
    }

    private func relayOnce(_ handoff: GatewayHandoff, inbound: ProviderAdapter,
                           session: MaskingSession,
                           connection: HTTPConnection) async throws {
        var response = try await downstream.send(handoff)
        // Rueckweg: Klardaten wieder einsetzen.
        response.content = session.unmask(response.content)
        connection.respond(status: 200, body: try inbound.encodeResponse(response))
    }

    private func relayStream(_ handoff: GatewayHandoff, inbound: ProviderAdapter,
                             session: MaskingSession,
                             connection: HTTPConnection) async throws {
        let model = handoff.request.model

        connection.beginStream(contentType: inbound.framing == .serverSentEvents
                               ? "text/event-stream" : "application/x-ndjson")

        // De-Maskierung muss ueber Chunk-Grenzen puffern. Der Rueckruf kommt aus
        // einem Hintergrund-Thread, deshalb gekapselt und gesperrt.
        let state = RewriteState(session: session)

        try await downstream.stream(handoff) { delta in
            let text = state.push(delta)
            guard !text.isEmpty else { return }
            connection.writeChunk(Self.frame(inbound.encodeStreamDelta(text, model: model),
                                             as: inbound.framing))
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

/// Gekapselter De-Maskierungs-Puffer. `StreamRewriter` ist ein mutierender
/// Wert und wird aus dem Hintergrund-Thread des Stroms bedient — deshalb
/// gesperrt.
private final class RewriteState: @unchecked Sendable {
    private var rewriter: StreamRewriter
    private let lock = NSLock()

    init(session: MaskingSession) {
        self.rewriter = StreamRewriter(session: session)
    }

    func push(_ delta: String) -> String {
        lock.lock(); defer { lock.unlock() }
        return rewriter.push(delta)
    }

    func flush() -> String {
        lock.lock(); defer { lock.unlock() }
        return rewriter.flush()
    }
}
