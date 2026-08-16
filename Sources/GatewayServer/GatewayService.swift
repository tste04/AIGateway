// Copyright (c) 2026 Tommy Stellmacher
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

import Foundation
import Dispatch
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
    /// Regel-IDs im 403 und Upstream-Detail im 502 mitsenden. Default AUS:
    /// beides sind Informationslecks an den Aufrufer (Tuning-Orakel bzw.
    /// fremder Fehlerkoerper). Betreiber korrelieren stattdessen ueber die
    /// `correlation_id` mit dem Audit-Log.
    public var debugErrorDetails: Bool
    /// Betriebsgrenzen des HTTP-Servers, an die Last anpassbar. Ihre
    /// Begruendung steht in `HTTPServer`; hier sind sie nur durchgereicht,
    /// damit ein Betreiber sie ohne Neucompilat setzen kann.
    public var readTimeoutSeconds: Int
    public var maxConcurrentConnections: Int
    /// Zeitlimit fuer den Upstream-Aufruf. Nur im Proxy-Betrieb wirksam (der
    /// bequeme Konstruktor baut daraus den `UpstreamClient`).
    public var upstreamTimeoutSeconds: TimeInterval

    public init(port: UInt16 = 8080, loopbackOnly: Bool = true,
                upstream: ProviderKind = .ollama,
                upstreamBaseURL: URL = URL(string: "http://127.0.0.1:11434")!,
                apiKey: String? = nil, maxBodyBytes: Int = 1_000_000,
                debugErrorDetails: Bool = false,
                readTimeoutSeconds: Int = 30,
                maxConcurrentConnections: Int = 64,
                upstreamTimeoutSeconds: TimeInterval = 120) {
        self.port = port
        self.loopbackOnly = loopbackOnly
        self.upstream = upstream
        self.upstreamBaseURL = upstreamBaseURL
        self.apiKey = apiKey
        self.maxBodyBytes = maxBodyBytes
        self.debugErrorDetails = debugErrorDetails
        self.readTimeoutSeconds = readTimeoutSeconds
        self.maxConcurrentConnections = maxConcurrentConnections
        self.upstreamTimeoutSeconds = upstreamTimeoutSeconds
    }
}

public final class GatewayService: @unchecked Sendable {

    private let configuration: GatewayConfiguration
    private let pipeline: GatewayPipeline
    private let downstream: Downstream
    private let principals: PrincipalResolver
    /// Steht VOR der Pipeline: die Arbeit ist die Kosten, also muss der Deckel
    /// greifen, bevor sie anfaellt. Ohne Guard laeuft alles wie bisher.
    private let rateGuard: RateGuard?
    private let onAudit: (@Sendable (AuditEvent) -> Void)?
    private let onCompletion: (@Sendable (CompletionEvent) -> Void)?
    private var server: HTTPServer?

    /// Betriebsart „Proxy": das Ziel ist der in der Konfiguration genannte
    /// Provider.
    public convenience init(configuration: GatewayConfiguration,
                           pipeline: GatewayPipeline,
                           client: UpstreamClient? = nil,
                           principals: PrincipalResolver = AnonymousPrincipalResolver(),
                           rateGuard: RateGuard? = nil,
                           onAudit: (@Sendable (AuditEvent) -> Void)? = nil,
                           onCompletion: (@Sendable (CompletionEvent) -> Void)? = nil) {
        // Ohne uebergebenen Client einen mit dem konfigurierten Upstream-Timeout
        // bauen — sonst bliebe `upstreamTimeoutSeconds` wirkungslos.
        self.init(configuration: configuration,
                  pipeline: pipeline,
                  downstream: ProviderDownstream(
                    dialect: Providers.adapter(for: configuration.upstream),
                    baseURL: configuration.upstreamBaseURL,
                    apiKey: configuration.apiKey,
                    client: client ?? UpstreamClient(timeout: configuration.upstreamTimeoutSeconds)),
                  principals: principals,
                  rateGuard: rateGuard,
                  onAudit: onAudit,
                  onCompletion: onCompletion)
    }

    /// Betriebsart „Stufe": das Ziel wird gesetzt. `configuration.upstream` und
    /// `upstreamBaseURL` bleiben dann ungenutzt.
    ///
    /// - Parameter principals: stellt die Identitaet des Aufrufers fest.
    ///   Default ist `AnonymousPrincipalResolver` — Identitaets-Header werden
    ///   dann IGNORIERT, nicht geglaubt. Mandanten-Trennung (und damit ein
    ///   partitionierter Cache) verlangt einen echten Resolver.
    public init(configuration: GatewayConfiguration,
                pipeline: GatewayPipeline,
                downstream: Downstream,
                principals: PrincipalResolver = AnonymousPrincipalResolver(),
                rateGuard: RateGuard? = nil,
                onAudit: (@Sendable (AuditEvent) -> Void)? = nil,
                onCompletion: (@Sendable (CompletionEvent) -> Void)? = nil) {
        self.configuration = configuration
        self.pipeline = pipeline
        self.downstream = downstream
        self.principals = principals
        self.rateGuard = rateGuard
        self.onAudit = onAudit
        self.onCompletion = onCompletion
    }

    public func start() throws {
        let server = HTTPServer(port: configuration.port,
                                loopbackOnly: configuration.loopbackOnly,
                                maxBodyBytes: configuration.maxBodyBytes,
                                readTimeoutSeconds: configuration.readTimeoutSeconds,
                                maxConcurrentConnections: configuration.maxConcurrentConnections) {
            [weak self] request, connection in
            await self?.handle(request, connection)
        }
        self.server = server
        try server.start()
    }

    /// Geordneter Stopp: kein Zulauf mehr, laufende Anfragen zu Ende.
    ///
    /// - Returns: `true`, wenn beim Ende nichts mehr lief. `false` heisst, dass
    ///   die Frist abgelaufen ist, bevor alle Anfragen fertig waren — der
    ///   Aufrufer soll das melden koennen, statt einen sauberen Stopp zu
    ///   behaupten.
    @discardableResult
    public func stop(drainSeconds: TimeInterval = 0) -> Bool {
        let drained = server?.stop(drainSeconds: drainSeconds) ?? true
        server = nil
        return drained
    }

    // MARK: - Bearbeitung

    // `internal` statt `private`: die Integrationstests fahren den kompletten
    // Pfad Firewall -> Downstream -> De-Maskierung ueber diese Methode, mit
    // einem aufzeichnenden `HTTPResponder` statt eines Sockets.
    //
    // Die Methode ist die Abfolge, die Schritte sind benannt. Jeder Schritt,
    // der antwortet, beendet die Bearbeitung — sichtbar am fruehen `return`.
    func handle(_ request: HTTPRequest, _ client: any HTTPResponder) async {
        // Die Korrelations-ID entsteht HIER, nicht erst in der Pipeline: der
        // dekorierte Responder stempelt sie als Header auf jede Antwort dieses
        // Aufrufs — auch auf 400/404/429, die vor der Firewall fallen. Ein
        // Client-Report mit diesem Header ist damit im Audit-Log auffindbar,
        // ohne dass der Fehlerkoerper geparst werden muss; bei Stroemen ist der
        // Header sogar der einzige Traeger, denn deren Fehler sind kein JSON.
        let correlationID = UUID().uuidString
        let connection = CorrelatedResponder(client, correlationID: correlationID)
        guard let (inbound, chat) = route(request, connection) else { return }
        guard let principal = resolvePrincipal(request, connection) else { return }
        guard await admitted(principal, model: chat.model,
                             correlationID: correlationID, connection) else { return }

        let outcome = await pipeline.process(chat, principal: principal,
                                             correlationID: correlationID)
        onAudit?(outcome.audit)
        guard let forward = outcome.forward else {
            return refuse(outcome, connection)
        }

        let handoff = GatewayHandoff(
            correlationID: outcome.decision.correlationID,
            principal: principal,
            request: forward,
            disposition: outcome.decision.disposition,
            riskScore: outcome.decision.riskScore,
            findings: outcome.decision.findings)

        if let cached = outcome.cached {
            serveFromCache(cached, handoff: handoff, forward: forward,
                           inbound: inbound, session: outcome.session, connection: connection)
        } else {
            await relay(handoff, forward: forward, inbound: inbound,
                        outcome: outcome, connection: connection)
        }
        // Die Klammer schliesst hier NUR im Alleinbetrieb: die Antwort ist
        // raus (oder gescheitert), die Zuordnung wird nicht mehr gebraucht.
        // Im Stufenbetrieb dagegen arbeitet die naechste Box Minuten bis
        // Stunden weiter (Agent Loop, menschliche Freigabe) und holt die
        // Rueckuebersetzung spaeter ueber den Rueckweg (/v1/session/...);
        // dort schliessen der ausdrueckliche Abschluss oder die Frist.
        // Ohne konfigurierten Speicher ist beides ein Leerlauf.
        if !(downstream is StageDownstream) {
            await closeSession(handoff)
        }
    }

    /// Weg und Dialekt der Anfrage. `nil` = bereits beantwortet (Healthcheck,
    /// unbekannte Route, unlesbarer Rumpf).
    private func route(_ request: HTTPRequest,
                       _ connection: any HTTPResponder) -> (ProviderAdapter, ChatRequest)? {
        if request.path == "/healthz" {
            connection.respond(status: 200, json: ["status": "ok"])
            return nil
        }
        guard request.method == "POST", let inbound = Providers.adapter(forPath: request.path) else {
            connection.respond(status: 404, json: ["error": "unknown route \(request.path)"])
            return nil
        }
        do {
            return (inbound, try inbound.decodeRequest(request.body))
        } catch {
            connection.respond(status: 400, json: ["error": "\(error)"])
            return nil
        }
    }

    /// Identitaet kommt von der Identity-Stufe davor — aber sie wird nicht
    /// blind geglaubt. Der Resolver entscheidet; sein Default ignoriert
    /// Behauptungen, statt ihnen zu folgen. Das ist die Vorbedingung fuer den
    /// partitionierten Cache: `cachePartition` entsteht aus Mandant und
    /// Scopes, und ein frei waehlbarer Mandant waere ein Zugriffs-Bypass.
    private func resolvePrincipal(_ request: HTTPRequest,
                                  _ connection: any HTTPResponder) -> Principal? {
        switch principals.resolve(request) {
        case .identified(let resolved):
            return resolved
        case .anonymous:
            return .anonymous
        case .rejected(let reason):
            var payload: [String: Any] = ["error": "unauthenticated"]
            if configuration.debugErrorDetails { payload["detail"] = reason }
            connection.respond(status: 401, json: payload)
            return nil
        }
    }

    /// Der Rate-Deckel greift HIER: nach der Identitaet (vorher gibt es
    /// niemanden zu deckeln) und vor der Firewall (die Arbeit ist die Kosten).
    /// Die Absage geht denselben payload-freien Audit-Weg wie jede andere
    /// Entscheidung — eine Drosselung, die im Log fehlt, ist als Angriffsspur
    /// unsichtbar.
    private func admitted(_ principal: Principal, model: String, correlationID: String,
                          _ connection: any HTTPResponder) async -> Bool {
        guard let rateGuard,
              case .limited(let retryAfter) = await rateGuard.admit(principal) else { return true }

        let decision = GatewayDecision(
            correlationID: correlationID, disposition: .block, riskScore: 1.0,
            findings: [RateGuard.finding(retryAfter: retryAfter)], content: "")
        onAudit?(AuditEvent(decision: decision, principal: principal, model: model))
        let body = (try? JSONSerialization.data(withJSONObject: [
            "error": "rate limit exceeded",
            "correlation_id": correlationID,
        ], options: [.sortedKeys])) ?? Data()
        // 429 statt 403: die Anfrage war nicht verboten, nur zu frueh. Der
        // Unterschied ist fuer den Client handlungsleitend — auf 403 hoert
        // ein vernuenftiger Client auf, auf 429 wartet er.
        connection.respond(status: 429, contentType: "application/json",
                           body: body,
                           extraHeaders: ["Retry-After": "\(Int(retryAfter))"])
        return false
    }

    /// Die Block-Antwort der Firewall. Die getroffenen Regel-IDs stehen NICHT
    /// in der Standard-Antwort: sie sind ein Tuning-Orakel — ein Angreifer
    /// erfaehrt regelgenau, was angeschlagen hat, und variiert dagegen.
    /// Betreiber korrelieren ueber die correlation_id mit dem Audit-Log; wer
    /// die IDs im Fehler sehen will (Entwicklung), setzt `debugErrorDetails`.
    private func refuse(_ outcome: GatewayPipeline.Outcome, _ connection: any HTTPResponder) {
        var payload: [String: Any] = [
            "error": "blocked by input firewall",
            "correlation_id": outcome.decision.correlationID,
        ]
        if configuration.debugErrorDetails {
            payload["rules"] = outcome.decision.findings.map { $0.ruleID.rawValue }
        }
        connection.respond(status: 403, json: payload)
    }

    /// Cache-Treffer: der Weg nach oben entfaellt.
    ///
    /// Die Antwort liegt MASKIERT im Cache und wird mit der Session DIESER
    /// Anfrage aufgeloest. Deshalb sieht jeder Aufrufer seine eigenen
    /// Klardaten und nie die des Vorgaengers — dieselbe Partition teilt sich
    /// einen Vault, also steht derselbe Platzhalter bei beiden fuer denselben
    /// Wert. Kennt die Session einen Platzhalter nicht, bleibt er stehen:
    /// sichtbar falsch statt still falsch aufgeloest.
    private func serveFromCache(_ cached: ChatResponse, handoff: GatewayHandoff,
                                forward: ChatRequest, inbound: ProviderAdapter,
                                session: MaskingSession, connection: any HTTPResponder) {
        let hitStart = DispatchTime.now().uptimeNanoseconds
        respondFromCache(cached, inbound: inbound, session: session,
                         streamed: forward.stream, model: forward.model,
                         connection: connection)
        emitCompletion(handoff, model: cached.model.isEmpty ? forward.model : cached.model,
                       usage: cached.usage, since: hitStart,
                       streamed: forward.stream, status: 200, cacheHit: true)
    }

    /// Der Weg nach oben, einmalig oder als Strom, samt Fehlerpfad und
    /// Cache-Ablage. Gemessen wird nur er — die Zeiten der Firewall stehen
    /// als `StageTiming` im Audit-Eintrag.
    private func relay(_ handoff: GatewayHandoff, forward: ChatRequest,
                       inbound: ProviderAdapter, outcome: GatewayPipeline.Outcome,
                       connection: any HTTPResponder) async {
        let upstreamStart = DispatchTime.now().uptimeNanoseconds
        do {
            let facts: RelayFacts
            if forward.stream {
                facts = try await relayStream(handoff, inbound: inbound,
                                              session: outcome.session, connection: connection)
            } else {
                facts = try await relayOnce(handoff, inbound: inbound,
                                            session: outcome.session, connection: connection)
            }
            // Ablegen, was der Provider geliefert hat — im MASKIERTEN Stand,
            // nicht in dem, den der Client gesehen hat.
            if let ticket = outcome.cacheTicket {
                await pipeline.store(ticket, maskedResponse: ChatResponse(
                    model: facts.model, content: facts.maskedContent, usage: facts.usage))
            }
            emitCompletion(handoff, model: facts.model, usage: facts.usage,
                           since: upstreamStart, streamed: forward.stream, status: 200)
        } catch {
            if forward.stream {
                // Der Strom hat begonnen (`beginStream` ist der erste Schritt von
                // `relayStream`) — ein 502 ist nicht mehr moeglich, `respond`
                // liefe in den Streaming-Riegel und taete NICHTS. Ein stummer
                // Abbruch saehe fuer den Client wie eine vollstaendige Antwort
                // aus. Stattdessen: Fehler-Ereignis im Dialekt des Clients,
                // dann Ende — und bewusst KEIN Terminator danach, der wuerde
                // regulaeren Abschluss signalisieren.
                connection.writeChunk(Self.frame(
                    inbound.encodeStreamError("upstream failure"), as: inbound.framing))
                connection.endStream()
            } else {
                var payload: [String: Any] = [
                    "error": "upstream failure",
                    "correlation_id": handoff.correlationID,
                ]
                // Das Upstream-Detail kann dessen Fehlerkoerper enthalten —
                // nicht ungefragt an den Client reichen.
                if configuration.debugErrorDetails { payload["detail"] = "\(error)" }
                connection.respond(status: 502, json: payload)
            }
            // Auch der Fehlschlag ist eine Kostenzeile: er hat Zeit gekostet und
            // je nach Abbruchzeitpunkt beim Provider auch Tokens.
            emitCompletion(handoff, model: forward.model, usage: nil,
                           since: upstreamStart, streamed: forward.stream, status: 502)
        }
    }

    private func closeSession(_ handoff: GatewayHandoff) async {
        await pipeline.closeSession(correlationID: handoff.correlationID,
                                    partition: handoff.principal.cachePartition)
    }

    /// Was der Rueckweg ueber sich selbst weiss.
    private struct RelayFacts {
        let model: String
        let usage: TokenUsage?
        /// Der Antworttext, wie der Provider ihn geliefert hat — also noch mit
        /// Platzhaltern. Das ist der Stand, der in den Cache gehoert.
        let maskedContent: String
    }

    /// Antwortet aus dem Cache, ohne den Provider zu fragen.
    private func respondFromCache(_ cached: ChatResponse, inbound: ProviderAdapter,
                                  session: MaskingSession, streamed: Bool, model: String,
                                  connection: any HTTPResponder) {
        let text = session.unmask(cached.content)
        guard streamed else {
            var response = cached
            response.content = text
            guard let body = try? inbound.encodeResponse(response) else {
                return connection.respond(status: 500, json: ["error": "encoding failed"])
            }
            return connection.respond(status: 200, contentType: "application/json",
                                      body: body, extraHeaders: [:])
        }
        // Der Strom wird nachgebildet: ein Ereignis mit dem ganzen Text, dann
        // der regulaere Abschluss. Die Antwort liegt vollstaendig vor — sie in
        // Haeppchen zu zerlegen taeuschte eine Erzeugung vor, die nicht
        // stattfindet.
        connection.beginStream(contentType: inbound.framing == .serverSentEvents
                               ? "text/event-stream" : "application/x-ndjson")
        if !text.isEmpty {
            connection.writeChunk(Self.frame(inbound.encodeStreamDelta(text, model: model),
                                             as: inbound.framing))
        }
        if let terminator = inbound.streamTerminator(model: model) {
            connection.writeChunk(Self.frame(terminator, as: inbound.framing))
        }
        connection.endStream()
    }

    private func relayOnce(_ handoff: GatewayHandoff, inbound: ProviderAdapter,
                           session: MaskingSession,
                           connection: any HTTPResponder) async throws -> RelayFacts {
        let upstream = try await downstream.send(handoff)
        var response = upstream
        // Rueckweg: Klardaten wieder einsetzen. `upstream` behaelt den
        // maskierten Stand fuer den Cache.
        response.content = session.unmask(upstream.content)
        connection.respond(status: 200, contentType: "application/json",
                           body: try inbound.encodeResponse(response), extraHeaders: [:])
        // Meldet der Provider kein Modell zurueck, gilt das angefragte.
        return RelayFacts(model: response.model.isEmpty ? handoff.request.model : response.model,
                          usage: response.usage,
                          maskedContent: upstream.content)
    }

    private func relayStream(_ handoff: GatewayHandoff, inbound: ProviderAdapter,
                             session: MaskingSession,
                             connection: any HTTPResponder) async throws -> RelayFacts {
        let model = handoff.request.model

        connection.beginStream(contentType: inbound.framing == .serverSentEvents
                               ? "text/event-stream" : "application/x-ndjson")

        // De-Maskierung muss ueber Chunk-Grenzen puffern. Der Rueckruf kommt aus
        // einem Hintergrund-Thread, deshalb gekapselt und gesperrt.
        let state = RewriteState(session: session)

        let usage = try await downstream.stream(handoff) { delta in
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
        return RelayFacts(model: model, usage: usage, maskedContent: state.maskedText())
    }

    // MARK: - Abschluss melden

    private func emitCompletion(_ handoff: GatewayHandoff, model: String,
                                usage: TokenUsage?, since start: UInt64,
                                streamed: Bool, status: Int, cacheHit: Bool = false) {
        guard let onCompletion else { return }
        onCompletion(CompletionEvent(
            correlationID: handoff.correlationID,
            principal: handoff.principal,
            model: model,
            usage: usage,
            upstreamMilliseconds: Double(DispatchTime.now().uptimeNanoseconds &- start) / 1_000_000,
            streamed: streamed,
            status: status,
            cacheHit: cacheHit))
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
    /// Der Strom im maskierten Originalstand — das, was in den Cache gehoert.
    /// Muss hier mitlaufen: nach der De-Maskierung ist der Platzhalter-Stand
    /// nicht mehr rekonstruierbar.
    private var masked = ""
    private let lock = NSLock()

    init(session: MaskingSession) {
        self.rewriter = StreamRewriter(session: session)
    }

    func push(_ delta: String) -> String {
        lock.lock(); defer { lock.unlock() }
        masked += delta
        return rewriter.push(delta)
    }

    func flush() -> String {
        lock.lock(); defer { lock.unlock() }
        return rewriter.flush()
    }

    func maskedText() -> String {
        lock.lock(); defer { lock.unlock() }
        return masked
    }
}

/// Stempelt die Korrelations-ID als `X-Correlation-ID` auf jede Antwort eines
/// Aufrufs. Als Dekorator statt an jeder Antwortstelle einzeln: die Stellen
/// sind verstreut (Route, Identitaet, Rate-Deckel, Firewall, Cache, Relay),
/// und eine vergessene waere genau die, deren Report sich nicht zuordnen
/// laesst. Der Header traegt dieselbe ID wie `AuditEvent` und
/// `CompletionEvent` — der Rueckweg vom Client-Report ins Log.
final class CorrelatedResponder: HTTPResponder, @unchecked Sendable {
    static let headerName = "X-Correlation-ID"

    private let base: any HTTPResponder
    private let correlationID: String

    init(_ base: any HTTPResponder, correlationID: String) {
        self.base = base
        self.correlationID = correlationID
    }

    func respond(status: Int, contentType: String, body: Data, extraHeaders: [String: String]) {
        var headers = extraHeaders
        headers[Self.headerName] = correlationID
        base.respond(status: status, contentType: contentType, body: body, extraHeaders: headers)
    }

    func beginStream(contentType: String, extraHeaders: [String: String]) {
        var headers = extraHeaders
        headers[Self.headerName] = correlationID
        base.beginStream(contentType: contentType, extraHeaders: headers)
    }

    @discardableResult
    func writeChunk(_ text: String) -> Bool { base.writeChunk(text) }

    func endStream() { base.endStream() }
}
