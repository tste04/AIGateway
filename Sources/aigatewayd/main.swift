// Copyright (c) 2026 Tommy Stellmacher
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

import Foundation
import Dispatch
import GatewayCore
import GatewayServer
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

// MARK: - Der Daemon
//
// Das Gateway war bis hierhin eine Bibliothek. Eine Box im Zielbild ist aber
// etwas, das man startet, ueberwacht und wieder anhaelt — und das lief bisher
// nur ueber ein selbstgeschriebenes Host-Programm. Diese Datei ist genau das
// Host-Programm, einmal richtig gebaut.
//
// Sie bleibt bewusst duenn: Konfiguration lesen, Stufen zusammenstecken,
// Signale abfangen, geordnet beenden. Jede Zeile Sicherheitslogik hier waere
// eine, die die Bibliothek nicht hat und die niemand testet.
//
// AUSGABE GEHT NACH STDERR und ist zeilenweises JSON. Audit- und
// Abschluss-Ereignisse sind payload-frei — das ist keine Eigenschaft dieses
// Programms, sondern von `AuditEvent` und `CompletionEvent`; hier wird nur
// nichts hinzugefuegt.
//
// Die Hilfsfunktionen stehen VOR dem ausfuehrbaren Teil: in `main.swift` laeuft
// alles auf oberster Ebene der Reihe nach, und die Lesereihenfolge soll der
// Ausfuehrungsreihenfolge entsprechen.

/// Serialisiert die Log-Ausgabe. Der Daemon ist thread-per-connection; ohne
/// Sperre verschraenkten sich die Writes zweier Ereignisse zu kaputten
/// JSON-Lines im Audit-Pfad.
let noteLock = NSLock()

func note(_ event: String, _ fields: [String: Any] = [:]) {
    var line = fields
    line["event"] = event
    var data = (try? JSONSerialization.data(withJSONObject: line, options: [.sortedKeys]))
        ?? Data(#"{"event":"log-encoding-failed"}"#.utf8)
    // Newline an dieselbe `Data` haengen und in EINEM Write ausgeben — zwei
    // getrennte Writes konnten sich zwischen Threads ueberkreuzen.
    data.append(0x0A)
    noteLock.lock()
    FileHandle.standardError.write(data)
    noteLock.unlock()
}

func fail(_ message: String) -> Never {
    note("startup-failed", ["error": message])
    exit(1)
}

// Beide Ereignistypen tragen bewusst KEINEN Nutzinhalt. Hier wird nur
// umgeformt; wer ein Feld ergaenzt, das Prompt-Text traegt, bricht die
// Kern-Invariante.

func auditFields(_ event: AuditEvent) -> [String: Any] {
    [
        "correlation_id": event.correlationID,
        "subject": event.subject,
        "tenant": event.tenant ?? "-",
        "model": event.model ?? "-",
        "disposition": event.disposition.rawValue,
        "risk_score": event.riskScore,
        "rules": event.ruleIDs.map(\.rawValue),
        "categories": event.categories.map(\.rawValue),
        "content_bytes": event.contentBytes,
        "total_ms": event.totalMilliseconds,
        "degraded": event.degraded,
    ]
}

func completionFields(_ event: CompletionEvent) -> [String: Any] {
    var fields: [String: Any] = [
        "correlation_id": event.correlationID,
        "subject": event.subject,
        "model": event.model,
        "upstream_ms": event.upstreamMilliseconds,
        "streamed": event.streamed,
        "status": event.status,
        "cache_hit": event.cacheHit,
    ]
    // Fehlt die Meldung des Providers, bleibt das Feld WEG. Eine 0 waere eine
    // erfundene Kostenzeile — geschaetzt wird nie.
    if let usage = event.usage {
        fields["prompt_tokens"] = usage.promptTokens
        fields["completion_tokens"] = usage.completionTokens
    }
    return fields
}

// MARK: - Aufruf

let arguments = CommandLine.arguments

if arguments.contains("--help") || arguments.contains("-h") {
    print("""
    aigatewayd — AI Gateway (Input Firewall)

      aigatewayd --config <pfad>   Konfigurationsdatei (JSON)
      aigatewayd                   Standardwerte, Loopback:8080, Ollama

    Der Upstream-API-Schluessel kommt aus AIGATEWAY_UPSTREAM_API_KEY,
    niemals aus der Konfigurationsdatei.

    SIGTERM/SIGINT beenden geordnet: kein Zulauf mehr, laufende Anfragen
    zu Ende, dann Schluss.
    """)
    exit(0)
}

var configuration = DaemonConfiguration()
if let index = arguments.firstIndex(of: "--config") {
    guard index + 1 < arguments.count else { fail("--config needs a path") }
    do {
        configuration = try DaemonConfiguration.load(
            contentsOf: URL(fileURLWithPath: arguments[index + 1]))
    } catch {
        fail("\(error)")
    }
}

// MARK: - Zusammenbau

let pipeline = configuration.makePipeline(
    embedder: configuration.makeEmbedder(),
    quarantineSink: configuration.makeQuarantineSink())
let rateGuard = configuration.makeRateGuard()

// Proxy- oder Stufenbetrieb. Der Unterschied ist eine Zeile hier und keine in
// der Firewall — genau dafuer ist die `Downstream`-Naht da.
let principals = configuration.makePrincipalResolver()
let service: GatewayService
if let next = configuration.nextStageURL {
    service = GatewayService(
        configuration: configuration.gateway,
        pipeline: pipeline,
        downstream: StageDownstream(url: next),
        principals: principals,
        rateGuard: rateGuard,
        onAudit: { note("audit", auditFields($0)) },
        onCompletion: { note("completion", completionFields($0)) })
} else {
    service = GatewayService(
        configuration: configuration.gateway,
        pipeline: pipeline,
        principals: principals,
        rateGuard: rateGuard,
        onAudit: { note("audit", auditFields($0)) },
        onCompletion: { note("completion", completionFields($0)) })
}

do {
    try service.start()
} catch {
    fail("\(error)")
}

note("started", [
    "port": Int(configuration.gateway.port),
    "loopback_only": configuration.gateway.loopbackOnly,
    "target": configuration.nextStageURL?.absoluteString
        ?? configuration.gateway.upstreamBaseURL.absoluteString,
    "stages": [
        "malware": configuration.malware,
        "pii": configuration.pii,
        "dlp": configuration.dlp,
    ],
    "cache": configuration.cache.enabled,
    "rate_limit": configuration.rateLimit.enabled,
])

// MARK: - Geordnet beenden
//
// Der Default-Handler von SIGTERM beendet den Prozess sofort — mitten in einer
// Anfrage, deren Modellaufruf bereits bezahlt ist. Deshalb ignoriert, und der
// eigentliche Ablauf haengt an einer `DispatchSourceSignal`: die feuert im
// regulaeren Programmfluss und darf deshalb tun, was ein Signal-Handler nicht
// darf (Speicher anfassen, Sperren nehmen, warten).

let stopped = DispatchSemaphore(value: 0)

// Die Quellen muessen am Leben bleiben, solange der Prozess laeuft: eine
// freigegebene `DispatchSourceSignal` hoert auf zu feuern, und das Signal
// faende dann keinen Empfaenger.
let signalSources: [DispatchSourceSignal] = [SIGTERM, SIGINT].map { number in
    signal(number, SIG_IGN)
    let source = DispatchSource.makeSignalSource(signal: number, queue: .global())
    source.setEventHandler {
        note("signal", ["signal": Int(number)])
        stopped.signal()
    }
    source.resume()
    return source
}

stopped.wait()

note("stopping", ["drain_seconds": configuration.drainSeconds,
                  "sources": signalSources.count])
let drained = service.stop(drainSeconds: configuration.drainSeconds)
// Ehrlich melden, statt einen sauberen Stopp zu behaupten: wer nach einem
// `false` sucht, findet die Laeufe, in denen Anfragen abgeschnitten wurden.
note("stopped", ["drained": drained])
exit(drained ? 0 : 1)
