# AIGateway

[![CI](https://github.com/tste04/AIGateway/actions/workflows/ci.yml/badge.svg)](https://github.com/tste04/AIGateway/actions/workflows/ci.yml)
[![License: PolyForm NC](https://img.shields.io/badge/License-PolyForm_Noncommercial_1.0.0-blue.svg)](LICENSE.md)
[![Swift 5.7+](https://img.shields.io/badge/Swift-5.7+-orange.svg)](Package.swift)

Eine Input Firewall in Swift: die Schicht zwischen Client und Sprachmodell, die
prüft, was hineingeht. Deterministisch, netzfrei im Kern, ohne externe
Abhängigkeiten außer `Foundation`.

**Lizenz:** PolyForm Noncommercial 1.0.0 — Quellcode offen, nichtkommerziell
frei; kommerzielle Nutzung nur mit Lizenz (siehe [Lizenz](#lizenz) /
[COMMERCIAL.md](COMMERCIAL.md)).

> **English:** AIGateway is an input firewall for AI systems, written in Swift
> with `Foundation` as the only dependency: prompt-injection detection
> (including homoglyph, spacing and Base64 obfuscation), secret and PII
> detection with round-trip masking, DLP redaction, a partitioned semantic
> cache, rate limiting and a small daemon — deterministic and network-free at
> its core. Docs and code comments are in German;
> [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md) and the API
> surface are English. Free for noncommercial use, commercial use requires a
> license ([COMMERCIAL.md](COMMERCIAL.md)).

## Einordnung

```
User → Identity/SSO → [ AI Gateway ] → Policy Engine → AI Router → …
                         ├── Input Firewall (PII • DLP • Malware • Injection)
                         └── Semantic Cache
```

Dieses Repo implementiert diese eine Box. Policy Engine, Router, Agent Loop und
Output Guardrails sind nicht Teil davon.

## Funktionen

- **Injection-Erkennung** für englische und deutsche Muster, inklusive
  Verschleierung: Homoglyphen (`Ignоre` mit kyrillischem о), Buchstaben-Sperrung
  (`I g n o r e …`), Trennzeichen (`IGNORE-ALL-PREVIOUS`) und Base64-Nutzlasten.
- **Secret-Erkennung** für gängige Zugangsdaten-Formate (private Schlüssel,
  AWS-Key-IDs, GitHub- und Slack-Tokens, JWTs).
- **PII-Maskierung mit Round-Trip**: Maskierung auf dem Hinweg, Klardaten auf dem
  Rückweg. Kategorien: Person, Mail, Telefon, IBAN, Adresse, Ort sowie eigene
  Denylist-Begriffe.
- **DLP** mit block/redact/allow je Regel — Redaktion entfernt die Fundstelle
  und lässt die Anfrage durch, statt sie abzuweisen. Der mitgelieferte Katalog
  meldet Klassifizierungs-Vermerke nur und redigiert interne Adressen.
- **Malware-Naht** auf Bytes (`PayloadScanner`), mit einer strukturellen Stufe
  ohne Signaturen: ausführbare Formate, behaupteter Typ gegen tatsächlichen
  Inhalt, ungeprüfte Archive, Größe.
- **Provenienz je Nachrichtenrolle**: `system` gilt als vertrauenswürdig,
  `user`/`assistant` als neutral, `tool` als fremd.
- **Payload-freie Audit-Einträge** mit stabilen Regel-IDs, dazu ein getrenntes
  Abschluss-Ereignis mit Modell, gemeldetem Token-Verbrauch und Latenz.
- **Semantic Cache**, partitioniert über Mandant und Scopes: exakter Treffer
  zuerst, semantisch als zweite Stufe mit Entitäten-Wächter. Abgelegt wird die
  maskierte Antwort. Verdrängung je Partition, Trefferquote als Zahl,
  Invalidierung je Partition und je Modell.
- **Rate-Guard** (`RateGuard`): Token-Eimer je Aufrufer, vor der Firewall statt
  dahinter — die Arbeit ist die Kosten. Antwortet mit 429 und `Retry-After`.
- **Identitäts-Naht** (`PrincipalResolver`): Identitäts-Header werden per
  Default ignoriert statt geglaubt; wer Mandanten trennt, belegt die Behauptung.
- **Maskierungs-Klammer über längere Vorgänge** (`MaskingSessionStore`): hält
  die Rückübersetzung für Agent Loop und menschliche Freigabe vor — nur im
  Speicher, partitionsgebunden, mit kurzer Default- und langer Freigabe-Frist.
- **Quarantäne für Eval-Daten** (`QuarantineSink`): bewahrt Blocks und
  Beinahe-Treffer befristet auf, damit sich Regeln nachschärfen lassen, ohne
  Prompts ins Audit zu schreiben. Default aus, drei Stufen. Standardmäßig nur
  im Speicher; ein `quarantine.directory` in der Daemon-Konfiguration schaltet
  auf eine persistente Datei-Senke um — eine Datei je Vorfall, Ablauffrist im
  Dateinamen und hart durchgesetzt, Schreibprobe beim Start.
- **HTTP-/SSE-Server** mit Provider-Adaptern für OpenAI, Anthropic und Ollama,
  eingehend wie ausgehend.
- **Zwei Betriebsarten nach unten** (`Downstream`): direkt auf einen Provider
  oder als Stufe vor einer Policy Engine — letztere bekommt die kanonische
  Anfrage samt Firewall-Urteil, statt die Bewertung zu wiederholen.
- **Daemon** (`aigatewayd`): JSON-Konfiguration, SIGTERM/SIGINT, geordneter
  Stopp mit Auslauffrist. Der Upstream-Schlüssel kommt aus der Umgebung,
  nie aus der Datei.

## Installation

Als SwiftPM-Abhängigkeit:

```swift
.package(url: "https://github.com/tste04/AIGateway.git", branch: "main")
```

Die drei Produkte sind `GatewayCore` (Typen und Verträge), `InputFirewall`
(Erkennungsstufen) und `GatewayServer` (Transport, Adapter, Pipeline).

## Anwendung

### Prüfen und entscheiden

```swift
import GatewayCore
import InputFirewall

let resolver = SourceTrustResolver()          // unbekannte Quelle = untrusted
let scanner  = InjectionScanner()
let policy   = GatewayPolicy.standard         // Schwelle 0.7, fail-closed

let trust  = resolver.trust(for: "confluence")
let result = scanner.scan(retrievedDocument, trust: trust)
let (disposition, risk) = policy.disposition(for: result)

switch disposition {
case .allow:         forward(result.content)
case .allowModified: forward(result.content)   // bereinigt
case .block:         quarantine(result.findings)
}

// Audit — enthält keinen Nutzinhalt.
let decision = GatewayDecision(
    correlationID: requestID, disposition: disposition, riskScore: risk,
    findings: result.findings, content: result.content)
let event = AuditEvent(decision: decision, principal: principal)
```

### PII maskieren und zurückübersetzen

Das Gateway ist eine Klammer: maskieren auf dem Hinweg, Klardaten zurück auf dem
Rückweg. Der Provider sieht nur Platzhalter.

```swift
let gate = PIIGate(policy: .gatewayDefault, baseDirectory: dataDir,
                   partition: principal.cachePartition)   // ein Vault je Partition

let out = await gate.mask(prompt, sparingQuery: userQuestion)
// out.maskedContent  -> "Bitte an Frau [Person-1] senden, IBAN [IBAN-1]."
let answer = await callModel(out.maskedContent)
let final  = out.session.unmask(answer)                   // Klardaten zurück
```

Ein PII-Treffer blockiert nicht: die Befunde erscheinen im Audit (`PII-001` …),
die Disposition ist `.allowModified`.

### Eigene Regeln

Das Regelwerk ist erweiterbar:

```swift
let own = InjectionRule(id: "ORG-001", category: .dlp, severity: .high, weight: 0.8,
                        message: "internal codename", pattern: #"\bprojekt\s+nordlicht\b"#)!
let scanner = InjectionScanner(rules: InjectionScanner.defaultRules + [own])
```

Fehlalarme werden über die Policy entschärft, ohne die Regel zu entfernen:

```swift
var policy = GatewayPolicy.standard
policy.suppressedRules = ["INJ-008"]   // zählt nicht mehr zum Risiko,
                                       // bleibt aber im Audit sichtbar
```

### Als Dienst betreiben

```swift
let pipeline = GatewayPipeline(
    pii: PIIGate(policy: .gatewayDefault, baseDirectory: dataDir),
    policy: .standard)

let service = GatewayService(
    configuration: GatewayConfiguration(
        port: 8080,
        upstream: .ollama,                                   // oder .openai / .anthropic
        upstreamBaseURL: URL(string: "http://127.0.0.1:11434")!),
    pipeline: pipeline,
    onAudit:      { event in auditLog.append(event) },
    onCompletion: { event in finops.record(event) })

try service.start()
```

Zwei Ereignisse, mit Absicht: `AuditEvent` feuert sofort nach der
Firewall-Entscheidung — stirbt der Prozess während des Modellaufrufs, steht sie
trotzdem im Log. `CompletionEvent` kommt auf dem Rückweg und trägt, was erst
dann bekannt ist: Modell, gemeldeten Token-Verbrauch, Upstream-Latenz und
Ausgang. Verknüpft sind beide über die `correlationID`. Meldet ein Provider
keinen Verbrauch, bleibt das Feld leer — geschätzt wird nie.

### Als Daemon starten

Wer nichts einbetten will, startet `aigatewayd`:

```bash
swift build -c release
export AIGATEWAY_UPSTREAM_API_KEY=…        # nie in die Konfigurationsdatei
.build/release/aigatewayd --config /etc/aigatewayd.json
```

Vorlage: [`docs/aigatewayd.example.json`](docs/aigatewayd.example.json). Die
Konfiguration schaltet Stufen an und ab, bestimmt aber **nie** ihre Position —
die Reihenfolge liegt in der Pipeline, nicht in einer Datei. Ein unbekannter
Schlüssel ist ein Fehler und kein Achselzucken: still ignoriert liefe das
Gateway mit einer Einstellung, die der Betreiber gesetzt zu haben glaubt.

Ereignisse gehen zeilenweise als JSON nach `stderr`. `SIGTERM` und `SIGINT`
beenden geordnet — kein Zulauf mehr, laufende Anfragen zu Ende, dann Schluss;
läuft die Auslauffrist ab, sagt der Daemon das (`drained: false`) und endet mit
Exit-Code 1, statt einen sauberen Stopp zu behaupten.

Ein optionaler Wurzel-Schlüssel `"nextStage"` (eine URL) schaltet den Daemon
vom Proxy- in den **Stufenbetrieb**: statt an den konfigurierten Provider
reicht er dann an diese Adresse weiter — die kanonische, maskierte Anfrage samt
Firewall-Urteil (siehe nächster Abschnitt). Fehlt der Schlüssel, läuft der
Proxy-Betrieb auf `server.upstream`. Die Beispiel-Konfiguration lässt ihn weg,
weil der Alleinbetrieb der Normalfall ist; für den Stufenbetrieb liegt eine
eigene Vorlage bei:
[`docs/aigatewayd.stage.example.json`](docs/aigatewayd.stage.example.json).

**Der Rückweg der Maskierungs-Klammer.** Im Stufenbetrieb mit aktivierten
`maskingSessions` bleibt die Zuordnung nach der Weitergabe **geparkt** — die
nächste Box arbeitet Minuten bis Stunden weiter (Agent Loop, menschliche
Freigabe) und holt sich die Klardaten am Ende der Kette selbst:

- `POST /v1/session/unmask` `{"correlation_id", "content"}` — ersetzt die
  Platzhalter durch Klardaten und schließt die Zuordnung; `"keep": true`
  lässt sie für eine Freigabe-Vorschau stehen. Fehlt die Zuordnung
  (abgelaufen, fremde Partition), kommt der Text **mit Platzhaltern** zurück
  und `"restored": false` sagt es — geraten wird nie.
- `POST /v1/session/extend` — hebt einen Vorgang auf die lange
  Freigabe-Frist.
- `POST /v1/session/close` — wirft die Zuordnung sofort weg (abgebrochener
  Vorgang).

Der Zugriff läuft über denselben Identitäts-Resolver wie der Hinweg und ist
an die Partition gebunden: eine fremde `correlation_id` zu kennen genügt
nicht. Im Alleinbetrieb schließt die Klammer weiterhin mit der Antwort —
den Rückweg gibt es dort nicht, weil niemand später vorbeikommt.

**Mandanten trennen.** Der Abschnitt `identity` (`enabled: true`) schaltet den
`SharedSecretPrincipalResolver` scharf; das Geheimnis kommt aus
`AIGATEWAY_IDENTITY_SECRET`, nie aus der Datei. Ohne ihn ist jeder Aufrufer
anonym und teilt sich **eine** Cache-Partition. Deshalb weist der Daemon eine
falsch-sichere Kombination beim Start ab: `cache.enabled` zusammen mit
`loopbackOnly: false` **ohne** Identität würde Cache-Antworten quer über
ungetrennte Aufrufer ausspielen — entweder Identität einschalten oder auf
Loopback binden. Auch `identity.enabled` ohne gesetztes Geheimnis ist ein
Fehler, kein stiller Abstieg auf anonym.

### Vor einer Policy Engine statt vor einem Provider

Im Zielbild liegt unter dem Gateway nicht das Modell, sondern die nächste Stufe.
Das ist eine Zeile Unterschied und keine in der Firewall:

```swift
let service = GatewayService(
    configuration: GatewayConfiguration(port: 8080),
    pipeline: pipeline,
    downstream: StageDownstream(url: URL(string: "https://policy.internal/v1/decide")!),
    rateGuard: RateGuard(policy: .on))
```

Die nächste Stufe bekommt die kanonische, **maskierte** Anfrage plus das Urteil
der Firewall (Disposition, Risiko, Regel-IDs) — damit muss sie die Bewertung
nicht wiederholen. Der Anzeigetext der Befunde geht nicht mit: er darf frei
umformuliert werden, und eine Gegenstelle, die darauf prüft, bricht beim
nächsten Textlauf.

### Mandanten trennen und cachen

Beides gehört zusammen: der Cache partitioniert über `Principal.cachePartition`
(Mandant + Scopes), also muss die Identität belegt sein, bevor er eingeschaltet
wird.

```swift
let cache = SemanticCache(policy: .on)          // Default AUS, hier eingeschaltet

let pipeline = GatewayPipeline(
    pii: PIIGate(policy: .gatewayDefault, baseDirectory: dataDir),
    policy: .standard,
    cache: cache,
    // Optional: ohne Embedder arbeitet der Cache rein exakt.
    embedder: HTTPEmbedder(baseURL: URL(string: "http://127.0.0.1:11434")!))

let service = GatewayService(
    configuration: GatewayConfiguration(port: 8080),
    pipeline: pipeline,
    // Ohne Resolver werden Identitäts-Header ignoriert — es gibt dann genau
    // eine Partition. Erst dieser Resolver macht Mandanten unterscheidbar.
    principals: SharedSecretPrincipalResolver(secret: gatewaySecret)!,
    onCompletion: { event in finops.record(event) })
```

Die vorgeschaltete Identity-Stufe setzt dann je Anfrage `x-gateway-auth` sowie
`x-gateway-subject`, `-tenant` und `-scopes`. Eine Behauptung ohne gültiges
Geheimnis wird mit **401** beantwortet, nicht stillschweigend auf anonym
zurückgestuft.

Was nicht in den Cache geht: Anfragen mit Tool-Nachrichten, mit ausdrücklich
hoher Temperatur und mit Zeitbezug („heute", „aktuell", „latest"). Ein Treffer
erscheint als `cacheHit` im `CompletionEvent`.

Eingehend werden drei Dialekte bedient: `/v1/chat/completions`, `/v1/messages`
und `/api/chat`. Eingehender und ausgehender Dialekt sind unabhängig — ein Client
im OpenAI-Dialekt kann bedient werden, während das Gateway nach Anthropic
weiterreicht; geantwortet wird im Dialekt der Frage. Streaming (SSE und NDJSON)
wird durchgereicht, inklusive De-Maskierung über Chunk-Grenzen hinweg.

## Sicherheit

Entwurfsregeln, die den Sicherheitseigenschaften zugrunde liegen:

- **Scanner erkennen, Policy entscheidet.** Schwellen sind änderbar, ohne eine
  Erkennungsregel anzufassen.
- **Stabile Regel-IDs** (`INJ-001`) statt Prosa — Suppressions und SIEM binden
  daran.
- **Audit ohne Nutzinhalt.** Regel-IDs, Kategorien, Größen, Zeiten; nie der
  Prompt.
- **Fail-closed.** Eine unbekannte Quelle gilt als fremd; ein Stufen-Ausfall
  blockt.
- **Normalisierung nur zur Erkennung.** Ausgeliefert wird immer der bloß
  sanitisierte Text, damit legitimer nicht-lateinischer Inhalt intakt bleibt.
- **Ein Vault je Mandanten-Partition**, und der Rückweg liest aus der Zuordnung
  der einzelnen Anfrage statt aus globalem Zustand.
- **Identitäts-Behauptungen werden nicht geglaubt**, sondern per Default
  ignoriert. Damit kann kein Aufrufer seine Cache-Partition wählen.
- **Der Cache liegt hinter der Firewall und hinter der Maskierung** und trägt
  nur maskierte Antworten. Er blockt nie: sein einziger Fehlerausgang ist der
  Fehltreffer.

**TLS ist nicht enthalten.** Der Server bindet per Default auf Loopback; die
Terminierung übernimmt ein Reverse Proxy davor. Selbstgeschriebene Krypto ist ein
Risiko, das dieses Projekt nicht eingeht.

**Der Reverse Proxy ist Teil des Sicherheitsmodells.** Das Gateway begrenzt
sich selbst (Verbindungs-Deckel mit 503, Lese-Timeout, Größen-Grenzen); gegen
gezielte volumetrische Angriffe und für Rate-Limiting je Client ist der Proxy
davor zuständig. Fehlerantworten nennen per Default keine Regel-IDs und kein
Upstream-Detail — Korrelation läuft über die `correlation_id` im Audit-Log.

Vollständige Begründungen in [`docs/DECISIONS.md`](docs/DECISIONS.md), inklusive
der verbindlichen Pipeline-Reihenfolge.

### Grenzen

**Das kanonische Modell trägt Chat-Text, keine Tool-Semantik.** Anfragen mit
`tools`, `tool_choice`, `functions` oder erzwungenen Antwortformaten
(`response_format`, Ollama-`format`) werden **abgewiesen statt still
beschnitten** — ein Gateway, das solche Felder kommentarlos entfernt, würde
aus einem Agent-Request einen Chat-Request machen, und die Antwort sähe
trotzdem gültig aus. Multimodale Inhalte (Bilder, Dateien) werden auf ihren
Textanteil reduziert.

Der Injection-Scanner ist eine deterministische Heuristik, kein Modell. Nicht
erkannt werden andere Sprachen als Englisch und Deutsch sowie semantische
Umschreibungen („tu so, als hättest du keine Vorgaben"). Er ist eine erste
Schicht und ersetzt weder Least-Privilege-Tool-Design noch Output-Guardrails.

Das PII-Gate ist auf deutschsprachige Muster optimiert (Anreden, Straßen, PLZ,
Vornamen-Lexikon). Andere Sprachräume brauchen eigene Muster. Pseudonymisierung
ergänzt Datenminimierung, sie ersetzt sie nicht.

## Build

Swift 5.7+, macOS 12+ / Linux. Einzige Abhängigkeit: `Foundation`.

```bash
swift build                  # alle vier Targets
swift test                   # gesamte Suite
swift build -c release
```

Jeder Push und jeder Pull Request wird auf Ubuntu und macOS gebaut und
getestet; beide Plattformen laufen, weil der Code für den Socket-Schreibpfad
und für `FoundationNetworking` auf `canImport(Darwin)` verzweigt.

Einzelne Tests:

```bash
swift test --filter InputFirewallTests            # ein Test-Target
swift test --filter PIIRoundTripTests             # eine Klasse
swift test --filter InputFirewallTests.PIIRoundTripTests/testMaskThenUnmaskRestoresOriginal
```

## Lizenz

AIGateway ist **dual-lizenziert** — der Quellcode ist offen einsehbar, die
Nutzung richtet sich nach dem Zweck:

- **Nichtkommerzielle Nutzung** ist kostenlos unter der
  [PolyForm Noncommercial License 1.0.0](LICENSE.md).
- **Kommerzielle Nutzung** (Einsatz im Unternehmen, Einbettung in ein Produkt,
  Teil eines bezahlten Dienstes) erfordert eine kommerzielle Lizenz — Konditionen
  auf Verhandlungsbasis, siehe [COMMERCIAL.md](COMMERCIAL.md).

Die komponentenübergreifende Lizenz-Policy (Schichtenmodell, Distribution,
Chain of Title) steht in [LICENSING.md](LICENSING.md).

Kommerzielle Anfragen: **[hello@tstellmacher.com](mailto:hello@tstellmacher.com)**

Copyright 2026 Tommy Stellmacher.

## Beiträge

Beiträge sind willkommen und erfordern das CLA ([docs/CLA.md](docs/CLA.md)) —
Details in [CONTRIBUTING.md](CONTRIBUTING.md).
