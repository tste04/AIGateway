# AIGateway

Eine Input Firewall in Swift: die Schicht zwischen Client und Sprachmodell, die
prüft, was hineingeht. Deterministisch, netzfrei im Kern, ohne externe
Abhängigkeiten außer `Foundation`.

**Lizenz:** PolyForm Noncommercial 1.0.0 — nichtkommerziell frei, kommerziell
kostenpflichtig (siehe [Lizenz](#lizenz) / [COMMERCIAL.md](COMMERCIAL.md)).

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
- **Provenienz je Nachrichtenrolle**: `system` gilt als vertrauenswürdig,
  `user`/`assistant` als neutral, `tool` als fremd.
- **Payload-freie Audit-Einträge** mit stabilen Regel-IDs.
- **HTTP-/SSE-Server** mit Provider-Adaptern für OpenAI, Anthropic und Ollama,
  eingehend wie ausgehend.

## Installation

Als SwiftPM-Abhängigkeit:

```swift
.package(url: "https://github.com/rdtste/AIGateway.git", branch: "main")
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
swift build                  # alle drei Targets
swift test                   # gesamte Suite
swift build -c release
```

Einzelne Tests:

```bash
swift test --filter InputFirewallTests            # ein Test-Target
swift test --filter PIIRoundTripTests             # eine Klasse
swift test --filter InputFirewallTests.PIIRoundTripTests/testMaskThenUnmaskRestoresOriginal
```

## Lizenz

AIGateway ist **dual-lizenziert**:

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
