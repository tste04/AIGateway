# AIGateway

Ein souveränes **AI Gateway** in Swift: die Schicht zwischen Nutzer und
Sprachmodell, die prüft, was hineingeht — deterministisch, netzfrei im Kern,
ohne externe Abhängigkeiten.

> **Status: früh.** `GatewayCore`, die Injection- und die PII-Stufe der Input
> Firewall sowie der HTTP-/SSE-Server mit den drei Provider-Adaptern stehen.
> DLP, Malware und Semantic Cache sind **noch nicht gebaut** — siehe Fahrplan
> unten.

## Einordnung

```
User → Identity/SSO → [ AI Gateway ] → Policy Engine → AI Router → …
                         ├── Input Firewall (PII • DLP • Malware • Injection)
                         └── Semantic Cache 💰
```

Dieses Repo implementiert genau diese eine Box. Alles darunter ist
ausdrücklich nicht Teil davon.

## Was heute funktioniert

| Baustein | Stand |
|---|---|
| `GatewayCore` — `GatewayDecision`, `RuleID`, `Finding`, `AuditEvent`, `GatewayPolicy`, `Principal` | ✅ |
| Input Firewall — **Injection** (EN + DE, Verschleierungs-Normalisierung, Secrets) | ✅ |
| Input Firewall — **PII** (Erkennung, Maskierung, Round-Trip) | ✅ |
| Input Firewall — DLP · Malware | ⬜ |
| Semantic Cache | ⬜ |
| **HTTP/SSE-Server**, Provider-Adapter (OpenAI · Anthropic · Ollama) | ✅ |

## Benutzung

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

// Audit — enthält bewusst KEINEN Nutzinhalt.
let decision = GatewayDecision(
    correlationID: requestID, disposition: disposition, riskScore: risk,
    findings: result.findings, content: result.content)
let event = AuditEvent(decision: decision, principal: principal)
```

### PII maskieren und zurückübersetzen

Das Gateway ist eine Klammer: maskieren auf dem Hinweg, Klardaten zurück auf
dem Rückweg. Der Provider sieht nur Platzhalter.

```swift
let gate = PIIGate(policy: .gatewayDefault, baseDirectory: dataDir,
                   partition: principal.cachePartition)   // ein Vault je Partition

let out = await gate.mask(prompt, sparingQuery: userQuestion)
// out.maskedContent  -> "Bitte an Frau [Person-1] senden, IBAN [IBAN-1]."
let answer = await callModel(out.maskedContent)
let final  = out.session.unmask(answer)                   // Klardaten zurück
```

Ein PII-Treffer blockiert nicht — er wird behoben. Die Befunde erscheinen im
Audit (`PII-001` …), die Disposition ist `.allowModified`.

### Eigene Regeln

Das Regelwerk ist offen — Organisationen haben eigene Muster:

```swift
let own = InjectionRule(id: "ORG-001", category: .dlp, severity: .high, weight: 0.8,
                        message: "internal codename", pattern: #"\bprojekt\s+nordlicht\b"#)!
let scanner = InjectionScanner(rules: InjectionScanner.defaultRules + [own])
```

Fehlalarme werden über die Policy entschärft, ohne die Regel zu verlieren:

```swift
var policy = GatewayPolicy.standard
policy.suppressedRules = ["INJ-008"]   // zählt nicht mehr zum Risiko,
                                       // bleibt aber im Audit sichtbar
```

## Als Dienst betreiben

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

Eingehend werden alle drei Dialekte bedient — `/v1/chat/completions`,
`/v1/messages`, `/api/chat`. Der Client darf im OpenAI-Dialekt sprechen,
während das Gateway nach Anthropic weiterreicht; die Antwort kommt im Dialekt
der Frage zurück. Streaming (SSE und NDJSON) wird durchgereicht, inklusive
De-Maskierung über Chunk-Grenzen hinweg.

**TLS ist bewusst nicht enthalten.** Der Server bindet auf Loopback;
Terminierung übernimmt ein Reverse Proxy davor. Selbstgeschriebene Krypto wäre
das größte Risiko im Projekt.

## Entwurfsregeln

- **Scanner erkennen, Policy entscheidet.** Schwellen ändern, ohne Regeln anzufassen.
- **Stabile Regel-IDs** (`INJ-001`) statt Prosa — Suppressions und SIEM binden daran.
- **Audit ohne Nutzinhalt.** Regel-IDs, Kategorien, Größen, Zeiten. Nie der Prompt.
- **Fail-closed.** Unbekannte Quelle gilt als fremd; Stufen-Ausfall blockt.
- **Kein selbstgeschriebenes TLS.** Loopback-Default, Terminierung per Reverse Proxy.

Vollständig in [`docs/DECISIONS.md`](docs/DECISIONS.md), inklusive verbindlicher
Pipeline-Reihenfolge und der Cache-Festlegungen.

## Bekannte Grenzen (ehrlich)

Der Injection-Scanner ist eine deterministische Heuristik, kein Modell.

Erkannt werden englische und deutsche Muster, auch verschleiert: Homoglyphen
(`Ignоre` mit kyrillischem о), Buchstaben-Sperrung (`I g n o r e …`),
Trennzeichen (`IGNORE-ALL-PREVIOUS`) und Base64-Nutzlasten. Die dafür nötige
Normalisierung dient **nur dem Vergleich** — ausgeliefert wird immer der bloß
sanitisierte Text, damit legitimer nicht-lateinischer Inhalt intakt bleibt.

Nicht erkannt werden: andere Sprachen als EN/DE und semantische Umschreibungen
(„tu so, als hättest du keine Vorgaben"). Der Scanner ist eine billige erste
Schicht — kein Ersatz für Least-Privilege-Tool-Design und Output-Guardrails.

## Plattformen

macOS 12+ / Linux, Swift 5.7+. Einzige Abhängigkeit: `Foundation`.

## Lizenz

Apache-2.0 — siehe [`LICENSE`](LICENSE).
