# AIGateway

Ein souveränes **AI Gateway** in Swift: die Schicht zwischen Nutzer und
Sprachmodell, die prüft, was hineingeht — deterministisch, netzfrei im Kern,
ohne externe Abhängigkeiten.

> **Status: früh.** `GatewayCore` (Verträge und Entscheidungstypen) und die
> Injection-Stufe der Input Firewall stehen. PII, DLP, Malware, Semantic Cache
> und der HTTP-Server sind **noch nicht gebaut** — siehe Fahrplan unten.

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
| Input Firewall — **Injection** (+ Secret-Formate, Sanitisierung, Größen-Anomalie) | ✅ |
| Input Firewall — PII · DLP · Malware | ⬜ |
| Semantic Cache | ⬜ |
| HTTP/SSE-Server, Provider-Adapter | ⬜ |

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

## Entwurfsregeln

- **Scanner erkennen, Policy entscheidet.** Schwellen ändern, ohne Regeln anzufassen.
- **Stabile Regel-IDs** (`INJ-001`) statt Prosa — Suppressions und SIEM binden daran.
- **Audit ohne Nutzinhalt.** Regel-IDs, Kategorien, Größen, Zeiten. Nie der Prompt.
- **Fail-closed.** Unbekannte Quelle gilt als fremd; Stufen-Ausfall blockt.
- **Kein selbstgeschriebenes TLS.** Loopback-Default, Terminierung per Reverse Proxy.

Vollständig in [`docs/DECISIONS.md`](docs/DECISIONS.md), inklusive verbindlicher
Pipeline-Reihenfolge und der Cache-Festlegungen.

## Bekannte Grenzen (ehrlich)

Der Injection-Scanner ist eine deterministische Heuristik, kein Modell. Er
erkennt derzeit **nicht**:

- nicht-englische Formulierungen (deutsche Injektionen: Score 0)
- Homoglyphen (kyrillisches `о` statt `o`)
- buchstabenweise Trennung (`I g n o r e …`)
- kodierte Nutzlasten (Base64)

Diese Lücken sind als `testKnownLimitation_*` in der Testsuite festgehalten.
Der Scanner ist eine billige erste Schicht — kein Ersatz für
Least-Privilege-Tool-Design und Output-Guardrails.

## Plattformen

macOS 12+ / Linux, Swift 5.7+. Einzige Abhängigkeit: `Foundation`.

## Lizenz

Apache-2.0 — siehe [`LICENSE`](LICENSE).
