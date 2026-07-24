# InjectionScanner

Ein reiner, abhängigkeitsfreier **Prompt-Injection-Wächter** für Swift. Bewertet
Fremdinhalt (E-Mails, Web-Snippets, Tool-Output, retrieved documents), bevor er in ein
LLM oder eine Memory-/RAG-Schicht gelangt — deterministisch, netzfrei, keine Telemetrie.

## Was es prüft

- **Sanitisierung** — entfernt unsichtbare/bidirektionale/Steuerzeichen (klassische
  Tarn-Vektoren für versteckte Anweisungen), zerstörungsfrei.
- **Injection-Heuristik** — kuratierte Muster bekannter Override-/Exfiltrations-Vektoren
  („ignore previous instructions", „reveal your system prompt", DAN, gefälschte Rollen-Tags,
  Markdown-Bild-Exfil-Kanäle …).
- **Secret-Erkennung** (OWASP-ASI06) — erkennbare Zugangsdaten-Formate (Private Keys,
  AWS-/GitHub-/Slack-Token, JWTs, `sk-…`).
- **Größen-Anomalie** — Context-Stuffing-Vektoren.
- **Provenance-Gewichtung** — vertrauenswürdige Quellen milder, externe strenger.

## Installation

```swift
.package(url: "https://github.com/<you>/InjectionScanner.git", from: "0.1.0")
```

## Benutzung

```swift
import InjectionScanner

let scanner = InjectionScanner()   // Schwelle/Quellen-Sets konfigurierbar

let a = scanner.assess(
    content: retrievedDocument,
    sourceType: "web"              // "note"/"manual" = trusted, "web"/"email"/"tool" = untrusted
)

switch a.verdict {
case .clean:
    use(a.sanitizedContent)
case .sanitized(let reasons):
    log(reasons); use(a.sanitizedContent)          // gesäubert weiterverwenden
case .quarantined(let reasons):
    hold(a.sanitizedContent, reasons)              // NICHT weitergeben — nur Audit/Review
}
// a.riskScore ∈ 0...1
```

`assess(...)` ist eine reine Funktion ohne Seiteneffekte — thread- und `Sendable`-sicher.

## Bewusste Grenzen (ehrlich)

Deterministische Heuristik, kein LLM und kein Netz. **Keine Vollständigkeitsgarantie** —
Freitext kann Anweisungen tragen, die keine Heuristik sieht. Der Scanner ist eine
Verteidigungsschicht, kein Ersatz für Least-Privilege-Tool-Design und Output-Guardrails.

## Plattformen

macOS 12+ / Linux, Swift 5.7+. Einzige Abhängigkeit: `Foundation`.

## Lizenz

Apache-2.0 — siehe `LICENSE`.
