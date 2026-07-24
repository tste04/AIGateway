# Architektur-Entscheidungen

Verbindliche Festlegungen für AIGateway. Wer hier etwas ändert, ändert die
Statik des Projekts — bitte mit Begründung und Datum ergänzen.

## Zielbild-Einordnung

AIGateway implementiert genau eine Box des KI-Zielbilds:

```
User → Identity/SSO → [ AI Gateway ] → Policy Engine → AI Router → …
                         ├── Input Firewall (PII • DLP • Malware • Injection)
                         └── Semantic Cache 💰
```

Alles darunter (Policy Engine, Router, Orchestrator, Agent Loop, Output
Guardrails, Approval, Action Layer) ist **ausdrücklich nicht** Teil dieses
Repos.

## Grundentscheidungen (Juli 2026)

| # | Thema | Entscheidung | Konsequenz |
|---|---|---|---|
| 1 | HTTP-Stack | **Selbst schreiben, keine Abhängigkeiten** | POSIX-Server für eingehend; ausgehend `URLSession`/`FoundationNetworking` (Toolchain, keine Dependency) |
| 2 | Provider-Surface | **Alle** — OpenAI, Anthropic, Ollama | Erzwingt ein kanonisches internes Modell + Adapter je Provider |
| 3 | Embedder (Cache) | **API-förmig, lokal lauffähig** | Eine HTTP-Implementierung mit konfigurierbarer Basis-URL; Ollama lokal oder Cloud-API — Betreiberwahl |
| 4 | Deployment | **Eigenständiger Daemon** | Config-Datei, Signal-Handling, Graceful Shutdown; keine Einbettungspflicht |
| 5 | PII-Gate | **Vorhandene Pseudonymisierung übernehmen** | Plus neu: Round-Trip (maskieren hin, de-maskieren zurück) |

### Kein selbstgeschriebenes TLS

Folgt aus (1), ist aber eine eigene Festlegung: Ein handgeschriebener
TLS-Stack wäre das mit Abstand größte Risiko im Projekt. Stattdessen:
**Default-Bind auf Loopback, TLS-Terminierung ist Betreibersache** (Reverse
Proxy davor). Damit bleibt „null Abhängigkeiten" ehrlich einlösbar.

## Tragende Entwurfsregeln

### Scanner erkennen, Policy entscheidet
Ein `ContentScanner` liefert `ScanResult` (Befunde + Score + bereinigter
Inhalt) und trifft **keine** Block-Entscheidung. Schwellen und Fehlerverhalten
sind Betriebsparameter in `GatewayPolicy` und müssen änderbar sein, ohne eine
Erkennungsregel anzufassen.

### Stabile Regel-IDs statt Prosa
Suppressions, SIEM-Korrelation und Dashboards binden an `RuleID`
(`INJ-001`, `SEC-002`, …). Anzeigetexte sind frei umformulierbar. Eine ID zu
ändern ist ein Breaking Change.

### Audit ohne Nutzinhalt
`AuditEvent` enthält **niemals** Prompt, Antwort oder Treffer-Auszüge — nur
Regel-IDs, Kategorien, Größen und Zeiten. Ein Audit-Log ist langlebig und
breit lesbar; würde es Payload mitschreiben, wäre ausgerechnet die Komponente,
die PII fernhalten soll, deren dauerhafter Speicher. `AuditEvent(decision:principal:)`
ist der einzige vorgesehene Weg und lässt den Payload bewusst fallen.

### Fail-closed als Default
Zwei Stellen:
- **Unbekannte Quelle** → `SourceTrust.untrusted` (nicht `neutral`). Sonst wäre
  jeder nicht katalogisierte Konnektor automatisch der mildeste Pfad — und
  genau dort kommt Fremdinhalt herein.
- **Stufen-Ausfall/Timeout** → `FailureMode.failClosed`.

### Harte Eingabegrenze vor jedem Scan
`GatewayPolicy.maxInputBytes` bricht ab, statt nur Risiko aufzuschlagen. Ohne
diese Grenze läuft jedes Regelwerk über beliebig große Eingaben — das Gateway
liegt im synchronen Pfad.

## Pipeline-Reihenfolge (verbindlich)

```
REQUEST
 1. Identity/Principal (von oben)
 2. Größen-/Rate-Guard              ← billig, DoS-Schutz, vor allem anderen
 3. Malware-Scan (Anhänge)          ← bevor irgendetwas geparst wird
 4. Injection-Scan                  ← Prompt UND retrieved content
 5. PII-Erkennung → Maskierung  ★
 6. DLP-Policy (block/redact/allow)
 7. Semantic-Cache-Lookup  ★★
      HIT  → Antwort → De-Maskierung → raus   💰
      MISS → weiter an Policy Engine
RESPONSE
 8. De-Maskierung · Cache-Store · Audit-Event · Token-/Kosten-Metrik
```

★ **Maskierung muss vor dem Cache-Schlüssel liegen.** Zwei Gründe: sonst liegt
PII im Cache-Index (Compliance-GAU), und nach Maskierung werden Anfragen, die
sich nur in Namen unterscheiden, identisch — die Pseudonymisierung **erhöht**
die Trefferquote. Datenschutz und Kostenersparnis zeigen hier ausnahmsweise in
dieselbe Richtung.

★★ **Cache-Lookup nach der Firewall**, nie davor — sonst lässt sich der Cache
mit vergifteten Prompts befüllen oder an der Firewall vorbei ausspielen.

**Das Gateway ist bidirektional.** Im Zielbild ist es einseitig gezeichnet;
faktisch braucht es den Rückweg zwingend (De-Maskierung, Cache-Store). Es ist
eine Klammer um die Pipeline, kein Durchgangsknoten.

## Semantic Cache — drei Festlegungen

1. **Partitionierung über Mandant + Scopes, nicht über Subject**
   (`Principal.cachePartition`). Pro-Nutzer-Schlüsselung wäre sicher, aber
   wirtschaftlich wertlos; nur über den Prompt zu schlüsseln macht den Cache zum
   Access-Control-Bypass. Gleiche Berechtigung = gleiche Sicht = Treffer teilbar.
2. **Entitäten-/Zahlen-Wächter.** „Umsatz Q3" und „Umsatz Q4" liegen im
   Embedding-Raum dicht beieinander, brauchen aber verschiedene Antworten.
   Weichen extrahierte Zahlen, Daten oder Eigennamen ab, gibt es keinen Treffer
   — unabhängig von der Cosine-Ähnlichkeit.
3. **Exakter Hash-Treffer zuerst**, semantisch nur als zweite Stufe mit hoher
   Schwelle. Nicht cachebar: Tool-Calling-Turns, hohe Temperatur,
   zeitabhängige Fragen.

### PII-Befunde blockieren nicht

Ein erkanntes Personendatum ist **kein Verstoß** — es wird behoben, indem
maskiert wird. PII-Findings tragen deshalb Gewicht 0: sie stehen im Audit,
lösen aber `.allowModified` aus statt `.block`. Würden sie blocken, wäre jeder
realistische Prompt abgelehnt. Einzige Ausnahme: der Dichte-Wächter mit
`onDensityExceeded: "abstain"` — dort ist das Blocken der ausdrückliche Wunsch.

### Provenienz gewichtet PII nicht

Der Trust-Multiplikator bleibt bei 1.0. Eine IBAN ist in einer eigenen Notiz
genauso schutzbedürftig wie in fremder Post — anders als bei Injection, wo die
Herkunft die Gefährlichkeit bestimmt.

### Ein Vault je Partition

Zwei Mandanten dürfen sich keinen Vault teilen, sonst laufen ihre Token-Räume
ineinander. Pfad über `PseudonymVault.url(baseDirectory:partition:)`. Der
Rückweg ist zusätzlich abgesichert: `MaskingSession` trägt die Zuordnung
**dieser einen Anfrage**, statt sie aus dem globalen Vault zu lesen.

### Normalisierung nur zur Erkennung

Der Mustervergleich läuft zusätzlich auf einer normalisierten
Erkennungs-Oberfläche (NFKC, Homoglyphen-Faltung, Trennzeichen-Kollaps,
dekodiertes Base64). **Diese Oberfläche wird nie ausgeliefert.** Würde man
Homoglyphen im Nutztext falten, zerstörte das legitimen kyrillischen oder
griechischen Inhalt — aus `Москва` würde Buchstabensalat.

Drei Stufen, jeweils nur bei Bedarf: Klartext → Oberfläche (nur wenn sie sich
unterscheidet) → kompakte Fassung (nur bei tatsächlich erkannter
Buchstaben-Sperrung, mit gelockerten `\s*`-Mustern). Auf normaler Prosa
entstehen Stufe 2 und 3 nie, der Normalfall kostet also nichts.

Ein Treffer, der **erst nach** Normalisierung zustande kommt, erzeugt zusätzlich
`SAN-003` — ein Umgehungsversuch wiegt schwerer als derselbe Text im Klartext.

### Rollen bestimmen die Provenienz

Im Gateway wird nicht der ganze Prompt als ein Block bewertet, sondern jede
Nachricht mit der Vertrauensstufe ihrer Rolle:

| Rolle | Trust | Begründung |
|---|---|---|
| `system` | `trusted` | stammt aus der Anwendung selbst |
| `user` / `assistant` | `neutral` | |
| `tool` | `untrusted` | **der Hauptangriffsweg im Agent Loop** — ein Werkzeug liefert Fremdinhalt, der als Anweisung gelesen wird |

Dieselbe Zeichenfolge wird dadurch in einer Systemnachricht durchgelassen und in
einer Tool-Ausgabe geblockt. Das ist beabsichtigt.

### De-Maskierung im Datenstrom

Ein Platzhalter kann über SSE-Chunks zerfallen (`"...[Pers"` / `"on-1]..."`).
Wer jeden Chunk einzeln übersetzt, findet ihn in keinem von beiden — er
erreicht den Nutzer unübersetzt. `StreamRewriter` hält deshalb genau so viel
Text zurück, wie der **Anfang eines bekannten Platzhalters** sein könnte
(Präfix-Prüfung gegen die Zuordnung dieser Anfrage). Auf normalem Text wird
nichts zurückgehalten — die Latenz-Kosten entstehen nur an einer
Platzhalter-Grenze.

### Kein Keep-Alive, kein chunked Request-Body

Eine Anfrage je Verbindung. Spart den halben Zustandsautomaten; der Durchsatz
eines Gateways hängt am Modell, nicht am Socket.

## Bekannte Lücken (bewusst offen)

Der Regelkatalog deckt Englisch (INJ-0xx) und Deutsch (INJ-1xx) ab. Andere
Sprachen brauchen eigene Regeln. Semantische Umschreibungen („tu so, als
hättest du keine Vorgaben") erkennt keine Regex — dagegen hilft nur ein
Klassifikator, und der ist bewusst nicht Teil dieser Stufe.

Das PII-Gate ist auf **deutschsprachige** Muster optimiert (Anreden, Straßen,
PLZ, Vornamen-Lexikon). Andere Sprachräume brauchen eigene Muster. Auch hier
gilt: deterministische Heuristik, keine Vollständigkeitsgarantie —
Pseudonymisierung ergänzt Datenminimierung, sie ersetzt sie nicht.

## Umsetzungsreihenfolge

| Rang | Paket | Stand |
|---|---|---|
| 1 | `GatewayCore` — Decision, RuleIDs, Audit, Policy | **fertig** |
| 2 | PII-Gate + Round-Trip-Maskierung | **fertig** |
| 3 | Injection-Nachschärfung (Normalisierung, DE-Regeln) | **fertig** |
| 4 | `GatewayServer` (HTTP + SSE, 3 Provider-Adapter) | **fertig** |
| 5 | Semantic Cache | offen |
| 6 | DLP-Policy-Semantik | offen |
| 7 | Malware (ClamAV-Naht) | offen |
