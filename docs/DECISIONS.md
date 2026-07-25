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

#### Was `stageBudgetMilliseconds` leistet — und was nicht (Juli 2026)

Das Budget wird **nach** jeder Stufe ausgewertet, nicht als Abbruch währenddessen.
Reißt eine Stufe es, trägt ihr `StageTiming` `timedOut`, die Entscheidung wird
`degraded`, und `failureMode` bestimmt den Ausgang: `failClosed` blockt mit
`GW-002`, `failOpen` lässt durch — beides sichtbar im Audit, denn auch das
Durchlassen ist dann eine ungeprüft getroffene Entscheidung.

Ein echter Abbruch wäre hier eine Illusion: beide Stufen sind reine Regex-Läufe
ohne Netz-I/O, und ein Backtracking-Lauf lässt sich in Swift nicht von außen
unterbrechen. Ihn in einer Nebenaufgabe verhungern zu lassen würde unter genau
der Last Threads stapeln, gegen die das Budget schützen soll. Die harte
Laufzeitgrenze der Regeln ist deshalb `maxInputBytes` (Stufe 2), nicht das
Budget. Sobald eine Stufe mit echtem I/O dazukommt (ClamAV-Socket, Embedder),
braucht **die** eine Abbruchsemantik — das ist dann eine eigene Festlegung.

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

### Risiko je Nachricht: Maximum statt Summe

Die Pipeline bewertet jede Nachricht einzeln und nimmt das **Maximum** der
Risiken, keine Summe über die Anfrage. Das ist eine Folge der Provenienz:
jede Nachricht trägt ihren eigenen Trust-Multiplikator, und eine Summe über
verschieden gewichtete Werte hätte keine sinnvolle Einheit — 0.3 aus einer
Systemnachricht und 0.3 aus einer Tool-Ausgabe sind nicht dasselbe Risiko.

Der bekannte Preis: zwei mittlere Befunde, auf zwei Nachrichten verteilt,
addieren sich nicht (2 × 0.405 blockt nicht, 1 × 0.81 schon). Das ist
akzeptiert, weil die Muster, die blocken sollen, innerhalb **einer** Nachricht
zünden — ein Angreifer, der seine Anweisung über Nachrichten verteilt,
zerreißt damit auch die Wortfolgen, auf denen die Regeln matchen. Wer
Kumulativ-Verhalten braucht, senkt `blockThreshold`, statt die Verrechnung zu
ändern.

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

### Betriebsgrenzen des Servers (Juli 2026)

Der Server bleibt Thread-per-Connection — einfach, auditierbar, und der
Durchsatz hängt ohnehin am Modell. Die Konsequenz wird aber begrenzt statt
ignoriert:

- **Verbindungs-Deckel** (`maxConcurrentConnections`, Default 64): über dem
  Deckel wird sofort mit 503 abgewiesen, statt einen weiteren Thread zu
  binden. N langsame Clients binden sonst N Threads.
- **Lese-Timeout** (`readTimeoutSeconds`, Default 30 s, `SO_RCVTIMEO`): ein
  Client, der den Rumpf nie zu Ende sendet, verliert die Verbindung, statt
  einen Thread unbegrenzt zu halten. Die Header-Obergrenze (64 KiB) begrenzt
  die Menge, das Timeout die Dauer.
- **413 gegen die angekündigte Größe**: `Content-Length` über
  `maxBodyBytes` wird als 413 abgewiesen — auch wenn der bereits gelesene
  Teil-Rumpf unter der Grenze liegt.

**Der Reverse Proxy davor ist Teil des Sicherheitsmodells**, nicht nur
TLS-Terminierer. Von ihm wird erwartet: Rate-Limiting je Client, ggf.
Auth-Durchsetzung, und Schutz gegen Verbindungs-Fluten jenseits des Deckels.
Das Gateway verteidigt sich gegen versehentliche Überlast; gegen gezielte
volumetrische Angriffe verteidigt es sich ausdrücklich nicht selbst.

### Fehler im laufenden Strom

Ein Upstream-Fehler nach `beginStream` ist als HTTP-Status nicht mehr
ausdrückbar. Ein stummer Abbruch sieht für den Client wie eine vollständige
Antwort aus — das ist das schlechteste Ergebnis, weil halbe Antworten als
ganze verarbeitet werden. Deshalb: ein Fehler-Ereignis **im Dialekt des
Clients** (`encodeStreamError`), danach Verbindungsende, und bewusst **kein
Terminator** (`[DONE]`/`message_stop`) — der würde regulären Abschluss
signalisieren.

### Fehlerdetails sind eine Betriebsoption

Die Standard-Fehlerantworten nennen **keine** Regel-IDs (403) und **kein**
Upstream-Detail (502). Regel-IDs sind ein Tuning-Orakel — ein Angreifer
erfährt regelgenau, was angeschlagen hat; der Upstream-Fehlerkörper ist
fremder Inhalt, der nicht ungefragt zum Client durchgereicht wird. Beides ist
über die `correlation_id` mit dem Audit-Log korrelierbar; `debugErrorDetails`
schaltet die ausführliche Form für Entwicklung frei.

## Nähte zum Gesamtbild (Juli 2026)

Das Zielbild ist mehr als diese Box: unterhalb folgen Policy Engine, Router,
Context Orchestrator, Agent Loop, Output Guardrails, Approval und Action Layer,
dahinter Audit • Metrics • FinOps • Evaluation mit einem Feedback Loop zurück.
Der Umfang dieses Repos bleibt die eine Box — aber die **Nähte** zu den
Nachbarn werden hier festgelegt, weil sie Signaturen bestimmen und weil sie
sonst später an der falschen Stelle entstehen.

### Der Geltungsbereich der Erkennung ist breiter als das Gateway

Der `⚠️ Injection-Scan auf Retrieved Content` im Context Orchestrator ist
derselbe Baustein wie die Injection-Stufe hier — `SourceTrustResolver`
katalogisiert bereits wörtlich dessen Quellen (`confluence`, `sharepoint`,
`jira`, `gitlab`, `rag_chunk`, `retrieval`, `wiki`, `crawl`).

Festlegung: **`GatewayCore` + `InputFirewall` sind ein wiederverwendbares Paar.**
Der Orchestrator zieht diese beiden Targets direkt; `GatewayServer` ist der
Gateway-spezifische Aufsatz und darf nie zur Voraussetzung für eine
Erkennungsstufe werden. Ohne diese Zusage baut der Orchestrator seinen eigenen
zweiten Scanner — mit eigenen Regel-IDs, an denen dann andere SIEM-Regeln
hängen.

### Identität wird vorausgesetzt, nicht geprüft

`Principal` entsteht aus den Headern `x-gateway-subject`, `x-gateway-tenant`,
`x-gateway-scopes` — **ungeprüft**. Das ist die Arbeitsteilung mit der
Identity/SSO-Stufe darüber und nur haltbar, solange das Gateway auf Loopback
bindet und nichts anderes es erreicht.

**Sperrvermerk für Rang 5:** `Principal.cachePartition` leitet sich aus Mandant
und Scopes ab. Solange beide aus einem fälschbaren Header stammen, wählt ein
Angreifer seine Cache-Partition frei — der Semantic Cache wäre dann genau der
Access-Control-Bypass, gegen den er partitioniert wird. Der Cache darf erst
beginnen, wenn die Herkunft des `Principal` verifiziert ist (signiertes Token
oder ein Transportweg, den nur die Identity-Stufe erreicht).

### Abwärts-Naht: heute Provider, später die nächste Box

Implementiert ist ein Proxy — `GatewayConfiguration.upstream` zeigt auf einen
Modellanbieter, nicht auf die Policy Engine. Das ist bewusst: so läuft das
Gateway allein und liefert sofort Wert.

Festlegung: Die Abwärts-Naht wird als Abstraktion eingezogen (`Downstream`),
mit der Provider-Variante als erster Implementierung. Die Stufen-Variante, die
`(maskierte Anfrage, Entscheidung, Principal)` an die nächste Box reicht, kommt
als **zusätzliche** Implementierung, wenn die Policy Engine existiert — nicht
als Umbau. Was nach unten geht, trägt **nie** den Rohtext: die nächste Box
bekommt die maskierte Anfrage plus Befunde und Risiko, nach demselben Prinzip,
nach dem `AuditEvent` den Payload fallen lässt.

### Die Maskierungs-Klammer muss den Agent Loop überleben

Zwischen Maskierung und De-Maskierung liegen im Zielbild Router, Orchestrator,
`n` Iterationen Agent Loop, Output Guardrails und — bei hohem Risiko — eine
**menschliche Freigabe**. Das sind Minuten bis Stunden, nicht Millisekunden.
`MaskingSession` als lokale Variable einer HTTP-Anfrage trägt das nicht.

Vier Festlegungen für den kommenden `MaskingSessionStore`:

1. **Nur im Speicher, niemals persistiert.** Die Zuordnung ist Klartext-PII.
   Sie auf Platte zu schreiben machte ausgerechnet die Komponente, die PII vom
   Provider fernhält, zu deren dauerhaftem Speicher — dasselbe Argument, das
   `AuditEvent` payload-frei hält.
2. **Verlust ist sichtbar, nicht still.** Fehlt die Session, geht die Antwort
   **mit Platzhaltern** hinaus. Nicht raten, und nicht ersatzweise aus dem
   globalen Vault auflösen — das wäre genau der mehrmandantenunsichere Rückweg,
   den `MaskingSession` vermeidet. Der Nutzer sieht `[Person-1]` und meldet es.
3. **Der Zugriff ist an die Partition gebunden**, nicht nur an die
   `correlationID`. Eine UUID zu raten ist unwahrscheinlich; die Bindung kostet
   nichts und schließt die Klasse aus.
4. **Zwei Fristen.** Kurzer Default (Größenordnung Minuten) für den
   Auto-Execute-Pfad, plus ein ausdrückliches Verlängern für Vorgänge, die in
   die menschliche Freigabe gehen. Eine einzige Frist, die beides abdeckt,
   hielte Klardaten stundenlang für **jede** Anfrage vor.

Dazu die Reihenfolge-Festlegung: **De-Maskierung ist der letzte Schritt der
Kette, nach den Output Guardrails.** Deren PII- und Compliance-Prüfung muss
Klartext sehen; hinter der De-Maskierung prüfte sie Platzhalter und fände
nichts.

### Audit und Abschluss sind zwei Ereignisse

`AuditEvent` bleibt und feuert **sofort nach der Entscheidung**, vor dem Weg
nach oben. Stirbt der Prozess während des Modellaufrufs, existiert die
Firewall-Entscheidung trotzdem im Log; ein einziges Ereignis am Ende verlöre
ausgerechnet die sicherheitsrelevante Aufzeichnung.

Auf dem Rückweg kommt ein zweites, über `correlationID` verknüpftes Ereignis:
Modell, Token-Verbrauch, Upstream-Latenz, Cache-Treffer. Begründung: Das
Gateway ist die **einzige** Stelle im Zielbild, die Anfrage und Antwort
zusammen sieht — lässt es die Zahlen fallen, kann die FinOps-Box sie nirgends
mehr einsammeln. Heute werden sie dekodiert und verworfen.

**Token-Zahlen werden nie geschätzt.** Liefert ein Provider keine, bleibt das
Feld leer. Eine erfundene Zahl in einer Kostenrechnung ist schlimmer als eine
fehlende.

### Eval-Daten kommen nicht aus dem Audit

Der Feedback Loop tunt Router und Guardrails mit Beispielen — also mit Text.
`AuditEvent` enthält per Invariante niemals Nutzinhalt. Beides ist richtig und
beides zusammen heißt: **der Feedback Loop kann nicht aus dem Audit-Log
gespeist werden.** Ohne eine ausdrückliche Festlegung endet das damit, dass
jemand Prompts ins Audit schreibt und die Invariante bricht.

Festlegung: ein **getrennter** Quarantäne-Pfad (`QuarantineSink`), Default
**aus** — Opt-in wie jede Expositions-Entscheidung. Drei Stufen:

| Stufe | Inhalt | Einsatz |
|---|---|---|
| `counts` | nur Regel-IDs und Häufigkeiten | sicherer Default, wenn überhaupt an |
| `masked` | PII-maskierter Text | die Arbeitsstufe |
| `raw` | Rohtext | nur mit ausdrücklicher Betreiber-Entscheidung |

`masked` ist keine Notlösung: Injection-Muster sind **strukturell**, nicht
namensabhängig — „ignore all previous instructions", Homoglyphen und
Buchstaben-Sperrung überstehen die Maskierung unbeschadet. Nur wer die
PII-Regeln selbst tunen will, braucht `raw`.

Gesammelt werden `.block`-Entscheidungen **und eine Stichprobe knapp unter der
Schwelle** — dort sitzen die Fehlalarme und die knapp durchgerutschten
Angriffe, also die wertvollsten Beispiele. Dazu eine harte Aufbewahrungsfrist
in Tagen, die ein Aufräumlauf durchsetzt. Der Haken dafür existiert bereits:
`GatewayDecision.content` trägt bei `.block` den Originalinhalt.

### Malware braucht erst eine Angriffsfläche (Vorbedingung für Rang 7)

`ChatRequest` kennt nur Text; die Adapter flachen auch Block-Arrays zu Text ab.
Es gibt keine Anhänge — der Malware-Scan ist also nicht „noch nicht gebaut",
sondern hat nichts, woran er ansetzen könnte. Vor Rang 7 braucht es eine
Anhang-Repräsentation im kanonischen Modell und die `PayloadScanner`-Naht auf
Bytes; `ContentScanner` arbeitet auf `String` und ist dort das falsche Modell.
Im Ablauf steht Malware **vor** der Injection-Stufe (Schritt 3), nicht daneben.

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
| 5 | Semantic Cache | offen — **gesperrt**, s. Identity-Vorbedingung |
| 6 | DLP-Policy-Semantik | offen |
| 7 | Malware (ClamAV-Naht) | offen — Anhang-Naht fehlt |

Die Ränge sind Feature-Boxen. Die Nähte laufen quer dazu und haben eine eigene
Reihenfolge:

| Naht | Träger | Stand |
|---|---|---|
| Erkennung ohne Transport nutzbar | `GatewayCore` + `InputFirewall` | entschieden, kein Code nötig |
| Identität vorausgesetzt | Betriebsdoku | entschieden, sperrt Rang 5 |
| Abwärts-Naht | `Downstream` (Abstraktion) | offen |
| Abschluss-Ereignis | `CompletionEvent` | offen |
| Klammer über den Agent Loop | `MaskingSessionStore` | offen |
| Quarantäne für Eval | `QuarantineSink` | offen |
