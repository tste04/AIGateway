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
ändern ist ein Breaking Change; Hinzufügen ist erlaubt.

#### Registry (Stand Juli 2026)

Die vollständige, verbindliche Liste. Familien: `INJ` Injection (0xx englisch,
1xx deutsch), `SEC` Secrets, `SAN` Sanitisierung, `PII` Personendaten, `DLP`
Data-Loss-Prevention, `MAL` Malware/Payload, `ANO` Struktur-Anomalie, `GW`
Gateway-Guards (Form der Anfrage, nicht Inhalt).

| ID | Bedeutung |
|---|---|
| INJ-001 | override: „ignore previous instructions" |
| INJ-002 | override: „disregard above/system" |
| INJ-003 | exfil: „reveal your system prompt" |
| INJ-004 | role-override: „you are now …" |
| INJ-005 | fake chat/role markup |
| INJ-006 | privilege-escalation mode |
| INJ-007 | jailbreak: DAN |
| INJ-008 | jailbreak keyword |
| INJ-009 | fake system-prompt delimiter |
| INJ-010 | instruction injection: „new instructions:" |
| INJ-011 | markdown image with query-string (Exfil-Kanal) |
| INJ-012 | embedded network call (Exfil) |
| INJ-013 | credential-exfiltration request |
| INJ-101…110 | dieselben Muster auf Deutsch (Ignorieren, Rollen-Override, Entwicklermodus, Delimiter, …) |
| SEC-001 | private-key block |
| SEC-002 | AWS access key id |
| SEC-003 | GitHub token |
| SEC-004 | Slack token |
| SEC-005 | JWT |
| SEC-006 | api key (`sk-…`) — deckt OpenAI und Anthropic generisch ab |
| SEC-007 | credential assignment |
| SEC-008 | Google API key |
| SEC-009 | Stripe live key (Test-Schlüssel bewusst nicht — legitim in Doku) |
| SEC-010 | GitLab personal access token |
| SEC-011 | npm access token |
| SEC-012 | Hugging Face token |
| SEC-013 | password assignment (de/en, nur mit zitiertem Wert) |
| SAN-001 | unsichtbare/Steuerzeichen entfernt |
| SAN-002 | Bidi-Override entfernt |
| SAN-003 | Treffer erst nach Normalisierung (Verschleierung) |
| PII-001…007 | Person, Mail, Telefon, IBAN, Adresse, Ort, Denylist-Begriff |
| PII-900 | Token-Dichte-Wächter (mit `abstain` der einzige PII-Block) |
| DLP-001/002 | Klassifizierungs-Vermerk (de/en) — Default `allow` |
| DLP-003 | interne URL/Host — Default `redact` |
| DLP-010…022 | Secret-Redaktion (private key, AWS, GitHub, Slack, JWT, `sk-…`, credential assignment, Google, Stripe live, GitLab, npm, Hugging Face, password assignment) — dieselben Muster wie SEC-0xx, aber `redact` |
| MAL-001 | ausführbarer Payload (blockt) |
| MAL-002 | behaupteter Typ ≠ Inhalt |
| MAL-003 | ungeprüftes Archiv |
| MAL-004 | übergroßer Payload |
| ANO-001 | Größen-Anomalie |
| GW-001 | Eingabe zu groß (`maxInputBytes`) |
| GW-002 | Stufen-Zeitbudget gerissen |
| GW-003 | zu viele Nachrichten (`maxMessages`) |
| GW-004 | Rate-Limit überschritten (429) |

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
3. **Exakter Treffer zuerst**, semantisch nur als zweite Stufe mit hoher
   Schwelle. Nicht cachebar: Tool-Calling-Turns, hohe Temperatur,
   zeitabhängige Fragen.
   *(Umsetzung: der Schlüssel trägt den kanonischen Text vollständig statt
   eines Hashes — Begründung unter „Semantic Cache — Umsetzung".)*

### PII-Befunde blockieren nicht

Ein erkanntes Personendatum ist **kein Verstoß** — es wird behoben, indem
maskiert wird. PII-Findings tragen deshalb Gewicht 0: sie stehen im Audit,
lösen aber `.allowModified` aus statt `.block`. Würden sie blocken, wäre jeder
realistische Prompt abgelehnt. Einzige Ausnahme: der Dichte-Wächter mit
`onDensityExceeded: "abstain"` — dort ist das Blocken der ausdrückliche Wunsch.

### Keine Query-Schonung im Gateway-Pfad (Juli 2026)

`keepQueriedEntity` (Personen aus der Nutzerfrage bleiben Klartext) ist ein
Feature der **Bibliothek**, nicht der Pipeline. Im Gateway ist die Frage Teil
des maskierten Bestands: bei einer Ein-Nachrichten-Anfrage wäre sie der
gesamte Bestand — die Personen-Maskierung liefe im häufigsten Fall leer. In
Mehr-Nachrichten-Anfragen stünde derselbe Name einmal klar (Frage) und einmal
als Token (Kontext) im selben Prompt; der Provider könnte die Zuordnung
ablesen, und die Pseudonymisierung wäre nur noch Dekoration. Die Pipeline
maskiert deshalb ohne `sparingQuery`. Wer die Schonung will (Frage und Bestand
getrennt, Qualität vor Maskierungstiefe), ruft `PIIGate.mask(_:sparingQuery:)`
direkt.

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

**Nachtrag (Juli 2026): der `system`-Rabatt ist eine Behauptung, wenn keine
Identität dahintersteht.** Die Begründung „stammt aus der Anwendung selbst"
gilt nur, wenn die Anwendung belegt ist. Im Gateway kommt das Rollen-Label
aber verbatim aus dem Client-Request; der Default-Resolver ist anonym. Ein
Angreifer, der seine Injection als `system` deklariert, erschleicht sich so den
stärksten Rabatt (0.55) und drückt sie unter die Schwelle. Neue Policy-Option
`capClientSystemTrust` (Default `false`) deckelt eine Client-`system`-Nachricht
auf `neutral`. Bewusst opt-in statt Default-Flip: wo `system` aus einer
identitätsbelegten Anwendung stammt, bleibt der Rabatt korrekt; wo nicht (der
häufige Fall vor dem Reverse Proxy), setzt der Betreiber den Deckel. Die
Sprengweite ist begrenzt — der Angreifer jailbreakt ein Modell, das er ohnehin
direkt ansprechen kann, und dieses Gateway injiziert keinen eigenen
System-Prompt —, aber die explizite Kontrolle gehört dem Betreiber, nicht einer
stillen Voreinstellung.

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

### Fail-closed statt still verändern (Tool-Felder)

Das kanonische Modell trägt Chat-Text. Felder, deren Verlust die **Semantik**
der Anfrage ändert — `tools`, `tool_choice`, `functions`, `response_format`,
Ollama-`format` — werden beim Dekodieren **abgewiesen**, nicht entfernt: aus
einem Agent-Request würde sonst still ein Chat-Request, und die Antwort sähe
gültig aus. Kosmetische Extras (`user`, `stream_options`, `seed`) passieren
weiterhin unbeachtet — ihr Verlust ändert keine Bedeutung.

Wer Tool-Calling durch das Gateway will, erweitert zuerst das kanonische
Modell (inklusive Firewall-Bewertung der Tool-Definitionen und -Antworten) —
das ist dieselbe Vorbedingungs-Logik wie bei Malware und Anhängen.

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

### Identität wird festgestellt, nicht geglaubt (Juli 2026, umgesetzt)

Ursprünglich entstand `Principal` direkt aus den Headern `x-gateway-subject`,
`x-gateway-tenant` und `x-gateway-scopes` — **ungeprüft**. Das war folgenlos,
solange der `Principal` nur ins Audit wanderte. Mit dem Semantic Cache wird er
zur **Zugriffsgrenze**: `cachePartition` entsteht aus Mandant und Scopes, also
hätte ein Aufrufer seine Partition frei gewählt und fremde Antworten abgeholt.

Festlegung: eine Naht (`PrincipalResolver`) statt eines festen Header-Lesens.
Entscheidend ist ihr **Default**:

- `AnonymousPrincipalResolver` (Voreinstellung) **ignoriert** jede
  Identitäts-Behauptung — er weist sie nicht ab, er übergeht sie. Damit gibt es
  genau eine Partition, und niemand kann eine wählen. Das ist der
  Einzelnutzer-Betrieb hinter Loopback.
- `SharedSecretPrincipalResolver` glaubt die Header nur, wenn die Anfrage ein
  vereinbartes Geheimnis mitbringt (`x-gateway-auth`, konstantzeitiger
  Vergleich). Er prüft nicht die Identität selbst, sondern dass die Behauptung
  von der Stufe stammt, die sie prüfen durfte — der Fall „Transportweg, den nur
  die Identity-Stufe erreicht".
- Eine Behauptung ohne gültigen Beleg führt zu **401**, nicht zum stillen
  Abstieg auf anonym: sonst bekäme derselbe Aufruf je nach Rateglück einmal die
  fremde und einmal die eigene Partition.

Wer signierte Token prüfen will, implementiert das Protokoll mit einer echten
Krypto-Bibliothek. Hier wird keine gebaut — die Festlegung „kein Krypto-Eigenbau"
gilt unverändert. Der konstantzeitige Vergleich ist keine Ausnahme davon: ein
Vergleich ist keine Primitive, aber ein früher Abbruch verriete über die
Laufzeit, wie viele Zeichen stimmen.

**Damit ist der Sperrvermerk für Rang 5 aufgehoben.**

### Semantic Cache — Umsetzung (Juli 2026)

Die drei Festlegungen von oben sind gebaut; dazu kamen vier Entscheidungen aus
der Umsetzung:

1. **Der Schlüssel trägt den kanonischen Text vollständig, nicht dessen Hash.**
   Ein Hash könnte kollidieren, und eine Kollision hieße, einem Aufrufer die
   Antwort auf eine fremde Frage auszuliefern. Der Speicher ist über
   `maxEntries` gedeckelt und der Text maskiert — der Preis ist tragbar.
   Rollen gehen mit Steuerzeichen-Trennern in den Schlüssel ein, sonst ergäben
   `system:"a" user:"b"` und `user:"a\nb"` denselben Eintrag.
2. **Abgelegt wird die maskierte Antwort.** Sie trägt Platzhalter, keine
   Klardaten. Ein späterer Aufrufer löst sie mit *seiner* Zuordnung auf; da
   eine Partition sich einen Vault teilt, steht derselbe Platzhalter bei beiden
   für denselben Wert. Wäre hier die de-maskierte Antwort gelandet, wäre der
   Cache ein PII-Leck zwischen Nutzern derselben Partition. Kennt eine Session
   einen Platzhalter nicht, bleibt er stehen — sichtbar falsch statt still
   falsch aufgelöst.
3. **Der Cache unterliegt nicht dem Fail-closed-Budget.** Er ist ein
   Kostenhebel, keine Schutzstufe; sein einziger legitimer Fehlerausgang ist
   der Fehltreffer. Ein langsamer Embedder darf keine Anfrage blocken, und eine
   langsame Cache-Stufe darf die Entscheidung nicht als `degraded` markieren —
   das Wort ist für unvollständige *Sicherheitsbewertung* reserviert. Ein
   Ausfall des Embedders kostet nur die zweite Stufe; die exakte bleibt.
4. **Fehlende Temperatur gilt als cachebar.** Wer nichts angibt, fordert keine
   Varianz an, sondern nimmt, was kommt. Ausdrücklich hohe Temperatur schließt
   den Cache aus, ebenso Tool-Nachrichten und Zeitbezüge („heute", „aktuell",
   „latest"). Die Zeitbezugs-Muster decken Deutsch und Englisch ab — wie beim
   Regelkatalog brauchen andere Sprachen eigene.
5. **Der Entitäten-Wächter erfasst auch großgeschriebene Wörter**, nicht nur
   Ziffern und Platzhalter. Die erste Fassung ließ „Umsatz Nord" und „Umsatz
   Süd" mit identischer Signatur durch — im Einbettungsraum praktisch gleich,
   inhaltlich verschieden. Im Deutschen ist damit ungefähr die Menge der
   Inhaltswörter im Schlüssel, was den Wächter streng macht. Diese Richtung ist
   die richtige: ein verpasster Treffer kostet einen Modellaufruf, ein falscher
   liefert eine falsche Antwort. Funktionswörter (Fragewörter, Artikel,
   Aufforderungen) sind ausgenommen, sonst unterschieden sich „Was ist
   Routing?" und „Erkläre Routing" und die semantische Stufe liefe leer.
6. **Sicherungsschalter am Embedder.** Ein *hängender* Embedder ist schlimmer
   als gar keiner: stirbt er, kostet jeder Versuch einen abgelehnten
   Verbindungsaufbau; antwortet er langsam, zahlt sonst jede cachebare Anfrage
   sein volles Zeitlimit, bevor sie in den Fehltreffer fällt — der Cache macht
   das Gateway dann langsamer statt schneller. Nach drei Fehlschlägen in Folge
   bleibt die semantische Stufe 30 Sekunden aus, danach entscheidet ein
   Probelauf. Der exakte Treffer läuft durchgehend weiter; der Cache verliert
   Reichweite, nie Funktion.

### Semantic Cache — was bewusst offen bleibt

Der Cache ist tragfähig für den Betrieb hinter Loopback mit lokalem Embedder,
aber nicht ausgebaut. Ursprünglich standen hier vier bekannte Lücken; drei
davon sind inzwischen gebaut und weiter unten begründet (Stand 24.08.2026):
die Verdrängung ist über `maxEntriesPerPartition` je Partition gedeckelt, die
Trefferquote zählt `CacheStatistics` payload-frei mit, und Invalidierung gibt
es je Partition und je Modell. Offen bleibt genau ein Punkt — mit Absicht:

- **Keine Persistenz-Implementierung.** Rein im Speicher; ein Neustart setzt
  den Kostenhebel auf null. Für die Vertraulichkeit ist das die richtige Wahl
  (keine maskierten Antworten auf Platte), für den Zweck spürbar. Die Naht
  dafür existiert (`snapshot()`/`restore(_:)`); wer sie auf Platte legt,
  trifft die Daten-in-Ruhe-Entscheidung selbst — Begründung im
  Umsetzungs-Abschnitt unten.

Dazu eine Grenze der zweiten Stufe: die semantische Suche ist ein linearer Lauf
über die Einträge der Partition. Bei `maxEntries` in der Größenordnung von
tausend ist das unkritisch; darüber bräuchte es einen Index.

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

Vier Festlegungen, umgesetzt in `MaskingSessionStore` (Juli 2026):

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

**Umsetzung des Rückwegs (13.08.2026).** Der Stufenbetrieb schließt die
Klammer nicht mehr mit der Antwort — sie bleibt geparkt, bis der Rückweg sie
holt oder die Frist fällt. Drei Endpunkte tragen ihn: `/v1/session/unmask`
(Klardaten, schließt per Default; `keep` für die Freigabe-Vorschau),
`/v1/session/extend` (die lange Frist der Zwei-Fristen-Festlegung) und
`/v1/session/close` (sofortiges Verwerfen). Der Zugriff läuft über denselben
`PrincipalResolver` wie der Hinweg und ist damit partitionsgebunden
(Festlegung 3); eine fehlende Zuordnung liefert Platzhalter samt
`restored: false` statt einer Auflösung aus dem Vault (Festlegung 2). Im
Alleinbetrieb schließt die Klammer unverändert mit der Antwort.

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

Gesammelt werden `.block`-Entscheidungen **und die Beinahe-Treffer knapp unter
der Schwelle** — dort sitzen die Fehlalarme und die knapp durchgerutschten
Angriffe, also die wertvollsten Beispiele. Dazu eine harte Aufbewahrungsfrist,
die eine Senke durchsetzen **muss**.

**Änderung (13.08.2026): eine persistente Senke gehört doch ins Repo.** Die
ursprüngliche Festlegung („wer Beispiele über einen Neustart hinaus braucht,
schreibt eine eigene Senke") verlagerte genau die Komponente zum Betreiber,
die am leichtesten falsch gebaut wird — eine selbstgeschriebene Senke, die
die Frist *nicht* durchsetzt, wäre unsichtbar kaputt. Deshalb liefert
`GatewayServer` jetzt eine `FileQuarantineSink` mit: eine Datei je Vorfall,
die Ablauffrist im Dateinamen kodiert und beim Schreiben wie per `sweep()`
exakt durchgesetzt, Schreibprobe beim Start (fail-closed), Kapazitätsdeckel.
Die Betreiber-Entscheidung bleibt ausdrücklich: Default ist weiterhin die
Speicher-Senke, erst die Zeile `quarantine.directory` in der
Daemon-Konfiguration legt Inhalt der konfigurierten Stufe auf Platte.
Zugriffsschutz des Verzeichnisses (Rechte, Verschlüsselung) bleibt
Betreibersache.

#### Umsetzung (Juli 2026)

Drei Punkte kamen beim Bauen dazu:

1. **Das Fenster ist die Auswahl, nicht der Zufall.** Ursprünglich war von
   einer „Stichprobe" die Rede. Umgesetzt ist ein Fenster (`nearMissBand`,
   Default 0.15 unter der Schwelle) ohne Zufallsziehung: eine zufällig
   ziehende Auswahl machte Vorfälle unreproduzierbar und brächte eine
   Nichtdeterminismus-Quelle in eine Sicherheitskomponente. Wer nur Blocks
   will, setzt das Fenster auf 0.
2. **Nicht maskierbar heißt abstufen, nicht roh ablegen.** Ist `masked`
   angefordert, aber keine PII-Stufe konfiguriert, fällt der Eintrag auf
   `counts` zurück statt den Rohtext zu behalten. `QuarantineSample.detail`
   trägt deshalb, was **tatsächlich** abgelegt wurde — nicht, was die Policy
   erlaubt hätte.
3. **Der Ursprungstext geht in die Quarantäne, auf beiden Pfaden.** Auf dem
   Allow-Pfad wäre der Inhalt der Entscheidung bereits maskiert; die Stufe
   soll aber entscheiden, was aufbewahrt wird, und nicht der Zufall, an
   welcher Stelle der Pipeline der Aufruf sitzt.

`MemoryQuarantineSink` liegt als Referenz bei und setzt die Frist wirklich
durch — abgelaufene Vorfälle sind nicht mehr lesbar. Wer die Beispiele über
einen Neustart hinaus braucht, schreibt eine eigene Senke und trifft damit
ausdrücklich die Entscheidung, Nutzinhalt dauerhaft abzulegen.

### DLP und Malware (Juli 2026, umgesetzt)

**DLP unterscheidet sich von einer weiteren Regelliste durch die Handlung**,
nicht durch das Regelwerk: `block` / `redact` / `allow`. `redact` ist der
eigentliche Punkt — wer nur blocken kann, zwingt jede Organisation zu „ganz
oder gar nicht" und bekommt Regeln, die niemand scharf schaltet. `allow` ist
der Weg, eine Regel zu beobachten, bevor man sie scharf stellt.

Unterschied zur PII-Maskierung, der leicht übersehen wird: **Maskierung ist
eine Klammer, Redaktion ist einweg.** Was DLP entfernt, kommt auf dem Rückweg
nicht wieder — bei PII geht es um Datensparsamkeit gegenüber dem Provider, bei
DLP um Inhalte, die das Haus nicht verlassen dürfen. Daraus folgt die Position:
DLP läuft **nach** der Maskierung, sonst entfernte es Text, den die Klammer noch
zurückübersetzen wollte. Provenienz gewichtet DLP nicht (Multiplikator 1.0),
gleiche Begründung wie bei PII.

Der mitgelieferte Katalog ist bewusst klein — echte DLP-Regeln sind
organisationsspezifisch und gehören in die Konfiguration. Seine zwei Klassen
haben aus gutem Grund **unterschiedliche** Default-Handlungen, und der
Unterschied ist die eigentliche Lehre aus dieser Stufe: Der
Klassifizierungs-Vermerk (DLP-001/002) wird nur **beobachtet**, denn der
Vermerk ist nicht das Geheimnis — das Dokument ist es. Ihn zu redigieren
entfernte genau das Wort, das den Betreiber gewarnt hätte, und ließe den
Inhalt unverändert ziehen: Redaktionstheater. Ihn zu blocken wäre umgekehrt
eine Zumutung, weil „vertraulich" auch in harmlosen Sätzen steht. Die interne
Adresse (DLP-003) wird dagegen **redigiert**, weil dort die Fundstelle selbst
der Verlust ist — ein Hostname verrät Topologie, und ihn zu entfernen behebt
den Schaden wirklich.

Daraus die Faustregel für jede weitere Regel: `redact` ist richtig, wenn die
Fundstelle der Schaden ist; ist sie nur sein Anzeiger, gehört sie in den
Audit, nicht in den Papierkorb.

**Nachtrag (Juli 2026): Secrets werden redigiert, nicht nur erkannt (DLP-010…016).**
Die Injection-Stufe erkennt Zugangsdaten-Formate (SEC-00x) und gibt ihnen
Gewicht, aber ein einzelnes Secret in einer `user`-Nachricht (neutral 1.0)
bleibt unter der Blockschwelle — es würde sonst verbatim zum Drittanbieter
gehen und, weil der Cache-Schlüssel aus dem Text entsteht, in den Cache-Index.
Eine Erkennung ohne Handlung ist ein Leck mit Logzeile. Die Secret-Formate
liegen deshalb zusätzlich als `redact`-Regeln im DLP-Katalog (`[SECRET]`,
einweg — für Zugangsdaten gibt es keinen legitimen Rückweg). Erkennung und
Redaktion teilen **eine** Musterquelle (`defaultSecretPatterns`): zwei Kopien
derselben Regexe würden auseinanderdriften. Der Ort ist die DLP-Stufe, weil sie
nach der Maskierung und **vor** dem Cache-Schlüssel läuft — die Redaktion greift
also vor beiden Lecks. Voraussetzung ist, dass die DLP-Stufe aktiv ist; wer sie
abschaltet, verzichtet bewusst auch auf die Secret-Redaktion.

**Malware ist eine Naht, keine Engine.** Signaturen zu pflegen ist eine eigene
Industrie; ein selbstgebauter Scanner wäre dasselbe Fehlurteil wie ein
selbstgebauter TLS-Stack. `PayloadScanner` arbeitet auf Bytes — ein `String`
wäre falsch, weil ein Anhang dafür dekodiert werden müsste, bevor er geprüft
ist. Genau das verhindert die Position im Ablauf: **Stufe 3, vor allem, was
Inhalt parst.**

`StructuralPayloadScanner` ist die abhängigkeitsfreie erste Schicht ohne
Signaturen: ausführbare Formate (`MAL-001`), behaupteter Typ gegen
tatsächlichen Inhalt (`MAL-002`), ungeprüfte Archive (`MAL-003`, kein Verstoß
sondern eine sichtbar gemachte Wissenslücke) und Größe (`MAL-004`). Dateiname
und Medientyp sind angreifer-kontrolliert und werden nie geglaubt, sondern nur
gegen den Inhalt geprüft.

**Grenze, die benannt gehört:** `ChatRequest.attachments` wird von den
HTTP-Adaptern nicht befüllt. Die Dialekte tragen Bilder in Inhaltsblöcken, und
die weiterzureichen wäre echte Multimodalität, die dieses Repo nicht baut.
Statt sie still fallen zu lassen — dieselbe Fehlerklasse wie ein still
entferntes `tools` — **weisen die Adapter solche Anfragen ab.** Wer die
Bibliothek direkt benutzt, füllt das Feld selbst und bekommt damit die
Malware-Stufe. Anhänge zählen in den Größen-Guard mit.

### Rate-Guard, Stufen-Ziel, Cache-Betrieb, Daemon (Juli 2026, umgesetzt)

Vier Stücke, die die Box aus dem Zielbild vollständig machen.

**Der Rate-Guard steht vor der Pipeline, nicht darin.** Das ist der ganze
Punkt: die Arbeit *ist* die Kosten. Ein Deckel, der erst nach Malware-,
Injection-, PII- und DLP-Lauf greift, hat die Rechenzeit bereits ausgegeben,
die er sparen sollte. Er sitzt deshalb in `GatewayService` zwischen Identität
und Firewall — früher geht nicht, denn ohne festgestellte Identität gibt es
niemanden zu deckeln. Geschlüsselt wird über **Subject**, nicht über
`cachePartition`: die Partition ist absichtlich geteilt, damit Nutzer gleicher
Berechtigung sich Cache-Treffer teilen; daraus ein geteiltes Kontingent zu
folgern hieße, dass ein Vielnutzer seine Kollegen aushungert. Die Absage ist
**429 mit `Retry-After`**, nicht 403 — auf 403 hört ein vernünftiger Client
auf, auf 429 wartet er. Die Regel-ID `GW-004` reiht sich in die GW-Familie ein:
Guards, die auf die Form der Anfrage schauen statt auf den Inhalt.

Die Buchhaltung ist gedeckelt (`maxTrackedSubjects`), sonst wäre sie ein
Speicherleck mit fremdgesteuertem Schlüssel. Verdrängt wird dabei
ausschließlich, was **voll** ist: ein voller Eimer ist informationsgleich mit
gar keinem, ein angebrochener *ist* das Gedächtnis der Drosselung. Wer den
verdrängt, baut die Umgehung ein — genug fremde Subject-Namen erzeugen, bis
der eigene Eimer hinausfliegt und voll zurückkommt. Bleibt kein Platz, wird
abgewiesen statt zugelassen.

**`StageDownstream` macht die Abwärts-Naht vollständig.** Der Unterschied zum
Provider-Ziel ist nicht die Adresse, sondern was übergeben wird: eine Anfrage
*plus* das Urteil der Firewall. Sonst müsste die Policy Engine die Bewertung
wiederholen, die hier bereits stattgefunden hat, und zwei Stellen entschieden
über dieselbe Frage. Das Format ist kanonisch und providerfrei. Der
`message`-Text der Befunde geht **nicht** mit — er ist Anzeigetext und darf
frei umformuliert werden; eine Gegenstelle, die darauf prüft, bricht beim
nächsten Textlauf.

**Am Cache waren vier Dinge offen; drei sind gebaut, eines bleibt bewusst eine
Naht.** Die Verdrängung greift jetzt zuerst je Partition, dann global — wäre es
umgekehrt, könnte der globale Deckel fremde Einträge wegwerfen, um Platz für
eine Partition zu schaffen, die ihr eigenes Kontingent gerade überzieht. Das
ist kein Datenleck, aber Nachbarschaftsschaden, und die Antwort darauf ist
dieselbe Überlegung wie beim Rate-Guard. Die Trefferquote ist die einzige Zahl,
an der sich entscheidet, ob der Cache seinen Preis wert ist; sie zu schätzen
hieße, den Kostenhebel im Dunkeln zu betreiben — `CacheStatistics` zählt
deshalb mit, payload-frei wie das Audit. Invalidierung gibt es je Partition und
je Modell: ändert sich Berechtigung oder Modellversion, sind die Einträge nicht
*abgelaufen*, sondern **falsch**, und die Frist hilft dagegen nicht — sie ist
ein Zeitmaß, kein Ereignis.

Persistenz bleibt eine **Naht** (`snapshot()`/`restore(_:)`), keine
Implementierung. Eine Bibliothek, die selbst auf Platte schreibt, entscheidet
über Ablageort, Verschlüsselung und Löschfristen des Betreibers mit — dieselbe
Linie wie bei `QuarantineSink` und `PayloadScanner`. Dazu kommt ein zweiter
Grund, der hier schwerer wiegt: der Inhalt ist nur dann platzhalterbehaftet,
wenn eine PII-Stufe konfiguriert ist. Ohne sie stehen dort rohe
Modellantworten, und ein Abzug wäre ein Daten-in-Ruhe-Problem mit demselben
Bedarf an Frist und Zugriffsschutz wie die Quarantäne.

**`aigatewayd` löst Grundentscheidung 4 ein.** Bis hierhin war das Gateway eine
Bibliothek; eine Box im Zielbild ist aber etwas, das man startet und wieder
anhält. Der Daemon bleibt dünn — Konfiguration lesen, Stufen stecken, Signale
abfangen, geordnet beenden. Jede Zeile Sicherheitslogik dort wäre eine, die die
Bibliothek nicht hat und die niemand testet; deshalb liegt das Lesen der
Konfiguration in `GatewayServer` (`DaemonConfiguration`) und ist ohne Prozess
testbar.

Zwei unbequeme Festlegungen dazu. Erstens: **der API-Schlüssel steht nicht in
der Datei**, er kommt aus `AIGATEWAY_UPSTREAM_API_KEY`. Konfigurationsdateien
landen in der Versionsverwaltung, in Backups und in Fehlerberichten; ein Feld
dafür anzubieten hieße, genau das zu erlauben. Zweitens: **ein unbekannter
Schlüssel ist ein Fehler.** Ein verschriebenes `similarityTreshold` still zu
ignorieren heißt, mit einer Einstellung zu laufen, die der Betreiber gesetzt zu
haben glaubt — bei einer Sicherheitskomponente ist das die schlechtere Hälfte
von „tolerant lesen". Die Konfiguration darf Stufen **an- und abschalten**,
niemals ihre Position bestimmen; sonst wäre die Reihenfolge oben eine
Einstellung.

Der geordnete Stopp (`stop(drainSeconds:)`) schließt erst den Zulauf und lässt
dann austrinken. Eine Anfrage, die beim Abschalten mitten im Upstream-Aufruf
steht, hat das Modell bereits bezahlt — sie abzuschneiden kostet Geld und
liefert dem Client nichts. Läuft die Frist ab, bevor alles fertig ist, meldet
der Daemon das (`drained: false`, Exit-Code 1), statt einen sauberen Stopp zu
behaupten.

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
| 5 | Semantic Cache | **fertig** — exakt + semantisch, partitioniert, Kennzahlen, Invalidierung, Abzug |
| 6 | DLP-Policy-Semantik | **fertig** — block/redact/allow |
| 7 | Malware (ClamAV-Naht) | **Naht fertig** — strukturelle Stufe gebaut, Engine ist Betreibersache |
| 8 | Rate-Guard | **fertig** — Token-Eimer je Subject, vor der Pipeline |
| 9 | Daemon (`aigatewayd`) | **fertig** — Konfigurationsdatei, SIGTERM/SIGINT, geordneter Stopp |

Die Ränge sind Feature-Boxen. Die Nähte laufen quer dazu und haben eine eigene
Reihenfolge:

| Naht | Träger | Stand |
|---|---|---|
| Erkennung ohne Transport nutzbar | `GatewayCore` + `InputFirewall` | entschieden, kein Code nötig |
| Identität festgestellt | `PrincipalResolver` | **fertig** — Default ignoriert Behauptungen |
| Abwärts-Naht | `Downstream` (Abstraktion) | **fertig** — Provider- und Stufen-Variante |
| Abschluss-Ereignis | `CompletionEvent` | **fertig** |
| Klammer über den Agent Loop | `MaskingSessionStore` | **fertig** — inkl. Rückweg der Stufen-Variante (`/v1/session/*`) |
| Betrieb als Box | `aigatewayd` + `DaemonConfiguration` | **fertig** |
| Quarantäne für Eval | `QuarantineSink` | **fertig** — persistente Datei-Senke eingebaut (opt-in per `quarantine.directory`), Zugriffsschutz ist Betreibersache |

## Lizenzmodell (August 2026)

Das Projekt ist **dual-lizenziert**: Quellcode offen einsehbar, nichtkommerzielle
Nutzung frei unter PolyForm Noncommercial 1.0.0, jede kommerzielle Nutzung nur
mit kommerzieller Lizenz ([COMMERCIAL.md](../COMMERCIAL.md)). Die Begründung und
das komponentenübergreifende Schichtenmodell stehen in
[LICENSING.md](../LICENSING.md); die Fähigkeit zur Relizenzierung sichert das
CLA ([CLA.md](CLA.md)).

**Historie, festgehalten wegen der Rechtsfolgen:** Vom 02.08. bis 07.08.2026
stand das Repo unter Apache 2.0. Diese Lizenz ist unwiderruflich — wer den
Stand aus diesem Fenster bezogen hat, behält die Apache-Rechte für genau diesen
Schnappschuss. Ab Commit `7fce487` (07.08.2026) gilt für alle weiteren Stände
wieder das Dual-Modell. Eine erneute Lockerung (NC → permissiv) wäre jederzeit
möglich und würde nur nach vorn wirken; eine erneute Verschärfung erzeugt
wieder ein solches dauerhaft freies Fenster — der Wechsel ist also nicht
beliebig wiederholbar, ohne Substanz zu verschenken. (13.08.2026)
