# Optimierungsplan

Stand: Juli 2026. Geschrieben auf `91af8a8` (309 Tests grün), **alle sechs
Phasen umgesetzt** in den Folge-Commits (Phase 0 einzeln, 1+2 zusammen, 3–6
zusammen — jede Welle mit eigenem CI-Lauf). Die Befundtabellen unten
beschreiben den Zustand VOR dem Umbau; sie bleiben stehen, weil sie die
Begründung der Änderungen sind.

Ziel: die Stellen beseitigen, an denen der Code wiederholt statt abstrahiert,
und die Kommentare korrigieren, die nicht mehr stimmen. **Keine Funktion darf
dabei verloren gehen** — weder öffentliche API noch geprüftes Verhalten.

## Wie gemessen wurde

Nicht behauptet, sondern gezählt: Zeilen je Datei nach Code und Kommentar,
Funktionslängen, wortgleiche Blockwiederholungen, öffentliche Symbole ohne
Vorkommen in Tests. Ausgangsstand: **4.386 Codezeilen, 1.920 Kommentarzeilen**
(Verhältnis 0,44) in 35 Quelldateien, dazu 3.821 Testzeilen mit 309 Tests.

## Befund

### A — Wiederholung ohne Nutzen

| # | Ort | Befund | Umfang |
|---|---|---|---|
| A1 | `GatewayPipeline.process` | 169 Codezeilen; darin **4× wortgleich** „Risiko-Schwelle prüfen → blocken" und **4× wortgleich** „Budget gerissen + fail-closed → blocken" | ~44 Zeilen |
| A2 | `Downstream.swift` / `StageDownstream.swift` | `EventState` und `StageEventState` sind zwei fast identische Klassen: NSLock + `EventStreamParser` + Usage-Verschmelzung + Delta-Sammlung. Verschieden ist nur, **wie eine Nutzlast gelesen wird** | ~40 Zeilen |
| A3 | `DaemonConfiguration.parse` | 126 Codezeilen, davon **21×** `if let value = x["y"] as? T { config.z = value }` | ~60 Zeilen |
| A4 | `GatewayService.handle` | 102 Codezeilen: Routing, Identität, Rate-Guard, Cache-Antwort, Relay, zwei Fehlerpfade — sechs Aufgaben in einer Funktion | — |
| A5 | Token-Usage-Parsing | dieselbe `prompt_tokens`/`completion_tokens`-Lesung an **drei** Stellen (`ProviderAdapter` 2×, `StageDownstream` 1×) | ~12 Zeilen |

**A1 ist nicht nur hässlich, sondern eine Fehlerquelle.** Die Regel „erst
Risiko, dann Budget, beides vor der nächsten Stufe" muss viermal korrekt
abgeschrieben werden, und jede fünfte Stufe schreibt sie ein fünftes Mal ab.
Eine vergessene Wiederholung ist eine Stufe, deren Befund folgenlos bleibt —
das wäre still, nicht laut.

**A3 trägt einen zweiten, versteckten Mangel:** die Liste erlaubter Schlüssel
(`reject(unknownIn:allowed:)`) ist von den tatsächlichen Lesungen **getrennt**
und muss von Hand synchron gehalten werden. Wer ein Feld ergänzt und die Liste
vergisst, bekommt einen Fehler für eine gültige Einstellung; wer die Liste
ergänzt und die Lesung vergisst, bekommt eine Einstellung ohne Wirkung —
genau das, was „unbekannter Schlüssel ist ein Fehler" verhindern sollte.

### B — Kommentare, die nicht mehr stimmen

Schwerer als zu viele Kommentare: falsche.

| # | Ort | Behauptung | Wirklichkeit |
|---|---|---|---|
| B1 | `GatewayPipeline.swift:220` | „Stufe 3 — PII maskieren" | PII ist Stufe **5**; „Stufe 3" ist Malware und steht doppelt |
| B2 | `GatewayPipeline.swift:307` | „Stufe 5 — Semantic-Cache-Lookup" | Cache ist Stufe **7** und steht im Code nach DLP (6) |
| B3 | `GatewayPipeline.swift:19` | „DLP und Semantic Cache sind noch nicht gebaut; ihre Plätze sind markiert" | beide sind gebaut und getestet |
| B4 | `Downstream.swift:10` | „implementiert ist heute der Modellanbieter selbst … damit daraus später eine Stufe wird" | `StageDownstream` existiert seit `c9caf6a` |

### C — Dieselbe Begründung an vier Orten

Der Satz „die Cache-Partition ist absichtlich geteilt, das Rate-Kontingent darf
es nicht sein" steht ausformuliert in `Principal.swift`, `RateGuard.swift`,
`CLAUDE.md` und `docs/DECISIONS.md`. Vier Fassungen desselben Gedankens driften
auseinander, sobald eine geändert wird. Dasselbe gilt für „maskiert vor dem
Cache-Schlüssel" (drei Orte) und „geschätzt wird nie" (vier Orte).

### D — Lücken, die vor dem Umbau zu schließen sind

| # | Was | Warum jetzt |
|---|---|---|
| D1 | `HTTPServer.stop(drainSeconds:)` und `activeConnectionCount()` haben **keinen Test** | wurde in `c9caf6a` eingeführt; A4 fasst genau diesen Pfad an |
| D2 | `EventState` (Provider-Strom) wird nur indirekt geprüft | A2 führt beide Klassen zusammen — ohne Test wäre das eine Blindoperation |
| D3 | Die Budget-Regel ist nicht für **jede** der vier Stufen einzeln geprüft | A1 ersetzt vier Kopien durch eine Stelle; die Äquivalenz muss vorher belegt sein |

## Reihenfolge — und warum sie so ist

Dieses Repo hat **keine lokale Toolchain**; die CI ist die einzige belastbare
Abnahme. „Keine Funktion darf verloren gehen" ist deshalb nur so weit
durchsetzbar, wie Tests es belegen. Daraus folgt zwingend: **erst das Netz,
dann der Sprung.** Jede Phase ist ein eigener Commit mit eigenem CI-Lauf, damit
ein Fehlschlag eindeutig zuzuordnen ist.

### Phase 0 — Netz spannen (kein Refactoring, nur Tests)

- **0.1** Test für den geordneten Stopp: Server binden, Verbindung offen halten,
  `stop(drainSeconds:)` rufen, prüfen dass (a) kein Zulauf mehr angenommen wird,
  (b) die laufende Anfrage fertig läuft, (c) `false` zurückkommt, wenn die Frist
  reißt. Deckt D1.
- **0.2** Charakterisierungstest der Pipeline: für jede Kombination
  aktiver Stufen die **Reihenfolge der `timings`** und die Entscheidung
  festhalten. Das ist das Sicherungsseil für A1 — nach dem Umbau muss dieselbe
  Reihenfolge herauskommen, Zeichen für Zeichen.
- **0.3** Budget-Test je Stufe: `stageBudgetMilliseconds = 0` erzwingt
  `timedOut` in jeder Stufe einzeln; geprüft wird `GW-002` **und** dass
  `failOpen` durchlässt statt zu blocken. Deckt D3.
- **0.4** Test für `EventState` über Chunk-Grenzen und geteilte Usage-Meldungen,
  gebaut wie `StageEventState`s Test. Deckt D2.

Erwartung: +14 Tests, keine Quellzeile geändert. **Risiko: keins.**

### Phase 1 — Die Wiederholung in der Pipeline auflösen

Der gemeinsame Abschluss jeder Stufe wird eine Funktion:

```swift
/// Liefert die fertige Entscheidung, wenn nach dieser Stufe abzubrechen ist —
/// sonst `nil`. Beide Abbruchgruende an EINER Stelle, damit eine neue Stufe
/// sie nicht vergessen kann.
private func verdictAfterStage(...) async -> Outcome?
```

Jede Stufe endet dann mit einer Zeile:

```swift
if let stop = await verdictAfterStage(...) { return stop }
```

Erwartung: `process` von 169 auf ~120 Codezeilen, −44 wiederholte Zeilen.
**Risiko: mittel** — es ist der sicherheitskritischste Pfad des Projekts.
Abgesichert durch 0.2 und 0.3; die Stufenreihenfolge selbst wird **nicht**
angefasst, nur ihr Abschluss.

### Phase 2 — Eine Strom-Zustandsklasse statt zwei

`EventState` und `StageEventState` werden zu einem `StreamCollector`, der einen
Leser als Parameter bekommt (`(String) -> (delta: String?, usage: TokenUsage?)`).
Provider- und Stufenseite liefern je einen Leser.

Erwartung: −40 Zeilen. **Risiko: mittel** — genau hier saßen die
Streaming-Fehler. Abgesichert durch 0.4 und die bestehenden
`StageDownstreamTests`.

### Phase 3 — Konfiguration: ein Leser statt 21 Zuweisungen

Ein kleiner `Section`-Leser mit `int`/`double`/`bool`/`string`, der **jede
gelesene Schlüsselung selbst mitschreibt** und am Ende alles Übrige als
unbekannt meldet. Damit verschwindet die separate `allowed`-Liste, und der
beschriebene Synchronisationsmangel ist strukturell ausgeschlossen statt
durch Disziplin verhindert.

Erwartung: `parse` von 126 auf ~60 Codezeilen. **Risiko: gering** — 9 Tests
decken das Format bereits, inklusive Tippfehler- und Falschwert-Pfad.

### Phase 4 — `GatewayService.handle` zerlegen

Sechs Aufgaben werden sechs benannte private Schritte; `handle` bleibt die
Abfolge. Kein Verhalten ändert sich, auch keine Statuscodes.

Erwartung: `handle` von 102 auf ~35 Codezeilen. **Risiko: gering bis mittel** —
26 Integrationstests fahren diesen Pfad bereits, plus 0.1.

### Phase 5 — Token-Usage an einer Stelle lesen

Eine Hilfsfunktion in `GatewayCore` (`TokenUsage.init?(json:)`), von allen drei
Stellen benutzt. Erwartung: −12 Zeilen. **Risiko: gering.**

### Phase 6 — Kommentare in Ordnung bringen

- **6a** Stufennummern korrigieren (B1, B2). Risikofrei, aber wichtig: die
  Nummern sind der Verweis auf `docs/DECISIONS.md`, und ein falscher Verweis
  ist schlimmer als keiner.
- **6b** Überholte Behauptungen entfernen (B3, B4).
- **6c** Die dreifach ausformulierten Begründungen (C) auf **einen** Ort
  reduzieren — den Ort der Entscheidung — und an den übrigen Stellen durch
  einen Verweis ersetzen. `docs/DECISIONS.md` bleibt die Langfassung.

**Risiko: keins für den Code.** Diese Phase darf ausdrücklich **nicht** dazu
benutzt werden, die Kommentardichte generell zu senken — siehe unten.

## Was ausdrücklich bleibt

Es wäre leicht, die Zahl 0,44 für zu hoch zu halten und zu kürzen. Das wäre
der falsche Schluss, und der Plan schließt es aus:

- **Die dichten Dateien sind die richtigen.** `Principal.swift` (1,62),
  `TokenUsage.swift` (1,29), `PrincipalResolver.swift` (1,07) tragen fast nur
  Invarianten-Begründungen. Genau sie halten jemanden davon ab, die
  Cache-Partition „zu reparieren" oder Token-Zahlen zu schätzen. Wer sie
  kürzt, spart Zeilen und verliert den Grund.
- **Öffentliche API ohne interne Verwendung wird nicht entfernt.**
  `ChatRequest.mappingContents`, `lastUserMessage`, `SemanticCache.resetStatistics`,
  `RateGuard.removeAll` und weitere sind Bibliotheksoberfläche, keine Leichen.
  Sie zu streichen wäre der Funktionsverlust, den die Aufgabe ausschließt.
  Stattdessen: in Phase 0 mit je einem Test belegen, damit sie nicht
  unbemerkt brechen.
- **`rawScore` und `trustMultiplier` bleiben getrennt.** Sie sehen redundant
  aus (`riskScore` leitet sich ab), sind es aber nicht: die Policy muss
  unterdrückte Regeln exakt herausrechnen können, und die Reihenfolge
  „erst abziehen, dann gewichten" ist nur mit beiden Werten möglich.
- **Tests, die dieselbe Sache aus zwei Richtungen prüfen, bleiben.** Der
  Malware-Test über das Existential und der Pipeline-Test decken bewusst
  denselben Gegenstand auf zwei Wegen — genau diese Doppelung hat hier schon
  einen Fehler gefunden.

## Erwartetes Ergebnis

| | vorher | nachher (geschätzt) |
|---|---|---|
| Codezeilen | 4.386 | ~4.200 |
| längste Funktion | 169 | ~120 |
| wortgleiche Blockwiederholungen | 8 | 0 |
| falsche Kommentare | 4 | 0 |
| Tests | 309 | ~325 |

Die Zeilenersparnis ist bescheiden und **nicht der Punkt**. Der Punkt ist, dass
die Regel „jede Stufe prüft Risiko und Budget" danach an einer Stelle steht
statt an vier, und dass die erlaubten Konfigurationsschlüssel nicht mehr von
Hand mit den gelesenen synchron gehalten werden müssen.
