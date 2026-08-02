# AIGateway — Code-Review-Bericht

**Datum:** 2026-07-30
**Grundlage:** 7 Review-Dimensionen (security-firewall, security-transport, correctness-concurrency, zielbild-gaps, code-quality, test-coverage, docs-consistency), verifizierte Befunde.
**Verworfen:** 1 Befund (dokumentierte Entscheidung, siehe Abschnitt 7). **Übernommen:** alle CONFIRMED + PLAUSIBLE, dimensionsübergreifend entdoppelt.

---

## 1. Executive Summary

Der Kern der Box ist solide: die vier Targets sind sauber gerichtet, der tragende Vertrag (Scanner erkennen, Policy entscheidet) hält, und die Firewall-Stufen sind implementiert und getestet (326 grüne Tests). Die schwerwiegenderen Befunde liegen nicht in der Erkennungslogik, sondern an zwei Rändern: den **Betriebsnähten des Daemons** und dem **ausgehenden Stream-Pfad**. Am auffälligsten ist ein systematisches Muster: `DaemonConfiguration` liest ganze Konfigurationsabschnitte fehlerfrei ein (Identität, Embedder, Quarantäne), aber `makePipeline`/`main.swift` verdrahten die zugehörigen Bausteine nicht — der Betreiber setzt `enabled: true` und bekommt stillen Wirkungsverlust, genau den Fehlermodus, den der Unknown-Key-Check eigentlich ausschließen soll. Das trifft mit dem Semantic Cache (Aushängeschild der Box), der Mandanten-Identität (Vorbedingung der Cache-Partitionierung) und der Quarantäne (Eval-Naht) drei als „fertig" markierte Stufen zugleich.

Der zweite Schwerpunkt ist der **Stream-Fehlerpfad**: `UpstreamClient.stream` prüft den HTTP-Status nicht, und `ProviderDownstream.stream` ruft — anders als `StageDownstream` — nie `pendingFailure()` auf. Ein Provider, der mit 429/500 oder einem In-Stream-`{"error":…}` antwortet, erzeugt eine leere, scheinbar vollständige 200-Antwort samt falschem Audit. Hinzu kommt eine stille UTF-8-Verfälschung an Chunk-Grenzen (`String(decoding:)` je Netz-Chunk) — für deutschsprachigen Inhalt realistisch.

Auf der Security-Seite gibt es zwei echte, wenn auch in der Sprengweite begrenzte Lücken: die **client-gewählte Nachrichtenrolle** verschafft einer Injection den `system`-Vertrauensrabatt (0.55), und **erkannte Secrets** (SEC-*) sind wirkungslos — sie werden erkannt, aber weder maskiert noch redigiert und wandern samt Cache-Index zum Upstream. Der Transport-Layer hat die bekannten Slowloris-/Slow-Reader-Löcher (kein Wanduhr-Deadline je Verbindung, kein `SO_SNDTIMEO`), die aber durch das dokumentierte Reverse-Proxy-Deployment gedämpft sind. Test- und Doku-Lücken sind zahlreich, aber niederschwellig; die wichtigste ist das ungetestete `ProviderDownstream`-Ende. Insgesamt: kein struktureller Fehlentwurf, sondern eine Reihe unvollständiger Nähte — genau die Art Arbeit, die der Scope („die Box und ihre Nähte vervollständigen") vorsieht.

---

## 2. Kritische & hohe Befunde

Es gibt keine als *high* verifizierten Befunde — die ursprünglich höher gemeldeten wurden mit Begründung auf *medium* abgestuft (Slowloris, Identitäts-Naht: gedämpft durch Loopback-Default + Reverse-Proxy-Sicherheitsmodell). Die folgende Tabelle führt die *medium*-Befunde, geordnet nach Handlungsdruck.

| # | Befund | Datei:Zeile | Kategorie |
|---|--------|-------------|-----------|
| M1 | Stream-Upstream-Fehler werden verschluckt (Status nie geprüft, `pendingFailure()` fehlt) | `UpstreamClient.swift:49`, `Downstream.swift:88-106` | error-handling |
| M2 | EventStreamParser korrumpiert Mehrbyte-UTF-8 an Chunk-Grenzen | `UpstreamClient.swift:120` | correctness |
| M3 | Identitäts-Naht aus Daemon nicht erreichbar → Cache kollabiert auf eine Partition | `DaemonConfiguration.swift:291`, `main.swift` | access-control / missing-seam |
| M4 | Semantische Cache-Stufe im Daemon nicht erreichbar — kein Embedder verdrahtbar | `main.swift:120`, `DaemonConfiguration.swift:291` | missing-seam |
| M5 | `quarantine.enabled` wirkungslos — kein Sink im Daemon verdrahtet | `DaemonConfiguration.swift:307`, `main.swift:120` | missing-seam |
| M6 | Client-gewählte Rolle erschleicht `system`-Trust und drückt Injection unter die Schwelle | `GatewayPipeline.swift:111`, `ProviderAdapter.swift:144` | injection-bypass |
| M7 | Erkannte Secrets (SEC-*) sind inert — verbatim zum Upstream und in den Cache-Index | `InjectionScanner.swift:84` | secret-leak |
| M8 | Slow-Body/Slowloris: Lese-Timeout pro `read()`, kein Gesamtdeckel je Verbindung | `HTTPServer.swift:378` | denial-of-service |
| M9 | Ablehnung binärer Inhaltsblöcke ungetestet + `carriesNonTextBlocks` per `text`-Feld umgehbar | `ProviderAdapter.swift:130` | test-coverage / silent-drop |
| M10 | HTTP-Parser (`readRequest`) und Fehlerpfade (413, Query-Strip, malformed) ungetestet | `HTTPServer.swift:337` | test-coverage |

### M1 — Stream-Upstream-Fehler werden verschluckt
`send(...)` prüft den HTTP-Status (`guard (200...299).contains(status)`, `UpstreamClient.swift:40f.`) und wirft bei 4xx/5xx. Der Stream-Pfad tut das **nicht**: `StreamDelegate` implementiert nur `didReceive data` und `didCompleteWithError`, aber kein `urlSession(_:dataTask:didReceive response:completionHandler:)` und wertet `HTTPURLResponse.statusCode` nirgends aus (`UpstreamClient.swift:49-101`). Antwortet der Provider auf eine Stream-Anfrage mit 429/500, landet das Fehler-JSON als vermeintliche Chunks im Collector; `streamDelta` liefert `nil`, die Continuation resümt erfolgreich → **leere, scheinbar vollständige Antwort**, für die `relay()` `status: 200` in Audit/`CompletionEvent` meldet. Verschärfend: `ProviderDownstream.stream` (`Downstream.swift:88-106`) endet mit `return events.reportedUsage()` und ruft — anders als `StageDownstream.stream` (`StageDownstream.swift:61`) — nie `events.pendingFailure()`; der Provider-Collector (`Downstream.swift:114-118`) setzt `Event.failure` nie. Ein In-Stream-`data: {"error":…}` wird also doppelt verschluckt.
**Fix:** Im `StreamDelegate` `urlSession(_:dataTask:didReceive:completionHandler:)` implementieren, Status prüfen, bei non-2xx die Continuation mit `GatewayServerError.upstream(status:body:)` beenden. Zusätzlich `ProviderDownstream.stream` nach dem Strom `events.pendingFailure()` werfen lassen und den Adaptern eine `streamFailure(fromEventPayload:)`-Erkennung geben. Der Catch-Zweig von `relay()` macht daraus dann sichtbar einen 502.

### M2 — UTF-8-Korruption an Chunk-Grenzen
`consume(_:)` hängt jeden Netz-Chunk mit `buffer += String(decoding: data, as: UTF8.self)` an (`UpstreamClient.swift:120`). `String(decoding:)` dekodiert die `Data` als Ganzes; endet ein Chunk mitten in einer Mehrbyte-Sequenz (Umlaut, Emoji), wird sie durch U+FFFD ersetzt — und die Fortsetzungsbytes des nächsten Chunks ebenso. Der Zeilenpuffer (`:123-125`) rettet nur Zeilen-Splits, nicht Codepoint-Splits. URLSession liefert `didReceive data` an beliebigen TCP-Grenzen (typisch ~16 KB).
**Fix:** Bytes statt Strings puffern: einen `Data`-Puffer führen, an `\n` (0x0A) trennen, nur vollständige Zeilen als UTF-8 dekodieren; der Rest-Bytepuffer trägt die angebrochene Sequenz in den nächsten `consume`-Aufruf. Testfall mit einem an der Codepoint-Grenze zerschnittenen Umlaut.

### M3 — Identitäts-Naht aus Daemon nicht erreichbar
`DaemonConfiguration` bietet `makePipeline()` (`:291`) und `makeRateGuard()` (`:310`), aber **kein `makePrincipalResolver()`** und keinen `identity`-Abschnitt im Parser. `main.swift` konstruiert `GatewayService` ohne `principals`-Argument → Default `AnonymousPrincipalResolver` (`GatewayService.swift:63/90`). Folge: `SharedSecretPrincipalResolver` (samt 401-Pfad und konstantzeitigem Vergleich, `PrincipalResolver.swift:67ff.`) ist über den ausgelieferten Daemon **nicht aktivierbar**; Mandantentrennung geht nur über ein handgeschriebenes Host-Programm. Sicherheitskritisch mit dem Cache: `cachePartition` entsteht aus Mandant+Scopes, aber ohne Resolver ist jeder Aufrufer `anonymous` und teilt sich **eine** Partition. `parse()` erlaubt gleichzeitig `cache.enabled=true` **und** `loopbackOnly=false` ohne jede Warnung — eine betreibbare Konfiguration, in der der Semantic Cache Antworten quer über alle (nicht getrennten) Nutzer ausspielt.
**Fix:** `identity`-Abschnitt + `makePrincipalResolver()` ergänzen (Geheimnis wie der API-Key **nur** aus der Umgebung, z. B. `AIGATEWAY_IDENTITY_SECRET`, nie aus der Datei), Resolver in `main.swift` durchreichen. **Fail-closed absichern:** `cache.enabled` zusammen mit `loopbackOnly=false` ohne nicht-anonymen Resolver als `ConfigurationError` ablehnen.

### M4 — Semantische Cache-Stufe im Daemon nicht erreichbar
Der Semantic Cache ist das Aushängeschild (README, DECISIONS Rang 5 „fertig"). Im Daemon läuft aber nur der exakte Treffer: `makePipeline(embedder:)` hat Default `nil` (`DaemonConfiguration.swift:291`), `main.swift:120` ruft `makePipeline()` ohne Embedder, und weder Parser noch Beispiel-Config kennen ein Embedder-Feld. `HTTPEmbedder` wird außerhalb der Tests nirgends konstruiert — bei `cache.enabled: true` bleibt die zweite Stufe tot.
**Fix:** `embedder`-Subsektion lesen (baseURL, path, model, apiKey aus Umgebung, timeout) und in `main.swift` einen `HTTPEmbedder` bauen und an `makePipeline(embedder:)` reichen. Bricht keine harte Regel (URLSession ausgehend ist erlaubt).

### M5 — `quarantine.enabled` wirkungslos
`parse` liest die gesamte `quarantine`-Sektion und akzeptiert sie fehlerfrei (`:187-198`), aber `makePipeline` baut die Quarantäne nur bei übergebenem `quarantineSink` (`quarantineSink.map { Quarantine(...) }`, `:307`). `main.swift:120` übergibt keinen Sink, `MemoryQuarantineSink` wird außerhalb der Tests nie konstruiert. `enabled: true` → kein Fehler, nichts aufbewahrt: genau der „stille wirkungslose Einstellung"-Fehlermodus.
**Fix:** Im Daemon bei `quarantine.enabled` einen `MemoryQuarantineSink` bauen und an `makePipeline(quarantineSink:)` reichen; alternativ beim Parsen fehlschlagen, wenn `enabled: true` ohne verdrahtbaren Sink gesetzt ist.

### M6 — Client-gewählte Rolle erschleicht `system`-Trust
Injection-Risiko wird je Nachricht mit dem `SourceTrust` der Rolle gewichtet (`system=trusted=0.55`, `user/assistant=neutral=1.0`, `tool=untrusted=1.35`; `GatewayPipeline.trust(for:)`, `:111`). Die Rolle kommt verbatim aus dem dekodierten Client-Request (`ChatMessage.Role(rawValue: roleRaw) ?? .user`, `ProviderAdapter.swift:144`; Anthropic synthetisiert sogar eine `.system`-Nachricht aus dem Client-`system`, `:285-286`). Nichts authentifiziert, dass eine `system`-Nachricht anwendungserzeugt ist. Rechnung: `rawScore` 1.10 (z. B. INJ-001+INJ-003, je 0.55) blockt als `user` (`min(1.0,1.10)=1.0 ≥ 0.7`), passiert aber als `system` (`1.10*0.55=0.605 < 0.7`). Widerspricht dem eigenen „Identität wird nicht geglaubt"-Ethos: Identitäts-Header werden ignoriert, das Rollen-Label — das den stärksten Rabatt gewährt — wird ohne Beleg geglaubt. Sprengweite begrenzt (der Angreifer jailbreakt ein Modell, das er ohnehin direkt anspricht; diese Box injiziert keinen eigenen System-Prompt), daher medium.
**Fix:** Policy-Option, die inbound-Message-Trust auf `neutral` deckelt (bzw. `system→trusted` nur bei via nicht-anonymem `PrincipalResolver`/vertrauenswürdigem Transport belegter Identität honoriert). Explizite Kontrolle, nicht nur Doku.

### M7 — Erkannte Secrets sind inert
Die Injection-Stufe erkennt Credential-Formate (SEC-001..007) mit Gewichten 0.35–0.45 (`defaultSecretRules`, `InjectionScanner.swift:274-297`), redigiert aber nichts — `scan` liefert `content: cleaned` (nur hidden-char-bereinigt, `:126-132`). Ein einzelnes Secret in einer `user`-Nachricht (neutral 1.0) scort < 0.7, wird also **erlaubt** und verbatim zum Drittanbieter geschickt; der maskierte-aber-secret-tragende Text wird zudem Teil von `CacheKey.prompt` (`SemanticCache.swift:61`). Keine Default-Stufe handelt auf `category == .secret`: PII maskiert nur person/mail/tel/iban/adresse/ort/custom, der DLP-Default-Katalog nur Klassifizierungs-Marker + interne URLs. Eine Erkennung ohne Handlung ist ein Leck mit Logzeile.
**Fix:** `.secret`-Findings einen Handlungspfad geben — Secret-Muster als DLP-`redact`-Regeln ausliefern (derselbe Einweg-Pfad wie DLP-003, greift **vor** Upstream und **vor** Cache-Key), oder eine `GatewayPolicy`-Option zum Blocken/Redigieren auf `category == .secret`. Der Scanner bleibt korrekt detection-only.

### M8 — Slowloris: kein Wanduhr-Deadline je Verbindung
`SO_RCVTIMEO` (einmalig in `serve()`, `HTTPServer.swift:305-307`) begrenzt nur **einen** `read()`-Aufruf. Kopf- (`:344-352`) und Rumpf-Leseschleife (`:378-382`) starten bei jedem eintreffenden Byte ein frisches 30-s-Fenster. Ein 1-Byte-alle-29-s-Tropf hält seinen Thread unbegrenzt; 64 solcher Verbindungen erschöpfen `maxConcurrentConnections=64`, danach 503 für alles weitere. Die Kommentare `:160-162`/`:302-304` behaupten fälschlich, das Timeout begrenze die „Dauer". Gedämpft durch Loopback-Default und das dokumentierte Reverse-Proxy-Modell (DECISIONS: volumetrische Angriffe sind Proxy-Sache), daher medium statt high.
**Fix:** Absoluten Deadline je Verbindung vor der ersten Lesung berechnen (`Date().addingTimeInterval(readTimeoutSeconds)`) und in beiden Schleifen je Durchlauf gegen `Date()` prüfen; bei Überschreitung schließen. Irreführende Kommentare korrigieren.

### M9 — Binärblock-Ablehnung ungetestet + per `text`-Feld umgehbar
Zwei verwandte Facetten derselben Naht (dimensionsübergreifend entdoppelt). **(a) Bug:** `carriesNonTextBlocks` flaggt einen Block nur bei **Abwesenheit** eines `text`-Schlüssels (`return blocks.contains { $0["text"] == nil }`, `ProviderAdapter.swift:130-133`). Ein Block mit **beidem** — Binärdaten und `text` (z. B. `{"type":"image_url","text":"…","image_url":{…}}`) — passiert die Prüfung; `flattenContent` extrahiert nur den Text, das Binäre wird still verworfen. Das verletzt die „refuse, don't drop"-Invariante (der Angreifer erzielt keinen Upstream-Schmuggel, da `ChatRequest` nur Text trägt — daher der Bug allein *low*). **(b) Test:** Der Ablehnungspfad (`messages()` wirft `.unsupported`, `:135-145`) hat **keinen Test** (grep leer) — laut CONTRIBUTING.md eine fail-closed-Sicherheitsnaht, dieselbe Fehlerklasse wie still entferntes `tools`. Zusammengenommen medium.
**Fix:** Ablehnung auf **positive** Binär-Erkennung stützen (`type ∈ {image, image_url, input_image, file, audio}` oder Präsenz von `image_url`/`source`/`data`), nicht auf fehlendes `text`. Tests: `testMessageWithBinaryContentBlockIsRejectedNotDropped` (OpenAI + Anthropic), Gegenprobe `testTextOnlyBlockArrayIsAccepted`.

### M10 — HTTP-Parser und Fehlerpfade ungetestet
`readRequest` und die 413-Logik sind reine Byte-Parsing-Logik mit mehreren Zweigen: Header-Case-Faltung, Query-Strip (`?`-Split, `:363`), 413 gegen **angekündigtes** Content-Length (`:320-322`, extra als Fallstrick kommentiert), 64-KB-Header-Deckel, malformte Request-Line → 400. Service-Tests konstruieren `HTTPRequest` direkt und umgehen den Parser; ShutdownTests fahren echte Sockets, aber nur `GET /healthz`. Kein Test deckt 413, Query-Strip oder eine kaputte Request-Line ab — DoS-/Härtungs-relevanter Byte-Parser ungeprüft.
**Fix:** Socket-Tests (freier Port, analog ShutdownTests): `testOversizedBodyGets413`, `testPathQueryStringIsStrippedBeforeRouting` (`POST /healthz?x=1` trifft healthz), `testMalformedRequestLineGets400`. Ggf. `readRequest` internal machen für einen direkten Parser-Test mit Pipe-fd.

---

## 3. Fehlende Bausteine fürs Zielbild — priorisiert

Alle drei Top-Bausteine sind Betriebsnähte im Daemon; sie teilen das Muster „Config wird gelesen, aber nicht verdrahtet". Sie respektieren die harten Regeln (reine Foundation-Verdrahtung; ausgehende URLSession ist erlaubt).

| Prio | Baustein | Warum wichtig für die Box | Aufwand | Risiko | Harte Regeln? |
|------|----------|---------------------------|---------|--------|---------------|
| 1 | **Identitäts-Naht im Daemon** (`makePrincipalResolver`, `identity`-Sektion, Fail-closed-Kreuzprüfung) — M3 | Vorbedingung der Cache-Partitionierung; ohne sie ist Mandantentrennung im Betrieb unmöglich und der Cache ein potenzielles Cross-User-PII-Leck | M | Sicherheit: hoch (verhindert falsch-sichere Config) | Ja — Secret nur aus Umgebung |
| 2 | **Embedder im Daemon verdrahten** (`embedder`-Sektion, `HTTPEmbedder` bauen) — M4 | Schaltet die als „fertig" gebaute semantische Cache-Stufe im Betrieb erst frei (Aushängeschild der Box) | S–M | Gering (Cache ist Kostenhebel, fail-open per Design) | Ja |
| 3 | **Quarantäne-Sink im Daemon** (`MemoryQuarantineSink` bei `enabled`) — M5 | Macht die Eval-/Feedback-Naht im Betrieb nutzbar; beseitigt stille wirkungslose Einstellung | S | Gering | Ja |
| 4 | **`.secret`-Handlungspfad** (DLP-`redact`-Regeln oder Policy-Option) — M7 | Schließt einen Detect-ohne-Action-Leak; Credentials verlassen sonst die Box | M | Mittel (Muster-Fehlklassifikation → über-redigieren) | Ja |
| 5 | **Inbound-Trust-Deckel** (Policy-Option gegen forged `system`) — M6 | Härtet die Provenienz-Bewertung gegen client-gewählte Rollen | S | Gering | Ja |
| 6 | **Betriebsgrenzen konfigurierbar** (`readTimeoutSeconds`, `maxConcurrentConnections`, Upstream-Timeout) | Betreiber kann DoS-/Slow-Client-Grenzen an Last anpassen | S | Gering | Ja (reine Verdrahtung) |
| 7 | **Correlation-ID auf Erfolgsantworten** (`X-Correlation-ID`-Header) | Schließt die Observability-Naht zum payload-freien Audit-Log für den häufigsten Fall (Durchlauf) | S | Kein | Ja (payload-frei) |

Nicht als „fehlender Baustein" gewertet, aber verwandt: **Slowloris-Deadline** (M8) und **`SO_SNDTIMEO`** (Abschnitt 4) sind Härtungen, keine neuen Bausteine — billig, korrekt, durch das Deployment-Modell entschärft.

---

## 4. Mittlere & kleine Verbesserungen

**Transport-Härtung (low):**
- **Kein `SO_SNDTIMEO`** (`HTTPServer.swift:305`): Nur `SO_RCVTIMEO` gesetzt; blockierendes `writeAll()`/`writeChunk()` hängt unbegrenzt, wenn ein Slow-Reader den Sendepuffer füllt (bes. SSE-Streaming). 64 Slow-Reader erschöpfen den Verbindungsdeckel. **Fix:** `SO_SNDTIMEO` analog setzen; `writeAll`/`writeChunk` geben den Fehler schon als `false` weiter, die Streaming-Produktion stoppt dann korrekt.
- **Transfer-Encoding ignoriert, doppeltes Content-Length last-wins** (`HTTPServer.swift:366`): Header-Dictionary überschreibt still; `Transfer-Encoding` wird nirgends behandelt (chunked → als CL fehlinterpretiert). Auf diesem Server durch `Connection: close` + eine Anfrage/Verbindung entschärft, aber CL/TE-Desync gegen einen Reverse Proxy bleibt möglich. **Fix:** Anfrage mit vorhandenem `Transfer-Encoding` → 400; mehrfaches/nicht-numerisches Content-Length → 400 statt last-wins.

**Concurrency (low):**
- **`running`/`listenFD` unsynchronisiert** (`HTTPServer.swift:244`, PLAUSIBLE): `@unchecked Sendable`, `stateLock` deckt nur `activeConnections`; `stop()` schreibt `running`/`listenFD`, `acceptLoop` liest sie — echtes (meist gutartiges) Data Race, unter striktem Swift-6-Checking ein Befund. **Fix:** beide unter denselben `stateLock` ziehen (oder `running` atomar führen).
- **Embedder-Breaker-Reentrancy** (`GatewayPipeline.swift:380`, PLAUSIBLE): `embedding(for:)` suspendiert an `await embedder.embed`; Actor-Reentrancy lässt mehrere `process`-Aufrufe `embedderOpenUntil == nil` lesen und alle in einen hängenden Embedder laufen, bevor `embedderFailures` hochzählt — der Schalter schützt gerade unter Last am schlechtesten. Nur Cache-Reichweite/Latenz. **Fix:** „probe in flight"-Flag vor dem Suspend setzen, oder Breaker in atomaren compare-and-set kapseln.
- **`serve`-Semaphore-Brücke** (`HTTPServer.swift:329`, PLAUSIBLE, informational): `done.wait()` blockiert je Anfrage einen dedizierten OS-Thread; kein aktueller Fehler (nicht-kooperativer Thread, Deckel = `maxConcurrentConnections`), aber deadlock-anfällig, falls der Handler je auf denselben begrenzten Executor gelegt würde. **Fix:** Invariante als Kommentar festhalten; später ggf. auf strukturiertes `await` umstellen.

**Determinismus/Robustheit (low):**
- **`PseudonymVault.restore` nichtdeterministisch + Alias-Präfix-Kollision** (`PseudonymVault.swift:184`): iteriert `tokenToValue` in Dictionary-Reihenfolge und sortiert die Ersatzformen **nicht** — anders als `MaskingSession.unmask` (`PIIGate.swift:41`, sortiert nach Länge absteigend). `aliasName` erzeugt ab dem 27. Person-Token `Alex A.1`, wovon `Alex A.` echtes Präfix ist; per Hash-Seed kann `Alex A.` zuerst ersetzt werden und zerstört `Alex A.1`. Genau die Dictionary-Ordnungs-Fehlerklasse, vor der CONTRIBUTING.md warnt. Nur CLI/Report-Pfad, Alias-Modus, >26 Personen. **Fix:** wie `unmask` Tokens+Aliasse einsammeln und nach Länge absteigend ersetzen.
- **`HTTPEmbedder.vector` NSNumber-Fallback nur für flaches `embedding`** (`Embedder.swift:74`, PLAUSIBLE): Der `[NSNumber]`-Fallback (nötig auf Linux, wo `as? [Double]` bridgen kann) existiert nur für `dict["embedding"]`, nicht für `embeddings` (`[[Double]]`) oder `data`. Auf Linux → `nil` → Breaker fällt, obwohl der Dienst korrekt antwortete. **Fix:** gemeinsame `doubles(from: Any?)`-Hilfe, die `[Double]` und `[NSNumber]` abdeckt, in allen drei Zweigen nutzen.

**Code-Qualität (low):**
- **`DensityAction.trim` unimplementiert** (`PseudonymizationPolicy.swift:101`): Doc-Kommentar bietet `onDensityExceeded: "trim"` an, `PIIGate.mask` unterscheidet aber nur `.abstain` (`:115`); `.trim` fällt still in den `warn`-Zweig. **Fix:** entweder Trimmen umsetzen (und `wasModified` setzen) **oder** `case trim` + Doc-Option entfernen.
- **`note()` zwei ungesicherte Writes** (`main.swift:39`): JSON-Körper und Newline in getrennten, unsynchronisierten `FileHandle.standardError.write`; thread-per-connection kann vier Writes zweier Zeilen verschränken → kaputte JSON-Lines im Audit-Pfad. **Fix:** Newline an `data` anhängen, in **einem** Write ausgeben, Zugriff mit statischem `NSLock` serialisieren.
- **`GatewayServerError.blocked(reason:)` toter Enum-Fall** (`ChatModel.swift:111`): nirgends geworfen/gematcht (der Block-Pfad liefert `forward=nil`, wirft nicht). **Fix:** entfernen oder mit Kommentar als geplante Naht begründen.
- **`StageTiming.timedOut`-Kommentar falsch** (`GatewayDecision.swift:27`): sagt „wurde abgebrochen", `budgetTiming` legt aber ausdrücklich fest „das ist eine Bewertung, KEIN Abbruch" (`GatewayPipeline.swift:529`). **Fix:** Kommentar angleichen.

---

## 5. Test- & Doku-Lücken

### Test-Lücken (konkrete Testnamen)

Die stärkste Lücke ist **`ProviderDownstream` end-to-end** — sie deckt gleichzeitig M1 auf:
- `testProviderMidStreamErrorIsSurfacedNotSwallowed` — OpenAI-Collector einen `{"error":…}`-Payload konsumieren lassen und erwarten, dass er als Failure sichtbar wird (deckt die fehlende `pendingFailure()`-Prüfung auf).
- `testProviderDownstreamRoundTripAgainstLocalUpstream` — gegen einen lokalen `HTTPServer` als Fake-Upstream.

Adapter-Ausgabepfade (reine Rahmungs-Korrektheit, low, aber je Dialekt nie ausgeführt):
- `testAnthropicEncodeResponseUsesBlockArrayAndUsage`, `testOllamaEncodeResponseCarriesEvalCounts` — `encodeResponse` je Dialekt (grep leer), am besten als Round-Trip `encodeResponse → decodeResponse` mit gesetztem `usage`/`finishReason`.
- `testEncodeStreamDeltaIsReadableByStreamDelta` (OpenAI/Anthropic/Ollama) und `testStreamTerminatorPerDialect` (OpenAI `[DONE]`, Ollama `done:true`, Anthropic `message_stop`) — `encodeStreamDelta`/`streamTerminator` (grep leer).
- `testSemanticFieldsAreRejectedPerDialect` — parametrisiert jedes gelistete Feld je Adapter einschmuggeln (`response_format`, `function_call`, Ollama `format`, Anthropic `tool_choice`); nur `tools` ist heute getestet. Gegenprobe: `user`/`stream_options` werden akzeptiert.

Ausgehende Naht `UpstreamClient` (grep leer):
- `testNon2xxBecomesUpstreamError`, `testStreamDeliversChunksAndCompletes`, `testStreamErrorResumesContinuationOnce` — gegen lokalen Fake-Upstream (send-Status-Mapping + StreamDelegate-Einmalauflösung).

Plus die in Abschnitt 2 genannten M9/M10-Tests.

### Doku-Fixes

- **Projektleitfaden (Reststand-Klammer)** (medium): „(offen: Semantic Cache, DLP-Semantik, Malware/ClamAV-Naht)" widerspricht DECISIONS.md:675-677 (alle drei „fertig"/„Naht fertig") und dem Code. Die verbindliche Arbeitsanweisung lässt drei gebaute Stufen als offen erscheinen. **Fix:** Klammerzusatz auf den echten Reststand aktualisieren (laut DECISIONS offen: persistente Quarantäne-Senke, Cache-Persistenz-Naht, Rückweg der Stufen-Variante von `MaskingSessionStore`).
- **README.md:307** (low): „# alle drei Targets" → „alle vier Targets" (Package.swift hat vier). Die Formulierung „Die drei Produkte" (README:74) bleibt korrekt (drei Bibliotheks-Produkte).
- **Umlaut-Konvention** (low): `RuleID.swift:6` „Identität" → „Identitaet"; `ChatModel.swift:52` „Inhaltsblöcken" → „Inhaltsbloecken". Beides Kommentare, keine Erkennungs-Literale. String-Literale mit deutschen Mustern unverändert lassen.
- **DECISIONS.md:403/405** (low): doppelte Überschrift „### Abwärts-Naht: heute Provider, später die nächste Box" — eine der beiden identischen Zeilen löschen.
- **Projektleitfaden (RuleID-Liste)** (low): RuleID-Liste wirkt als geschlossene 12er-Bindungsmenge, Code definiert ~53 IDs. **Fix:** als exemplarisch kennzeichnen (Auslassungszeichen wie DECISIONS.md:47) oder — besser — eine vollständige RuleID-Registry-Tabelle in DECISIONS.md ergänzen, an die der Leitfaden verweist.
- **`nextStage` undokumentiert** (low): `DaemonConfiguration.swift:215` liest den Root-Schlüssel und schaltet auf `StageDownstream`, aber weder `aigatewayd.example.json` noch der README-Daemon-Abschnitt erwähnen ihn. **Fix:** `nextStage` in der Beispiel-Config (als Variante) und im README dokumentieren.

---

## 6. Umsetzungs-Roadmap (geordnete Commits)

> **Stand 2026-07-30: alle 32 Roadmap-Commits sind umgesetzt und auf `main`
> gepusht.** Jede Welle wurde per CI abgenommen (Ubuntu + macOS, Zeile
> `Executed N tests, with 0 failures` gelesen); die Suite ist dabei von 326
> auf über 370 Tests gewachsen. Die Befunde M1–M10 sind damit geschlossen,
> die Verzichtsentscheidungen aus Abschnitt 7 gelten unverändert.

Reihenfolge: erst Netz (Tests/Absicherung), dann Fixes, dann neue Bausteine. Jeder Commit ist klein genug für einen CI-Lauf. **Abnahme ist die CI** — nach jedem Push den Lauf abwarten und die Zeile `Executed N tests, with 0 failures` lesen.

**A — Netz zuerst (Tests, die aktuelles Verhalten festnageln, bevor etwas geändert wird)**

1. `test: HTTP-Parser-Fehlerpfade absichern (413, Query-Strip, malformed)` — Tests/GatewayServerTests (Socket-Tests) → deckt M10.
2. `test: Binaerblock-Ablehnung als fail-closed Naht festnageln` — `testMessageWithBinaryContentBlockIsRejectedNotDropped` + Gegenprobe → deckt M9(b), macht M9(a)-Fix beweisbar.
3. `test: Provider-Stream verschluckt Fehler nicht (Regressionsnetz fuer M1)` — `testProviderMidStreamErrorIsSurfacedNotSwallowed` (erwartet zunaechst rot/xfail, siehe Commit 8).
4. `test: UpstreamClient send/stream Status-Mapping gegen lokalen Upstream`.
5. `test: encodeResponse + encodeStreamDelta/streamTerminator je Dialekt` — Round-Trips OpenAI/Anthropic/Ollama.
6. `test: semantik-aendernde Felder je Dialekt abgelehnt` — parametrisiert (`response_format`, `function_call`, Ollama `format`, Anthropic `tool_choice`).

**B — Fixes (klein, verhaltensändernd, jeweils durch A gedeckt)**

7. `fix: StreamRewriter/EventStreamParser puffert Bytes statt Strings (UTF-8 an Chunk-Grenze)` — `UpstreamClient.swift:120` → M2. Neuer Testfall mit zerschnittenem Umlaut.
8. `fix: Stream-Upstream-Status pruefen und pendingFailure() im Provider-Pfad werfen` — `UpstreamClient.stream`, `ProviderDownstream.stream`, Adapter-`streamFailure(fromEventPayload:)` → M1. Macht Commit 3 grün.
9. `fix: carriesNonTextBlocks positiv auf Binaer-Indikatoren pruefen` — `ProviderAdapter.swift:130` → M9(a).
10. `fix: PseudonymVault.restore laengenabsteigend ersetzen (deterministisch)` — `PseudonymVault.swift:184`.
11. `fix: note() eine Zeile pro Write, NSLock-serialisiert` — `main.swift:39`.
12. `fix: SO_SNDTIMEO auf Client-Socket setzen` — `HTTPServer.swift`.
13. `fix: absoluter Lese-Deadline je Verbindung + Kommentare korrigieren` — `HTTPServer.swift:344/378` → M8.
14. `fix: Transfer-Encoding und mehrfaches Content-Length mit 400 ablehnen` — `HTTPServer.swift:366`.
15. `fix: running/listenFD unter stateLock` — `HTTPServer.swift:244`.
16. `fix: HTTPEmbedder.vector NSNumber-Fallback in allen drei Zweigen` — `Embedder.swift:74`.
17. `fix: Embedder-Breaker reentrancy-fest (probe-in-flight-Flag)` — `GatewayPipeline.swift:380`.
18. `chore: DensityAction.trim entfernen (oder umsetzen) + Doc` — `PseudonymizationPolicy.swift`, `PIIGate.swift`.
19. `chore: toten Enum-Fall blocked(reason:) entfernen` — `ChatModel.swift:111`.
20. `docs: StageTiming.timedOut-Kommentar an Nicht-Abbruch-Entwurf angleichen` — `GatewayDecision.swift:27`.

**C — Doku-Fixes (billig, keine CI-Verhaltensänderung)**

21. `docs: Leitfaden-Reststand korrigieren (Cache/DLP/Malware sind fertig)`.
22. `docs: README alle vier Targets; Umlaut-Transliteration in RuleID.swift/ChatModel.swift`.
23. `docs: DECISIONS.md doppelte Ueberschrift entfernen; RuleID-Registry-Tabelle ergaenzen`.
24. `docs: nextStage-Schluessel in example.json und README dokumentieren`.

**D — Neue Bausteine (Nähte schließen)**

25. `feat: Inbound-Trust auf neutral deckelbar (Policy-Option gegen forged system)` — `GatewayPolicy`, `GatewayPipeline.trust` → M6. Test: forged `system` blockt mit Deckel.
26. `feat: .secret als DLP-redact-Regel im Default-Katalog` — `DLPScanner`-Default → M7. Test: SEC-Fund wird vor Upstream und vor Cache-Key redigiert.
27. `feat: Betriebsgrenzen konfigurierbar (readTimeout, maxConcurrent, Upstream-Timeout)` — `GatewayConfiguration`, `DaemonConfiguration` (server), `GatewayService.start`.
28. `feat: X-Correlation-ID-Header auf allen Antworten (auch Erfolg/Cache/Stream)` — `GatewayService` respond-Pfade.
29. `feat: Quarantaene-Sink im Daemon verdrahten` — `DaemonConfiguration.makePipeline`/`main.swift` `MemoryQuarantineSink` bei `enabled` → M5. Test/Config-Fehler bei `enabled` ohne Sink.
30. `feat: Embedder-Sektion + HTTPEmbedder im Daemon` — `DaemonConfiguration` (embedder), `main.swift` → M4. Beispiel-Config ergänzen.
31. `feat: Identitaets-Sektion + makePrincipalResolver im Daemon` — `DaemonConfiguration` (identity), `main.swift`, Secret aus `AIGATEWAY_IDENTITY_SECRET` → M3.
32. `feat: fail-closed Kreuzpruefung cache.enabled + loopbackOnly=false ohne nicht-anonymen Resolver` — `DaemonConfiguration.parse` → schließt M3.

---

## 7. Was bewusst NICHT gemacht wird

- **Kein `/metrics`-/`/readyz`-Scrape-Endpunkt** *(REJECTED — dokumentierte Entscheidung).* Der Befund forderte einen Prometheus-artigen Pull-Endpunkt für Cache-Trefferquote/FinOps. DECISIONS.md:393-395 benennt „Keine Trefferquote … nichts aggregiert sie für die FinOps-Box" **ausdrücklich als bewusst offen**. Observability ist absichtlich ein payload-freier stderr-JSON-Strom, der eine **separate** FinOps-Box speist — außerhalb des Scopes dieser Box. Ein Scrape-Endpunkt zöge deren Aufgabe herein. Der `/readyz`-vs-`/healthz`-Split ist ein Nice-to-have, kein Defekt. `cacheStatistics()` existiert (`GatewayPipeline.swift:406`); die fehlende Aggregation ist eine benannte Design-Lücke, kein Bug. **Nicht umgesetzt.**

- **Keine neuen Box-fremden Stufen.** Policy Engine, AI Router, Context Orchestrator, Agent Loop, Output Guardrails, Approval, Action Layer gehören laut Scope nicht in dieses Repo. Die Roadmap vervollständigt nur die eine Gateway-Box und ihre Nähte (`nextStage` bleibt eine reine Naht zur nächsten Box, keine eingebaute Policy).

- **Keine Selbstverteidigung gegen volumetrische Angriffe über das dokumentierte Maß hinaus.** DECISIONS.md:243-247 weist gezielte Fluten/Slow-Reader ausdrücklich dem Reverse Proxy zu; Default-Bind ist Loopback. Die Härtungen M8 und `SO_SNDTIMEO` werden umgesetzt (billig, korrekt), aber ohne Ratenbegrenzung/Connection-Throttling in den Server zu bauen, die per Entwurf vorgelagert liegen.

- **Kein selbstgeschriebenes TLS/Krypto, keine Package-Dependency.** Alle Roadmap-Punkte sind reine Foundation-Verdrahtung; ausgehende `URLSession` (Embedder/Upstream) bleibt die einzige erlaubte Netz-Ausnahme. Der konstantzeitige Vergleich im `SharedSecretPrincipalResolver` existiert bereits und wird nur verdrahtet, nicht neu erfunden.

- **`RuleID`s werden nur ergänzt, nie umbenannt.** Etwaige neue Secret-DLP-Regeln (Commit 26) bekommen neue, stabile IDs; bestehende (`DLP-001..003`, `SEC-001..007` etc.) bleiben unverändert — Suppressions/SIEM/Dashboards binden daran.