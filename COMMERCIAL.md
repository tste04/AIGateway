# Kommerzielle Lizenzierung

AIGateway ist dual-lizenziert.

- **Persönliche & nichtkommerzielle Nutzung ist kostenlos** unter der
  [PolyForm Noncommercial License 1.0.0](LICENSE.md) — eigene Projekte, eigene
  Experimente, eigene Maschine.
- **Jede kommerzielle Nutzung erfordert eine kommerzielle Lizenz** — Einsatz
  innerhalb eines Unternehmens, Einbettung in ein Produkt oder Bereitstellung als
  Teil eines bezahlten Dienstes.

„Kommerziell" und „nichtkommerziell" richten sich nach den Definitionen der
PolyForm Noncommercial License 1.0.0. Im Zweifel: eine kurze Anfrage klärt es.

## Warum eine kommerzielle Lizenz

AIGateway ist kein Prompt-Filter, sondern die **Input Firewall** zwischen Client
und Sprachmodell — die Stelle, an der geprüft wird, was hineingeht:

| Was du bekommst | Warum es kommerziell zählt |
|---|---|
| Injection-Erkennung für Englisch **und** Deutsch, gegen Verschleierung normalisiert (Homoglyphen, Buchstaben-Sperrung, Trennzeichen, Base64) | Ein rein englischer Regelsatz ist im deutschsprachigen Betrieb praktisch blind; die Normalisierung schließt die trivialen Bypässe. |
| Bewertung je Nachricht mit der Vertrauensstufe ihrer Rolle — Tool-Ausgaben gelten als fremd | Der Hauptangriffsweg im Agent Loop ist fremder Inhalt, der als Anweisung gelesen wird. Dieselbe Zeichenfolge passiert im System-Prompt und blockt in der Tool-Ausgabe. |
| PII-Maskierung mit Round-Trip: der Provider sieht nur Platzhalter, der Nutzer bekommt Klardaten zurück | Reduziert, was den Auftragsverarbeiter überhaupt erreicht — inklusive De-Maskierung über SSE-Chunk-Grenzen hinweg. |
| Ein Pseudonym-Vault je Mandanten-Partition, Rückweg an die einzelne Anfrage gebunden | Token-Räume verschiedener Mandanten laufen nicht ineinander. |
| Audit-Einträge ohne Nutzinhalt, mit stabilen Regel-IDs | SIEM-Korrelation und Suppressions binden an IDs; das Audit-Log wird nicht selbst zum PII-Speicher. |
| Trennung von Erkennung und Entscheidung (`ContentScanner` / `GatewayPolicy`) | Schwellen und Fehlalarm-Unterdrückung sind Betriebsparameter — änderbar, ohne eine Erkennungsregel anzufassen. |
| Drei Provider-Dialekte ein- und ausgehend, unabhängig voneinander | Der Client spricht OpenAI, das Gateway reicht nach Anthropic weiter — ohne Call-Sites anzufassen. |
| Keine Paket-Abhängigkeiten außer `Foundation` | Kleine Angriffs- und Auditfläche; keine fremde Supply Chain im sicherheitskritischen Pfad. |

## Editionen

| Edition | Für | Umfang | Konditionen |
|---|---|---|---|
| **Personal** | Einzelpersonen, nichtkommerziell | Alles in diesem Repo | Kostenlos (PolyForm NC) |
| **Pro** | Freelancer & kommerzielle Einzelnutzung | Kommerzielle Lizenz, priorisierte Issues | Auf Anfrage |
| **Team** | Unternehmen mit mehreren Seats | Kommerzielle Lizenz, E-Mail-Support | Auf Anfrage |
| **Enterprise / OEM** | Einbettung in Produkte, Compliance-Deployments | OEM-Lizenz, SLA, Roadmap-Einfluss | Auf Anfrage |

Kommerzielle Konditionen werden **individuell auf Verhandlungsbasis** vereinbart —
abhängig von Seat-Zahl, Nutzungsart (intern, Produkt-Einbettung, SaaS) und
Support-Umfang. Frag einfach mit einer kurzen Beschreibung deines Einsatzes an;
du erhältst ein passendes Angebot.

## Wie die Lizenzierung funktioniert

AIGateway prüft keine Lizenz. Es gibt **keinen Lizenzserver, keine
Aktivierungs-Calls, keine Telemetrie, keine Lizenzdateien und keinen
Kill-Switch**. Die Durchsetzung ist **rechtlicher, nicht technischer** Natur:

1. **PolyForm NC macht unlizenzierte kommerzielle Nutzung zur
   Urheberrechtsverletzung** — derselbe Hebel, auf dem jedes betriebliche
   Software-Asset-Management beruht. Unternehmen lizenzieren, weil ihre eigenen
   Compliance-Regeln unlizenzierte Software verbieten.
2. **Enterprise-Verträge enthalten eine jährliche Selbstauskunft** zur Seat-Zahl,
   die auf der nächsten Rechnung angepasst wird — übliche Praxis, keine Audits per
   Default.

## Lizenz erhalten

Schreib an **[hello@tstellmacher.com](mailto:hello@tstellmacher.com)** mit einer
kurzen Beschreibung deines geplanten Einsatzes (interne Nutzung, Produkt-Einbettung
oder SaaS; ungefähre Seat-Zahl). Alternativ: ein GitHub-Issue mit dem Titel
`commercial license` in diesem Repository. Du erhältst ein Angebot auf
Verhandlungsbasis und eine kurze Lizenzvereinbarung — kein Call nötig, außer du
möchtest einen.

## FAQ

**Kann ich kommerziell zuerst evaluieren?** Ja — 30 Tage, ohne Registrierung.

**Telefoniert die freie Version nach Hause?** Nein. Es gibt keine Lizenzprüfung
und keine Telemetrie. Ausgehende Verbindungen gehen ausschließlich an den
Provider, den du selbst konfigurierst.

**Beiträge?** Willkommen — sie erfordern das CLA
([docs/CLA.md](docs/CLA.md), siehe [CONTRIBUTING.md](CONTRIBUTING.md)): du behältst
dein Copyright und räumst dem Maintainer eine übertragbare, unwiderrufliche Lizenz
ein — das hält das Projekt als Ganzes relicensierbar und verkaufbar (saubere
Rechtekette).

**Wie hängt das mit Engram zusammen?** AIGateway kann Teil der
Engram-Distribution werden. Deren Distributionslizenz deckt die kommerzielle
Nutzung der enthaltenen Komponenten im Rahmen der Distribution ab — Details in
[LICENSING.md](LICENSING.md).
