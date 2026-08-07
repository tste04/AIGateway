# Lizenz-Policy (Komponenten & Distribution)

Dieses Dokument definiert, wie die Komponenten dieses Portfolios (u. a. AIRouter,
Engram, AIGateway) lizenziert werden — einzeln und als Distribution. Es ist die
verbindliche Default-Antwort für jede neue Komponente.

## Drei Schichten

| Schicht | Lizenz | Zweck | Beispiele |
|---|---|---|---|
| **1 — Commodity** | Apache-2.0 | Verbreitung/Adoption; Wert liegt in der Nutzung, nicht in der Exklusivität. Patent-Grant inklusive, enterprise-freundlich. | *(derzeit keine — siehe Default-Regel)* |
| **2 — Differenzierend** | PolyForm Noncommercial 1.0.0 + kommerzielle Lizenz | Kaufgrund-Komponenten: nichtkommerziell frei, jede kommerzielle Nutzung führt zum Maintainer. | AIRouter, Engram, AIGateway |
| **3 — Distribution** | Kommerzielle Distributionslizenz (EULA/Subscription) | Das Bundle als Produkt: bündelt kommerzielle Rechte an Schicht-2-Komponenten, enthält Schicht-1-Komponenten mit Attribution, plus Marke, Support, SLA, signierte Builds. | Engram-Distribution |

## Default-Regel

**Jede neue Komponente startet in Schicht 2 (PolyForm NC + kommerziell).**

Begründung — die Asymmetrie der Relicensierung:

- **Lockern (NC → Apache) geht jederzeit** für künftige Versionen.
- **Verschärfen (Apache → NC) wirkt nur nach vorn** — einmal permissiv
  Veröffentlichtes bleibt permissiv in der Welt.

Eine Komponente wandert erst dann nach Schicht 1, wenn es einen konkreten,
dokumentierten Adoption-Grund gibt (z. B. Funnel-Wirkung nachweislich größer als
Lizenz-Umsatzpotenzial). Die Entscheidung trifft der Maintainer und wird hier
im Komponenten-Register festgehalten.

## Chain of Title (Voraussetzung für alles)

Bundling und Relicensierung setzen voraus, dass der Maintainer sämtliche Rechte
hält:

- Jede Contribution erfolgt unter dem **CLA** ([docs/CLA.md](docs/CLA.md), siehe
  [CONTRIBUTING.md](CONTRIBUTING.md)): Contributor behält Copyright, Maintainer
  erhält eine unbefristete, unwiderrufliche, übertragbare Lizenz inkl.
  Relicensierungs- und Sublizenzierungsrecht.
- PRs ohne CLA-Zustimmung werden nicht gemergt — ausnahmslos.
- Dieselbe CLA-Mechanik gilt in jedem Repo des Portfolios (identischer Wortlaut).

## Komponenten-Register

| Komponente | Schicht | Lizenz | Kommerziell |
|---|---|---|---|
| **AIRouter** | 2 | PolyForm NC 1.0.0 | Kommerzielle Lizenz, Konditionen auf Verhandlungsbasis |
| **Engram** | 2 | PolyForm NC 1.0.0 | Kommerzielle Editionen, Konditionen auf Verhandlungsbasis |
| **AIGateway** *(dieses Repo)* | 2 | [PolyForm NC 1.0.0](LICENSE.md) | [COMMERCIAL.md](COMMERCIAL.md), Konditionen auf Verhandlungsbasis |
| **Engram-Distribution** (Bundle) | 3 | Kommerzielle Distributionslizenz | Seats/Laufzeit/Nutzungsart individuell; umfasst die kommerziellen Rechte der enthaltenen Schicht-2-Komponenten |

Fließt eine Schicht-2-Komponente in die Distribution ein, deckt die
Distributionslizenz des Kunden deren kommerzielle Nutzung **im Rahmen der
Distribution** ab; eine separate Einzellizenz ist dann nicht nötig.
Standalone-Nutzung derselben Komponente außerhalb der Distribution bleibt
separat lizenzpflichtig.

## Grundsätze (gelten in allen Schichten)

- **Keine öffentlichen Preislisten** — kommerzielle Konditionen auf
  Verhandlungsbasis (Seats, Nutzungsart, Support-Umfang).
- **Keine technische Durchsetzung** — kein Lizenzserver, keine Telemetrie, kein
  Kill-Switch. Durchsetzung ist rechtlich (Urheberrecht + Vertrag).
- **Copyright-Inhaber:** Tommy Stellmacher.
- **Kontakt für kommerzielle Anfragen:**
  [hello@tstellmacher.com](mailto:hello@tstellmacher.com)
