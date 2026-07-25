// Copyright (c) 2026 Tommy Stellmacher
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

import Foundation

// MARK: - Das Gate
//
// Erkennt personenbezogene Klardaten deterministisch (kein LLM, kein Netz) und
// ersetzt sie durch stabile Tokens (oder generische Aliasse). Die Zuordnung
// bleibt ausschliesslich lokal — der Provider sieht Struktur, nie Klarnamen.
//
// BEWUSSTE GRENZEN (ehrlich, gehoeren in jede Betriebsdoku):
// - Deterministische Heuristiken. KEINE Vollstaendigkeitsgarantie — Freitext
//   kann Personenbezug tragen, den keine Heuristik sieht. Pseudonymisierung
//   ergaenzt Datenminimierung, sie ersetzt sie nicht.
// - Erkennung ist auf deutschsprachige Muster optimiert (Anreden, Strassen,
//   PLZ). Andere Sprachraeume brauchen eigene Muster.
// - Tokens sind absichtlich lesbar ([Person-1]); der Alias-Modus ersetzt
//   Personen stattdessen durch klar generische Namen ('Alex M.'), weil Modelle
//   ueber natuerliche Namen besser schliessen. Kollisionsrisiko mit echten
//   Namen ist dokumentiert.

public actor Pseudonymizer {

    /// Ergebnis eines Maskier-Laufs inklusive Rueckuebersetzung.
    public struct MaskingOutcome: Sendable {
        public let content: String
        /// Ersatzform -> Klarwert, gueltig fuer GENAU diese Anfrage.
        public let mapping: [String: String]
        /// Treffer je Kategorie (Grundlage der Befunde).
        public let counts: [PseudonymCategory: Int]
        /// Anteil Tokens an den Inhaltswoertern nach der Maskierung.
        public let density: Double
    }

    private let vault: PseudonymVault
    public nonisolated let policy: PseudonymizationPolicy
    private let allowSet: Set<String>

    public init(vault: PseudonymVault, policy: PseudonymizationPolicy = .standard) {
        self.vault = vault
        self.policy = policy
        self.allowSet = Set((policy.allowlist ?? []).map { Self.canonicalize($0) })
    }

    // MARK: - Maskierung

    /// Maskiert Text und liefert die Zuordnung fuer den Rueckweg mit.
    ///
    /// - Parameter sparingQuery: die Nutzerfrage. Bei `keepQueriedEntity` bleiben
    ///   Personen, die darin selbst genannt sind, Klartext (Korrelations-Grenze:
    ///   der Empfaenger kennt sie ohnehin) — maskiert wird die Masse der anderen.
    public func mask(_ text: String, sparingQuery: String? = nil) async -> MaskingOutcome {
        guard !text.isEmpty else {
            return MaskingOutcome(content: text, mapping: [:], counts: [:], density: 0)
        }
        var result = text
        var counts: [PseudonymCategory: Int] = [:]
        var usedTokens = Set<String>()

        let spared = await sparedPersonKeys(query: sparingQuery)
        var hits = Self.detect(in: text, denylist: policy.denylist ?? [],
                               strictChains: policy.strictNameChains)
        hits = hits.filter { hit in
            guard policy.mode(for: hit.category) != .off else { return false }
            let canon = Self.canonicalize(hit.value)
            if allowSet.contains(canon) { return false }
            if hit.category == .person, isSpared(canon, spared: spared) { return false }
            return true
        }

        // Rechts-nach-links ersetzen, damit fruehere Ranges gueltig bleiben.
        for hit in hits.sorted(by: { $0.range.location > $1.range.location }) {
            guard let range = Range(hit.range, in: result) else { continue }
            let token = await tokenFor(hit)
            usedTokens.insert(token)
            counts[hit.category, default: 0] += 1
            result.replaceSubrange(range, with: replacement(for: token, category: hit.category))
        }

        // Nachschlag-Durchgang: einmal gelernte Personen werden UEBERALL ersetzt,
        // auch ohne Trigger ('Akte Mueller' im Titel, nachdem 'Herr Mueller' bekannt ist).
        if policy.mode(for: .person) != .off {
            let known = await vault.personNames().sorted { $0.name.count > $1.name.count }
            for (name, token) in known where !name.isEmpty {
                if allowSet.contains(name) { continue }
                if isSpared(name, spared: spared) { continue }
                // Guards: '[' davor schliesst aus, dass in bereits gesetzten Tokens
                // ersetzt wird (Nachname 'Ort' vs. [Ort-1]); '-' danach schuetzt
                // Kompositum-Namen vor Teil-Zerlegung.
                let pattern = "(?<![\\p{L}\\[])" + NSRegularExpression.escapedPattern(for: name) + "(?![\\p{L}-])"
                guard let regex = try? NSRegularExpression(pattern: pattern, options: [.caseInsensitive]) else { continue }
                let ns = NSRange(result.startIndex..., in: result)
                guard regex.firstMatch(in: result, range: ns) != nil else { continue }
                let repl = replacement(for: token, category: .person)
                result = regex.stringByReplacingMatches(
                    in: result, range: ns,
                    withTemplate: NSRegularExpression.escapedTemplate(for: repl))
                usedTokens.insert(token)
                counts[.person, default: 0] += 1
            }
        }

        // Rueckuebersetzung aufbauen: Token- UND Alias-Form auf den Klarwert.
        var mapping: [String: String] = [:]
        for token in usedTokens {
            guard let value = await vault.value(forToken: token), !value.isEmpty else { continue }
            mapping[token] = value
            if let alias = Self.aliasName(forToken: token) { mapping[alias] = value }
        }

        return MaskingOutcome(content: result, mapping: mapping, counts: counts,
                              density: Self.tokenDensity(of: result))
    }

    /// Nur der maskierte Text.
    public func pseudonymize(_ text: String, sparingQuery: String? = nil) async -> String {
        await mask(text, sparingQuery: sparingQuery).content
    }

    /// Rueckuebersetzung aus dem Vault-Wissen. Fuer den Antwortpfad ist
    /// `MaskingSession.unmask` vorzuziehen — sie traegt exakt die Zuordnung
    /// DIESER Anfrage und ist damit unabhaengig vom Vault-Zustand.
    public func restore(_ text: String) async -> String { await vault.restore(text) }

    public func mappings() async -> [(token: String, value: String, category: String)] {
        await vault.allEntries()
    }

    // MARK: - Dichte-Waechter

    /// Anteil der Tokens an den Inhaltswoertern. Ab `policy.effectiveMaxDensity`
    /// gilt ein Text als semantisch entkernt.
    /// (Alias-Ersetzungen zaehlen bewusst nicht: sie erhalten die Lesbarkeit.)
    public static func tokenDensity(of text: String) -> Double {
        let words = text.split(whereSeparator: { $0.isWhitespace }).count
        guard words > 0 else { return 0 }
        let ns = NSRange(text.startIndex..., in: text)
        let tokens = tokenRegex.numberOfMatches(in: text, range: ns)
        return Double(tokens) / Double(words)
    }

    // MARK: - Alias-Modus (Personen)

    /// Deterministischer, klar generischer Alias: [Person-1] -> 'Alex A.'
    public static func aliasName(forToken token: String) -> String? {
        guard token.hasPrefix("[Person-"), token.hasSuffix("]"),
              let n = Int(token.dropFirst("[Person-".count).dropLast()), n >= 1 else { return nil }
        let first = aliasFirstNames[(n - 1) % aliasFirstNames.count]
        let letterIndex = (n - 1) % 26
        let letter = Character(UnicodeScalar(UInt8(65 + letterIndex)))
        // Ab der zweiten Runde eine Ziffer anhaengen, damit Aliasse eindeutig bleiben.
        let round = (n - 1) / aliasFirstNames.count
        return round == 0 ? "\(first) \(letter)." : "\(first) \(letter).\(round)"
    }

    private func replacement(for token: String, category: PseudonymCategory) -> String {
        if category == .person, policy.mode(for: .person) == .alias,
           let alias = Self.aliasName(forToken: token) {
            return alias
        }
        return token
    }

    private static let aliasFirstNames = [
        "Alex", "Bela", "Chris", "Dana", "Elia", "Falk", "Gero", "Hedi", "Ida", "Jona",
        "Kim", "Lou", "Mika", "Noa", "Ole", "Pia", "Quin", "Rene", "Sam", "Toni",
        "Ulf", "Vera", "Wim", "Xenia", "Yara", "Zoe",
    ]

    // MARK: - Query-Schonung (keepQueriedEntity)

    private func sparedPersonKeys(query: String?) async -> Set<String> {
        guard policy.effectiveKeepQueriedEntity, let query, !query.isEmpty else { return [] }
        var spared = Set<String>()
        for hit in Self.detect(in: query, denylist: [], strictChains: policy.strictNameChains)
        where hit.category == .person {
            let canon = Self.canonicalize(hit.value)
            spared.insert(canon)
            if let last = canon.split(separator: " ").last { spared.insert(String(last)) }
        }
        // Auch bereits bekannte Vault-Namen, die in der Anfrage stehen.
        let q = query.lowercased()
        for (name, _) in await vault.personNames() where !name.isEmpty {
            if q.range(of: "(?<!\\p{L})" + NSRegularExpression.escapedPattern(for: name) + "(?!\\p{L})",
                       options: [.regularExpression, .caseInsensitive]) != nil {
                spared.insert(name)
                if let last = name.split(separator: " ").last { spared.insert(String(last)) }
            }
        }
        return spared
    }

    private func isSpared(_ canonicalName: String, spared: Set<String>) -> Bool {
        guard !spared.isEmpty else { return false }
        if spared.contains(canonicalName) { return true }
        if let last = canonicalName.split(separator: " ").last, spared.contains(String(last)) { return true }
        return false
    }

    private func tokenFor(_ hit: Detection) async -> String {
        let canonical = hit.category.rawValue + "|" + Self.canonicalize(hit.value)
        if hit.category == .person {
            let words = Self.canonicalize(hit.value).split(separator: " ").map(String.init)
            // Nachnamen-Verkettung: 'Frau Schmidt' und 'Anna Schmidt' -> EIN Token.
            if words.count == 1, let linked = await vault.personToken(forSurname: words[0]) {
                await vault.registerAlias(canonical: canonical, value: "", token: linked, category: .person)
                return linked
            }
            if words.count > 1 {
                if let link = await vault.personLink(forSurname: words[words.count - 1]) {
                    if link.isBareSurname {
                        // Bisher nur 'Frau Schmidt' bekannt -> voller Name gehoert dazu.
                        await vault.registerAlias(canonical: canonical, value: hit.value,
                                                  token: link.token, category: .person)
                        return link.token
                    }
                    // Ein ANDERER voller Name mit gleichem Nachnamen existiert bereits
                    // (Anna Schmidt vs. Bernd Schmidt) -> eigenes Token, KEIN
                    // Nachnamen-Alias mehr (der Nachname ist jetzt mehrdeutig).
                    return await vault.token(for: hit.value, canonical: canonical,
                                             category: .person, aliasCanonicals: [])
                }
                let surnameCanonical = hit.category.rawValue + "|" + words[words.count - 1]
                return await vault.token(for: hit.value, canonical: canonical,
                                         category: .person, aliasCanonicals: [surnameCanonical])
            }
        }
        return await vault.token(for: hit.value, canonical: canonical, category: hit.category)
    }

    static func canonicalize(_ value: String) -> String {
        value.lowercased()
            .components(separatedBy: .whitespacesAndNewlines)
            .filter { !$0.isEmpty }
            .joined(separator: " ")
    }

    // MARK: - Deterministische Erkennung (rein, testbar)

    struct Detection {
        let range: NSRange       // Ersetzungs-Range im Ursprungstext
        let value: String        // erkannter Klarwert (bei Personen OHNE Anrede)
        let category: PseudonymCategory
    }

    /// Erkennt Kandidaten in Prioritaetsreihenfolge und loest Ueberlappungen auf
    /// (fruehere Kategorie gewinnt). Denylist zuerst — expliziter Nutzerwille.
    static func detect(in text: String, denylist: [String] = [],
                       strictChains: Bool = false) -> [Detection] {
        var raw: [Detection] = []
        raw += denylistMatches(in: text, terms: denylist)
        raw += matches(ibanRegex, in: text, category: .iban)
        raw += matches(mailRegex, in: text, category: .mail)
        raw += matches(streetRegex, in: text, category: .adresse)
        raw += matches(plzCityRegex, in: text, category: .ort)
        raw += phoneMatches(in: text)
        raw += honorificPersons(in: text)
        raw += lexiconPersons(in: text)
        if strictChains { raw += chainPersons(in: text) }

        var accepted: [Detection] = []
        for cand in raw where !accepted.contains(where: { NSIntersectionRange($0.range, cand.range).length > 0 }) {
            accepted.append(cand)
        }
        return accepted
    }

    private static func matches(_ regex: NSRegularExpression, in text: String,
                                category: PseudonymCategory) -> [Detection] {
        let ns = NSRange(text.startIndex..., in: text)
        return regex.matches(in: text, range: ns).compactMap { m in
            guard let r = Range(m.range, in: text) else { return nil }
            return Detection(range: m.range, value: String(text[r]), category: category)
        }
    }

    /// Nutzer-kuratierte Begriffe: ganze Woerter/Phrasen, case-insensitiv.
    private static func denylistMatches(in text: String, terms: [String]) -> [Detection] {
        var out: [Detection] = []
        for term in terms where !term.trimmingCharacters(in: .whitespaces).isEmpty {
            let pattern = "(?<![\\p{L}\\[])" + NSRegularExpression.escapedPattern(for: term) + "(?!\\p{L})"
            guard let regex = try? NSRegularExpression(pattern: pattern, options: [.caseInsensitive]) else { continue }
            let ns = NSRange(text.startIndex..., in: text)
            for m in regex.matches(in: text, range: ns) where Range(m.range, in: text) != nil {
                // Wert auf den KONFIGURIERTEN Begriff normieren, damit alle
                // Schreibweisen EIN Token bekommen.
                out.append(Detection(range: m.range, value: term, category: .custom))
            }
        }
        return out
    }

    private static func phoneMatches(in text: String) -> [Detection] {
        matches(phoneRegex, in: text, category: .tel).filter { d in
            // Mindestens 7 Ziffern — filtert PLZ-Reste, Hausnummern, Kurz-Zahlen.
            d.value.unicodeScalars.filter { CharacterSet.decimalDigits.contains($0) }.count >= 7
        }
    }

    /// Anrede-/Titel-getriggerte Personen: 'Herr Mueller', 'Frau Dr. Anna Schmidt'.
    /// Ersetzt wird NUR der Name (Capture-Gruppe) — die Anrede bleibt lesbar.
    ///
    /// Im Deutschen ist JEDES Substantiv grossgeschrieben — die rohe Capture frisst
    /// sonst Folgewoerter ('Herrn Mueller Bescheid') und vergiftet den Vault mit
    /// Muell-Nachnamen ('bescheid', 'montag', 'gmbh'), die der Nachschlag-Durchgang
    /// dann ueberall ersetzt. Deshalb wird die Capture in Code beschnitten.
    private static func honorificPersons(in text: String) -> [Detection] {
        let ns = NSRange(text.startIndex..., in: text)
        return honorificRegex.matches(in: text, range: ns).compactMap { m in
            let nameRange = m.range(at: 1)
            guard nameRange.location != NSNotFound, let r = Range(nameRange, in: text) else { return nil }
            let raw = String(text[r])
            let words = raw.split(whereSeparator: { $0.isWhitespace }).map(String.init)
            guard let keep = personWordCount(words), keep >= 1 else { return nil }
            if keep == words.count {
                return Detection(range: nameRange, value: raw, category: .person)
            }
            // Range auf die behaltenen Woerter verkuerzen (alle Separatoren sind
            // einzelne \s-Zeichen — Laenge == Laenge der mit " " gejointen Woerter).
            let kept = words.prefix(keep).joined(separator: " ")
            let trimmed = NSRange(location: nameRange.location, length: (kept as NSString).length)
            return Detection(range: trimmed, value: kept, category: .person)
        }
    }

    /// Wie viele der Woerter bilden wirklich einen Personennamen? `nil` = gar keiner
    /// (Firma oder reines Stopwort). Regel: Wort n+1 gehoert nur dazu, wenn alle
    /// Woerter 1...n Lexikon-Vornamen sind; Firmen-Suffixe und Nachnamen-Stopwoerter
    /// beenden bzw. verwerfen die Kette.
    private static func personWordCount(_ words: [String]) -> Int? {
        guard let first = words.first else { return nil }
        if corporateSuffixes.contains(first.lowercased()) { return nil }
        if surnameStopwords.contains(first.lowercased()) { return nil }
        var keep = 1
        while keep < words.count {
            let next = words[keep].lowercased()
            if corporateSuffixes.contains(next) { return nil }   // 'Acme GmbH' = Firma
            if surnameStopwords.contains(next) { break }          // 'Mueller Bescheid'
            guard firstNames.contains(words[keep - 1].lowercased()) else { break }
            keep += 1
        }
        return keep
    }

    /// Firmen-Suffixe — eine Kette mit so einem Wort ist eine FIRMA, keine Person.
    private static let corporateSuffixes: Set<String> = [
        "gmbh", "mbh", "ag", "kg", "ug", "ohg", "gbr", "se", "co", "inc", "ltd", "llc",
    ]

    /// Woerter, die (grossgeschrieben) auf einen Namen folgen koennen, aber praktisch
    /// nie Nachnamen sind — Wochentage, Monate, Kanzlei-Alltagsbegriffe.
    private static let surnameStopwords: Set<String> = [
        "montag", "dienstag", "mittwoch", "donnerstag", "freitag", "samstag", "sonntag",
        "januar", "februar", "märz", "april", "mai", "juni", "juli", "august",
        "september", "oktober", "november", "dezember",
        "bescheid", "termin", "frist", "akte", "vertrag", "rechnung", "anfrage",
        "ende", "anfang", "morgen", "gestern", "heute", "uhr", "mitte",
    ]

    /// Lexikon-getriggerte Personen: 'Anna Schmidt' — nur wenn das ERSTE Wort ein
    /// bekannter Vorname ist. Deutsche Substantiv-Grossschreibung loest so nie aus.
    private static func lexiconPersons(in text: String) -> [Detection] {
        let ns = NSRange(text.startIndex..., in: text)
        return namePairRegex.matches(in: text, range: ns).compactMap { m in
            guard let first = Range(m.range(at: 1), in: text) else { return nil }
            guard firstNames.contains(text[first].lowercased()) else { return nil }
            guard let second = Range(m.range(at: 2), in: text) else { return nil }
            // 'Anna GmbH' ist eine Firma, 'Anna Montag' ein Termin-Artefakt.
            let surname = text[second].lowercased()
            guard !corporateSuffixes.contains(surname), !surnameStopwords.contains(surname) else { return nil }
            guard let full = Range(m.range, in: text) else { return nil }
            return Detection(range: m.range, value: String(text[full]), category: .person)
        }
    }

    /// NUR Profil 'streng': ALLE Ketten aus 2 grossgeschriebenen Woertern — ausser sie
    /// beginnen mit einem Funktionswort. Bewusst falsch-positiv-freudig (Privatsphaere
    /// vor Praezision); der Dichte-Waechter macht die Kosten sichtbar.
    private static func chainPersons(in text: String) -> [Detection] {
        let ns = NSRange(text.startIndex..., in: text)
        return namePairRegex.matches(in: text, range: ns).compactMap { m in
            guard let first = Range(m.range(at: 1), in: text) else { return nil }
            guard !chainStopwords.contains(text[first].lowercased()) else { return nil }
            guard let second = Range(m.range(at: 2), in: text) else { return nil }
            let surname = text[second].lowercased()
            guard !corporateSuffixes.contains(surname), !surnameStopwords.contains(surname),
                  !chainStopwords.contains(surname) else { return nil }
            guard let full = Range(m.range, in: text) else { return nil }
            return Detection(range: m.range, value: String(text[full]), category: .person)
        }
    }

    /// Funktionswoerter/Satzanfaenge, die im streng-Modus KEINE Namens-Kette einleiten.
    private static let chainStopwords: Set<String> = [
        "der", "die", "das", "den", "dem", "des", "ein", "eine", "einer", "einem",
        "einen", "eines", "im", "am", "um", "beim", "vom", "zum", "zur", "nach",
        "vor", "mit", "ohne", "und", "oder", "aber", "wenn", "dann", "als", "auch",
        "auf", "aus", "bei", "bis", "durch", "für", "gegen", "in", "über", "unter",
        "während", "wegen", "zwischen", "sehr", "neue", "neuer", "neues", "alle",
        "viele", "diese", "dieser", "dieses", "jene", "kein", "keine", "mein",
        "meine", "sein", "seine", "ihr", "ihre", "unser", "unsere", "the", "a", "an",
    ]

    // MARK: - Muster

    /// Erkennt ausgelieferte Tokens (fuer den Dichte-Waechter).
    private static let tokenRegex = try! NSRegularExpression(
        pattern: #"\[(?:Person|Mail|Tel|IBAN|Adresse|Ort|Begriff)-\d+\]"#)

    private static let mailRegex = try! NSRegularExpression(
        pattern: #"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"#)

    /// Case-insensitiv: auch "de22..." ist eine IBAN.
    private static let ibanRegex = try! NSRegularExpression(
        pattern: #"\b[A-Z]{2}\d{2}(?:\s?[A-Z0-9]{4}){2,7}(?:\s?[A-Z0-9]{1,4})?\b"#,
        options: [.caseInsensitive])

    /// +49 170 1234567 · 0170/1234567 · (030) 123456 — Punkte bewusst KEIN Trenner,
    /// damit Datumsangaben (01.02.2026) nie matchen. Ziffern-Minimum prueft der Filter.
    private static let phoneRegex = try! NSRegularExpression(
        pattern: #"(?<![\d.])(?:\+\d{1,3}[\s/-]?(?:\(0\)[\s/-]?)?\d{2,4}|\(0\d{1,4}\)|0\d{1,4})(?:[\s/-]?\d{2,}){1,4}\b"#)

    /// Hauptstrasse 5 · Bahnhofstr. 5 · Berliner Strasse 12a — Kompositum ODER Zwei-Wort-Form.
    private static let streetRegex = try! NSRegularExpression(
        pattern: #"\b(?:\p{Lu}[\p{L}-]*(?:straße|strasse|str\.|weg|allee|platz|gasse|ring|damm|ufer)|\p{Lu}[\p{L}-]+\s+(?:Straße|Strasse|Str\.|Weg|Allee|Platz|Gasse|Ring|Damm|Ufer))\s+\d+\s?[a-z]?\b"#)

    /// OHNE den Lookahead wuerde jede 5-stellige Zahl vor einem grossgeschriebenen
    /// Wort maskiert — 'Streitwert 50000 Euro' wurde zu [Ort-1]. Betraege und
    /// Einheiten bleiben Klartext.
    private static let plzCityRegex = try! NSRegularExpression(
        pattern: #"\b\d{5}\s+(?!(?:Euro\b|EUR\b|CHF\b|USD\b|GBP\b|Dollar\b|Cent\b|Prozent\b|Punkte?\b|Stück\b|Seiten\b|Zeilen\b|Zeichen\b|Mitarbeiter\b|Einwohner\b|Kilometer\b|Meter\b|Tonnen\b|Kilo\b))\p{Lu}[\p{L}-]+\b"#)

    /// Anreden/Titel (wiederholbar: 'Frau Dr.'), danach 1-3 grossgeschriebene Namensteile.
    private static let honorificRegex = try! NSRegularExpression(
        pattern: #"\b(?:(?:Herrn?|Frau|Dr\.|Prof\.|RAin|RA|Rechtsanwältin|Rechtsanwalt|Mandantin|Mandant|Kollegin|Kollege|Richterin|Richter|Notarin|Notar|StB|WP)\s+)+(\p{Lu}[\p{L}'-]+(?:\s\p{Lu}[\p{L}'-]+){0,2})"#)

    private static let namePairRegex = try! NSRegularExpression(
        pattern: #"\b(\p{Lu}[\p{L}'-]+)\s(\p{Lu}[\p{L}'-]+)\b"#)

    /// Haeufige Vornamen (DE + international) fuer den Lexikon-Trigger. Bewusst als
    /// Positiv-Liste: lieber einen exotischen Namen verpassen (der Anrede-Trigger
    /// faengt ihn meist) als deutsche Substantive fluten.
    static let firstNames: Set<String> = [
        "alexander", "andrea", "andreas", "angelika", "anna", "anne", "anton", "antje",
        "ayse", "barbara", "bernd", "birgit", "brigitte", "carlos", "carsten", "charlotte",
        "christa", "christian", "christina", "christine", "christoph", "clara", "claudia",
        "dagmar", "daniel", "daniela", "david", "dennis", "dieter", "dirk", "dmitri",
        "elias", "elisabeth", "emil", "emma", "erika", "ernst", "eva", "fatima", "felix",
        "finn", "florian", "francesca", "frank", "friedrich", "gabriele", "gerhard",
        "gisela", "giovanni", "hannah", "hans", "heike", "heinrich", "helga", "helmut",
        "henry", "hildegard", "horst", "ingo", "ingrid", "ivan", "jakob", "james", "jan",
        "jana", "jean", "jennifer", "jens", "joachim", "johanna", "john", "jonas", "jose",
        "josef", "joseph", "julia", "juergen", "jürgen", "jörg", "karin", "karl",
        "katharina", "katja", "kerstin", "kevin", "klaus", "kurt", "lars", "laura", "lea",
        "lena", "leon", "leonie", "linda", "lisa", "luis", "luigi", "lukas", "manfred",
        "manuela", "marcel", "maria", "marie", "mario", "markus", "martin", "martina",
        "mary", "matthias", "max", "mehmet", "melanie", "mia", "michael", "michaela",
        "mohammed", "monika", "moritz", "mustafa", "nadine", "natalia", "nele", "nicole",
        "nils", "noah", "norbert", "olaf", "olga", "oliver", "oskar", "otto", "pablo",
        "patrick", "paul", "peter", "petra", "philipp", "pierre", "rainer", "ralf",
        "renate", "richard", "robert", "rolf", "sabine", "sandra", "sarah", "sebastian",
        "silke", "simon", "sophia", "sophie", "stefan", "stefanie", "stephanie", "susan",
        "susanne", "sven", "tanja", "theo", "thomas", "tim", "tobias", "torsten", "ursula",
        "ute", "uwe", "volker", "walter", "werner", "william", "wilhelm", "wolfgang",
    ]
}
