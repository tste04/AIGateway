// Copyright (c) 2026 Tommy Stellmacher
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

import Foundation
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

// MARK: - Tresor
//
// Klarwert <-> Token, als 0600-JSON-Datei. Tokens sind stabil ueber Neustarts:
// dieselbe Person bekommt immer dasselbe Token. Das haelt Antworten kohaerent
// und erhoeht die Cache-Trefferquote.
//
// MEHRMANDANTEN-REGEL (wichtig): Ein Vault gehoert GENAU EINER Partition.
// Zwei Mandanten duerfen sich keinen Vault teilen — sonst laufen ihre
// Token-Raeume ineinander. Pfad ueber `PseudonymVault.url(baseDirectory:partition:)`
// bilden, Partition aus `Principal.cachePartition` bzw. dem Mandanten.

public actor PseudonymVault {

    struct Entry: Codable {
        let token: String
        let value: String      // Anzeige-/Erstwert
        let canonical: String  // normalisierter Schluessel ("person|anna schmidt")
        let category: String
    }

    private var entries: [Entry] = []
    private var canonicalToToken: [String: String] = [:]
    private var tokenToValue: [String: String] = [:]
    private var counters: [String: Int] = [:]
    private let fileURL: URL?
    private let onWarning: (@Sendable (String) -> Void)?

    /// - Parameters:
    ///   - fileURL: Ablage (0600). `nil` = nur In-Memory (Tests, zustandslose Knoten).
    ///   - onWarning: Diagnose-Senke. Bewusst injiziert statt fest verdrahtet —
    ///     der Kern soll kein Logging-Framework kennen.
    public init(fileURL: URL?, onWarning: (@Sendable (String) -> Void)? = nil) {
        self.fileURL = fileURL
        self.onWarning = onWarning
        reloadAndMerge()
    }

    /// Pfad eines partitionsgebundenen Vaults. Die Partition wird dateisystem-sicher
    /// kodiert, damit Mandanten-/Scope-Strings keine Pfad-Tricks erlauben.
    public static func url(baseDirectory: URL, partition: String) -> URL {
        let safe = partition.unicodeScalars.map { s -> String in
            let ok = CharacterSet.alphanumerics.contains(s) || s == "-" || s == "_"
            return ok ? String(s) : String(format: "%%%02X", s.value)
        }.joined()
        return baseDirectory.appendingPathComponent("pseudonyms-\(safe.isEmpty ? "default" : safe).json")
    }

    /// Liest die Datei (neu) ein und vereinigt sie mit dem In-Memory-Zustand.
    /// Mehrere Prozesse koennen auf derselben Datei arbeiten — vor jedem Praegen
    /// wird unter File-Lock neu geladen, damit Zaehler und Zuordnungen stimmen.
    /// Eine NICHT dekodierbare Datei wird beiseitegelegt statt still als leer
    /// behandelt — sonst spraengen Zaehler zurueck und Tokens wuerden fuer FREMDE
    /// Personen wiederverwendet.
    private func reloadAndMerge() {
        guard let fileURL, let data = try? Data(contentsOf: fileURL) else { return }
        guard let stored = try? JSONDecoder().decode([Entry].self, from: data) else {
            let aside = fileURL.appendingPathExtension("corrupt")
            try? FileManager.default.removeItem(at: aside)
            try? FileManager.default.moveItem(at: fileURL, to: aside)
            onWarning?("vault file unreadable, moved aside to \(aside.lastPathComponent); counters restart, verify old mappings manually")
            return
        }
        for e in stored where canonicalToToken[e.canonical] == nil {
            entries.append(e)
            canonicalToToken[e.canonical] = e.token
            if tokenToValue[e.token] == nil, !e.value.isEmpty { tokenToValue[e.token] = e.value }
        }
        // Zaehler aus dem hoechsten vergebenen Suffix rekonstruieren ("[Person-12]").
        for e in entries {
            let body = e.token.dropFirst().dropLast()
            let parts = body.split(separator: "-", maxSplits: 1)
            if parts.count == 2, let n = Int(parts[1]) {
                let prefix = String(parts[0])
                counters[prefix] = max(counters[prefix] ?? 0, n)
            }
        }
    }

    /// Exklusiver Datei-Lock um Reload+Mint+Save — verhindert Last-Writer-Wins und
    /// doppelt vergebene Token-Nummern zwischen parallelen Prozessen.
    private func withFileLock<T>(_ body: () -> T) -> T {
        guard let fileURL else { return body() }
        // Verzeichnis VOR dem Lock anlegen — sonst liefe der allererste Mint ungelockt.
        try? FileManager.default.createDirectory(
            at: fileURL.deletingLastPathComponent(), withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700])
        let lockPath = fileURL.path + ".lock"
        let fd = open(lockPath, O_CREAT | O_RDWR, 0o600)
        guard fd >= 0 else { return body() }
        defer { close(fd) }
        _ = flock(fd, LOCK_EX)
        defer { _ = flock(fd, LOCK_UN) }
        return body()
    }

    /// Liefert das stabile Token fuer einen Klarwert — legt bei Bedarf ein neues an.
    func token(for value: String, canonical: String, category: PseudonymCategory,
               aliasCanonicals: [String] = []) -> String {
        if let existing = canonicalToToken[canonical] {
            registerAliases(aliasCanonicals, token: existing, category: category)
            return existing
        }
        return withFileLock {
            reloadAndMerge()
            if let existing = canonicalToToken[canonical] {
                registerAliases(aliasCanonicals, token: existing, category: category)
                return existing
            }
            let next = (counters[category.tokenPrefix] ?? 0) + 1
            counters[category.tokenPrefix] = next
            let token = "[\(category.tokenPrefix)-\(next)]"
            append(Entry(token: token, value: value, canonical: canonical, category: category.rawValue))
            registerAliases(aliasCanonicals, token: token, category: category)
            save()
            return token
        }
    }

    /// Bestehende Personen-Zuordnung fuer einen Nachnamen — mit dem Wissen, ob sie
    /// von einer BLOSSEN Nachnamens-Nennung stammt oder von einem vollen Namen.
    /// Namensvettern-Schutz: "Bernd Schmidt" darf NICHT auf das Token von
    /// "Anna Schmidt" verschmolzen werden.
    func personLink(forSurname surname: String) -> (token: String, isBareSurname: Bool)? {
        let s = surname.lowercased()
        let prefix = PseudonymCategory.person.rawValue + "|"
        var fullMatch: String?
        for e in entries where e.category == PseudonymCategory.person.rawValue {
            let name = e.canonical.hasPrefix(prefix) ? String(e.canonical.dropFirst(prefix.count)) : e.canonical
            if name == s {
                // Echte Bloss-Nennung ('Frau Schmidt' zuerst gesehen) traegt einen Wert;
                // ein von 'Anna Schmidt' ABGELEITETER Nachnamen-Alias ist wertlos
                // (value "") und zaehlt wie der volle Name — sonst verschmilzt
                // 'Bernd Schmidt' doch.
                if e.value.isEmpty { fullMatch = fullMatch ?? e.token; continue }
                return (e.token, true)
            }
            if name.hasSuffix(" " + s), fullMatch == nil { fullMatch = e.token }
        }
        if let fullMatch { return (fullMatch, false) }
        return nil
    }

    /// Sucht ein bestehendes Personen-Token, dessen kanonischer Name auf diesen
    /// Nachnamen endet (Verkettung 'Frau Schmidt' <-> 'Anna Schmidt').
    func personToken(forSurname surname: String) -> String? {
        let s = surname.lowercased()
        let prefix = PseudonymCategory.person.rawValue + "|"
        for e in entries where e.category == PseudonymCategory.person.rawValue {
            let name = e.canonical.hasPrefix(prefix) ? String(e.canonical.dropFirst(prefix.count)) : e.canonical
            if name == s || name.hasSuffix(" " + s) { return e.token }
        }
        return nil
    }

    /// Registriert einen weiteren Schluessel fuer ein BESTEHENDES Token —
    /// Nachnamen-Verkettung, ohne ein neues Token zu praegen.
    func registerAlias(canonical: String, value: String, token: String, category: PseudonymCategory) {
        guard canonicalToToken[canonical] == nil else { return }
        withFileLock {
            reloadAndMerge()
            guard canonicalToToken[canonical] == nil else { return }
            canonicalToToken[canonical] = token
            entries.append(Entry(token: token, value: value, canonical: canonical, category: category.rawValue))
            if tokenToValue[token] == nil, !value.isEmpty { tokenToValue[token] = value }
            save()
        }
    }

    /// Rueckuebersetzung aus dem Vault-Wissen (Tokens UND Alias-Formen).
    /// Fuer den Antwortpfad ist `MaskingSession.unmask` vorzuziehen — die traegt
    /// exakt die Zuordnung DIESER Anfrage.
    func restore(_ text: String) -> String {
        guard !text.isEmpty, !tokenToValue.isEmpty else { return text }
        // Alle Suchformen (Token UND Alias-Name) einsammeln und LAENGSTE zuerst
        // ersetzen — genau wie `MaskingSession.unmask`. Sonst zerlegt eine
        // kuerzere Form eine laengere: `[Person-1]` ist ein Praefix von
        // `[Person-10]`, und der Alias `Alex A.` ist einer von `Alex A.1`. Die
        // Reihenfolge darf NICHT von der Dictionary-Iteration abhaengen — Swift
        // wuerfelt den Hash-Seed je Prozess, sonst waere die Ersetzung ein
        // Muenzwurf (genau die Fehlerklasse, vor der CONTRIBUTING.md warnt).
        var forms: [(search: String, value: String)] = []
        for (token, value) in tokenToValue {
            forms.append((token, value))
            if let alias = Pseudonymizer.aliasName(forToken: token) {
                forms.append((alias, value))
            }
        }
        var out = text
        for form in forms.sorted(by: { $0.search.count > $1.search.count }) {
            out = out.replacingOccurrences(of: form.search, with: form.value)
        }
        return out
    }

    /// Anzeige-Klarwert eines Tokens. Basis fuer die Rueckuebersetzung.
    func value(forToken token: String) -> String? { tokenToValue[token] }

    /// Alle bekannten Personen-Klarnamen mit ihrem Token — fuer den
    /// Nachschlag-Durchgang: einmal gelernte Namen werden ueberall ersetzt.
    func personNames() -> [(name: String, token: String)] {
        let prefix = PseudonymCategory.person.rawValue + "|"
        return entries.compactMap { e in
            guard e.category == PseudonymCategory.person.rawValue,
                  e.canonical.hasPrefix(prefix) else { return nil }
            let name = String(e.canonical.dropFirst(prefix.count))
            return name.isEmpty ? nil : (name: name, token: e.token)
        }
    }

    /// Alle Zuordnungen — lokal, Klartext, gewollt (Betreiber-Einsicht).
    public func allEntries() -> [(token: String, value: String, category: String)] {
        var seen = Set<String>()
        var out: [(token: String, value: String, category: String)] = []
        for e in entries where !e.value.isEmpty && seen.insert(e.token).inserted {
            out.append((token: e.token, value: e.value, category: e.category))
        }
        return out
    }

    private func registerAliases(_ canonicals: [String], token: String, category: PseudonymCategory) {
        var changed = false
        for c in canonicals where canonicalToToken[c] == nil {
            canonicalToToken[c] = token
            entries.append(Entry(token: token, value: "", canonical: c, category: category.rawValue))
            changed = true
        }
        if changed { save() }
    }

    private func append(_ e: Entry) {
        entries.append(e)
        canonicalToToken[e.canonical] = e.token
        if tokenToValue[e.token] == nil, !e.value.isEmpty { tokenToValue[e.token] = e.value }
    }

    private func save() {
        guard let fileURL else { return }
        let dir = fileURL.deletingLastPathComponent()
        try? FileManager.default.createDirectory(
            at: dir, withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700])
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        guard let data = try? encoder.encode(entries) else {
            onWarning?("vault mapping not encodable — mapping is NOT persisted")
            return
        }
        // Crash-sicher: erst 0600-Tempdatei, dann POSIX-rename(2) — atomar, ersetzt
        // bestehende Ziele und verhaelt sich auf macOS UND Linux gleich.
        // (FileManager.replaceItemAt ist auf corelibs-foundation unzuverlaessig und
        // kann im Fehlerfall sogar die ZIELDATEI entfernen.)
        let tmp = fileURL.deletingLastPathComponent()
            .appendingPathComponent(fileURL.lastPathComponent + ".tmp")
        try? FileManager.default.removeItem(at: tmp)
        guard FileManager.default.createFile(atPath: tmp.path, contents: data,
                                             attributes: [.posixPermissions: 0o600]),
              rename(tmp.path, fileURL.path) == 0 else {
            onWarning?("vault file not writable (errno \(errno)) — mapping only in memory")
            return
        }
    }
}
