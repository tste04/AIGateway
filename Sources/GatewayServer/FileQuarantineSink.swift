// Copyright (c) 2026 Tommy Stellmacher
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

import Foundation
import GatewayCore

// MARK: - Persistente Quarantaene-Senke
//
// Die Referenz-Senke haelt Vorfaelle im Speicher; ein Neustart leert den
// Beweismittelschrank. Wer den Injection-Katalog an echten Vorfaellen
// nachschaerfen will, braucht sie ueber den Prozess hinaus — und trifft mit
// der Angabe eines Ablageverzeichnisses AUSDRUECKLICH die Entscheidung,
// Inhalt der konfigurierten Stufe auf Platte zu legen. Der Default bleibt
// die Speicher-Senke.
//
// Bauform: EINE Datei je Vorfall, die Ablauffrist steht im Dateinamen
// (`q-<ablauf-ms>-<kennung>.json`). Loeschen heisst damit: Verzeichnis
// lesen, Namen vergleichen, Datei entfernen — keine Datei muss dafuer
// geoeffnet oder umgeschrieben werden. Ein Sammel-Journal (eine Datei pro
// Tag) hielte Eintraege bis zu 24 Stunden ueber ihre Frist hinaus; die
// Frist ist aber laut `QuarantineSink`-Vertrag eine Zusage, keine
// Empfehlung.

public actor FileQuarantineSink: QuarantineSink {

    public struct SetupError: Error, CustomStringConvertible, Sendable {
        public let description: String
    }

    private let directory: URL
    private let encoder: JSONEncoder
    private var failedWrites = 0

    /// Legt das Verzeichnis an und prueft mit einer Schreibprobe, dass es
    /// beschreibbar ist. Fail-closed beim Start: ein Betreiber, der eine
    /// persistente Quarantaene konfiguriert, soll den Fehler sofort sehen —
    /// nicht als stillen Verlust beim ersten Vorfall.
    public init(directory: URL) throws {
        self.directory = directory
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = [.sortedKeys]
        self.encoder = encoder

        do {
            try FileManager.default.createDirectory(
                at: directory, withIntermediateDirectories: true)
        } catch {
            throw SetupError(description:
                "quarantine directory '\(directory.path)' cannot be created: \(error)")
        }
        let probe = directory.appendingPathComponent(".write-probe")
        do {
            try Data("probe".utf8).write(to: probe)
            try FileManager.default.removeItem(at: probe)
        } catch {
            throw SetupError(description:
                "quarantine directory '\(directory.path)' is not writable: \(error)")
        }
    }

    public func store(_ sample: QuarantineSample) async {
        sweep(now: sample.timestamp)
        let expiryMilliseconds = Int(sample.expiresAt.timeIntervalSince1970 * 1000)
        let name = "q-\(expiryMilliseconds)-\(UUID().uuidString).json"
        do {
            let data = try encoder.encode(sample)
            try data.write(to: directory.appendingPathComponent(name), options: .atomic)
        } catch {
            // Der Vertrag laesst `store` nicht werfen; ein Zaehler macht den
            // Verlust wenigstens sichtbar, statt ihn zu verschlucken.
            failedWrites += 1
        }
    }

    /// Wie viele Vorfaelle nicht geschrieben werden konnten.
    public func failedWriteCount() -> Int { failedWrites }

    /// Entfernt abgelaufene Vorfaelle. Laeuft vor jedem `store` mit; ein
    /// Betreiber kann sie zusaetzlich periodisch aufrufen, damit auch eine
    /// stille Instanz ihre Frist haelt. Dateien, deren Name nicht dem Schema
    /// entspricht, werden nie angefasst — loeschen ist hier die gefaehrliche
    /// Richtung, nicht behalten.
    public func sweep(now: Date = Date()) {
        for url in storedFileURLs() {
            guard let expiry = Self.expiry(of: url) else { continue }
            if expiry <= now {
                try? FileManager.default.removeItem(at: url)
            }
        }
    }

    private func storedFileURLs() -> [URL] {
        let contents = (try? FileManager.default.contentsOfDirectory(
            at: directory, includingPropertiesForKeys: nil)) ?? []
        return contents.filter {
            $0.lastPathComponent.hasPrefix("q-") && $0.pathExtension == "json"
        }
    }

    /// Liest die Ablauffrist aus dem Dateinamen `q-<ablauf-ms>-<kennung>.json`.
    private static func expiry(of url: URL) -> Date? {
        let parts = url.lastPathComponent.split(separator: "-", maxSplits: 2)
        guard parts.count == 3, let milliseconds = Double(parts[1]) else { return nil }
        return Date(timeIntervalSince1970: milliseconds / 1000)
    }
}
