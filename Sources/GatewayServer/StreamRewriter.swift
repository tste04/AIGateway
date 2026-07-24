// Copyright (c) 2026 Tommy Stellmacher
// SPDX-License-Identifier: Apache-2.0

import Foundation
import InputFirewall

// MARK: - De-Maskierung im Datenstrom
//
// Das Problem, das jede streamende Gateway-Implementierung trifft: Ein
// Platzhalter kommt zerteilt an.
//
//   Chunk 1: "Ich habe [Pers"
//   Chunk 2: "on-1] notiert."
//
// Wer jeden Chunk einzeln zurueckuebersetzt, findet in keinem der beiden den
// vollstaendigen Platzhalter — er wandert unuebersetzt zum Nutzer. Deshalb
// haelt der Rewriter ein Stueck Text zurueck, bis feststeht, dass es kein
// angefangener Platzhalter mehr sein kann.
//
// Zurueckgehalten wird nur, was tatsaechlich der Anfang eines bekannten
// Platzhalters sein KOENNTE (Praefix-Pruefung). Auf normalem Text fliesst
// dadurch alles ohne Verzoegerung durch — die Latenz-Kosten entstehen nur
// unmittelbar an einer Platzhalter-Grenze.

public struct StreamRewriter {

    private let session: MaskingSession
    /// Alle echten Praefixe aller Ersatzformen. Einmal gebaut, dann O(1)-Pruefung.
    private let prefixes: Set<String>
    private let maxKeyLength: Int
    private var buffer = ""

    public init(session: MaskingSession) {
        self.session = session
        var prefixes = Set<String>()
        var maxLength = 0
        for key in session.mapping.keys {
            maxLength = max(maxLength, key.count)
            var partial = ""
            // Nur ECHTE Praefixe: der vollstaendige Schluessel wird sofort
            // ersetzt und muss nicht zurueckgehalten werden.
            for ch in key.dropLast() {
                partial.append(ch)
                prefixes.insert(partial)
            }
        }
        self.prefixes = prefixes
        self.maxKeyLength = maxLength
    }

    /// Ist ueberhaupt nichts zu ersetzen, arbeitet der Rewriter als Durchreiche
    /// ohne jede Pufferung.
    public var isPassthrough: Bool { session.isEmpty }

    /// Nimmt ein Bruchstueck entgegen und gibt zurueck, was sicher ausgeliefert
    /// werden kann — bereits zurueckuebersetzt.
    public mutating func push(_ chunk: String) -> String {
        guard !isPassthrough else { return chunk }
        buffer += chunk

        let holdback = pendingPrefixLength()
        guard holdback < buffer.count else { return "" }

        let splitIndex = buffer.index(buffer.endIndex, offsetBy: -holdback)
        let emittable = String(buffer[..<splitIndex])
        buffer = String(buffer[splitIndex...])
        return session.unmask(emittable)
    }

    /// Gibt den Rest frei. Nach dem Ende des Stroms kann nichts mehr folgen,
    /// also darf auch ein angefangener Platzhalter raus — er war keiner.
    public mutating func flush() -> String {
        guard !buffer.isEmpty else { return "" }
        let rest = session.unmask(buffer)
        buffer = ""
        return rest
    }

    /// Laenge des Endstuecks, das der Anfang eines Platzhalters sein koennte.
    private func pendingPrefixLength() -> Int {
        guard maxKeyLength > 1 else { return 0 }
        let limit = min(maxKeyLength - 1, buffer.count)
        guard limit > 0 else { return 0 }
        // Vom laengsten moeglichen Anfang abwaerts: der erste Treffer ist der
        // sichere Rueckhalt.
        for length in stride(from: limit, through: 1, by: -1) {
            let suffix = String(buffer.suffix(length))
            if prefixes.contains(suffix) { return length }
        }
        return 0
    }
}
