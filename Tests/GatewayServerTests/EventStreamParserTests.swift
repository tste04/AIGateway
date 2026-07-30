// Copyright (c) 2026 Tommy Stellmacher
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

import XCTest
@testable import GatewayServer

// MARK: - EventStreamParser: Chunk-Grenzen zerstoeren keine Zeichen (M2)
//
// Die Zeilen-Pufferung ueber Chunk-Grenzen ist bereits in
// GatewayServerTests.EventStreamParserTests belegt. Hier steht der Fall, der
// vorher fehlschlug: eine Mehrbyte-UTF-8-Sequenz, die MITTEN zwischen ihren
// Bytes zerschnitten wird, darf nicht durch U+FFFD ersetzt werden. Fuer
// deutschsprachigen Inhalt realistisch — URLSession schneidet an beliebigen
// TCP-Grenzen.

final class EventStreamParserUTF8Tests: XCTestCase {

    func testMultibyteCharSplitAcrossChunksIsNotCorrupted() {
        var parser = EventStreamParser(framing: .newlineDelimitedJSON)

        // Zeile: {"m":"gruen"} mit echtem ue = U+00FC (0xC3 0xBC), plus \n.
        var line = Data(#"{"m":"gr"#.utf8)
        line.append(contentsOf: [0xC3, 0xBC] as [UInt8])   // ue
        line.append(Data(#"n"}"#.utf8))
        line.append(0x0A)

        // Schnitt MITTEN in der ue-Sequenz — zwischen 0xC3 und 0xBC.
        let cut = #"{"m":"gr"#.utf8.count + 1
        let first = parser.consume(line.prefix(cut))
        let second = parser.consume(line.suffix(from: line.index(line.startIndex, offsetBy: cut)))

        XCTAssertEqual(first, [], "vor der Zeilengrenze wird nichts geliefert")
        XCTAssertEqual(second, [#"{"m":"grün"}"#])
        XCTAssertFalse((second.first ?? "").contains("\u{FFFD}"),
                       "kein Ersetzungszeichen — die Sequenz blieb im Byte-Puffer")
    }
}
