// Copyright (c) 2026 Tommy Stellmacher
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

import XCTest
@testable import GatewayServer

// MARK: - EventStreamParser: Chunk-Grenzen zerstoeren keine Zeichen
//
// Der Parser puffert auf Bytes, damit eine Mehrbyte-UTF-8-Sequenz, die ueber
// zwei Netz-Chunks zerfaellt, nicht durch U+FFFD ersetzt wird. Fuer
// deutschsprachigen Inhalt ist der Fall realistisch: URLSession schneidet an
// beliebigen TCP-Grenzen.

final class EventStreamParserTests: XCTestCase {

    func testMultibyteCharSplitAcrossChunksIsNotCorrupted() {
        var parser = EventStreamParser(framing: .newlineDelimitedJSON)

        // Zeile: {"m":"gruen"} mit echtem ue = U+00FC (0xC3 0xBC), plus \n.
        var line = Data(#"{"m":"gr"#.utf8)
        let ue: [UInt8] = [0xC3, 0xBC]   // ue
        line.append(contentsOf: ue)
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

    func testMultipleLinesInOneChunk() {
        var parser = EventStreamParser(framing: .newlineDelimitedJSON)
        let payloads = parser.consume(Data("a\nb\nc\n".utf8))
        XCTAssertEqual(payloads, ["a", "b", "c"])
    }

    func testSSEOnlyDataLinesCarryPayload() {
        var parser = EventStreamParser(framing: .serverSentEvents)
        let payloads = parser.consume(Data("event: ping\ndata: hallo\nid: 7\n".utf8))
        XCTAssertEqual(payloads, ["hallo"])
    }

    func testIncompleteTrailingLineIsHeldUntilNewline() {
        var parser = EventStreamParser(framing: .newlineDelimitedJSON)
        XCTAssertEqual(parser.consume(Data("teil".utf8)), [])
        XCTAssertEqual(parser.consume(Data("weise\n".utf8)), ["teilweise"])
    }
}
