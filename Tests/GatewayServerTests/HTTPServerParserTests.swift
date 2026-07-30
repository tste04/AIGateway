// Copyright (c) 2026 Tommy Stellmacher
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

import XCTest
@testable import GatewayServer
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

// MARK: - Loopback-Client fuer Socket-Tests
//
// Der HTTP-Parser und die Haertungspfade (413, Query-Strip, malformte
// Request-Line) sind reine Byte-Logik mit mehreren Zweigen und liefen bisher
// ungeprueft: die Service-Tests bauen `HTTPRequest` direkt und umgehen den
// Parser. Diese Tests fahren echte Sockets und nageln das Verhalten fest,
// bevor der Slowloris-Fix (M8) und die 400-Ablehnung (Transfer-Encoding) es
// anfassen.

enum LoopbackClient {

    /// Verbindet auf 127.0.0.1:port. `-1` bei Fehlschlag.
    static func connect(_ port: UInt16) -> Int32 {
        #if canImport(Darwin)
        let fd = socket(AF_INET, SOCK_STREAM, 0)
        #else
        let fd = socket(AF_INET, Int32(SOCK_STREAM.rawValue), 0)
        #endif
        guard fd >= 0 else { return -1 }
        var addr = sockaddr_in()
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = port.bigEndian
        addr.sin_addr = in_addr(s_addr: inet_addr("127.0.0.1"))
        let ok = withUnsafePointer(to: &addr) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa -> Int32 in
                #if canImport(Darwin)
                return Darwin.connect(fd, sa, socklen_t(MemoryLayout<sockaddr_in>.size))
                #else
                return Glibc.connect(fd, sa, socklen_t(MemoryLayout<sockaddr_in>.size))
                #endif
            }
        }
        guard ok == 0 else { close(fd); return -1 }
        return fd
    }

    static func send(_ fd: Int32, _ text: String) {
        _ = text.withCString { write(fd, $0, strlen($0)) }
    }

    /// Liest bis zum Verbindungsschluss (der Server sendet `Connection: close`).
    static func readAll(_ fd: Int32) -> String {
        var buffer = [UInt8](repeating: 0, count: 4096)
        var received = Data()
        while true {
            let n = read(fd, &buffer, buffer.count)
            guard n > 0 else { break }
            received.append(contentsOf: buffer[0..<n])
        }
        return String(data: received, encoding: .utf8) ?? ""
    }

    /// Startet einen Server auf einem freien Port und gibt (Server, Port).
    static func serve(maxBodyBytes: Int = 1_000_000,
                      handler: @escaping HTTPServer.Handler) throws -> (HTTPServer, UInt16) {
        var lastError: Error = GatewayServerError.unsupported("no port tried")
        for _ in 0..<20 {
            let port = UInt16.random(in: 29_000...59_000)
            let server = HTTPServer(port: port, maxBodyBytes: maxBodyBytes, handler: handler)
            do { try server.start(); return (server, port) } catch { lastError = error }
        }
        throw lastError
    }
}

/// Faengt die geparste Anfrage ein, damit Tests pruefen koennen, was der Parser
/// an den Handler gereicht hat.
private final class ParsedBox: @unchecked Sendable {
    private let lock = NSLock()
    private var value: HTTPRequest?
    func set(_ r: HTTPRequest) { lock.lock(); defer { lock.unlock() }; value = r }
    func get() -> HTTPRequest? { lock.lock(); defer { lock.unlock() }; return value }
}

final class HTTPServerParserTests: XCTestCase {

    func testMalformedRequestLineGets400AndDoesNotReachHandler() throws {
        let box = ParsedBox()
        let (server, port) = try LoopbackClient.serve { request, conn in
            box.set(request)
            conn.respond(status: 200, json: ["ok": true])
        }
        defer { server.stop() }

        let fd = LoopbackClient.connect(port)
        XCTAssertGreaterThanOrEqual(fd, 0)
        LoopbackClient.send(fd, "GARBAGE\r\n\r\n")
        let response = LoopbackClient.readAll(fd)
        close(fd)

        XCTAssertTrue(response.contains("400"), "Antwort war: \(response)")
        XCTAssertNil(box.get(), "eine kaputte Request-Line darf den Handler nicht erreichen")
    }

    func testOversizedBodyGets413BeforeReachingHandler() throws {
        let box = ParsedBox()
        let (server, port) = try LoopbackClient.serve(maxBodyBytes: 64) { request, conn in
            box.set(request)
            conn.respond(status: 200, json: ["ok": true])
        }
        defer { server.stop() }

        let fd = LoopbackClient.connect(port)
        XCTAssertGreaterThanOrEqual(fd, 0)
        // Angekuendigte Groesse ueber der Grenze — das ist der Fallstrick, der
        // im Server extra kommentiert ist: gegen Content-Length pruefen, nicht
        // nur gegen das bereits Gelesene.
        let body = String(repeating: "x", count: 200)
        LoopbackClient.send(fd, "POST /v1/chat/completions HTTP/1.1\r\nHost: x\r\n"
            + "Content-Length: 200\r\n\r\n\(body)")
        let response = LoopbackClient.readAll(fd)
        close(fd)

        XCTAssertTrue(response.contains("413"), "Antwort war: \(response)")
        XCTAssertNil(box.get(), "ein zu grosser Rumpf darf den Handler nicht erreichen")
    }

    func testQueryStringIsStrippedFromPath() throws {
        let box = ParsedBox()
        let (server, port) = try LoopbackClient.serve { request, conn in
            box.set(request)
            conn.respond(status: 200, json: ["ok": true])
        }
        defer { server.stop() }

        let fd = LoopbackClient.connect(port)
        XCTAssertGreaterThanOrEqual(fd, 0)
        LoopbackClient.send(fd, "POST /v1/chat/completions?model=x&debug=1 HTTP/1.1\r\n"
            + "Host: x\r\nContent-Length: 0\r\n\r\n")
        _ = LoopbackClient.readAll(fd)
        close(fd)

        XCTAssertEqual(box.get()?.path, "/v1/chat/completions",
                       "der Query-String muss vor dem Routing entfernt sein")
    }

    func testHeaderNamesAreCaseInsensitive() throws {
        let box = ParsedBox()
        let (server, port) = try LoopbackClient.serve { request, conn in
            box.set(request)
            conn.respond(status: 200, json: ["ok": true])
        }
        defer { server.stop() }

        let fd = LoopbackClient.connect(port)
        XCTAssertGreaterThanOrEqual(fd, 0)
        // Gross-/Kleinschreibung gemischt: der Parser faltet auf lowercase.
        LoopbackClient.send(fd, "POST /x HTTP/1.1\r\nHOST: y\r\nContent-LENGTH: 3\r\n\r\nabc")
        _ = LoopbackClient.readAll(fd)
        close(fd)

        XCTAssertEqual(box.get()?.header("content-length"), "3")
        XCTAssertEqual(box.get()?.header("Content-Length"), "3", "header(_:) faltet selbst")
        XCTAssertEqual(box.get()?.body.count, 3)
    }
}
