// Copyright (c) 2026 Tommy Stellmacher
// SPDX-License-Identifier: Apache-2.0

import XCTest
@testable import GatewayServer
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

// MARK: - Geordneter Stopp
//
// Die einzigen Tests, die einen echten Socket anfassen. Sie existieren, weil
// `stop(drainSeconds:)` sonst nur ueber sein Konfigurationsfeld geprueft
// waere — und der Abschaltpfad ist genau die Sorte Code, die im Betrieb zum
// ersten Mal laeuft, wenn es darauf ankommt.

final class ShutdownTests: XCTestCase {

    /// Startet den Server auf irgendeinem freien Port. Feste Ports kollidieren
    /// auf geteilten CI-Maschinen; deshalb wird probiert statt behauptet.
    private func startServer(handler: @escaping HTTPServer.Handler) throws -> (HTTPServer, UInt16) {
        var lastError: Error = GatewayServerError.unsupported("no port tried")
        for _ in 0..<20 {
            let port = UInt16.random(in: 29_000...59_000)
            let server = HTTPServer(port: port, handler: handler)
            do {
                try server.start()
                return (server, port)
            } catch {
                lastError = error
            }
        }
        throw lastError
    }

    /// Roher TCP-Client — URLSession wuerde die Verbindung selbst verwalten,
    /// und hier geht es gerade darum, sie halb offen zu halten.
    private func connect(_ port: UInt16) -> Int32 {
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
        // Voller Modulname: die Testmethode heisst selbst `connect`.
        let connected = withUnsafePointer(to: &addr) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa -> Int32 in
                #if canImport(Darwin)
                return Darwin.connect(fd, sa, socklen_t(MemoryLayout<sockaddr_in>.size))
                #else
                return Glibc.connect(fd, sa, socklen_t(MemoryLayout<sockaddr_in>.size))
                #endif
            }
        }
        guard connected == 0 else { close(fd); return -1 }
        return fd
    }

    private func send(_ fd: Int32, _ text: String) {
        _ = text.withCString { cstr in
            write(fd, cstr, strlen(cstr))
        }
    }

    func testStopWaitsForARunningRequestAndReportsClean() throws {
        // Eine Anfrage, deren Bearbeitung dauert — wie ein Upstream-Aufruf.
        let (server, port) = try startServer { _, connection in
            try? await Task.sleep(nanoseconds: 300_000_000)
            connection.respond(status: 200, json: ["ok": true])
        }

        let client = connect(port)
        XCTAssertGreaterThanOrEqual(client, 0)
        send(client, "GET /healthz HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n")
        // Der Anfrage Zeit geben, im Handler anzukommen.
        Thread.sleep(forTimeInterval: 0.1)

        let drained = server.stop(drainSeconds: 5)
        XCTAssertTrue(drained, "die laufende Anfrage muss zu Ende gekommen sein")

        // Die Antwort ist trotz Stopp vollstaendig angekommen — genau der
        // Punkt des Austrinkens: der bereits bezahlte Aufruf wird ausgeliefert.
        var buffer = [UInt8](repeating: 0, count: 4096)
        var received = Data()
        while true {
            let n = read(client, &buffer, buffer.count)
            guard n > 0 else { break }
            received.append(contentsOf: buffer[0..<n])
        }
        close(client)
        let text = String(data: received, encoding: .utf8) ?? ""
        XCTAssertTrue(text.contains("200"), "Antwort war: \(text)")
    }

    func testStopReportsFalseWhenTheDeadlinePasses() throws {
        let (server, port) = try startServer { _, connection in
            connection.respond(status: 200, json: ["ok": true])
        }

        // Eine Verbindung, die nie einen Rumpf sendet: `serve` haengt im Lesen,
        // die Verbindung zaehlt als aktiv.
        let client = connect(port)
        XCTAssertGreaterThanOrEqual(client, 0)
        send(client, "GET /healthz HTTP/1.1\r\n")
        Thread.sleep(forTimeInterval: 0.15)
        XCTAssertEqual(server.activeConnectionCount(), 1)

        let drained = server.stop(drainSeconds: 0.3)
        XCTAssertFalse(drained, "die Frist ist gerissen — das darf nicht als sauber gemeldet werden")
        close(client)
    }

    func testNoNewConnectionsAfterStop() throws {
        let (server, port) = try startServer { _, connection in
            connection.respond(status: 200, json: ["ok": true])
        }
        _ = server.stop(drainSeconds: 0)
        // Der Annahme-Socket ist zu; ein neuer Verbindungsversuch scheitert.
        Thread.sleep(forTimeInterval: 0.05)
        XCTAssertEqual(connect(port), -1)
    }
}
