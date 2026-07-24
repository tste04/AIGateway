// Copyright (c) 2026 Tommy Stellmacher
// SPDX-License-Identifier: Apache-2.0

import Foundation
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

// MARK: - Minimaler HTTP/1.1-Server auf POSIX-Sockets
//
// Bewusst klein und ohne Abhaengigkeiten. Was er NICHT tut, ist Absicht:
//
// - **Kein TLS.** Ein handgeschriebener TLS-Stack waere das groesste Risiko im
//   ganzen Projekt. Der Server bindet per Default auf Loopback; Terminierung
//   uebernimmt ein Reverse Proxy davor. Wer `loopbackOnly: false` setzt,
//   uebernimmt die Verantwortung fuer die Absicherung davor.
// - **Kein Keep-Alive.** Eine Anfrage je Verbindung, danach schliessen. Spart
//   den halben Zustandsautomaten; der Durchsatz eines Gateways haengt ohnehin
//   am Modell, nicht am Socket.
// - **Kein chunked Request-Body.** Nur `Content-Length`. Alle drei
//   Provider-Clients senden so.

public struct HTTPRequest: Sendable {
    public let method: String
    public let path: String
    public let headers: [String: String]
    public let body: Data

    public func header(_ name: String) -> String? {
        headers[name.lowercased()]
    }
}

/// Schreibseite einer Verbindung. Genau EINE der beiden Betriebsarten
/// verwenden: entweder `respond`, oder `beginStream`/`writeChunk`/`endStream`.
public final class HTTPConnection: @unchecked Sendable {

    private let fd: Int32
    private var streaming = false
    private var closed = false
    private let lock = NSLock()

    init(fd: Int32) { self.fd = fd }

    public func respond(status: Int, contentType: String = "application/json",
                        body: Data, extraHeaders: [String: String] = [:]) {
        lock.lock(); defer { lock.unlock() }
        guard !closed, !streaming else { return }
        var head = "HTTP/1.1 \(status) \(Self.reason(status))\r\n"
        head += "Content-Type: \(contentType)\r\n"
        head += "Content-Length: \(body.count)\r\n"
        for (k, v) in extraHeaders { head += "\(k): \(v)\r\n" }
        head += "Connection: close\r\n\r\n"
        _ = Self.writeAll(fd, Data(head.utf8))
        _ = Self.writeAll(fd, body)
        closed = true
    }

    public func respond(status: Int, json object: [String: Any]) {
        let data = (try? JSONSerialization.data(withJSONObject: object, options: [.sortedKeys]))
            ?? Data(#"{"error":"encoding failed"}"#.utf8)
        respond(status: status, body: data)
    }

    /// Beginnt einen Antwortstrom. Ohne `Content-Length` — das Ende ist der
    /// Verbindungsschluss, was HTTP/1.1 mit `Connection: close` ausdruecklich
    /// erlaubt und jeder SSE-Client versteht.
    public func beginStream(contentType: String) {
        lock.lock(); defer { lock.unlock() }
        guard !closed, !streaming else { return }
        streaming = true
        var head = "HTTP/1.1 200 OK\r\n"
        head += "Content-Type: \(contentType)\r\n"
        head += "Cache-Control: no-cache\r\n"
        head += "Connection: close\r\n\r\n"
        _ = Self.writeAll(fd, Data(head.utf8))
    }

    /// Schreibt ein Bruchstueck. Gibt `false` zurueck, wenn die Gegenseite weg
    /// ist — der Aufrufer sollte dann aufhoeren zu produzieren.
    @discardableResult
    public func writeChunk(_ text: String) -> Bool {
        lock.lock(); defer { lock.unlock() }
        guard streaming, !closed else { return false }
        if Self.writeAll(fd, Data(text.utf8)) { return true }
        closed = true
        return false
    }

    public func endStream() {
        lock.lock(); defer { lock.unlock() }
        closed = true
    }

    func finish() {
        lock.lock(); defer { lock.unlock() }
        closed = true
        shutdown(fd, Int32(SHUT_RDWR))
        close(fd)
    }

    private static func writeAll(_ fd: Int32, _ data: Data) -> Bool {
        var ok = true
        data.withUnsafeBytes { (raw: UnsafeRawBufferPointer) in
            guard let base = raw.baseAddress else { return }
            var sent = 0
            while sent < raw.count {
                #if canImport(Darwin)
                let n = write(fd, base.advanced(by: sent), raw.count - sent)
                #else
                let n = send(fd, base.advanced(by: sent), raw.count - sent, Int32(MSG_NOSIGNAL))
                #endif
                if n <= 0 { ok = false; return }
                sent += n
            }
        }
        return ok
    }

    private static func reason(_ status: Int) -> String {
        switch status {
        case 200: return "OK"
        case 400: return "Bad Request"
        case 401: return "Unauthorized"
        case 403: return "Forbidden"
        case 404: return "Not Found"
        case 413: return "Payload Too Large"
        case 422: return "Unprocessable Entity"
        case 502: return "Bad Gateway"
        default: return "Error"
        }
    }
}

public final class HTTPServer: @unchecked Sendable {

    public typealias Handler = @Sendable (HTTPRequest, HTTPConnection) async -> Void

    private let port: UInt16
    private let loopbackOnly: Bool
    private let maxBodyBytes: Int
    private let handler: Handler
    private var listenFD: Int32 = -1
    private var running = false

    public init(port: UInt16, loopbackOnly: Bool = true,
                maxBodyBytes: Int = 1_000_000, handler: @escaping Handler) {
        self.port = port
        self.loopbackOnly = loopbackOnly
        self.maxBodyBytes = maxBodyBytes
        self.handler = handler
    }

    /// Bindet und startet die Annahme-Schleife in einem eigenen Thread.
    public func start() throws {
        // Ein geschlossener Socket der Gegenseite darf den Prozess nicht toeten.
        signal(SIGPIPE, SIG_IGN)

        #if canImport(Darwin)
        let streamType = SOCK_STREAM
        #else
        let streamType = Int32(SOCK_STREAM.rawValue)
        #endif
        let fd = socket(AF_INET, streamType, 0)
        guard fd >= 0 else { throw GatewayServerError.unsupported("socket() failed") }

        var yes: Int32 = 1
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, socklen_t(MemoryLayout<Int32>.size))
        #if canImport(Darwin)
        setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &yes, socklen_t(MemoryLayout<Int32>.size))
        #endif

        var addr = sockaddr_in()
        #if canImport(Darwin)
        addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        #endif
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = port.bigEndian
        addr.sin_addr = in_addr(s_addr: loopbackOnly ? inet_addr("127.0.0.1") : in_addr_t(0))

        let bound = withUnsafePointer(to: &addr) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        guard bound == 0 else {
            close(fd)
            throw GatewayServerError.unsupported("bind() failed on port \(port) (errno \(errno))")
        }
        guard listen(fd, 64) == 0 else {
            close(fd)
            throw GatewayServerError.unsupported("listen() failed (errno \(errno))")
        }

        listenFD = fd
        running = true
        Thread.detachNewThread { [weak self] in self?.acceptLoop() }
    }

    public func stop() {
        running = false
        if listenFD >= 0 {
            shutdown(listenFD, Int32(SHUT_RDWR))
            close(listenFD)
            listenFD = -1
        }
    }

    private func acceptLoop() {
        while running {
            var clientAddr = sockaddr()
            var length = socklen_t(MemoryLayout<sockaddr>.size)
            let client = accept(listenFD, &clientAddr, &length)
            guard client >= 0 else {
                if running { continue } else { return }
            }
            Thread.detachNewThread { [weak self] in self?.serve(client) }
        }
    }

    private func serve(_ fd: Int32) {
        let connection = HTTPConnection(fd: fd)
        defer { connection.finish() }

        guard let request = readRequest(fd) else {
            connection.respond(status: 400, json: ["error": "malformed request"])
            return
        }
        if request.body.count > maxBodyBytes {
            connection.respond(status: 413, json: ["error": "payload too large"])
            return
        }

        // Bruecke vom blockierenden Verbindungs-Thread in die async-Welt.
        let done = DispatchSemaphore(value: 0)
        let handler = self.handler
        Task {
            await handler(request, connection)
            done.signal()
        }
        done.wait()
    }

    /// Liest Kopf und Rumpf. Nur `Content-Length`, kein chunked.
    private func readRequest(_ fd: Int32) -> HTTPRequest? {
        var buffer = Data()
        var chunk = [UInt8](repeating: 0, count: 16 * 1024)
        let separator = Data("\r\n\r\n".utf8)

        // 1. Kopf lesen.
        var headerEnd: Range<Data.Index>?
        while headerEnd == nil {
            let n = read(fd, &chunk, chunk.count)
            guard n > 0 else { return nil }
            buffer.append(contentsOf: chunk[0..<n])
            // Obergrenze fuer den Kopf — sonst haelt eine Endlos-Headerflut die
            // Verbindung offen (Slowloris-Variante).
            if buffer.count > 64 * 1024 { return nil }
            headerEnd = buffer.range(of: separator)
        }
        guard let headerRange = headerEnd,
              let head = String(data: buffer[..<headerRange.lowerBound], encoding: .utf8) else {
            return nil
        }

        var lines = head.components(separatedBy: "\r\n")
        guard !lines.isEmpty else { return nil }
        let requestLine = lines.removeFirst().split(separator: " ", omittingEmptySubsequences: true)
        guard requestLine.count >= 2 else { return nil }
        let method = String(requestLine[0])
        let path = String(requestLine[1]).components(separatedBy: "?").first ?? "/"

        var headers: [String: String] = [:]
        for line in lines where line.contains(":") {
            let parts = line.split(separator: ":", maxSplits: 1)
            guard parts.count == 2 else { continue }
            headers[parts[0].trimmingCharacters(in: .whitespaces).lowercased()] =
                parts[1].trimmingCharacters(in: .whitespaces)
        }

        // 2. Rumpf lesen.
        var body = Data(buffer[headerRange.upperBound...])
        let expected = Int(headers["content-length"] ?? "0") ?? 0
        if expected > maxBodyBytes { return HTTPRequest(method: method, path: path,
                                                        headers: headers, body: body) }
        while body.count < expected {
            let n = read(fd, &chunk, chunk.count)
            guard n > 0 else { break }
            body.append(contentsOf: chunk[0..<n])
        }
        return HTTPRequest(method: method, path: path, headers: headers, body: body)
    }
}
