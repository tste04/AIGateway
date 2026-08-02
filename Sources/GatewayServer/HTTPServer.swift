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

/// Schreibseite einer Antwort. Genau EINE der beiden Betriebsarten verwenden:
/// entweder `respond`, oder `beginStream`/`writeChunk`/`endStream`.
///
/// Als Naht geschnitten, damit `GatewayService` gegen eine Attrappe testbar
/// ist — der Pfad Firewall -> Downstream -> De-Maskierung war sonst nur mit
/// echten Sockets erreichbar und blieb deshalb ungetestet.
public protocol HTTPResponder: AnyObject, Sendable {
    func respond(status: Int, contentType: String, body: Data, extraHeaders: [String: String])
    func beginStream(contentType: String, extraHeaders: [String: String])
    @discardableResult func writeChunk(_ text: String) -> Bool
    func endStream()
}

public extension HTTPResponder {
    func respond(status: Int, json object: [String: Any]) {
        let data = (try? JSONSerialization.data(withJSONObject: object, options: [.sortedKeys]))
            ?? Data(#"{"error":"encoding failed"}"#.utf8)
        respond(status: status, contentType: "application/json", body: data, extraHeaders: [:])
    }

    func beginStream(contentType: String) {
        beginStream(contentType: contentType, extraHeaders: [:])
    }
}

/// Die Socket-Implementierung der Schreibseite.
public final class HTTPConnection: HTTPResponder, @unchecked Sendable {

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

    /// Beginnt einen Antwortstrom. Ohne `Content-Length` — das Ende ist der
    /// Verbindungsschluss, was HTTP/1.1 mit `Connection: close` ausdruecklich
    /// erlaubt und jeder SSE-Client versteht.
    public func beginStream(contentType: String, extraHeaders: [String: String] = [:]) {
        lock.lock(); defer { lock.unlock() }
        guard !closed, !streaming else { return }
        streaming = true
        var head = "HTTP/1.1 200 OK\r\n"
        head += "Content-Type: \(contentType)\r\n"
        head += "Cache-Control: no-cache\r\n"
        for (k, v) in extraHeaders { head += "\(k): \(v)\r\n" }
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
        case 429: return "Too Many Requests"
        case 502: return "Bad Gateway"
        case 503: return "Service Unavailable"
        default: return "Error"
        }
    }
}

public final class HTTPServer: @unchecked Sendable {

    public typealias Handler = @Sendable (HTTPRequest, HTTPConnection) async -> Void

    private let port: UInt16
    private let loopbackOnly: Bool
    private let maxBodyBytes: Int
    /// Lese-Timeout je Socket. Ohne ihn haelt ein Client, der den Rumpf nie
    /// zu Ende sendet, seinen Verbindungs-Thread unbegrenzt (Slow-Body).
    private let readTimeoutSeconds: Int
    /// Deckel fuer gleichzeitige Verbindungen. Thread-per-Connection ohne
    /// Limit hiesse: N langsame Clients binden N Threads. Ueber dem Deckel
    /// wird sofort mit 503 abgewiesen, statt einen Thread zu starten.
    private let maxConcurrentConnections: Int
    private let handler: Handler
    private var listenFD: Int32 = -1
    private var running = false
    private var activeConnections = 0
    private let stateLock = NSLock()

    public init(port: UInt16, loopbackOnly: Bool = true,
                maxBodyBytes: Int = 1_000_000,
                readTimeoutSeconds: Int = 30,
                maxConcurrentConnections: Int = 64,
                handler: @escaping Handler) {
        self.port = port
        self.loopbackOnly = loopbackOnly
        self.maxBodyBytes = maxBodyBytes
        self.readTimeoutSeconds = readTimeoutSeconds
        self.maxConcurrentConnections = maxConcurrentConnections
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

        stateLock.lock()
        listenFD = fd
        running = true
        stateLock.unlock()
        Thread.detachNewThread { [weak self] in self?.acceptLoop() }
    }

    // `running` und `listenFD` werden vom Accept-Thread gelesen und vom
    // Aufrufer-Thread (stop) geschrieben — beide Zugriffe liegen unter
    // `stateLock`, sonst ist es ein Data Race (unter striktem Swift-6-Checking
    // ein Fehler). Der blockierende `accept` laeuft ausserhalb der Sperre auf
    // einer lokalen Kopie des fd.
    private func isRunning() -> Bool {
        stateLock.lock(); defer { stateLock.unlock() }
        return running
    }

    private func currentListenFD() -> Int32 {
        stateLock.lock(); defer { stateLock.unlock() }
        return listenFD
    }

    /// Hoert sofort auf, Verbindungen anzunehmen.
    ///
    /// - Parameter drainSeconds: So lange wird auf laufende Anfragen gewartet.
    ///   `0` beendet ohne Warten (das alte Verhalten). Der Unterschied ist
    ///   nicht kosmetisch: eine Anfrage, die beim Abschalten mitten im
    ///   Upstream-Aufruf steht, hat das Modell bereits bezahlt — sie
    ///   abzuschneiden kostet Geld und liefert dem Client nichts. Deshalb erst
    ///   den Zulauf schliessen, dann austrinken lassen.
    ///
    /// - Returns: `true`, wenn beim Ende nichts mehr lief.
    @discardableResult
    public func stop(drainSeconds: TimeInterval = 0) -> Bool {
        stateLock.lock()
        running = false
        let fd = listenFD
        listenFD = -1
        stateLock.unlock()
        if fd >= 0 {
            // Schliesst den Annahme-Socket: der blockierende `accept` im
            // Accept-Thread kehrt dann mit Fehler zurueck und die Schleife
            // endet, weil `isRunning()` jetzt false ist.
            shutdown(fd, Int32(SHUT_RDWR))
            close(fd)
        }
        guard drainSeconds > 0 else { return activeConnectionCount() == 0 }

        // Gepollt statt per Bedingungsvariable: das hier ist der Abschaltpfad,
        // er laeuft genau einmal, und eine Sperrdisziplin mit Signalen waere
        // mehr Zustand fuer weniger Verlaesslichkeit.
        let deadline = Date().addingTimeInterval(drainSeconds)
        while activeConnectionCount() > 0, Date() < deadline {
            Thread.sleep(forTimeInterval: 0.02)
        }
        return activeConnectionCount() == 0
    }

    public func activeConnectionCount() -> Int {
        stateLock.lock(); defer { stateLock.unlock() }
        return activeConnections
    }

    private func acceptLoop() {
        while isRunning() {
            let listen = currentListenFD()
            guard listen >= 0 else { return }
            var clientAddr = sockaddr()
            var length = socklen_t(MemoryLayout<sockaddr>.size)
            let client = accept(listen, &clientAddr, &length)
            guard client >= 0 else {
                if isRunning() { continue } else { return }
            }

            stateLock.lock()
            let overloaded = activeConnections >= maxConcurrentConnections
            if !overloaded { activeConnections += 1 }
            stateLock.unlock()

            if overloaded {
                // Abweisen kostet einen kurzen blockierenden Write im
                // Accept-Thread — deutlich billiger als der Thread, den die
                // Annahme kosten wuerde.
                let rejected = HTTPConnection(fd: client)
                rejected.respond(status: 503, json: ["error": "server overloaded"])
                rejected.finish()
                continue
            }

            Thread.detachNewThread { [weak self] in
                self?.serve(client)
                guard let self else { return }
                self.stateLock.lock()
                self.activeConnections -= 1
                self.stateLock.unlock()
            }
        }
    }

    private func serve(_ fd: Int32) {
        // Zwei Timeouts, zwei verschiedene Gefahren:
        // - SO_RCVTIMEO begrenzt EINEN blockierenden `read`. Ohne den haengt
        //   ein Client, der nach dem Verbindungsaufbau schweigt.
        // - SO_SNDTIMEO begrenzt EINEN blockierenden `write`/`send`. Ohne den
        //   haengt ein Slow-Reader, der den Sendepuffer nicht leert (besonders
        //   beim SSE-Streaming): `writeAll`/`writeChunk` gaeben sonst nie auf.
        var timeout = timeval(tv_sec: time_t(readTimeoutSeconds), tv_usec: 0)
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout,
                   socklen_t(MemoryLayout<timeval>.size))
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout,
                   socklen_t(MemoryLayout<timeval>.size))

        let connection = HTTPConnection(fd: fd)
        defer { connection.finish() }

        // Absoluter Deadline fuer das GESAMTE Lesen der Anfrage. Das
        // Socket-Timeout begrenzt nur einen einzelnen `read`; ein Tropf von
        // einem Byte knapp vor jedem Ablauf haelt seinen Thread sonst
        // unbegrenzt (Slowloris). Die Deadline deckelt die Dauer ueber ALLE
        // Lesevorgaenge dieser Verbindung.
        let deadline = Date().addingTimeInterval(TimeInterval(readTimeoutSeconds))
        guard let request = readRequest(fd, deadline: deadline) else {
            connection.respond(status: 400, json: ["error": "malformed request"])
            return
        }
        // Gegen die ANGEKUENDIGTE Groesse pruefen, nicht nur gegen das bereits
        // Gelesene: `readRequest` bricht bei zu grossem Content-Length frueh ab
        // und liefert einen Teil-Rumpf — der laege unter der Grenze, und die
        // Antwort waere faelschlich 400 (Parse-Fehler) statt 413.
        let declaredBytes = Int(request.header("content-length") ?? "0") ?? 0
        if request.body.count > maxBodyBytes || declaredBytes > maxBodyBytes {
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
    ///
    /// `deadline` deckelt die Gesamtdauer ueber ALLE Lesevorgaenge: das
    /// Socket-Timeout unterbricht nur einen einzelnen `read`, ein Tropf knapp
    /// vor jedem Ablauf haelt die Verbindung sonst unbegrenzt.
    private func readRequest(_ fd: Int32, deadline: Date) -> HTTPRequest? {
        var buffer = Data()
        var chunk = [UInt8](repeating: 0, count: 16 * 1024)
        let separator = Data("\r\n\r\n".utf8)

        // 1. Kopf lesen.
        var headerEnd: Range<Data.Index>?
        while headerEnd == nil {
            guard Date() < deadline else { return nil }
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
        var seenContentLength: String?
        var conflictingContentLength = false
        var hasTransferEncoding = false
        for line in lines where line.contains(":") {
            let parts = line.split(separator: ":", maxSplits: 1)
            guard parts.count == 2 else { continue }
            let name = parts[0].trimmingCharacters(in: .whitespaces).lowercased()
            let value = parts[1].trimmingCharacters(in: .whitespaces)
            if name == "transfer-encoding" { hasTransferEncoding = true }
            if name == "content-length" {
                if let prev = seenContentLength, prev != value { conflictingContentLength = true }
                seenContentLength = value
            }
            headers[name] = value
        }

        // Request-Smuggling-Schutz: dieser Server beherrscht KEIN chunked (nur
        // Content-Length), also ist ein `Transfer-Encoding` gegen einen
        // vorgelagerten Proxy ein CL/TE-Desync-Vektor — ablehnen statt still als
        // Content-Length fehlzudeuten. Ebenso zwei widerspruechliche
        // Content-Length-Header (last-wins waere genau die Desync-Luecke) und
        // ein nicht-numerisches Content-Length.
        if hasTransferEncoding || conflictingContentLength { return nil }
        if let raw = seenContentLength, Int(raw) == nil { return nil }

        // 2. Rumpf lesen.
        var body = Data(buffer[headerRange.upperBound...])
        let expected = Int(headers["content-length"] ?? "0") ?? 0
        if expected > maxBodyBytes { return HTTPRequest(method: method, path: path,
                                                        headers: headers, body: body) }
        while body.count < expected {
            guard Date() < deadline else { break }
            let n = read(fd, &chunk, chunk.count)
            guard n > 0 else { break }
            body.append(contentsOf: chunk[0..<n])
        }
        return HTTPRequest(method: method, path: path, headers: headers, body: body)
    }
}
