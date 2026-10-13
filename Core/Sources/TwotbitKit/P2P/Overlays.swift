import Foundation
import Synchronization

/// OverlayClient is the running client of an anonymity network, Tor or I2P:
/// it dials the network's peers once ready.
public protocol OverlayClient: Dialer {
    func close()
}

/// Backoff paces retries: five seconds at first, doubled after each further
/// failure up to two minutes.
struct Backoff {
    static let first: Duration = .seconds(5)
    static let max: Duration = .seconds(120)
    var delay = first

    mutating func next() -> Duration {
        defer { delay = min(delay * 2, Backoff.max) }
        return delay
    }

    mutating func reset() { delay = Backoff.first }
}

/// TorClient reaches onion peers through the SOCKS5 proxy of a Tor client
/// running next to the wallet: the tor daemon on 127.0.0.1:9050 or Tor
/// Browser on 127.0.0.1:9150, or the proxy set in the settings. It looks
/// for a working proxy in the background, retrying with a growing delay,
/// and is ready once one answers. Every connection authenticates with
/// fresh random credentials, so Tor builds a separate circuit for each
/// peer, as Bitcoin Core's -proxyrandomize does.
public final class TorClient: OverlayClient {
    public static let defaultProxies = ["127.0.0.1:9050", "127.0.0.1:9150"]

    private let proxies: [String]
    private let proxy = Mutex<String?>(nil)
    private let ready = Signal()
    private let stopped = Signal()
    private let task = Mutex<Task<Void, Never>?>(nil)

    /// Starts looking for a proxy among the candidates, reporting every
    /// state change through onState.
    public static func start(proxies: [String], onState: @escaping @Sendable (OverlayState) -> Void) -> TorClient {
        let client = TorClient(proxies: proxies)
        let task = Task { await client.findProxy(onState: onState) }
        client.task.withLock { $0 = task }
        return client
    }

    private init(proxies: [String]) {
        self.proxies = proxies.isEmpty ? TorClient.defaultProxies : proxies
    }

    private func findProxy(onState: @escaping @Sendable (OverlayState) -> Void) async {
        var backoff = Backoff()
        while !stopped.isFired && !Task.isCancelled {
            onState(.starting)
            for candidate in proxies {
                guard let (host, port) = try? candidate.splitHostPort() else { continue }
                do {
                    let stream = try await TCPStream.connect(host: host, port: port, timeout: .seconds(5))
                    defer { stream.close() }
                    try await SOCKS5.greet(stream)
                    proxy.withLock { $0 = candidate }
                    Log.info("tor: SOCKS proxy ready at \(candidate)")
                    ready.fire()
                    onState(.ready)
                    return
                } catch {
                    Log.info("tor: no SOCKS proxy at \(candidate): \(error)")
                }
            }
            let delay = backoff.next()
            Log.info("tor: no Tor SOCKS proxy at \(proxies.joined(separator: " or ")); retrying in \(delay.formatted)")
            onState(.failed("no Tor proxy at \(proxies.joined(separator: " or "))"))
            guard await pause(delay) else { return }
        }
    }

    /// The proxy in use once ready.
    public var proxyAddress: String? { proxy.withLock { $0 } }

    public func dial(host: String, port: UInt16, timeout: Duration) async throws -> TCPStream {
        let ready = self.ready
        let stopped = self.stopped
        try await withTimeout(timeout, "tor not ready") {
            await withTaskGroup(of: Void.self) { group in
                group.addTask { await ready.wait() }
                group.addTask { await stopped.wait() }
                await group.next()
                group.cancelAll()
            }
        }
        guard !stopped.isFired, let proxy = proxyAddress else { throw NetError(.closed, "tor client closed") }
        let (proxyHost, proxyPort) = try proxy.splitHostPort()
        let stream = try await TCPStream.connect(host: proxyHost, port: proxyPort, timeout: .seconds(10))
        do {
            try await withTimeout(timeout, "tor connect to \(host.withPort(port))") {
                try await SOCKS5.connect(stream, host: host, port: port, isolate: true)
            }
            return stream
        } catch {
            stream.close()
            throw error
        }
    }

    public func close() {
        stopped.fire()
        task.withLock { $0?.cancel() }
    }
}

/// SOCKS5 speaks the client side of RFC 1928 with the username/password
/// authentication of RFC 1929.
enum SOCKS5 {
    struct Failure: Error, CustomStringConvertible {
        let description: String
    }

    /// Checks that the stream is a SOCKS5 proxy accepting no
    /// authentication.
    static func greet(_ stream: TCPStream) async throws {
        stream.send(Data([0x05, 0x01, 0x00]))
        let reply = try await stream.read(2)
        guard reply[0] == 0x05, reply[1] == 0x00 else { throw Failure(description: "not a SOCKS5 proxy") }
    }

    /// Asks the proxy to connect to the host, an onion name or an IP,
    /// passed by name so the proxy resolves it. With isolate, random
    /// credentials make Tor use a fresh circuit.
    static func connect(_ stream: TCPStream, host: String, port: UInt16, isolate: Bool) async throws {
        stream.send(isolate ? Data([0x05, 0x02, 0x00, 0x02]) : Data([0x05, 0x01, 0x00]))
        let method = try await stream.read(2)
        guard method[0] == 0x05 else { throw Failure(description: "not a SOCKS5 proxy") }
        switch method[1] {
        case 0x00:
            break
        case 0x02:
            let user = Data(Hashes.randomBytes(8).hex.utf8)
            let pass = Data(Hashes.randomBytes(8).hex.utf8)
            stream.send(Data([0x01, UInt8(user.count)]) + user + Data([UInt8(pass.count)]) + pass)
            let auth = try await stream.read(2)
            guard auth[1] == 0x00 else { throw Failure(description: "SOCKS5 authentication failed") }
        default:
            throw Failure(description: "SOCKS5 proxy accepts no offered authentication")
        }
        var request = Data([0x05, 0x01, 0x00])
        if let ip = host.ipBytes, !host.contains(":") {
            request.append(0x01)
            request.append(contentsOf: ip.suffix(4))
        } else if host.isIP {
            request.append(0x04)
            request.append(contentsOf: host.ipBytes!)
        } else {
            let name = Data(host.utf8)
            guard name.count <= 255 else { throw Failure(description: "host name too long") }
            request.append(0x03)
            request.append(UInt8(name.count))
            request.append(name)
        }
        request.append(UInt8(port >> 8))
        request.append(UInt8(port & 0xff))
        stream.send(request)
        let head = try await stream.read(4)
        guard head[0] == 0x05 else { throw Failure(description: "malformed SOCKS5 reply") }
        guard head[1] == 0x00 else { throw Failure(description: reply(head[1])) }
        switch head[3] {
        case 0x01: _ = try await stream.read(4 + 2)
        case 0x04: _ = try await stream.read(16 + 2)
        case 0x03: _ = try await stream.read(Int(try await stream.read(1)[0]) + 2)
        default: throw Failure(description: "malformed SOCKS5 reply address")
        }
    }

    /// The meaning of a SOCKS5 reply code, Tor's extended codes included.
    static func reply(_ code: UInt8) -> String {
        switch code {
        case 0x01: return "general SOCKS server failure"
        case 0x02: return "connection not allowed by ruleset"
        case 0x03: return "network unreachable"
        case 0x04: return "host unreachable"
        case 0x05: return "connection refused"
        case 0x06: return "TTL expired"
        case 0x07: return "command not supported"
        case 0x08: return "address type not supported"
        case 0xf0: return "onion service descriptor can not be found"
        case 0xf1: return "onion service descriptor is invalid"
        case 0xf2: return "onion service introduction failed"
        case 0xf3: return "onion service rendezvous failed"
        case 0xf4: return "onion service missing client authorization"
        case 0xf5: return "onion service wrong client authorization"
        case 0xf6: return "onion service invalid address"
        case 0xf7: return "onion service introduction timed out"
        default: return "SOCKS5 error \(code)"
        }
    }
}

/// I2PClient reaches I2P peers through the SAM bridge of an I2P router
/// running next to the wallet, such as i2pd, as Bitcoin Core does. It keeps
/// one SAM stream session with a transient destination and opens a stream
/// over it to every peer dialed. SAM 3.1 is spoken, without ports, which is
/// what Bitcoin Core's I2P nodes accept.
public final class I2PClient: OverlayClient {
    /// The address of the SAM bridge of i2pd and Java I2P.
    public static let defaultSAM = "127.0.0.1:7656"
    /// How long a session must have lasted for a new one to be created at
    /// once when it is lost; one lost sooner counts as a failure.
    static let stableSession: Duration = .seconds(60)
    /// Bounds creating the session, which waits for the router to build its
    /// tunnels.
    static let sessionTimeout: Duration = .seconds(180)
    /// The session options Bitcoin Core uses: an Ed25519 destination with
    /// the X25519 and ElGamal lease set encryption, and one tunnel each way.
    static let sessionOptions = "SIGNATURE_TYPE=7 i2cp.leaseSetEncType=4,0 inbound.quantity=1 outbound.quantity=1"

    private struct Session {
        var id: String?
        var ready = Signal()
    }

    public let sam: String
    private let session = Mutex(Session())
    private let stopped = Signal()
    private let task = Mutex<Task<Void, Never>?>(nil)

    /// Creates the session with the router's SAM bridge in the background,
    /// and a new one whenever it is lost, reporting every state change
    /// through onState.
    public static func start(sam: String, onState: @escaping @Sendable (OverlayState) -> Void) -> I2PClient {
        let client = I2PClient(sam: sam)
        let task = Task { await client.keepSession(onState: onState) }
        client.task.withLock { $0 = task }
        return client
    }

    private init(sam: String) { self.sam = sam }

    private func keepSession(onState: @escaping @Sendable (OverlayState) -> Void) async {
        var backoff = Backoff()
        while !stopped.isFired && !Task.isCancelled {
            onState(.starting)
            let started = ContinuousClock.now
            var failure: String
            do {
                let (control, id) = try await withTimeout(I2PClient.sessionTimeout, "create session") { try await self.createSession() }
                Log.info("i2p: session \(id) ready in \((ContinuousClock.now - started).formatted)")
                let ready = session.withLock { s -> Signal in
                    s.id = id
                    return s.ready
                }
                ready.fire()
                onState(.ready)
                let readyAt = ContinuousClock.now
                await hold(control)
                control.close()
                session.withLock { $0 = Session() }
                if stopped.isFired || Task.isCancelled { return }
                if ContinuousClock.now - readyAt >= I2PClient.stableSession {
                    Log.info("i2p: session \(id) lost, creating a new one")
                    backoff.reset()
                    continue
                }
                failure = "session \(id) lost after \((ContinuousClock.now - readyAt).formatted)"
            } catch {
                failure = "\(error)"
            }
            if stopped.isFired || Task.isCancelled { return }
            let delay = backoff.next()
            Log.info("i2p: \(failure); retrying in \(delay.formatted)")
            onState(.failed(failure))
            guard await pause(delay) else { return }
        }
    }

    /// Opens the control connection and creates a stream session with a
    /// transient destination and a fresh id on it.
    private func createSession() async throws -> (TCPStream, String) {
        let control = try await hello()
        let id = "twotbit-" + Hashes.randomBytes(8).hex
        do {
            _ = try await I2PClient.command(control, "SESSION CREATE STYLE=STREAM ID=\(id) DESTINATION=TRANSIENT \(I2PClient.sessionOptions)")
        } catch {
            control.close()
            throw PeerError("create session: \(error)")
        }
        return (control, id)
    }

    /// Waits until the control connection closes, the session being lost
    /// with it, or the client is closed, answering the router's pings.
    private func hold(_ control: TCPStream) async {
        let stopped = self.stopped
        await withTaskGroup(of: Void.self) { group in
            group.addTask {
                while true {
                    guard let line = try? await control.readLine() else { return }
                    if line.hasPrefix("PING") {
                        control.send(Data(("PONG" + line.dropFirst(4) + "\n").utf8))
                    }
                }
            }
            group.addTask { await stopped.wait() }
            await group.next()
            group.cancelAll()
            control.close()
        }
    }

    /// Opens a stream to the I2P peer at the b32 address, the port being
    /// ignored, once the session is ready: it looks the name up and
    /// connects to the destination.
    public func dial(host: String, port: UInt16, timeout: Duration) async throws -> TCPStream {
        guard host.isI2P else { throw PeerError("\"\(host)\" is not an I2P b32 address") }
        let ready = session.withLock { $0.ready }
        let stopped = self.stopped
        try await withTimeout(timeout, "i2p not ready") {
            await withTaskGroup(of: Void.self) { group in
                group.addTask { await ready.wait() }
                group.addTask { await stopped.wait() }
                await group.next()
                group.cancelAll()
            }
        }
        guard !stopped.isFired else { throw NetError(.closed, "i2p client closed") }
        guard let id = session.withLock({ $0.id }) else { throw PeerError("i2p session lost") }
        let stream = try await hello()
        do {
            return try await withTimeout(timeout, "i2p connect to \(host)") {
                let reply = try await I2PClient.command(stream, "NAMING LOOKUP NAME=\(host)")
                guard let dest = reply["VALUE"], !dest.isEmpty else { throw PeerError("look up \(host): no destination") }
                _ = try await I2PClient.command(stream, "STREAM CONNECT ID=\(id) DESTINATION=\(dest) SILENT=false")
                return stream
            }
        } catch {
            stream.close()
            throw error
        }
    }

    public func close() {
        stopped.fire()
        task.withLock { $0?.cancel() }
    }

    /// Connects to the SAM bridge and agrees on SAM 3.1.
    private func hello() async throws -> TCPStream {
        let (host, port) = try sam.splitHostPort()
        let stream: TCPStream
        do {
            stream = try await TCPStream.connect(host: host, port: port, timeout: .seconds(10))
        } catch {
            throw PeerError("no I2P router SAM bridge at \(sam): \(error)")
        }
        do {
            _ = try await I2PClient.command(stream, "HELLO VERSION MIN=3.1 MAX=3.1")
        } catch {
            stream.close()
            throw PeerError("SAM hello: \(error)")
        }
        return stream
    }

    /// Sends one SAM command and reads its reply line, failing unless the
    /// reply's RESULT is OK. The reply's fields are returned.
    static func command(_ stream: TCPStream, _ line: String) async throws -> [String: String] {
        stream.send(Data((line + "\n").utf8))
        let reply = try await stream.readLine()
        let fields = parseReply(reply)
        guard fields["RESULT"] == "OK" else {
            if let message = fields["MESSAGE"], !message.isEmpty { throw PeerError("\(fields["RESULT"] ?? ""): \(message)") }
            throw PeerError(reply.trimmingCharacters(in: .whitespaces))
        }
        return fields
    }

    /// The key=value fields of a SAM reply line, a quoted value possibly
    /// holding spaces; bare words map to "".
    static func parseReply(_ line: String) -> [String: String] {
        var fields = [String: String]()
        var rest = Substring(line.trimmingCharacters(in: .whitespacesAndNewlines))
        while !rest.isEmpty {
            let space = rest.firstIndex(of: " ")
            let equals = rest.firstIndex(of: "=")
            if equals == nil || (space != nil && space! < equals!) {
                let token = space.map { rest[..<$0] } ?? rest
                fields[String(token)] = ""
                rest = space.map { rest[rest.index(after: $0)...] } ?? ""
                rest = rest.drop { $0 == " " }
                continue
            }
            let key = String(rest[..<equals!])
            var value = rest[rest.index(after: equals!)...]
            if value.hasPrefix("\"") {
                value = value.dropFirst()
                let close = value.firstIndex(of: "\"")
                fields[key] = String(close.map { value[..<$0] } ?? value)
                rest = close.map { value[value.index(after: $0)...] } ?? ""
            } else {
                let end = value.firstIndex(of: " ")
                fields[key] = String(end.map { value[..<$0] } ?? value)
                rest = end.map { value[$0...] } ?? ""
            }
            rest = rest.drop { $0 == " " }
        }
        return fields
    }
}
