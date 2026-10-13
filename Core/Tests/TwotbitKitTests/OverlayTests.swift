import Foundation
import Network
import Synchronization
import Testing
@testable import TwotbitKit

/// A local TCP listener handing every accepted connection to serve.
final class MockServer: Sendable {
    private let listener: NWListener
    let port: UInt16

    var address: String { "127.0.0.1:\(port)" }

    private init(listener: NWListener, port: UInt16) {
        self.listener = listener
        self.port = port
    }

    static func start(_ serve: @escaping @Sendable (TCPStream) async -> Void) async throws -> MockServer {
        let parameters = NWParameters.tcp
        parameters.requiredLocalEndpoint = NWEndpoint.hostPort(host: "127.0.0.1", port: .any)
        let listener = try NWListener(using: parameters)
        let ready = Mutex<CheckedContinuation<UInt16, Error>?>(nil)
        listener.newConnectionHandler = { connection in
            Task {
                guard let stream = try? await TCPStream.accept(connection) else { return }
                await serve(stream)
            }
        }
        let port: UInt16 = try await withCheckedThrowingContinuation { continuation in
            ready.withLock { $0 = continuation }
            listener.stateUpdateHandler = { state in
                switch state {
                case .ready: ready.withLock { $0?.resume(returning: listener.port?.rawValue ?? 0); $0 = nil }
                case .failed(let error): ready.withLock { $0?.resume(throwing: error); $0 = nil }
                default: break
                }
            }
            listener.start(queue: DispatchQueue(label: "mock.server"))
        }
        return MockServer(listener: listener, port: port)
    }

    func stop() { listener.cancel() }
}

/// Recorder collects what a mock server saw, from any thread.
final class Recorder<T: Sendable>: Sendable {
    private let items = Mutex<[T]>([])

    func append(_ item: T) { items.withLock { $0.append(item) } }
    var all: [T] { items.withLock { $0 } }
}

/// Pumps bytes both ways between two streams until either closes.
func pump(_ a: TCPStream, _ b: TCPStream) async {
    await withTaskGroup(of: Void.self) { group in
        group.addTask { while let data = try? await a.readAvailable() { b.send(data) } }
        group.addTask { while let data = try? await b.readAvailable() { a.send(data) } }
        await group.next()
        group.cancelAll()
        a.close()
        b.close()
    }
}

/// A SOCKS5 proxy, as a Tor client offers, that tunnels every connection to
/// the node and records the hosts asked for and the credentials used.
func socksProxy(to node: MockNode, requests: Recorder<String>, users: Recorder<String>) async throws -> MockServer {
    try await MockServer.start { client in
        guard let greeting = try? await client.read(2), greeting[0] == 5,
              let methods = try? await client.read(Int(greeting[1])) else { return }
        if methods.contains(2) {
            client.send(Data([5, 2]))
            guard let head = try? await client.read(2), let user = try? await client.read(Int(head[1])),
                  let plen = try? await client.read(1), (try? await client.read(Int(plen[0]))) != nil else { return }
            users.append(String(decoding: user, as: UTF8.self))
            client.send(Data([1, 0]))
        } else {
            client.send(Data([5, 0]))
        }
        guard let request = try? await client.read(4), request[1] == 1 else { return }
        var host = ""
        switch request[3] {
        case 3:
            guard let n = try? await client.read(1), let name = try? await client.read(Int(n[0])) else { return }
            host = String(decoding: name, as: UTF8.self)
        case 1:
            guard let ip = try? await client.read(4) else { return }
            host = [UInt8](ip).ipString
        default:
            return
        }
        guard let port = try? await client.read(2) else { return }
        requests.append("\(host):\(UInt16(port[0]) << 8 | UInt16(port[1]))")
        guard let upstream = try? await TCPStream.connect(host: "127.0.0.1", port: node.port, timeout: .seconds(5)) else {
            client.send(Data([5, 5, 0, 1, 0, 0, 0, 0, 0, 0]))
            return
        }
        client.send(Data([5, 0, 0, 1, 0, 0, 0, 0, 0, 0]))
        await pump(client, upstream)
    }
}

/// An I2P router's SAM bridge that creates sessions and tunnels every
/// stream to the node.
func samBridge(to node: MockNode, lookups: Recorder<String>) async throws -> MockServer {
    try await MockServer.start { conn in
        while let line = try? await conn.readLine() {
            if line.hasPrefix("HELLO VERSION") {
                conn.send(Data("HELLO REPLY RESULT=OK VERSION=3.1\n".utf8))
            } else if line.hasPrefix("SESSION CREATE") {
                conn.send(Data("SESSION STATUS RESULT=OK DESTINATION=TRANSIENTDEST\n".utf8))
            } else if line.hasPrefix("NAMING LOOKUP") {
                let name = I2PClient.parseReply(line)["NAME"] ?? ""
                lookups.append(name)
                conn.send(Data("NAMING REPLY RESULT=OK NAME=\(name) VALUE=DEST\(name.prefix(8))\n".utf8))
            } else if line.hasPrefix("STREAM CONNECT") {
                guard let upstream = try? await TCPStream.connect(host: "127.0.0.1", port: node.port, timeout: .seconds(5)) else {
                    conn.send(Data("STREAM STATUS RESULT=CANT_REACH_PEER\n".utf8))
                    return
                }
                conn.send(Data("STREAM STATUS RESULT=OK\n".utf8))
                await pump(conn, upstream)
                return
            }
        }
    }
}

@Suite(.serialized) struct OverlayTests {
    static let onionPeer = PeerAddress(host: Seeds.onion[0].host, port: 8333)
    static let i2pPeer = PeerAddress(host: Seeds.i2p[0].host, port: 8333)

    @Test func samReplies() {
        #expect(I2PClient.parseReply("HELLO REPLY RESULT=OK VERSION=3.1") == ["HELLO": "", "REPLY": "", "RESULT": "OK", "VERSION": "3.1"])
        #expect(I2PClient.parseReply(#"STREAM STATUS RESULT=I2P_ERROR MESSAGE="no route to peer""#)["MESSAGE"] == "no route to peer")
        #expect(I2PClient.parseReply("PING 1234") == ["PING": "", "1234": ""])
    }

    /// With Tor on, the wallet dials only onion peers, each through the
    /// proxy with its own credentials, and syncs through them; the direct
    /// peer it knows is never dialed.
    @Test func torMode() async throws {
        let w = try TestWallet()
        var chain = ChainBuilder()
        let blocks = chain.mine(count: 3) + [chain.mine([payment([TxOut(value: 4_242, pkScript: w.address(0).script)], seed: 21)])]
        let node = try await MockNode.start(blocks: blocks)
        defer { node.stop() }
        let direct = try await MockNode.start(blocks: blocks)
        defer { direct.stop() }
        try w.addPeer(direct)
        try w.store.upsertPeer(host: Self.onionPeer.host, port: Self.onionPeer.port, services: ServiceFlags([.network, .witness, .compactFilters]).rawValue, latencyMs: 0)
        let requests = Recorder<String>()
        let users = Recorder<String>()
        let proxy = try await socksProxy(to: node, requests: requests, users: users)
        defer { proxy.stop() }
        let states = Recorder<OverlayState>()
        let tor = TorClient.start(proxies: ["127.0.0.1:1", proxy.address]) { states.append($0) }
        defer { tor.close() }
        try await eventually(.seconds(10), "tor ready") { states.all.last == .ready }
        #expect(tor.proxyAddress == proxy.address)

        let engine = try SyncEngine(network: .regtest, store: w.store)
        engine.setOverlay(.tor, on: true, dialer: nil)
        try engine.start { _ in }
        defer { Task { await engine.stop() } }
        try await Task.sleep(for: .milliseconds(300))
        #expect(engine.status().text == "Connecting over Tor...")
        engine.setOverlay(.tor, on: true, dialer: tor)
        try await eventually(.seconds(20), "sync over Tor") { engine.status().synced && engine.chainHeight == 4 }
        #expect(engine.status().text == "Connected over Tor")
        #expect(engine.status().balance == 4_242)
        #expect(requests.all.allSatisfy { $0.hasSuffix(".onion:8333") })
        #expect(requests.all.contains(Self.onionPeer.description))
        #expect(Set(users.all).count == users.all.count && !users.all.isEmpty)
        #expect(direct.state.withLock { $0.connections } == 0)

        engine.setOverlay(.tor, on: false, dialer: nil)
        try await eventually(.seconds(20), "back to direct peers") { direct.state.withLock { $0.connections } > 0 }
        await engine.stop()
    }

    /// With I2P on, the wallet opens a SAM session and reaches I2P peers
    /// through streams over it.
    @Test func i2pMode() async throws {
        let w = try TestWallet()
        var chain = ChainBuilder()
        let blocks = chain.mine(count: 2)
        let node = try await MockNode.start(blocks: blocks)
        defer { node.stop() }
        let direct = try await MockNode.start(blocks: blocks)
        defer { direct.stop() }
        try w.addPeer(direct)
        try w.store.upsertPeer(host: Self.i2pPeer.host, port: Self.i2pPeer.port, services: ServiceFlags([.network, .witness, .compactFilters]).rawValue, latencyMs: 0)
        let lookups = Recorder<String>()
        let sam = try await samBridge(to: node, lookups: lookups)
        defer { sam.stop() }
        let states = Recorder<OverlayState>()
        let i2p = I2PClient.start(sam: sam.address) { states.append($0) }
        defer { i2p.close() }
        try await eventually(.seconds(10), "i2p ready") { states.all.last == .ready }
        let engine = try SyncEngine(network: .regtest, store: w.store)
        engine.setOverlay(.i2p, on: true, dialer: i2p)
        try engine.start { _ in }
        defer { Task { await engine.stop() } }
        try await eventually(.seconds(20), "sync over I2P") { engine.status().synced && engine.chainHeight == 2 }
        #expect(engine.status().text == "Connected over I2P")
        #expect(lookups.all.contains(Self.i2pPeer.host))
        #expect(direct.state.withLock { $0.connections } == 0)
        await engine.stop()
    }

    /// Without a router the I2P client reports it, and without a proxy the
    /// Tor client does, and both keep retrying.
    @Test func failures() async throws {
        let states = Recorder<OverlayState>()
        let i2p = I2PClient.start(sam: "127.0.0.1:1") { states.append($0) }
        try await eventually(.seconds(10), "i2p failure") {
            states.all.contains { if case .failed(let why) = $0 { return why.contains("no I2P router") } else { return false } }
        }
        i2p.close()
        let torStates = Recorder<OverlayState>()
        let tor = TorClient.start(proxies: ["127.0.0.1:1"]) { torStates.append($0) }
        try await eventually(.seconds(10), "tor failure") {
            torStates.all.contains { if case .failed = $0 { return true } else { return false } }
        }
        tor.close()
        await #expect(throws: (any Error).self) { try await tor.dial(host: "x.onion", port: 1, timeout: .seconds(1)) }
    }
}
