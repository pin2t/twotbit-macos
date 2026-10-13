import Foundation
import Synchronization

/// RemoteVersion is what a peer told about itself in its version message.
public struct RemoteVersion: Sendable {
    public let protocolVersion: Int32
    public let services: ServiceFlags
    public let userAgent: String
    /// The height of the peer's best block when it connected.
    public let startHeight: Int32
}

/// PeerError is a peer that failed or broke the protocol, with the error
/// that caused it when there is one.
public struct PeerError: Error, CustomStringConvertible, Sendable {
    public let description: String
    public let underlying: (any Error)?

    init(_ description: String, underlying: (any Error)? = nil) {
        self.description = description
        self.underlying = underlying
    }
}

/// PeerConnection is one connected Bitcoin peer after the version/verack
/// handshake: it reads the peer's messages, answers pings, hands responses
/// to the mailbox of their kind for the request waiting on them, and passes
/// announcements, relayed transactions and addresses to the handler. The
/// local node advertises no services: it is a light client.
public final class PeerConnection: Sendable {
    /// The user agent the wallet introduces itself with.
    public static let userAgent = "/twotbit:0.1.0/"
    /// Bounds on the TCP dial and the handshake; reaching an onion peer
    /// through Tor or an I2P peer through I2P takes far longer.
    public static let handshakeTimeout: Duration = .seconds(15)
    public static let overlayDialTimeout: Duration = .seconds(120)
    public static let overlayHandshakeTimeout: Duration = .seconds(45)
    /// How often a ping goes out, and how long a peer may send nothing
    /// before it is dropped, as btcd's peer does.
    static let pingInterval: Duration = .seconds(120)
    static let idleTimeout: Duration = .seconds(300)

    public let address: String
    public let host: String
    public let port: UInt16
    /// A pinned peer was asked for explicitly and is never dropped.
    public let pinned: Bool
    public let network: Network
    public let remote: RemoteVersion
    let stream: TCPStream
    let handler: @Sendable (PeerConnection, Message) -> Void

    /// Fires once the peer is disconnected, for whatever reason.
    let quit = Signal()
    private let lastReceived = Mutex(ContinuousClock.now)
    private let tasks = Mutex<[Task<Void, Never>]>([])
    private let reason = Mutex<String?>(nil)

    /// BlockReply is the answer to a block request: the block, or the
    /// peer's notfound.
    enum BlockReply: Sendable {
        case block(Block)
        case notFound([InvVect])
    }

    let headers = Mailbox<[BlockHeader]>(capacity: 4)
    let cfHeaders = Mailbox<CFHeaders>(capacity: 4)
    let cfilters = Mailbox<CFilter>(capacity: 2000)
    let blockReplies = Mailbox<BlockReply>(capacity: 8)

    private init(address: String, host: String, port: UInt16, pinned: Bool, network: Network, remote: RemoteVersion,
                 stream: TCPStream, handler: @escaping @Sendable (PeerConnection, Message) -> Void) {
        self.address = address
        self.host = host
        self.port = port
        self.pinned = pinned
        self.network = network
        self.remote = remote
        self.stream = stream
        self.handler = handler
    }

    public var services: ServiceFlags { remote.services }
    public var isLive: Bool { !quit.isFired }

    /// Dials the peer at the host:port address through the dialer,
    /// completes the handshake and starts reading its messages. It returns
    /// the connected peer and how long dial and handshake took. relay sets
    /// the version message's relay flag: whether the peer should announce
    /// the transactions it relays without a bloom filter.
    public static func connect(network: Network, address: String, dialer: any Dialer, relay: Bool, pinned: Bool = false,
                               handler: @escaping @Sendable (PeerConnection, Message) -> Void) async throws -> (PeerConnection, Duration) {
        let (host, port) = try address.splitHostPort()
        let overlay = OverlayNetwork.of(host) != .direct
        let started = ContinuousClock.now
        let stream: TCPStream
        do {
            stream = try await dialer.dial(host: host, port: port, timeout: overlay ? overlayDialTimeout : handshakeTimeout)
        } catch {
            throw PeerError("dial peer \(address): \(error)", underlying: error)
        }
        let remote: RemoteVersion
        do {
            remote = try await withTimeout(overlay ? overlayHandshakeTimeout : handshakeTimeout, "handshake") {
                try await handshake(stream: stream, network: network, host: host, port: port, relay: relay)
            }
        } catch is TimeoutError {
            stream.close()
            throw PeerError("handshake with \(address) timed out")
        } catch {
            stream.close()
            throw PeerError("handshake with \(address): \(error)", underlying: error)
        }
        let peer = PeerConnection(address: address, host: host, port: port, pinned: pinned, network: network,
                                  remote: remote, stream: stream, handler: handler)
        peer.start()
        return (peer, ContinuousClock.now - started)
    }

    /// Sends the version message and reads the peer's until its verack,
    /// answering its version with sendaddrv2, as BIP155 asks before verack,
    /// and verack.
    private static func handshake(stream: TCPStream, network: Network, host: String, port: UInt16, relay: Bool) async throws -> RemoteVersion {
        let nonce = UInt64.random(in: 1...UInt64.max)
        let mappedZero = [UInt8](repeating: 0, count: 10) + [0xff, 0xff, 0, 0, 0, 0]
        let recv = host.ipBytes.map { NetAddress(ip: $0, port: port) } ?? NetAddress(ip: mappedZero, port: port)
        let version = VersionMessage(protocolVersion: Message.protocolVersion, services: [], timestamp: Int64(Date().timeIntervalSince1970),
                                     addrRecv: recv, addrFrom: NetAddress(), nonce: nonce, userAgent: userAgent, startHeight: 0, relay: relay)
        stream.send(Wire.frame(.version(version), magic: network.magic))
        var remote: RemoteVersion?
        while true {
            let (command, payload) = try await readFrame(stream, network: network)
            switch try Message.decode(command: command, payload: payload) {
            case .version(let v):
                guard remote == nil else { throw PeerError("duplicate version message") }
                guard v.nonce != nonce else { throw PeerError("disconnecting peer connected to self") }
                guard v.protocolVersion >= 209 else { throw PeerError("protocol version \(v.protocolVersion) is too old") }
                remote = RemoteVersion(protocolVersion: v.protocolVersion, services: v.services, userAgent: v.userAgent, startHeight: v.startHeight)
                if min(v.protocolVersion, Message.protocolVersion) >= 70016 {
                    stream.send(Wire.frame(.sendAddrV2, magic: network.magic))
                }
                stream.send(Wire.frame(.verack, magic: network.magic))
            case .verack:
                guard let remote else { throw PeerError("verack before version") }
                return remote
            default:
                continue
            }
        }
    }

    /// Reads one framed message: the header, then the payload, checking the
    /// network magic and the checksum.
    static func readFrame(_ stream: TCPStream, network: Network) async throws -> (String, Data) {
        let header = try Wire.parseHeader(try await stream.read(Wire.headerSize))
        guard header.magic == network.magic else {
            throw PeerError("message from network \(String(header.magic, radix: 16)), want \(network.name)")
        }
        let payload = header.length > 0 ? try await stream.read(header.length) : Data()
        guard header.checksumMatches(payload: payload) else { throw PeerError("\(header.command) message checksum mismatch") }
        return (header.command, payload)
    }

    private func start() {
        let reader = Task { [self] in await readLoop() }
        let pinger = Task { [self] in await pingLoop() }
        tasks.withLock { $0 = [reader, pinger] }
        if quit.isFired { reader.cancel(); pinger.cancel() }
    }

    private func readLoop() async {
        while !quit.isFired {
            do {
                let (command, payload) = try await PeerConnection.readFrame(stream, network: network)
                lastReceived.withLock { $0 = .now }
                dispatch(try Message.decode(command: command, payload: payload))
            } catch {
                disconnect(isLive ? "\(error)" : nil)
                return
            }
        }
    }

    private func pingLoop() async {
        while await pause(PeerConnection.pingInterval), isLive {
            let silent = ContinuousClock.now - lastReceived.withLock { $0 }
            if silent > PeerConnection.idleTimeout {
                disconnect("no activity for \(silent.formatted)")
                return
            }
            send(.ping(UInt64.random(in: 0...UInt64.max)))
        }
    }

    private func dispatch(_ message: Message) {
        switch message {
        case .ping(let nonce): send(.pong(nonce))
        case .headers(let h): headers.deliver(h)
        case .cfHeaders(let m): cfHeaders.deliver(m)
        case .cfilter(let m): cfilters.deliver(m)
        case .block(let b): blockReplies.deliver(.block(b))
        case .notFound(let list): blockReplies.deliver(.notFound(list))
        case .tx, .inv, .addr, .addrV2: handler(self, message)
        default: break
        }
    }

    /// Queues a message for the peer. Transactions go out with their
    /// witness data.
    public func send(_ message: Message) {
        guard isLive else { return }
        stream.send(Wire.frame(message, magic: network.magic))
    }

    /// Disconnects the peer: pending and later requests fail, and quit
    /// fires. The reason, when given, is kept for the log.
    public func disconnect(_ why: String? = nil) {
        guard !quit.isFired else { return }
        if let why { reason.withLock { if $0 == nil { $0 = why } } }
        let error = PeerError("peer disconnected")
        headers.close(error)
        cfHeaders.close(error)
        cfilters.close(error)
        blockReplies.close(error)
        stream.close()
        quit.fire()
        for task in tasks.withLock({ $0 }) { task.cancel() }
    }

    /// Why the peer disconnected, when it was not asked to.
    public var disconnectReason: String? { reason.withLock { $0 } }

    /// Waits until the peer is disconnected.
    public func waitForDisconnect() async { await quit.wait() }
}
