import Foundation
import Network
import Synchronization

/// NetError is a failed connection, with the short reason the settings
/// show for a peer that could not be reached.
public struct NetError: Error, CustomStringConvertible, Sendable {
    public enum Kind: Sendable, Equatable {
        case timeout
        case refused
        case unreachable
        case closed
        case other
    }

    public let kind: Kind
    public let description: String

    init(_ kind: Kind, _ description: String) {
        self.kind = kind
        self.description = description
    }

    static func from(_ error: NWError) -> NetError {
        switch error {
        case .posix(let code):
            switch code {
            case .ECONNREFUSED: return NetError(.refused, "connection refused")
            case .ETIMEDOUT: return NetError(.timeout, "i/o timeout")
            case .ENETUNREACH, .EHOSTUNREACH, .EHOSTDOWN, .ENETDOWN: return NetError(.unreachable, String(cString: strerror(code.rawValue)).lowercased())
            case .ECONNRESET, .EPIPE, .ENOTCONN, .ECANCELED: return NetError(.closed, String(cString: strerror(code.rawValue)).lowercased())
            default: return NetError(.other, String(cString: strerror(code.rawValue)).lowercased())
            }
        case .dns(let code): return NetError(.unreachable, "no such host (\(code))")
        default: return NetError(.other, error.localizedDescription)
        }
    }
}

/// TCPStream is a TCP connection read as a byte stream: exact lengths for
/// protocol messages and lines for the I2P SAM bridge, from one buffer, so
/// bytes read past a line are not lost. TCP keepalives drop a peer that
/// went silent within KeepAlive.
public final class TCPStream: Sendable {
    /// How long a connection may stay silent, its keepalive probes
    /// unanswered, before it is dropped: the first probe goes out after
    /// half of it, then three probes, the last timing out at the end.
    public static let keepAlive = 30

    private let connection: NWConnection
    private let queue: DispatchQueue
    private let buffer = Mutex(Data())
    private let closed = Mutex<NetError?>(nil)
    public let remote: String

    private init(connection: NWConnection, queue: DispatchQueue, remote: String) {
        self.connection = connection
        self.queue = queue
        self.remote = remote
    }

    /// Connects to the host and port, an IP address or a host name, giving
    /// up after the timeout or when the task is cancelled. System proxies
    /// are not used: peers are reached directly unless a Tor or I2P dialer
    /// is chosen.
    public static func connect(host: String, port: UInt16, timeout: Duration) async throws -> TCPStream {
        let tcp = NWProtocolTCP.Options()
        tcp.noDelay = true
        tcp.enableKeepalive = true
        tcp.keepaliveIdle = keepAlive / 2
        tcp.keepaliveInterval = keepAlive / 2 / 3
        tcp.keepaliveCount = 3
        tcp.connectionTimeout = max(1, Int(timeout.components.seconds))
        let parameters = NWParameters(tls: nil, tcp: tcp)
        parameters.preferNoProxies = true
        guard let nwPort = NWEndpoint.Port(rawValue: port) else { throw NetError(.other, "invalid port \(port)") }
        let connection = NWConnection(host: NWEndpoint.Host(host), port: nwPort, using: parameters)
        let queue = DispatchQueue(label: "twotbit.tcp.\(host)")
        let stream = TCPStream(connection: connection, queue: queue, remote: host.withPort(port))
        try await stream.start(timeout: timeout)
        return stream
    }

    /// Wraps a connection a listener accepted, as test nodes serve the
    /// wallet.
    static func accept(_ connection: NWConnection) async throws -> TCPStream {
        let stream = TCPStream(connection: connection, queue: DispatchQueue(label: "twotbit.tcp.accepted"), remote: "\(connection.endpoint)")
        try await stream.start(timeout: .seconds(5))
        return stream
    }

    private func start(timeout: Duration) async throws {
        let resumed = Mutex(false)
        let connection = self.connection
        let queue = self.queue
        do {
            try await withTimeout(timeout, "dial \(remote)") {
                try await withTaskCancellationHandler {
                    try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
                        let finish: @Sendable (Result<Void, Error>) -> Void = { result in
                            let first = resumed.withLock { done -> Bool in
                                defer { done = true }
                                return !done
                            }
                            if first { continuation.resume(with: result) }
                        }
                        connection.stateUpdateHandler = { state in
                            switch state {
                            case .ready: finish(.success(()))
                            case .failed(let error): finish(.failure(NetError.from(error)))
                            case .waiting(let error): finish(.failure(NetError.from(error)))
                            case .cancelled: finish(.failure(NetError(.closed, "connection cancelled")))
                            default: break
                            }
                        }
                        connection.start(queue: queue)
                    }
                } onCancel: {
                    connection.cancel()
                }
            }
        } catch let error as TimeoutError {
            connection.cancel()
            throw NetError(.timeout, error.description)
        } catch {
            connection.cancel()
            throw error
        }
        connection.stateUpdateHandler = { [weak self] state in
            switch state {
            case .failed(let error): self?.markClosed(NetError.from(error))
            case .cancelled: self?.markClosed(NetError(.closed, "connection closed"))
            default: break
            }
        }
    }

    private func markClosed(_ error: NetError) {
        closed.withLock { if $0 == nil { $0 = error } }
    }

    /// Whether the connection was closed or failed.
    public var isClosed: Bool { closed.withLock { $0 != nil } }

    /// Closes the connection; pending and later reads and writes fail.
    public func close() {
        markClosed(NetError(.closed, "connection closed"))
        connection.cancel()
    }

    /// Queues the bytes for sending without waiting. A failed send closes
    /// the connection.
    public func send(_ data: Data) {
        connection.send(content: data, completion: .contentProcessed { [weak self] error in
            if let error {
                self?.markClosed(NetError.from(error))
                self?.connection.cancel()
            }
        })
    }

    /// Sends the bytes and waits until they are handed to the network.
    public func write(_ data: Data) async throws {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            connection.send(content: data, completion: .contentProcessed { error in
                if let error { continuation.resume(throwing: NetError.from(error)) } else { continuation.resume() }
            })
        }
    }

    /// Reads more bytes into the buffer.
    private func fill() async throws {
        if let error = closed.withLock({ $0 }) { throw error }
        let connection = self.connection
        let chunk: Data = try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Data, Error>) in
                connection.receive(minimumIncompleteLength: 1, maximumLength: 1 << 16) { data, _, isComplete, error in
                    if let error {
                        continuation.resume(throwing: NetError.from(error))
                    } else if let data, !data.isEmpty {
                        continuation.resume(returning: data)
                    } else if isComplete {
                        continuation.resume(throwing: NetError(.closed, "EOF"))
                    } else {
                        continuation.resume(returning: Data())
                    }
                }
            }
        } onCancel: {
            connection.cancel()
        }
        buffer.withLock { $0.append(chunk) }
    }

    /// Reads exactly count bytes.
    public func read(_ count: Int) async throws -> Data {
        while true {
            let out = buffer.withLock { b -> Data? in
                guard b.count >= count else { return nil }
                let head = Data(b.prefix(count))
                b.removeFirst(count)
                return head
            }
            if let out { return out }
            try await fill()
        }
    }

    /// Reads whatever bytes are buffered or arrive next.
    func readAvailable() async throws -> Data {
        while true {
            let out = buffer.withLock { b -> Data? in
                guard !b.isEmpty else { return nil }
                defer { b.removeAll() }
                return b
            }
            if let out { return out }
            try await fill()
        }
    }

    /// Reads one line, without its newline.
    public func readLine(limit: Int = 64 * 1024) async throws -> String {
        while true {
            let line = buffer.withLock { b -> Data? in
                guard let nl = b.firstIndex(of: UInt8(ascii: "\n")) else { return nil }
                let head = Data(b[b.startIndex..<nl])
                b.removeSubrange(b.startIndex...nl)
                return head
            }
            if let line { return String(decoding: line, as: UTF8.self) }
            if buffer.withLock({ $0.count }) > limit { throw NetError(.other, "line too long") }
            try await fill()
        }
    }
}

/// Dialer opens connections to peers: directly on the internet, or through
/// the client of an anonymity network.
public protocol Dialer: Sendable {
    func dial(host: String, port: UInt16, timeout: Duration) async throws -> TCPStream
}

/// DirectDialer connects to peers on the internet over plain TCP.
public struct DirectDialer: Dialer {
    public init() {}

    public func dial(host: String, port: UInt16, timeout: Duration) async throws -> TCPStream {
        try await TCPStream.connect(host: host, port: port, timeout: timeout)
    }
}

/// DNS resolves the network's seed names to peer addresses.
public enum DNS {
    /// The IPv4 and IPv6 addresses of the host name, empty when it does not
    /// resolve.
    public static func lookup(_ host: String) async -> [String] {
        await Task.detached {
            var hints = addrinfo()
            hints.ai_family = AF_UNSPEC
            hints.ai_socktype = SOCK_STREAM
            var result: UnsafeMutablePointer<addrinfo>?
            guard getaddrinfo(host, nil, &hints, &result) == 0 else { return [String]() }
            defer { freeaddrinfo(result) }
            var out = [String]()
            var cursor = result
            while let info = cursor {
                var buffer = [CChar](repeating: 0, count: Int(NI_MAXHOST))
                if getnameinfo(info.pointee.ai_addr, info.pointee.ai_addrlen, &buffer, socklen_t(buffer.count), nil, 0, NI_NUMERICHOST) == 0 {
                    let ip = String(decoding: buffer.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) }, as: UTF8.self)
                    if !out.contains(ip) { out.append(ip) }
                }
                cursor = info.pointee.ai_next
            }
            return out
        }.value
    }

    /// Every peer address the network's DNS seeds advertise, looked up all
    /// at once.
    public static func seeds(_ network: Network) async -> [PeerAddress] {
        await withTaskGroup(of: [PeerAddress].self) { group in
            for seed in network.dnsSeeds {
                group.addTask { await lookup(seed.host).map { PeerAddress(host: $0, port: seed.port) } }
            }
            var out = [PeerAddress]()
            for await list in group { out += list }
            return out
        }
    }
}
