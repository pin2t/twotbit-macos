import Foundation

/// PeerAddress is one candidate peer: a host, an IP address, onion or I2P
/// name, or a DNS seed name, and its TCP port.
public struct PeerAddress: Hashable, Sendable, CustomStringConvertible {
    public var host: String
    public var port: UInt16

    public init(host: String, port: UInt16) {
        self.host = host
        self.port = port
    }

    /// The dialable host:port form, the host in brackets when it is an IPv6
    /// address, as Go's net.JoinHostPort writes it.
    public var description: String { host.withPort(port) }

    /// Parses the host:port form.
    public init?(_ text: String) {
        guard let (host, port) = try? text.splitHostPort() else { return nil }
        self.init(host: host, port: port)
    }

    /// Which network the peer is on: Tor for an onion name, I2P for an I2P
    /// name and the internet otherwise.
    public var network: OverlayNetwork { OverlayNetwork.of(host) }
}

/// Namespace of the built-in peer lists.
public enum Seeds {
    /// The onion peers of the network to start from over Tor: mainnet nodes
    /// serving compact filters. Other networks have none.
    public static func onion(for network: Network) -> [PeerAddress] {
        network.kind == .mainnet ? onion : []
    }

    /// The I2P peers of the network to start from over I2P: mainnet nodes
    /// serving compact filters. Other networks have none.
    public static func i2p(for network: Network) -> [PeerAddress] {
        network.kind == .mainnet ? i2p : []
    }
}

public struct HostPortError: Error, Equatable, Sendable, CustomStringConvertible {
    public let description: String
}

/// Splitting and joining host:port addresses the way Go's net package
/// does, and IP addresses parsed and printed as Go's net.IP does.
extension String {
    /// The host joined with the port, an IPv6 host in brackets, as
    /// net.JoinHostPort does.
    public func withPort(_ port: UInt16) -> String {
        contains(":") ? "[\(self)]:\(port)" : "\(self):\(port)"
    }

    /// Splits host:port or [host]:port, as net.SplitHostPort does, and
    /// parses the port.
    public func splitHostPort() throws -> (String, UInt16) {
        let (host, portText) = try splitHostPortRaw()
        guard !portText.isEmpty, portText.allSatisfy(\.isASCIIDigit), let port = UInt16(portText) else {
            throw HostPortError(description: "address \(self): invalid port")
        }
        return (host, port)
    }

    /// Splits without parsing the port.
    public func splitHostPortRaw() throws -> (String, String) {
        guard let colon = lastIndex(of: ":") else {
            throw HostPortError(description: "address \(self): missing port in address")
        }
        let port = String(self[index(after: colon)...])
        var host: String
        if hasPrefix("[") {
            guard let close = firstIndex(of: "]") else {
                throw HostPortError(description: "address \(self): missing ']' in address")
            }
            guard index(after: close) == colon else {
                throw HostPortError(description: "address \(self): missing port in address")
            }
            host = String(self[index(after: startIndex)..<close])
            guard !host.contains("[") && !host.contains("]") else {
                throw HostPortError(description: "address \(self): unexpected bracket")
            }
        } else {
            host = String(self[..<colon])
            guard !host.contains(":") else {
                throw HostPortError(description: "address \(self): too many colons in address")
            }
            guard !host.contains("[") && !host.contains("]") else {
                throw HostPortError(description: "address \(self): unexpected bracket")
            }
        }
        return (host, port)
    }

    /// The 16-byte form of an IPv4 or IPv6 address, IPv4 mapped into IPv6,
    /// or nil for text that is not an IP address.
    public var ipBytes: [UInt8]? {
        var v4 = in_addr()
        if inet_pton(AF_INET, self, &v4) == 1 {
            let raw = withUnsafeBytes(of: v4) { [UInt8]($0) }
            return [UInt8](repeating: 0, count: 10) + [0xff, 0xff] + raw
        }
        var v6 = in6_addr()
        if inet_pton(AF_INET6, self, &v6) == 1 {
            return withUnsafeBytes(of: v6) { [UInt8]($0) }
        }
        return nil
    }

    /// Whether the text is an IPv4 or IPv6 address.
    public var isIP: Bool { ipBytes != nil }

    /// The canonical text of an IP address: dotted for IPv4 and IPv4-mapped
    /// IPv6, RFC 5952 for IPv6. Text that is not an IP gives nil.
    public var canonicalIP: String? { ipBytes?.ipString }
}

extension [UInt8] {
    /// The text of a 4- or 16-byte IP address.
    public var ipString: String {
        if count == 4 { return map(String.init).joined(separator: ".") }
        if count == 16 && self[0..<10].allSatisfy({ $0 == 0 }) && self[10] == 0xff && self[11] == 0xff {
            return self[12...].map(String.init).joined(separator: ".")
        }
        guard count == 16 else { return "?" }
        var words = [UInt16]()
        for i in stride(from: 0, to: 16, by: 2) { words.append(UInt16(self[i]) << 8 | UInt16(self[i + 1])) }
        var bestStart = -1, bestLength = 0, start = -1
        for i in 0...8 {
            if i < 8 && words[i] == 0 {
                if start < 0 { start = i }
            } else if start >= 0 {
                if i - start > bestLength { bestStart = start; bestLength = i - start }
                start = -1
            }
        }
        if bestLength < 2 { bestStart = -1 }
        var out = ""
        var i = 0
        while i < 8 {
            if i == bestStart {
                out += "::"
                i += bestLength
                continue
            }
            if !out.isEmpty && !out.hasSuffix(":") { out += ":" }
            out += String(words[i], radix: 16)
            i += 1
        }
        return out
    }
}
