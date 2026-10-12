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
    public var description: String { HostPort.join(host, port) }

    /// Parses the host:port form.
    public init?(_ text: String) {
        guard let (host, port) = try? HostPort.split(text) else { return nil }
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

/// HostPort splits and joins host:port addresses the way Go's net package
/// does.
public enum HostPort {
    public static func join(_ host: String, _ port: UInt16) -> String {
        host.contains(":") ? "[\(host)]:\(port)" : "\(host):\(port)"
    }

    /// Splits host:port or [host]:port, as net.SplitHostPort does, and
    /// parses the port.
    public static func split(_ text: String) throws -> (String, UInt16) {
        let (host, portText) = try splitRaw(text)
        guard !portText.isEmpty, portText.allSatisfy(\.isASCIIDigit), let port = UInt16(portText) else {
            throw HostPortError(description: "address \(text): invalid port")
        }
        return (host, port)
    }

    /// Splits without parsing the port.
    public static func splitRaw(_ text: String) throws -> (String, String) {
        guard let colon = text.lastIndex(of: ":") else {
            throw HostPortError(description: "address \(text): missing port in address")
        }
        let port = String(text[text.index(after: colon)...])
        var host: String
        if text.hasPrefix("[") {
            guard let close = text.firstIndex(of: "]") else {
                throw HostPortError(description: "address \(text): missing ']' in address")
            }
            guard text.index(after: close) == colon else {
                throw HostPortError(description: "address \(text): missing port in address")
            }
            host = String(text[text.index(after: text.startIndex)..<close])
            guard !host.contains("[") && !host.contains("]") else {
                throw HostPortError(description: "address \(text): unexpected bracket")
            }
        } else {
            host = String(text[..<colon])
            guard !host.contains(":") else {
                throw HostPortError(description: "address \(text): too many colons in address")
            }
            guard !host.contains("[") && !host.contains("]") else {
                throw HostPortError(description: "address \(text): unexpected bracket")
            }
        }
        return (host, port)
    }
}

/// IPAddress parses and prints IP addresses as Go's net.IP does.
public enum IPAddress {
    /// The 16-byte form of an IPv4 or IPv6 address, IPv4 mapped into IPv6,
    /// or nil for text that is not an IP address.
    public static func bytes(_ text: String) -> [UInt8]? {
        var v4 = in_addr()
        if inet_pton(AF_INET, text, &v4) == 1 {
            let raw = withUnsafeBytes(of: v4) { [UInt8]($0) }
            return [UInt8](repeating: 0, count: 10) + [0xff, 0xff] + raw
        }
        var v6 = in6_addr()
        if inet_pton(AF_INET6, text, &v6) == 1 {
            return withUnsafeBytes(of: v6) { [UInt8]($0) }
        }
        return nil
    }

    /// Whether the text is an IPv4 or IPv6 address.
    public static func isIP(_ text: String) -> Bool { bytes(text) != nil }

    /// The canonical text of an IP address: dotted for IPv4 and IPv4-mapped
    /// IPv6, RFC 5952 for IPv6. Text that is not an IP gives nil.
    public static func canonical(_ text: String) -> String? {
        guard let raw = bytes(text) else { return nil }
        return string(raw)
    }

    /// The text of a 4- or 16-byte address.
    public static func string(_ raw: [UInt8]) -> String {
        if raw.count == 4 { return raw.map(String.init).joined(separator: ".") }
        if raw.count == 16 && raw[0..<10].allSatisfy({ $0 == 0 }) && raw[10] == 0xff && raw[11] == 0xff {
            return raw[12...].map(String.init).joined(separator: ".")
        }
        guard raw.count == 16 else { return "?" }
        var words = [UInt16]()
        for i in stride(from: 0, to: 16, by: 2) { words.append(UInt16(raw[i]) << 8 | UInt16(raw[i + 1])) }
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
