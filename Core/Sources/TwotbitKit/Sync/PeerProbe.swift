import Foundation

/// PeerProbe checks a peer typed in the settings before the sync is pinned
/// to it.
public enum PeerProbe {
    /// NoCompactFilters is a peer that does not serve the BIP157 filters the
    /// wallet syncs from.
    public struct NoCompactFilters: Error, CustomStringConvertible, Sendable {
        public let address: String
        public var description: String { "\(address): no compact filter service" }
    }

    /// Reads a peer typed as an IP address with a port, or without one,
    /// which takes the network's default port, and returns it in host:port
    /// form; nil for anything else.
    public static func parse(_ text: String, defaultPort: UInt16) -> String? {
        var bare = text
        if bare.hasPrefix("[") && bare.hasSuffix("]") { bare = String(bare.dropFirst().dropLast()) }
        if let ip = IPAddress.canonical(bare) { return HostPort.join(ip, defaultPort) }
        guard let (host, port) = try? HostPort.splitRaw(text), let ip = IPAddress.canonical(host),
              !port.isEmpty, port.allSatisfy(\.isASCIIDigit), let num = UInt16(port), num != 0 else { return nil }
        return HostPort.join(ip, num)
    }

    /// Connects directly to the peer, completes the handshake and checks it
    /// serves compact filters, then disconnects.
    public static func probe(network: Network, address: String) async throws {
        let (peer, _) = try await PeerConnection.connect(network: network, address: address, dialer: DirectDialer(), relay: false) { _, _ in }
        defer { peer.disconnect() }
        guard peer.services.contains(.compactFilters) else { throw NoCompactFilters(address: address) }
    }

    /// Why a peer could not be connected to, briefly.
    public static func reason(_ error: Error) -> String {
        switch error {
        case is NoCompactFilters:
            return "no compact filters (needs blockfilterindex=1 and peerblockfilters=1)"
        case let e as PeerError:
            return e.underlying.map(reason) ?? "no handshake"
        case is TimeoutError:
            return "no answer"
        case let e as NetError:
            switch e.kind {
            case .timeout: return "no answer"
            case .closed: return "no handshake"
            default: return e.description
            }
        default:
            return "no handshake"
        }
    }
}
