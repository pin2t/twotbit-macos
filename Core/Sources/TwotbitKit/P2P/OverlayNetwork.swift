import Foundation

/// OverlayNetwork is how a peer is reached: directly over the internet, as
/// an onion service over Tor, or as an I2P destination over I2P.
public enum OverlayNetwork: Int, Sendable, Hashable, CaseIterable, CustomStringConvertible {
    case direct = 0
    case tor = 1
    case i2p = 2

    public var description: String {
        switch self {
        case .direct: return "direct"
        case .tor: return "Tor"
        case .i2p: return "I2P"
        }
    }

    /// The network a peer host is on.
    public static func of(_ host: String) -> OverlayNetwork {
        if host.isOnion { return .tor }
        if host.isI2P { return .i2p }
        return .direct
    }
}

/// OverlayState is how far the client of an anonymity network, Tor or I2P,
/// got: it starts, is ready to dial peers, or failed and retries.
public enum OverlayState: Sendable, Equatable {
    case starting
    case ready
    case failed(String)
}

/// Onion and I2P names.
enum Onion {
    /// The version byte of a v3 onion address, and the length of its name
    /// without the ".onion" suffix: the base32 encoding of the 32-byte
    /// service key, a 2-byte checksum and the version.
    static let version: UInt8 = 3
    static let nameLength = 56

    /// The length of an I2P b32 name without ".b32.i2p": the unpadded
    /// base32 encoding of the SHA-256 hash of the destination.
    static let i2pLength = 52

    static func checksum(_ key: Data) -> Data {
        (Data(".onion checksum".utf8) + key + Data([version])).sha3_256().prefix(2)
    }
}

extension String {
    /// Whether the host is a v3 onion service address with a valid
    /// checksum.
    public var isOnion: Bool { onionKey != nil }

    /// The 32-byte service key of a v3 onion address, its version and
    /// checksum checked.
    public var onionKey: Data? {
        let lower = lowercased()
        guard lower.hasSuffix(".onion") else { return nil }
        let name = String(lower.dropLast(6))
        guard name.utf8.count == Onion.nameLength, let raw = name.base32Decoded(), raw.count == 35 else { return nil }
        let key = raw.prefix(32)
        guard raw[raw.startIndex + 34] == Onion.version, raw.subdata(in: raw.startIndex + 32..<raw.startIndex + 34) == Onion.checksum(Data(key)) else {
            return nil
        }
        return Data(key)
    }

    /// Whether the host is an I2P b32 address.
    public var isI2P: Bool {
        let lower = lowercased()
        guard lower.hasSuffix(".b32.i2p") else { return false }
        let name = String(lower.dropLast(8))
        guard name.utf8.count == Onion.i2pLength, let raw = name.base32Decoded() else { return false }
        return raw.count == 32
    }
}

extension Data {
    /// The v3 onion address of a 32-byte service key, as rend-spec-v3 and
    /// BIP155 define it.
    public var onionAddress: String {
        (self + Onion.checksum(self) + Data([Onion.version])).base32Encoded() + ".onion"
    }
}
