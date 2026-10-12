import Foundation

/// Hash256 is a 32-byte double SHA256 hash, such as a block hash or a
/// transaction id, kept in its internal byte order. Its text form is the
/// reverse byte order the Bitcoin tools show.
public struct Hash256: Hashable, Sendable, Comparable, CustomStringConvertible {
    /// The bytes as four little-endian words: w0 holds bytes 0-7.
    public var w0: UInt64
    public var w1: UInt64
    public var w2: UInt64
    public var w3: UInt64

    public static let zero = Hash256(w0: 0, w1: 0, w2: 0, w3: 0)

    public init(w0: UInt64, w1: UInt64, w2: UInt64, w3: UInt64) {
        self.w0 = w0
        self.w1 = w1
        self.w2 = w2
        self.w3 = w3
    }

    /// Reads 32 bytes in internal order.
    public init(raw: UnsafeRawBufferPointer) {
        precondition(raw.count == 32, "a hash is 32 bytes")
        w0 = UInt64(littleEndian: raw.loadUnaligned(fromByteOffset: 0, as: UInt64.self))
        w1 = UInt64(littleEndian: raw.loadUnaligned(fromByteOffset: 8, as: UInt64.self))
        w2 = UInt64(littleEndian: raw.loadUnaligned(fromByteOffset: 16, as: UInt64.self))
        w3 = UInt64(littleEndian: raw.loadUnaligned(fromByteOffset: 24, as: UInt64.self))
    }

    /// Reads 32 bytes in internal order; other lengths give nil.
    public init?(data: Data) {
        guard data.count == 32 else { return nil }
        self = data.withUnsafeBytes { Hash256(raw: $0) }
    }

    /// Reads 32 bytes in internal order; other lengths give nil.
    public init?(bytes: [UInt8]) {
        guard bytes.count == 32 else { return nil }
        self = bytes.withUnsafeBytes { Hash256(raw: $0) }
    }

    /// Parses the displayed, byte-reversed hex form.
    public init?(hex: String) {
        guard hex.utf8.count == 64, let data = Data(hex: hex) else { return nil }
        self.init(data: Data(data.reversed()))
    }

    /// The bytes in internal order.
    public var data: Data {
        var out = Data(capacity: 32)
        append(to: &out)
        return out
    }

    public var bytes: [UInt8] { [UInt8](data) }

    /// Appends the bytes in internal order.
    public func append(to out: inout Data) {
        for word in [w0, w1, w2, w3] {
            withUnsafeBytes(of: word.littleEndian) { out.append(contentsOf: $0) }
        }
    }

    /// The displayed hex form: the bytes reversed, as block explorers show
    /// block hashes and transaction ids.
    public var hex: String { Data(data.reversed()).hex }

    public var description: String { hex }

    /// Hashes compare as the numbers their displayed form spells, which is
    /// also the order BIP69 sorts transaction inputs in.
    public static func < (a: Hash256, b: Hash256) -> Bool {
        UInt256(a) < UInt256(b)
    }
}
