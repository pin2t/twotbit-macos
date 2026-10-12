import Foundation

/// DecodeError is returned when serialized data cannot be read: it ends
/// early, or holds a value the format does not allow.
public enum DecodeError: Error, Equatable, Sendable, CustomStringConvertible {
    case truncated
    case invalid(String)

    public var description: String {
        switch self {
        case .truncated: return "data ends early"
        case .invalid(let what): return what
        }
    }
}

extension Data {
    /// The bytes in lower case hex.
    public var hex: String {
        var out = [UInt8]()
        out.reserveCapacity(count * 2)
        let digits = Array("0123456789abcdef".utf8)
        for byte in self {
            out.append(digits[Int(byte >> 4)])
            out.append(digits[Int(byte & 0x0f)])
        }
        return String(decoding: out, as: UTF8.self)
    }

    /// Parses hex, upper or lower case, without separators. It fails on an odd
    /// length or a character that is not a hex digit.
    public init?(hex: String) {
        let chars = Array(hex.utf8)
        guard chars.count % 2 == 0 else { return nil }
        var bytes = [UInt8]()
        bytes.reserveCapacity(chars.count / 2)
        var i = 0
        while i < chars.count {
            guard let hi = hexValue(chars[i]), let lo = hexValue(chars[i + 1]) else { return nil }
            bytes.append(hi << 4 | lo)
            i += 2
        }
        self.init(bytes)
    }
}

private func hexValue(_ c: UInt8) -> UInt8? {
    switch c {
    case UInt8(ascii: "0")...UInt8(ascii: "9"): return c - UInt8(ascii: "0")
    case UInt8(ascii: "a")...UInt8(ascii: "f"): return c - UInt8(ascii: "a") + 10
    case UInt8(ascii: "A")...UInt8(ascii: "F"): return c - UInt8(ascii: "A") + 10
    default: return nil
    }
}

/// ByteWriter builds serialized data: little-endian integers, Bitcoin
/// compact sizes and length-prefixed byte strings.
public struct ByteWriter: Sendable {
    public private(set) var data: Data

    public init(capacity: Int = 0) {
        data = Data()
        data.reserveCapacity(capacity)
    }

    public mutating func write(_ bytes: Data) { data.append(bytes) }
    public mutating func write(_ bytes: [UInt8]) { data.append(contentsOf: bytes) }
    public mutating func write(_ hash: Hash256) { hash.append(to: &data) }
    public mutating func writeUInt8(_ v: UInt8) { data.append(v) }
    public mutating func writeBool(_ v: Bool) { data.append(v ? 1 : 0) }

    public mutating func writeUInt16(_ v: UInt16) { appendLE(v) }
    public mutating func writeUInt32(_ v: UInt32) { appendLE(v) }
    public mutating func writeInt32(_ v: Int32) { appendLE(UInt32(bitPattern: v)) }
    public mutating func writeUInt64(_ v: UInt64) { appendLE(v) }
    public mutating func writeInt64(_ v: Int64) { appendLE(UInt64(bitPattern: v)) }

    /// Writes a port, which the protocol sends big-endian.
    public mutating func writeUInt16BE(_ v: UInt16) {
        data.append(UInt8(v >> 8))
        data.append(UInt8(v & 0xff))
    }

    /// Writes a Bitcoin compact size.
    public mutating func writeVarInt(_ v: UInt64) {
        switch v {
        case ..<0xfd:
            data.append(UInt8(v))
        case ...0xffff:
            data.append(0xfd)
            appendLE(UInt16(v))
        case ...0xffff_ffff:
            data.append(0xfe)
            appendLE(UInt32(v))
        default:
            data.append(0xff)
            appendLE(v)
        }
    }

    /// Writes the bytes preceded by their length as a compact size.
    public mutating func writeVarBytes(_ bytes: Data) {
        writeVarInt(UInt64(bytes.count))
        data.append(bytes)
    }

    private mutating func appendLE<T: FixedWidthInteger>(_ v: T) {
        withUnsafeBytes(of: v.littleEndian) { data.append(contentsOf: $0) }
    }
}

/// The size in bytes of a compact size holding the value.
public func varIntSize(_ v: UInt64) -> Int {
    switch v {
    case ..<0xfd: return 1
    case ...0xffff: return 3
    case ...0xffff_ffff: return 5
    default: return 9
    }
}

/// ByteReader reads serialized data front to back: little-endian integers,
/// canonical Bitcoin compact sizes and length-prefixed byte strings. Every
/// read past the end throws DecodeError.truncated.
public struct ByteReader {
    private let bytes: [UInt8]
    public private(set) var offset = 0

    public init(_ data: Data) { bytes = [UInt8](data) }
    public init(_ bytes: [UInt8]) { self.bytes = bytes }

    public var remaining: Int { bytes.count - offset }
    public var isAtEnd: Bool { offset >= bytes.count }

    public mutating func readBytes(_ n: Int) throws -> Data {
        guard n >= 0, remaining >= n else { throw DecodeError.truncated }
        defer { offset += n }
        return Data(bytes[offset..<offset + n])
    }

    public mutating func readByteArray(_ n: Int) throws -> [UInt8] {
        guard n >= 0, remaining >= n else { throw DecodeError.truncated }
        defer { offset += n }
        return Array(bytes[offset..<offset + n])
    }

    public mutating func skip(_ n: Int) throws {
        guard n >= 0, remaining >= n else { throw DecodeError.truncated }
        offset += n
    }

    public mutating func readUInt8() throws -> UInt8 {
        guard remaining >= 1 else { throw DecodeError.truncated }
        defer { offset += 1 }
        return bytes[offset]
    }

    public func peekUInt8(at ahead: Int = 0) throws -> UInt8 {
        guard remaining > ahead else { throw DecodeError.truncated }
        return bytes[offset + ahead]
    }

    public mutating func readBool() throws -> Bool { try readUInt8() != 0 }
    public mutating func readUInt16() throws -> UInt16 { try readLE() }
    public mutating func readUInt32() throws -> UInt32 { try readLE() }
    public mutating func readInt32() throws -> Int32 { Int32(bitPattern: try readLE()) }
    public mutating func readUInt64() throws -> UInt64 { try readLE() }
    public mutating func readInt64() throws -> Int64 { Int64(bitPattern: try readLE()) }

    public mutating func readUInt16BE() throws -> UInt16 {
        let hi = try readUInt8()
        let lo = try readUInt8()
        return UInt16(hi) << 8 | UInt16(lo)
    }

    public mutating func readHash() throws -> Hash256 {
        guard remaining >= 32 else { throw DecodeError.truncated }
        defer { offset += 32 }
        return bytes.withUnsafeBufferPointer { Hash256(raw: UnsafeRawBufferPointer(rebasing: UnsafeRawBufferPointer($0)[offset..<offset + 32])) }
    }

    /// Reads a compact size, refusing a non-canonical encoding as Bitcoin
    /// Core and btcd do.
    public mutating func readVarInt() throws -> UInt64 {
        let first = try readUInt8()
        switch first {
        case 0xfd:
            let v = UInt64(try readUInt16())
            guard v >= 0xfd else { throw DecodeError.invalid("non-canonical compact size") }
            return v
        case 0xfe:
            let v = UInt64(try readUInt32())
            guard v > 0xffff else { throw DecodeError.invalid("non-canonical compact size") }
            return v
        case 0xff:
            let v = try readUInt64()
            guard v > 0xffff_ffff else { throw DecodeError.invalid("non-canonical compact size") }
            return v
        default:
            return UInt64(first)
        }
    }

    /// Reads a count that sizes what follows: a compact size no larger than
    /// limit, so a hostile length cannot allocate without bound.
    public mutating func readCount(limit: Int) throws -> Int {
        let n = try readVarInt()
        guard n <= UInt64(limit) else { throw DecodeError.invalid("count \(n) exceeds \(limit)") }
        return Int(n)
    }

    /// Reads bytes preceded by their length as a compact size, no longer
    /// than limit.
    public mutating func readVarBytes(limit: Int = 4_000_000) throws -> Data {
        let n = try readCount(limit: limit)
        return try readBytes(n)
    }

    private mutating func readLE<T: FixedWidthInteger>() throws -> T {
        let size = MemoryLayout<T>.size
        guard remaining >= size else { throw DecodeError.truncated }
        var v = T.zero
        for i in 0..<size {
            v |= T(bytes[offset + i]) << (8 * i)
        }
        offset += size
        return v
    }
}
