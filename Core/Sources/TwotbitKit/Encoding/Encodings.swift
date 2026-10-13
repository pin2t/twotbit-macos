import Foundation

/// Base58 and Base58Check, the encoding of legacy addresses and extended
/// keys.
enum Base58 {
    static let alphabet = Array("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz".utf8)
    static let indexes: [Int8] = {
        var table = [Int8](repeating: -1, count: 128)
        for (i, c) in alphabet.enumerated() { table[Int(c)] = Int8(i) }
        return table
    }()
}

extension Data {
    /// The bytes in Base58.
    public func base58Encoded() -> String {
        let alphabet = Base58.alphabet
        let bytes = [UInt8](self)
        let zeros = bytes.prefix { $0 == 0 }.count
        var digits = [UInt8]()
        for byte in bytes {
            var carry = Int(byte)
            for i in 0..<digits.count {
                carry += Int(digits[i]) << 8
                digits[i] = UInt8(carry % 58)
                carry /= 58
            }
            while carry > 0 {
                digits.append(UInt8(carry % 58))
                carry /= 58
            }
        }
        var out = [UInt8](repeating: alphabet[0], count: zeros)
        for digit in digits.reversed() { out.append(alphabet[Int(digit)]) }
        return String(decoding: out, as: UTF8.self)
    }

    /// The bytes with their 4-byte double SHA256 checksum, in Base58.
    public func base58ChecksumEncoded() -> String {
        (self + sha256d().data.prefix(4)).base58Encoded()
    }

    /// Lower case Base32 of RFC 4648 without padding, the encoding of onion
    /// and I2P names.
    public func base32Encoded() -> String {
        let alphabet = Base32.alphabet
        var out = [UInt8]()
        var buffer = 0
        var bits = 0
        for byte in self {
            buffer = (buffer << 8 | Int(byte)) & 0xffff
            bits += 8
            while bits >= 5 {
                bits -= 5
                out.append(alphabet[(buffer >> bits) & 31])
            }
        }
        if bits > 0 { out.append(alphabet[(buffer << (5 - bits)) & 31]) }
        return String(decoding: out, as: UTF8.self).lowercased()
    }

    /// The program as a segwit address: version 0 in Bech32, later versions
    /// in Bech32m.
    public func segwitEncoded(hrp: String, version: UInt8) -> String {
        let data = [version] + Bech32.convertBits([UInt8](self), from: 8, to: 5, pad: true)!
        return data.bech32Encoded(hrp: hrp, variant: version == 0 ? .bech32 : .bech32m)
    }
}

extension String {
    /// The bytes of Base58 text.
    public func base58Decoded() -> Data? {
        let alphabet = Base58.alphabet, indexes = Base58.indexes
        let chars = Array(utf8)
        let zeros = chars.prefix { $0 == alphabet[0] }.count
        var bytes = [UInt8]()
        for c in chars {
            guard c < 128, indexes[Int(c)] >= 0 else { return nil }
            var carry = Int(indexes[Int(c)])
            for i in 0..<bytes.count {
                carry += Int(bytes[i]) * 58
                bytes[i] = UInt8(carry & 0xff)
                carry >>= 8
            }
            while carry > 0 {
                bytes.append(UInt8(carry & 0xff))
                carry >>= 8
            }
        }
        return Data(repeating: 0, count: zeros) + Data(bytes.reversed())
    }

    /// The payload of Base58Check text, when its checksum matches.
    public func base58ChecksumDecoded() -> Data? {
        guard let raw = base58Decoded(), raw.count >= 4 else { return nil }
        let payload = Data(raw.prefix(raw.count - 4))
        guard payload.sha256d().data.prefix(4) == raw.suffix(4) else { return nil }
        return payload
    }

    /// The bytes of upper or lower case Base32 text without padding. Bits
    /// left over past the last whole byte are dropped, as Go's decoder does.
    public func base32Decoded() -> Data? {
        var out = [UInt8]()
        var buffer = 0
        var bits = 0
        for c in uppercased().utf8 {
            guard let value = Base32.alphabet.firstIndex(of: c) else { return nil }
            buffer = (buffer << 5 | value) & 0xffff
            bits += 5
            if bits >= 8 {
                bits -= 8
                out.append(UInt8((buffer >> bits) & 0xff))
            }
        }
        let rem = utf8.count % 8
        guard [0, 2, 4, 5, 7].contains(rem) else { return nil }
        return Data(out)
    }

    /// Decodes Bech32 or Bech32m text into its lower case human readable
    /// part, its 5-bit data and the variant its checksum matches.
    public func bech32Decoded() -> (hrp: String, data: [UInt8], variant: Bech32.Variant)? {
        let chars = Array(utf8)
        guard chars.count <= 90 else { return nil }
        let hasLower = chars.contains { $0 >= UInt8(ascii: "a") && $0 <= UInt8(ascii: "z") }
        let hasUpper = chars.contains { $0 >= UInt8(ascii: "A") && $0 <= UInt8(ascii: "Z") }
        guard !(hasLower && hasUpper) else { return nil }
        let lower = chars.map { $0 >= UInt8(ascii: "A") && $0 <= UInt8(ascii: "Z") ? $0 + 32 : $0 }
        guard let sep = lower.lastIndex(of: UInt8(ascii: "1")), sep >= 1, sep + 7 <= lower.count else { return nil }
        let hrp = Array(lower[0..<sep])
        guard hrp.allSatisfy({ $0 >= 33 && $0 <= 126 }) else { return nil }
        var data = [UInt8]()
        for c in lower[(sep + 1)...] {
            guard let i = Bech32.charset.firstIndex(of: c) else { return nil }
            data.append(UInt8(i))
        }
        let mod = Bech32.polymod(Bech32.expand(hrp) + data)
        let variant: Bech32.Variant
        switch mod {
        case Bech32.Variant.bech32.constant: variant = .bech32
        case Bech32.Variant.bech32m.constant: variant = .bech32m
        default: return nil
        }
        return (String(decoding: hrp, as: UTF8.self), Array(data.dropLast(6)), variant)
    }

    /// The witness version and program of a segwit address of the human
    /// readable part, enforcing the BIP173 and BIP350 rules.
    public func segwitDecoded(hrp: String) -> (version: UInt8, program: Data)? {
        guard let decoded = bech32Decoded(), decoded.hrp == hrp.lowercased(), let version = decoded.data.first, version <= 16,
              let program = Bech32.convertBits(Array(decoded.data.dropFirst()), from: 5, to: 8, pad: false),
              program.count >= 2, program.count <= 40 else { return nil }
        if version == 0 && program.count != 20 && program.count != 32 { return nil }
        guard decoded.variant == (version == 0 ? .bech32 : .bech32m) else { return nil }
        return (version, Data(program))
    }
}

/// Bech32 (BIP173) and Bech32m (BIP350), the encodings of segwit addresses:
/// version 0 programs in Bech32 and later versions, taproot first, in
/// Bech32m.
public enum Bech32 {
    public enum Variant: Sendable {
        case bech32
        case bech32m

        var constant: UInt32 { self == .bech32 ? 1 : 0x2bc8_30a3 }
    }

    static let charset = Array("qpzry9x8gf2tvdw0s3jn54khce6mua7l".utf8)
    private static let generator: [UInt32] = [0x3b6a_57b2, 0x2650_8e6d, 0x1ea1_19fa, 0x3d42_33dd, 0x2a14_62b3]

    static func polymod(_ values: [UInt8]) -> UInt32 {
        var chk: UInt32 = 1
        for v in values {
            let top = chk >> 25
            chk = (chk & 0x1ff_ffff) << 5 ^ UInt32(v)
            for i in 0..<5 where (top >> i) & 1 == 1 {
                chk ^= generator[i]
            }
        }
        return chk
    }

    static func expand(_ hrp: [UInt8]) -> [UInt8] {
        hrp.map { $0 >> 5 } + [0] + hrp.map { $0 & 31 }
    }

    /// Regroups bits, as 8-bit bytes into 5-bit groups and back. Without
    /// padding, leftover bits must be fewer than from and all zero.
    static func convertBits(_ data: [UInt8], from: Int, to: Int, pad: Bool) -> [UInt8]? {
        var acc = 0
        var bits = 0
        var out = [UInt8]()
        let maxv = (1 << to) - 1
        for value in data {
            guard Int(value) >> from == 0 else { return nil }
            acc = (acc << from) | Int(value)
            bits += from
            while bits >= to {
                bits -= to
                out.append(UInt8((acc >> bits) & maxv))
            }
        }
        if pad {
            if bits > 0 { out.append(UInt8((acc << (to - bits)) & maxv)) }
        } else if bits >= from || (acc << (to - bits)) & maxv != 0 {
            return nil
        }
        return out
    }
}

/// Base32 of RFC 4648, the encoding of onion and I2P names.
enum Base32 {
    static let alphabet = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".utf8)
}

extension [UInt8] {
    /// The 5-bit groups in Bech32 or Bech32m under the human readable part.
    public func bech32Encoded(hrp: String, variant: Bech32.Variant) -> String {
        let h = Array(hrp.lowercased().utf8)
        let values = Bech32.expand(h) + self
        let mod = Bech32.polymod(values + [0, 0, 0, 0, 0, 0]) ^ variant.constant
        let checksum = (0..<6).map { UInt8((mod >> (5 * (5 - UInt32($0)))) & 31) }
        let encoded = (self + checksum).map { Bech32.charset[Int($0)] }
        return String(decoding: h + [UInt8(ascii: "1")] + encoded, as: UTF8.self)
    }
}
