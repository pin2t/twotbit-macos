import Foundation

/// Base58 and Base58Check, the encoding of legacy addresses and extended
/// keys.
public enum Base58 {
    private static let alphabet = Array("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz".utf8)
    private static let indexes: [Int8] = {
        var table = [Int8](repeating: -1, count: 128)
        for (i, c) in alphabet.enumerated() { table[Int(c)] = Int8(i) }
        return table
    }()

    public static func encode(_ data: Data) -> String {
        let bytes = [UInt8](data)
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

    public static func decode(_ text: String) -> Data? {
        let chars = Array(text.utf8)
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

    /// Encodes the payload with its 4-byte double SHA256 checksum.
    public static func encodeCheck(_ payload: Data) -> String {
        let checksum = Hashes.sha256d(payload).data.prefix(4)
        return encode(payload + checksum)
    }

    /// Decodes Base58Check text and returns the payload when the checksum
    /// matches.
    public static func decodeCheck(_ text: String) -> Data? {
        guard let raw = decode(text), raw.count >= 4 else { return nil }
        let payload = raw.prefix(raw.count - 4)
        let checksum = raw.suffix(4)
        guard Hashes.sha256d(Data(payload)).data.prefix(4) == checksum else { return nil }
        return Data(payload)
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

    private static let charset = Array("qpzry9x8gf2tvdw0s3jn54khce6mua7l".utf8)
    private static let generator: [UInt32] = [0x3b6a_57b2, 0x2650_8e6d, 0x1ea1_19fa, 0x3d42_33dd, 0x2a14_62b3]

    private static func polymod(_ values: [UInt8]) -> UInt32 {
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

    private static func expand(_ hrp: [UInt8]) -> [UInt8] {
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

    public static func encode(hrp: String, data: [UInt8], variant: Variant) -> String {
        let h = Array(hrp.lowercased().utf8)
        let values = expand(h) + data
        let mod = polymod(values + [0, 0, 0, 0, 0, 0]) ^ variant.constant
        let checksum = (0..<6).map { UInt8((mod >> (5 * (5 - UInt32($0)))) & 31) }
        let encoded = (data + checksum).map { charset[Int($0)] }
        return String(decoding: h + [UInt8(ascii: "1")] + encoded, as: UTF8.self)
    }

    /// Decodes Bech32 or Bech32m text into its lower case human readable
    /// part, its 5-bit data and the variant its checksum matches.
    public static func decode(_ text: String) -> (hrp: String, data: [UInt8], variant: Variant)? {
        let chars = Array(text.utf8)
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
            guard let i = charset.firstIndex(of: c) else { return nil }
            data.append(UInt8(i))
        }
        let mod = polymod(expand(hrp) + data)
        let variant: Variant
        switch mod {
        case Variant.bech32.constant: variant = .bech32
        case Variant.bech32m.constant: variant = .bech32m
        default: return nil
        }
        return (String(decoding: hrp, as: UTF8.self), Array(data.dropLast(6)), variant)
    }

    /// Encodes a segwit address: version 0 in Bech32, later versions in
    /// Bech32m.
    public static func encodeSegwit(hrp: String, version: UInt8, program: Data) -> String {
        let data = [version] + convertBits([UInt8](program), from: 8, to: 5, pad: true)!
        return encode(hrp: hrp, data: data, variant: version == 0 ? .bech32 : .bech32m)
    }

    /// Decodes a segwit address of the human readable part into its witness
    /// version and program, enforcing the BIP173 and BIP350 rules.
    public static func decodeSegwit(hrp: String, _ text: String) -> (version: UInt8, program: Data)? {
        guard let decoded = decode(text), decoded.hrp == hrp.lowercased(), let version = decoded.data.first, version <= 16,
              let program = convertBits(Array(decoded.data.dropFirst()), from: 5, to: 8, pad: false),
              program.count >= 2, program.count <= 40 else { return nil }
        if version == 0 && program.count != 20 && program.count != 32 { return nil }
        guard decoded.variant == (version == 0 ? .bech32 : .bech32m) else { return nil }
        return (version, Data(program))
    }
}

/// Base32 of RFC 4648, the encoding of onion and I2P names.
public enum Base32 {
    private static let alphabet = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".utf8)

    /// Encodes in lower case without padding.
    public static func encode(_ data: Data) -> String {
        var out = [UInt8]()
        var buffer = 0
        var bits = 0
        for byte in data {
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

    /// Decodes upper or lower case text without padding. Bits left over
    /// past the last whole byte are dropped, as Go's decoder does.
    public static func decode(_ text: String) -> Data? {
        var out = [UInt8]()
        var buffer = 0
        var bits = 0
        for c in text.uppercased().utf8 {
            guard let value = alphabet.firstIndex(of: c) else { return nil }
            buffer = (buffer << 5 | value) & 0xffff
            bits += 5
            if bits >= 8 {
                bits -= 8
                out.append(UInt8((buffer >> bits) & 0xff))
            }
        }
        let rem = text.utf8.count % 8
        guard [0, 2, 4, 5, 7].contains(rem) else { return nil }
        return Data(out)
    }
}
