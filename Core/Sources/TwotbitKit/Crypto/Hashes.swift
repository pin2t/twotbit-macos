import CommonCrypto
import CryptoKit
import Foundation

/// The hash functions Bitcoin uses, over CryptoKit and CommonCrypto where
/// they provide them.
extension Data {
    public func sha256() -> Data {
        Data(SHA256.hash(data: self))
    }

    /// SHA256 applied twice, as block hashes, transaction ids and checksums
    /// are.
    public func sha256d() -> Hash256 {
        let first = SHA256.hash(data: self)
        return first.withUnsafeBytes { raw in
            SHA256.hash(data: raw).withUnsafeBytes { Hash256(raw: $0) }
        }
    }

    /// RIPEMD160 of SHA256: the 20-byte hash of public keys and scripts in
    /// addresses.
    public func hash160() -> Data {
        sha256().ripemd160()
    }

    public func hmacSHA512(key: Data) -> Data {
        Data(HMAC<SHA512>.authenticationCode(for: self, using: SymmetricKey(data: key)))
    }

    /// PBKDF2 with HMAC-SHA512 of the bytes as the password, as BIP39
    /// stretches a mnemonic into a seed.
    public func pbkdf2SHA512(salt: Data, rounds: UInt32, length: Int) -> Data {
        var out = [UInt8](repeating: 0, count: length)
        let status = withUnsafeBytes { pw in
            salt.withUnsafeBytes { s in
                CCKeyDerivationPBKDF(
                    CCPBKDFAlgorithm(kCCPBKDF2),
                    pw.baseAddress?.assumingMemoryBound(to: CChar.self), pw.count,
                    s.baseAddress?.assumingMemoryBound(to: UInt8.self), s.count,
                    CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA512), rounds,
                    &out, length)
            }
        }
        precondition(status == kCCSuccess, "PBKDF2 failed with status \(status)")
        return Data(out)
    }

    /// RIPEMD-160, which CryptoKit does not provide.
    public func ripemd160() -> Data { RIPEMD160.hash(self) }

    /// SHA3-256, the Keccak hash v3 onion addresses checksum with.
    public func sha3_256() -> Data { SHA3_256.hash(self) }
}

extension [UInt8] {
    public func sha256() -> Data {
        Data(SHA256.hash(data: self))
    }
}

extension UnsafeRawBufferPointer {
    /// SHA256 applied twice to the bytes in place.
    public func sha256d() -> Hash256 {
        let first = SHA256.hash(data: self)
        return first.withUnsafeBytes { inner in
            SHA256.hash(data: inner).withUnsafeBytes { Hash256(raw: $0) }
        }
    }
}

public enum Hashes {
    /// Cryptographically secure random bytes.
    public static func randomBytes(_ count: Int) -> Data {
        var bytes = [UInt8](repeating: 0, count: count)
        let status = SecRandomCopyBytes(kSecRandomDefault, count, &bytes)
        precondition(status == errSecSuccess, "no secure random bytes")
        return Data(bytes)
    }
}

/// RIPEMD-160, which CryptoKit does not provide.
enum RIPEMD160 {
    static func hash(_ message: Data) -> Data {
        var h: [UInt32] = [0x6745_2301, 0xEFCD_AB89, 0x98BA_DCFE, 0x1032_5476, 0xC3D2_E1F0]
        var padded = [UInt8](message)
        let bitLength = UInt64(message.count) * 8
        padded.append(0x80)
        while padded.count % 64 != 56 { padded.append(0) }
        withUnsafeBytes(of: bitLength.littleEndian) { padded.append(contentsOf: $0) }
        var x = [UInt32](repeating: 0, count: 16)
        for block in stride(from: 0, to: padded.count, by: 64) {
            for i in 0..<16 {
                let o = block + i * 4
                x[i] = UInt32(padded[o]) | UInt32(padded[o + 1]) << 8 | UInt32(padded[o + 2]) << 16 | UInt32(padded[o + 3]) << 24
            }
            compress(&h, x)
        }
        var out = Data(capacity: 20)
        for word in h { withUnsafeBytes(of: word.littleEndian) { out.append(contentsOf: $0) } }
        return out
    }

    private static let rl: [Int] = [
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
        7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
        3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
        1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
        4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13,
    ]
    private static let rr: [Int] = [
        5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
        6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
        15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
        8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
        12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11,
    ]
    private static let sl: [UInt32] = [
        11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
        7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
        11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
        11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
        9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6,
    ]
    private static let sr: [UInt32] = [
        8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
        9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
        9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
        15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
        8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11,
    ]
    private static let kl: [UInt32] = [0x0000_0000, 0x5A82_7999, 0x6ED9_EBA1, 0x8F1B_BCDC, 0xA953_FD4E]
    private static let kr: [UInt32] = [0x50A2_8BE6, 0x5C4D_D124, 0x6D70_3EF3, 0x7A6D_76E9, 0x0000_0000]

    private static func f(_ j: Int, _ x: UInt32, _ y: UInt32, _ z: UInt32) -> UInt32 {
        switch j / 16 {
        case 0: return x ^ y ^ z
        case 1: return (x & y) | (~x & z)
        case 2: return (x | ~y) ^ z
        case 3: return (x & z) | (y & ~z)
        default: return x ^ (y | ~z)
        }
    }

    private static func rol(_ x: UInt32, _ n: UInt32) -> UInt32 { (x << n) | (x >> (32 - n)) }

    private static func compress(_ h: inout [UInt32], _ x: [UInt32]) {
        var (al, bl, cl, dl, el) = (h[0], h[1], h[2], h[3], h[4])
        var (ar, br, cr, dr, er) = (h[0], h[1], h[2], h[3], h[4])
        for j in 0..<80 {
            var t = rol(al &+ f(j, bl, cl, dl) &+ x[rl[j]] &+ kl[j / 16], sl[j]) &+ el
            al = el; el = dl; dl = rol(cl, 10); cl = bl; bl = t
            t = rol(ar &+ f(79 - j, br, cr, dr) &+ x[rr[j]] &+ kr[j / 16], sr[j]) &+ er
            ar = er; er = dr; dr = rol(cr, 10); cr = br; br = t
        }
        let t = h[1] &+ cl &+ dr
        h[1] = h[2] &+ dl &+ er
        h[2] = h[3] &+ el &+ ar
        h[3] = h[4] &+ al &+ br
        h[4] = h[0] &+ bl &+ cr
        h[0] = t
    }
}

/// SHA3-256, the Keccak hash v3 onion addresses checksum with.
enum SHA3_256 {
    private static let roundConstants: [UInt64] = [
        0x0000_0000_0000_0001, 0x0000_0000_0000_8082, 0x8000_0000_0000_808A, 0x8000_0000_8000_8000,
        0x0000_0000_0000_808B, 0x0000_0000_8000_0001, 0x8000_0000_8000_8081, 0x8000_0000_0000_8009,
        0x0000_0000_0000_008A, 0x0000_0000_0000_0088, 0x0000_0000_8000_8009, 0x0000_0000_8000_000A,
        0x0000_0000_8000_808B, 0x8000_0000_0000_008B, 0x8000_0000_0000_8089, 0x8000_0000_0000_8003,
        0x8000_0000_0000_8002, 0x8000_0000_0000_0080, 0x0000_0000_0000_800A, 0x8000_0000_8000_000A,
        0x8000_0000_8000_8081, 0x8000_0000_0000_8080, 0x0000_0000_8000_0001, 0x8000_0000_8000_8008,
    ]
    private static let rotations: [UInt64] = [
        0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14,
    ]
    private static let rate = 136

    static func hash(_ message: Data) -> Data {
        var state = [UInt64](repeating: 0, count: 25)
        var padded = [UInt8](message)
        padded.append(0x06)
        while padded.count % rate != 0 { padded.append(0) }
        padded[padded.count - 1] |= 0x80
        for block in stride(from: 0, to: padded.count, by: rate) {
            for i in 0..<(rate / 8) {
                var lane: UInt64 = 0
                for b in 0..<8 { lane |= UInt64(padded[block + i * 8 + b]) << (8 * UInt64(b)) }
                state[i] ^= lane
            }
            keccakF(&state)
        }
        var out = Data(capacity: 32)
        for i in 0..<4 { withUnsafeBytes(of: state[i].littleEndian) { out.append(contentsOf: $0) } }
        return out
    }

    private static func rotl(_ x: UInt64, _ n: UInt64) -> UInt64 { n == 0 ? x : (x << n) | (x >> (64 - n)) }

    private static func keccakF(_ a: inout [UInt64]) {
        var b = [UInt64](repeating: 0, count: 25)
        var c = [UInt64](repeating: 0, count: 5)
        for round in 0..<24 {
            for x in 0..<5 { c[x] = a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20] }
            for x in 0..<5 {
                let d = c[(x + 4) % 5] ^ rotl(c[(x + 1) % 5], 1)
                for y in 0..<5 { a[x + 5 * y] ^= d }
            }
            for x in 0..<5 {
                for y in 0..<5 {
                    b[y + 5 * ((2 * x + 3 * y) % 5)] = rotl(a[x + 5 * y], rotations[x + 5 * y])
                }
            }
            for x in 0..<5 {
                for y in 0..<5 {
                    a[x + 5 * y] = b[x + 5 * y] ^ (~b[(x + 1) % 5 + 5 * y] & b[(x + 2) % 5 + 5 * y])
                }
            }
            a[0] ^= roundConstants[round]
        }
    }
}

extension [UInt8] {
    /// SipHash-2-4, the keyed hash BIP158 filters map their items with.
    public func sipHash(k0: UInt64, k1: UInt64) -> UInt64 {
        var v0: UInt64 = k0 ^ 0x736f_6d65_7073_6575
        var v1: UInt64 = k1 ^ 0x646f_7261_6e64_6f6d
        var v2: UInt64 = k0 ^ 0x6c79_6765_6e65_7261
        var v3: UInt64 = k1 ^ 0x7465_6462_7974_6573
        @inline(__always) func round() {
            v0 = v0 &+ v1; v1 = (v1 << 13) | (v1 >> 51); v1 ^= v0; v0 = (v0 << 32) | (v0 >> 32)
            v2 = v2 &+ v3; v3 = (v3 << 16) | (v3 >> 48); v3 ^= v2
            v0 = v0 &+ v3; v3 = (v3 << 21) | (v3 >> 43); v3 ^= v0
            v2 = v2 &+ v1; v1 = (v1 << 17) | (v1 >> 47); v1 ^= v2; v2 = (v2 << 32) | (v2 >> 32)
        }
        let blocks = count / 8
        for i in 0..<blocks {
            var m: UInt64 = 0
            for b in 0..<8 { m |= UInt64(self[i * 8 + b]) << (8 * UInt64(b)) }
            v3 ^= m
            round(); round()
            v0 ^= m
        }
        var last = UInt64(count & 0xff) << 56
        for b in 0..<(count % 8) { last |= UInt64(self[blocks * 8 + b]) << (8 * UInt64(b)) }
        v3 ^= last
        round(); round()
        v0 ^= last
        v2 ^= 0xff
        round(); round(); round(); round()
        return v0 ^ v1 ^ v2 ^ v3
    }

    /// MurmurHash3 x86 32-bit, the hash BIP37 bloom filters set their bits
    /// with.
    public func murmur3Hash(seed: UInt32) -> UInt32 {
        let c1: UInt32 = 0xcc9e_2d51
        let c2: UInt32 = 0x1b87_3593
        var h = seed
        let blocks = count / 4
        for i in 0..<blocks {
            var k = UInt32(self[i * 4]) | UInt32(self[i * 4 + 1]) << 8 | UInt32(self[i * 4 + 2]) << 16 | UInt32(self[i * 4 + 3]) << 24
            k = k &* c1
            k = (k << 15) | (k >> 17)
            k = k &* c2
            h ^= k
            h = (h << 13) | (h >> 19)
            h = h &* 5 &+ 0xe654_6b64
        }
        var k: UInt32 = 0
        let tail = blocks * 4
        switch count & 3 {
        case 3:
            k ^= UInt32(self[tail + 2]) << 16
            fallthrough
        case 2:
            k ^= UInt32(self[tail + 1]) << 8
            fallthrough
        case 1:
            k ^= UInt32(self[tail])
            k = k &* c1
            k = (k << 15) | (k >> 17)
            k = k &* c2
            h ^= k
        default:
            break
        }
        h ^= UInt32(truncatingIfNeeded: count)
        h ^= h >> 16
        h = h &* 0x85eb_ca6b
        h ^= h >> 13
        h = h &* 0xc2b2_ae35
        h ^= h >> 16
        return h
    }
}
