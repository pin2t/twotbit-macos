import Foundation

/// BIP39 mnemonics: the 12 to 24 English words a wallet seed is written
/// down as, and the seed they stretch into.
public enum BIP39 {
    public enum Error: Swift.Error, Equatable, CustomStringConvertible {
        case invalidEntropy
        case invalidMnemonic

        public var description: String {
            switch self {
            case .invalidEntropy: return "entropy must be 128 to 256 bits in steps of 32"
            case .invalidMnemonic: return "invalid BIP39 mnemonic"
            }
        }
    }

    public static var wordlist: [String] { BIP39Words.english }

    static let wordIndex: [String: Int] = {
        var index = [String: Int]()
        for (i, word) in BIP39Words.english.enumerated() { index[word] = i }
        return index
    }()

    /// A fresh mnemonic from the system's secure random source; 128 bits of
    /// entropy make the default 12 words.
    public static func generateMnemonic(bits: Int = 128) throws -> String {
        guard bits % 32 == 0 else { throw Error.invalidEntropy }
        return try Hashes.randomBytes(bits / 8).mnemonic()
    }
}

extension Data {
    /// The entropy, 16 to 32 bytes in steps of 4, as a BIP39 mnemonic: the
    /// entropy and the first bits of its SHA256 as a checksum, in 11-bit
    /// words.
    public func mnemonic() throws -> String {
        guard count >= 16, count <= 32, count % 4 == 0 else { throw BIP39.Error.invalidEntropy }
        let checksumBits = count * 8 / 32
        var bits = [Bool]()
        for byte in self {
            for i in (0..<8).reversed() { bits.append(byte >> i & 1 == 1) }
        }
        let hash = sha256()
        for i in 0..<checksumBits {
            bits.append(hash[hash.startIndex + i / 8] >> (7 - i % 8) & 1 == 1)
        }
        var words = [String]()
        for chunk in stride(from: 0, to: bits.count, by: 11) {
            var index = 0
            for bit in bits[chunk..<chunk + 11] { index = index << 1 | (bit ? 1 : 0) }
            words.append(BIP39Words.english[index])
        }
        return words.joined(separator: " ")
    }
}

extension String {
    /// The entropy a valid BIP39 mnemonic encodes. Words are split on whitespace,
    /// must number 12, 15, 18, 21 or 24, must all be in the English list
    /// exactly, and must carry a matching checksum.
    public func mnemonicEntropy() throws -> Data {
        let words = split(whereSeparator: { $0.isWhitespace }).map(String.init)
        guard [12, 15, 18, 21, 24].contains(words.count) else { throw BIP39.Error.invalidMnemonic }
        var bits = [Bool]()
        for word in words {
            guard let index = BIP39.wordIndex[word] else { throw BIP39.Error.invalidMnemonic }
            for i in (0..<11).reversed() { bits.append(index >> i & 1 == 1) }
        }
        let checksumBits = bits.count / 33
        let entropyBits = bits.count - checksumBits
        var entropy = Data(count: entropyBits / 8)
        for i in 0..<entropyBits where bits[i] {
            entropy[i / 8] |= 1 << (7 - UInt8(i % 8))
        }
        let hash = entropy.sha256()
        for i in 0..<checksumBits {
            let want = hash[hash.startIndex + i / 8] >> (7 - i % 8) & 1 == 1
            guard bits[entropyBits + i] == want else { throw BIP39.Error.invalidMnemonic }
        }
        return entropy
    }

    public var isValidMnemonic: Bool {
        (try? mnemonicEntropy()) != nil
    }

    /// The 64-byte BIP39 seed of the mnemonic and the optional passphrase:
    /// PBKDF2-HMAC-SHA512 over the NFKD normalized sentence, salted with
    /// "mnemonic" and the passphrase, 2048 rounds.
    public func mnemonicSeed(passphrase: String = "") -> Data {
        let password = Data(decomposedStringWithCompatibilityMapping.utf8)
        let salt = Data(("mnemonic" + passphrase).decomposedStringWithCompatibilityMapping.utf8)
        return password.pbkdf2SHA512(salt: salt, rounds: 2048, length: 64)
    }
}
