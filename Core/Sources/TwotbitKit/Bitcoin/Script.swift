import Foundation

/// Script builds and inspects the standard output and input scripts.
public enum Script {
    public static let opDup: UInt8 = 0x76
    public static let opHash160: UInt8 = 0xa9
    public static let opEqual: UInt8 = 0x87
    public static let opEqualVerify: UInt8 = 0x88
    public static let opCheckSig: UInt8 = 0xac
    public static let opReturn: UInt8 = 0x6a
    public static let op1: UInt8 = 0x51

    /// P2WPKH: OP_0 <20-byte key hash>.
    public static func p2wpkh(_ hash: Data) -> Data { Data([0x00, 0x14]) + hash }

    /// P2WPKH paying the compressed public key.
    public static func p2wpkh(pubkey: Data) -> Data { p2wpkh(pubkey.hash160()) }

    /// P2PKH: OP_DUP OP_HASH160 <20-byte key hash> OP_EQUALVERIFY OP_CHECKSIG.
    public static func p2pkh(_ hash: Data) -> Data { Data([opDup, opHash160, 0x14]) + hash + Data([opEqualVerify, opCheckSig]) }

    /// P2SH: OP_HASH160 <20-byte script hash> OP_EQUAL.
    public static func p2sh(_ hash: Data) -> Data { Data([opHash160, 0x14]) + hash + Data([opEqual]) }

    /// A witness program: the version as OP_0 or OP_1 to OP_16 and the
    /// program pushed.
    public static func witnessProgram(version: UInt8, program: Data) -> Data {
        Data([version == 0 ? 0x00 : 0x50 + version, UInt8(program.count)]) + program
    }

    /// P2PK: <public key> OP_CHECKSIG.
    public static func p2pk(_ pubkey: Data) -> Data { Data([UInt8(pubkey.count)]) + pubkey + Data([opCheckSig]) }
}

extension Data {
    /// Whether the script is a witness program: a version opcode followed
    /// by one canonical push of 2 to 40 bytes and nothing else.
    public var isWitnessProgram: Bool {
        let s = [UInt8](self)
        guard s.count >= 4, s.count <= 42 else { return false }
        guard s[0] == 0x00 || (s[0] >= 0x51 && s[0] <= 0x60) else { return false }
        return Int(s[1]) == s.count - 2 && s[1] >= 2 && s[1] <= 40
    }

    /// The data every push of the script pushes, OP_0 included as empty
    /// data and OP_1 to OP_16 not, as btcd's PushedData returns it. A push
    /// running past the end of the script is an error.
    public func pushedData() throws -> [Data] {
        let s = [UInt8](self)
        var out = [Data]()
        var i = 0
        while i < s.count {
            let op = s[i]
            i += 1
            var length = -1
            switch op {
            case 0x00:
                out.append(Data())
                continue
            case 0x01...0x4b:
                length = Int(op)
            case 0x4c:
                guard i + 1 <= s.count else { throw DecodeError.invalid("truncated OP_PUSHDATA1") }
                length = Int(s[i])
                i += 1
            case 0x4d:
                guard i + 2 <= s.count else { throw DecodeError.invalid("truncated OP_PUSHDATA2") }
                length = Int(s[i]) | Int(s[i + 1]) << 8
                i += 2
            case 0x4e:
                guard i + 4 <= s.count else { throw DecodeError.invalid("truncated OP_PUSHDATA4") }
                length = Int(s[i]) | Int(s[i + 1]) << 8 | Int(s[i + 2]) << 16 | Int(s[i + 3]) << 24
                i += 4
            default:
                continue
            }
            guard length >= 0, i + length <= s.count else { throw DecodeError.invalid("push past the end of the script") }
            out.append(Data(s[i..<i + length]))
            i += length
        }
        return out
    }

    /// Whether the data is a compressed or uncompressed public key by its
    /// length and prefix.
    public var isPubKey: Bool {
        switch count {
        case 33: return first == 0x02 || first == 0x03
        case 65: return first == 0x04
        default: return false
        }
    }

    /// Whether the data is shaped like the control block ending a taproot
    /// script path witness.
    public var isControlBlock: Bool {
        count >= 33 && (count - 33) % 32 == 0 && (first ?? 0) & 0xfe == 0xc0
    }
}
