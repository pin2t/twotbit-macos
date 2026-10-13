import Foundation
import Testing
@testable import TwotbitKit

struct SyncFixture: Decodable {
    struct Spent: Decodable { let sigScript: String; let witness: [String]?; let address: String }
    struct ScriptAddress: Decodable { let script: String; let address: String }
    struct TxAddress: Decodable { let address: String; let mine: Bool }
    struct WalletTx: Decodable {
        let txid: String
        let time: Int64
        let confirmed: Bool
        let net: Int64
        let fee: Int64
        let inputs: [TxAddress]
        let outputs: [TxAddress]
    }
    struct History: Decodable {
        let walletScripts: [String]
        let walletAddresses: [String]
        let txs: [String]
        let times: [Int64]
        let confirmed: Int
        let history: [WalletTx]
        let balance: Int64
        let pending: Int64
    }
    struct Bloom: Decodable {
        let elements: UInt32
        let tweak: UInt32
        let fpRate: Double
        let items: [String]
        let outPoints: [String]
        let filter: String
        let hashFuncs: UInt32
        let message: String
    }
    struct Murmur: Decodable { let seed: UInt32; let data: String; let hash: UInt32 }
    struct Sip: Decodable { let key: String; let data: String; let hash: UInt64 }
    struct Majority: Decodable { let votes: [String]?; let anchor: String?; let error: Bool }

    let spent: [Spent]
    let scriptAddresses: [ScriptAddress]
    let testnetScriptAddresses: [ScriptAddress]
    let histories: [History]
    let blooms: [Bloom]
    let murmur: [Murmur]
    let siphash: [Sip]
    let majority: [Majority]
}

@Suite struct CryptoTests {
    @Test func ripemd160() {
        let cases = [
            ("", "9c1185a5c5e9fc54612808977ee8f548b2258d31"),
            ("abc", "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc"),
            ("message digest", "5d0689ef49d2fae572b881b123a85ffa21595f36"),
            ("abcdefghijklmnopqrstuvwxyz", "f71c27109c692c1b56bbdceb5b9d2865b3708dbc"),
            ("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "12a053384a9c0c88e405a06c27dcf49ada62eb2b"),
            (String(repeating: "1234567890", count: 8), "9b752e45573d4b39f4dbd3323cab82bf63326bfb"),
        ]
        for (input, want) in cases {
            #expect(Data(input.utf8).ripemd160().hex == want)
        }
        #expect(Data(String(repeating: "a", count: 1_000_000).utf8).ripemd160().hex == "52783243c1697bdbe16d37f97f68f08325dc1528")
    }

    @Test func sha3() {
        #expect(Data().sha3_256().hex == "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a")
        #expect(Data("abc".utf8).sha3_256().hex == "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532")
        let long = Data("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq".utf8)
        #expect(long.sha3_256().hex == "41c0dba2a9d6240849100376a8235e2c82e1b9998a999e21db32dd97496d3376")
        #expect(Data(repeating: 0x61, count: 200).sha3_256().count == 32)
    }

    @Test func sipHash() {
        let fixture = Fixtures.load("sync", as: SyncFixture.self)
        for v in fixture.siphash {
            let key = [UInt8](Data(h: v.key))
            let k0 = key[0..<8].enumerated().reduce(UInt64(0)) { $0 | UInt64($1.element) << (8 * UInt64($1.offset)) }
            let k1 = key[8..<16].enumerated().reduce(UInt64(0)) { $0 | UInt64($1.element) << (8 * UInt64($1.offset)) }
            #expect([UInt8](Data(h: v.data)).sipHash(k0: k0, k1: k1) == v.hash)
        }
        let key = (0..<16).map { UInt8($0) }
        let k0 = key[0..<8].enumerated().reduce(UInt64(0)) { $0 | UInt64($1.element) << (8 * UInt64($1.offset)) }
        let k1 = key[8..<16].enumerated().reduce(UInt64(0)) { $0 | UInt64($1.element) << (8 * UInt64($1.offset)) }
        #expect(((0..<15).map { UInt8($0) }).sipHash(k0: k0, k1: k1) == 0xa129_ca61_49be_45e5)
    }

    @Test func murmur3() {
        let fixture = Fixtures.load("sync", as: SyncFixture.self)
        for v in fixture.murmur {
            #expect([UInt8](Data(h: v.data)).murmur3Hash(seed: v.seed) == v.hash)
        }
    }

    @Test func pbkdf2AndHMAC() {
        let mac = Data("Hi There".utf8).hmacSHA512(key: Data(repeating: 0x0b, count: 20))
        #expect(mac.hex == "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854")
        let key = Data("password".utf8).pbkdf2SHA512(salt: Data("salt".utf8), rounds: 1, length: 64)
        #expect(key.hex == "867f70cf1ade02cff3752599a3a53dc4af34c7a669815ae5d513554e1c8cf252c02d470a285a0501bad999bfe943c08f050235d7d68b1da55e63f73b60a57fce")
    }

    @Test func secp256k1SignAndVerify() throws {
        let key = Data(h: "0000000000000000000000000000000000000000000000000000000000000001")
        let pub = try Secp256k1.publicKey(of: key)
        #expect(pub.hex == "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
        let hash = Data("Satoshi Nakamoto".utf8).sha256()
        let sig = try Secp256k1.sign(hash: hash, privateKey: key)
        // RFC6979 vector for key 1 and "Satoshi Nakamoto" (low S).
        #expect(sig.hex == "3045022100934b1ea10a4b3c1757e2b0c017d0b6143ce3c9a7e6a4a49860d7a6ab210ee3d802202442ce9d2b916064108014783e923ec36b49743e2ffa1c4496f01a512aafd9e5")
        #expect(Secp256k1.verify(signature: sig, hash: hash, publicKey: pub))
        #expect(!Secp256k1.verify(signature: sig, hash: Data("x".utf8).sha256(), publicKey: pub))
        #expect(!Secp256k1.isValidPrivateKey(Data(count: 32)))
        #expect(!Secp256k1.isValidPrivateKey(Data(h: "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141")))
        #expect(throws: KeyError.invalidChild) {
            try Secp256k1.tweakAdd(privateKey: key, tweak: Data(h: "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"))
        }
    }
}

@Suite struct EncodingTests {
    @Test func base58() {
        #expect(Data(h: "00000000000000000000").base58Encoded() == "1111111111")
        #expect(Data("hello world".utf8).base58Encoded() == "StV1DL6CwTryKyV")
        #expect("StV1DL6CwTryKyV".base58Decoded() == Data("hello world".utf8))
        #expect("0OIl".base58Decoded() == nil)
        #expect("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2".base58ChecksumDecoded()?.hex == "0077bff20c60e522dfaa3350c39b030a5d004e839a")
        #expect("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN3".base58ChecksumDecoded() == nil)
    }

    @Test func bech32BIP173AndBIP350() {
        for valid in ["A12UEL5L", "a12uel5l", "an83characterlonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1tt5tgs",
                      "abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw", "split1checkupstagehandshakeupstreamerranterredcaperred2y9e3w"] {
            #expect(valid.bech32Decoded()?.variant == .bech32, "\(valid)")
        }
        for valid in ["A1LQFN3A", "a1lqfn3a", "abcdef1l7aum6echk45nj3s0wdvt2fg8x9yrzpqzd3ryx", "?1v759aa"] {
            #expect(valid.bech32Decoded()?.variant == .bech32m, "\(valid)")
        }
        for invalid in ["pzry9x0s0muk", "1pzry9x0s0muk", "x1b4n0q5v", "li1dgmt3", "A1G7SGD8", "10a06t8", "1qzzfhee", "a12UEL5L"] {
            #expect(invalid.bech32Decoded() == nil, "\(invalid)")
        }
        let segwit = "BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4".segwitDecoded(hrp: "bc")
        #expect(segwit?.version == 0)
        #expect(segwit?.program.hex == "751e76e8199196d454941c45d1b3a323f1433bd6")
        #expect(Data(h: "751e76e8199196d454941c45d1b3a323f1433bd6").segwitEncoded(hrp: "bc", version: 0) == "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4")
        let taproot = "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0".segwitDecoded(hrp: "bc")
        #expect(taproot?.version == 1)
        #expect("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kemeawh".segwitDecoded(hrp: "bc") == nil)
        #expect("bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqh2y7hd".segwitDecoded(hrp: "bc") == nil)
        #expect("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4".segwitDecoded(hrp: "tb") == nil)
    }

    @Test func base32() {
        #expect(Data("foobar".utf8).base32Encoded() == "mzxw6ytboi")
        #expect("MZXW6YTBOI".base32Decoded() == Data("foobar".utf8))
        #expect("mzxw6ytboi".base32Decoded() == Data("foobar".utf8))
        #expect("mzxw6ytbo1".base32Decoded() == nil)
    }

    @Test func varInts() throws {
        for (value, size) in [(UInt64(0), 1), (0xfc, 1), (0xfd, 3), (0xffff, 3), (0x10000, 5), (0xffff_ffff, 5), (0x1_0000_0000, 9)] {
            var w = ByteWriter()
            w.writeVarInt(value)
            #expect(w.data.count == size)
            #expect(varIntSize(value) == size)
            var r = ByteReader(w.data)
            #expect(try r.readVarInt() == value)
        }
        var r = ByteReader(Data(h: "fd0100"))
        #expect(throws: DecodeError.self) { try r.readVarInt() }
    }

    @Test func uint256AndCompact() {
        let limit = UInt256(hex: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffff")!
        #expect(limit.compactBits == 0x1d00_ffff)
        #expect(UInt32(0x1d00_ffff).compactTarget!.hex == "00000000ffff0000000000000000000000000000000000000000000000000000")
        #expect(limit.bitLength == 224)
        #expect((limit >> 200).hex == String(repeating: "0", count: 58) + "ffffff")
        #expect(UInt256(1000).scaled(by: 3, dividedBy: 7) == UInt256(428))
    }
}
