import Foundation
import Testing
@testable import TwotbitKit

struct WalletFixture: Decodable {
    struct Mnemonic: Decodable { let entropy: String; let mnemonic: String; let seed: String; let seedTrezor: String }
    struct Addr: Decodable { let index: UInt32; let path: String; let address: String; let pubkey: String }
    struct Wallet: Decodable { let network: String; let mnemonic: String; let xpub: String; let receive: [Addr]; let change: [Addr] }
    struct CoinV: Decodable {
        let txid: String
        let vout: UInt32
        let value: Int64
        let chain: UInt32
        let index: UInt32
        let confirmed: Bool
        let address: String
        let path: String
        let script: String
    }
    struct SpendV: Decodable {
        let name: String
        let network: String
        let coins: [CoinV]
        let useAll: Bool
        let dest: String
        let destScript: String
        let amount: Int64
        let feeRate: Int64
        let changeIndex: UInt32
        let changeScript: String
        let error: String?
        let inputs: [Int]?
        let fee: Int64
        let change: Int64
        let max: Int64
        let txHex: String?
        let txid: String?
        let vsize: Int
        let estimate: Int64
    }
    struct Size: Decodable { let inputs: Int; let outputs: [String]; let vsize: Int64 }
    struct Dust: Decodable { let script: String; let dust: Int64 }
    struct AddrScript: Decodable { let network: String; let address: String; let script: String?; let error: Bool }

    let mnemonics: [Mnemonic]
    let invalidMnemonics: [String]
    let wallets: [Wallet]
    let spends: [SpendV]
    let sizes: [Size]
    let dust: [Dust]
    let addressScripts: [AddrScript]
}

@Suite struct WalletTests {
    static let fixture = Fixtures.load("wallet", as: WalletFixture.self)
    static let vectorMnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

    @Test func wordlist() {
        #expect(BIP39.wordlist.count == 2048)
        #expect(BIP39.wordlist == BIP39.wordlist.sorted())
        #expect(BIP39.wordlist.first == "abandon")
        #expect(BIP39.wordlist.last == "zoo")
    }

    @Test func mnemonics() throws {
        for v in Self.fixture.mnemonics {
            #expect(try Data(h: v.entropy).mnemonic() == v.mnemonic)
            #expect(try v.mnemonic.mnemonicEntropy().hex == v.entropy)
            #expect(v.mnemonic.mnemonicSeed().hex == v.seed)
            #expect(v.mnemonic.mnemonicSeed(passphrase: "TREZOR").hex == v.seedTrezor)
        }
        for bad in Self.fixture.invalidMnemonics {
            #expect(!bad.isValidMnemonic, "\(bad)")
        }
        let fresh = try BIP39.generateMnemonic()
        #expect(fresh.split(separator: " ").count == 12)
        #expect(fresh.isValidMnemonic)
    }

    @Test func derivation() throws {
        for v in Self.fixture.wallets {
            let wallet = try HDWallet(mnemonic: v.mnemonic, network: .fixture(v.network))
            #expect(wallet.accountXPub == v.xpub, "\(v.network)")
            for a in v.receive {
                let d = try wallet.receiveAddress(a.index)
                #expect(d.address == a.address)
                #expect(d.path == a.path)
                #expect(d.pubkey.hex == a.pubkey)
            }
            for a in v.change {
                let d = try wallet.changeAddress(a.index)
                #expect(d.address == a.address)
                #expect(d.path == a.path)
                #expect(d.pubkey.hex == a.pubkey)
            }
        }
    }

    @Test func bip84Vectors() throws {
        let wallet = try HDWallet(mnemonic: Self.vectorMnemonic, network: .mainnet)
        #expect(try wallet.receiveAddress(0).address == "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu")
        #expect(try wallet.receiveAddress(1).address == "bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g")
        #expect(try wallet.changeAddress(0).address == "bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el")
        #expect(wallet.accountXPub == "zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs")
        #expect(throws: (any Error).self) { try HDWallet(mnemonic: "abandon abandon", network: .mainnet) }
    }

    @Test func paths() throws {
        #expect(try "m/84'/0'/0'/1/3".derivationPath() == [84 + 0x8000_0000, 0x8000_0000, 0x8000_0000, 1, 3])
        for bad in ["", "m", "84'/0'", "m/x", "m/2147483648", "m/+1", "m//1", "n/1"] {
            #expect(throws: KeyError.self, "\(bad)") { try bad.derivationPath() }
        }
    }

    /// Every planned and signed spend matches the Go wallet byte for byte:
    /// coin selection, fees, change, BIP69 order and RFC6979 signatures.
    @Test func spends() throws {
        for v in Self.fixture.spends {
            let network = Network.fixture(v.network)
            let wallet = try HDWallet(mnemonic: Self.vectorMnemonic, network: network)
            let coins = v.coins.map { c in
                Coin(outPoint: OutPoint(hash: Hash256(hex: c.txid)!, index: c.vout), value: c.value, pkScript: Data(h: c.script),
                     address: c.address, path: c.path, confirmed: c.confirmed, time: 0)
            }
            for (coin, c) in zip(coins, v.coins) {
                let derived = try wallet.derive(chain: c.chain, index: c.index)
                #expect(derived.address == coin.address)
                #expect(derived.script == coin.pkScript)
            }
            let dest = try wallet.addressScript(v.dest)
            #expect(dest.hex == v.destScript, "\(v.name)")
            let change = try wallet.changeAddress(v.changeIndex).script
            #expect(change.hex == v.changeScript)
            #expect(SpendPlanner.maxAmount(coins: coins, dest: dest, feeRate: v.feeRate) == v.max, "\(v.name)")
            do {
                let spend = try SpendPlanner.plan(coins: coins, useAll: v.useAll, dest: dest, amount: v.amount, feeRate: v.feeRate, change: change)
                #expect(v.error == nil, "\(v.name)")
                #expect(spend.inputs.map(\.outPoint) == (v.inputs ?? []).map { coins[$0].outPoint }, "\(v.name)")
                #expect(spend.fee == v.fee, "\(v.name)")
                #expect(spend.change == v.change, "\(v.name)")
                let tx = try wallet.sign(spend, dest: dest, change: change)
                #expect(tx.serialized().hex == v.txHex, "\(v.name)")
                #expect(tx.txid.hex == v.txid, "\(v.name)")
                #expect(tx.vsize == v.vsize, "\(v.name)")
                var outputs = [dest]
                if spend.change > 0 { outputs.append(change) }
                #expect(SpendPlanner.estimateVSize(inputs: spend.inputs.count, outputs: outputs) == v.estimate)
                #expect(try Transaction(data: tx.serialized()) == tx)
                for (i, input) in tx.inputs.enumerated() {
                    let coin = coins.first { $0.outPoint == input.previousOutPoint }!
                    let hash = SigHashes(tx).p2wpkh(tx, input: i, pkScript: coin.pkScript, value: coin.value)
                    #expect(Secp256k1.verify(signature: input.witness[0].dropLast(), hash: hash, publicKey: input.witness[1]))
                    #expect(Script.p2wpkh(pubkey: input.witness[1]) == coin.pkScript)
                }
            } catch let error as SpendError {
                #expect(v.error == error.description, "\(v.name)")
            }
        }
    }

    @Test func sizesAndDust() {
        for v in Self.fixture.sizes {
            #expect(SpendPlanner.estimateVSize(inputs: v.inputs, outputs: v.outputs.map { Data(h: $0) }) == v.vsize)
        }
        for v in Self.fixture.dust {
            #expect(Data(h: v.script).dustLimit == v.dust, "\(v.script)")
        }
    }

    @Test func addressScripts() {
        for v in Self.fixture.addressScripts {
            let script = try? v.address.addressScript(network: .fixture(v.network))
            #expect((script == nil) == v.error, "\(v.network) \(v.address)")
            if let script, let want = v.script {
                #expect(script.hex == want, "\(v.address)")
            }
        }
    }

    /// BIP143's native P2WPKH example: the sighash of its second input.
    @Test func bip143Sighash() throws {
        let raw = "0100000002fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f0000000000eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a0100000000ffffffff02202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac11000000"
        let tx = try Transaction(data: Data(h: raw))
        let hash = SigHashes(tx).p2wpkh(tx, input: 1, pkScript: Data(h: "00141d0f172a0ecb48aee1be1f2687d2963ae33f71a1"), value: 600_000_000)
        #expect(hash.hex == "c37af31116d1b27caf68aae9e3ac82f1477929014d5b917657d0eb49478cb670")
    }
}
