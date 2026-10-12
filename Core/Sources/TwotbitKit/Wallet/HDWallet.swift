import Foundation

/// DerivedAddress is one derived wallet address with its derivation path
/// and compressed public key.
public struct DerivedAddress: Sendable, Hashable {
    public let index: UInt32
    public let address: String
    public let path: String
    public let pubkey: Data

    /// The P2WPKH output script paying the address.
    public var script: Data { Script.p2wpkh(pubkey: pubkey) }
}

/// HDWallet is a BIP84 hierarchical deterministic wallet for account 0,
/// with its external (receive) and internal (change) chains of native
/// segwit P2WPKH addresses, derived from a BIP39 mnemonic.
public final class HDWallet: Sendable {
    /// BIP84: native segwit, derivation m/84'/coin'/account'/chain/index.
    public static let purpose: UInt32 = 84
    public static let receiveChain: UInt32 = 0
    public static let changeChain: UInt32 = 1

    public let network: Network
    public let mnemonic: String
    private let master: ExtendedKey
    private let account: ExtendedKey
    private let chains: [ExtendedKey]

    /// Restores the wallet of the mnemonic, with the optional BIP39
    /// passphrase, for the network.
    public init(mnemonic: String, passphrase: String = "", network: Network) throws {
        guard BIP39.isValid(mnemonic) else { throw BIP39.Error.invalidMnemonic }
        self.network = network
        self.mnemonic = mnemonic
        master = try ExtendedKey.master(seed: BIP39.seed(mnemonic: mnemonic, passphrase: passphrase))
        let h = ExtendedKey.hardened
        account = try master.derive(path: [HDWallet.purpose + h, network.coinType + h, h])
        chains = [try account.derive(HDWallet.receiveChain), try account.derive(HDWallet.changeChain)]
    }

    /// The account's extended public key (m/84'/coin'/0'), safe to share
    /// for watching the wallet: a zpub on mainnet and a vpub on the test
    /// networks, the SLIP-132 versions for BIP84.
    public var accountXPub: String {
        account.publicString(version: HDWallet.slip132(network.hdPublicKeyID))
    }

    /// The SLIP-132 BIP84 version of BIP32 public key version bytes: xpub
    /// becomes zpub and tpub vpub; others stay.
    static func slip132(_ version: Data) -> Data {
        switch [UInt8](version) {
        case [0x04, 0x88, 0xb2, 0x1e]: return Data([0x04, 0xb2, 0x47, 0x46])
        case [0x04, 0x35, 0x87, 0xcf]: return Data([0x04, 0x5f, 0x1c, 0xf6])
        default: return version
        }
    }

    /// The receive address at the index of the external chain.
    public func receiveAddress(_ index: UInt32) throws -> DerivedAddress {
        try derive(chain: HDWallet.receiveChain, index: index)
    }

    /// The change address at the index of the internal chain.
    public func changeAddress(_ index: UInt32) throws -> DerivedAddress {
        try derive(chain: HDWallet.changeChain, index: index)
    }

    func derive(chain: UInt32, index: UInt32) throws -> DerivedAddress {
        let key = try chains[Int(chain)].derive(index)
        let pubkey = key.publicKey
        let path = "m/\(HDWallet.purpose)'/\(network.coinType)'/0'/\(chain)/\(index)"
        return DerivedAddress(index: index, address: Address.p2wpkh(pubkey: pubkey, network: network), path: path, pubkey: pubkey)
    }

    /// The output script paying a destination address of the wallet's
    /// network.
    public func addressScript(_ address: String) throws -> Data {
        try Address.script(for: address, network: network)
    }

    /// The private key at a derivation path such as m/84'/0'/0'/1/3.
    func privateKey(path: String) throws -> Data {
        try master.derive(path: ExtendedKey.parsePath(path)).privateKey
    }

    /// Builds the planned transaction paying the destination script, with
    /// change to the change script, and signs every input with the key at
    /// its coin's derivation path. Inputs and outputs are sorted per BIP69,
    /// so the change position reveals nothing, and every input signals RBF.
    public func sign(_ spend: Spend, dest: Data, change: Data) throws -> Transaction {
        var tx = Transaction(version: 2)
        var coins = [OutPoint: Coin]()
        for coin in spend.inputs {
            tx.inputs.append(TxIn(previousOutPoint: coin.outPoint, sequence: SpendPlanner.sequenceRBF))
            coins[coin.outPoint] = coin
        }
        tx.outputs.append(TxOut(value: spend.amount, pkScript: dest))
        if spend.change > 0 {
            tx.outputs.append(TxOut(value: spend.change, pkScript: change))
        }
        tx.sortBIP69()
        let hashes = SigHashes(tx)
        for i in tx.inputs.indices {
            guard let coin = coins[tx.inputs[i].previousOutPoint] else { continue }
            let key: Data
            do {
                key = try privateKey(path: coin.path)
            } catch {
                throw SpendError.signing("key for \(coin.address): \(error)")
            }
            let pubkey = try Secp256k1.publicKey(of: key)
            let sighash = hashes.p2wpkh(tx, input: i, pkScript: coin.pkScript, value: coin.value)
            var signature = try Secp256k1.sign(hash: sighash, privateKey: key)
            signature.append(SigHashes.all)
            tx.inputs[i].witness = [signature, pubkey]
        }
        return tx
    }
}

extension Transaction {
    /// Sorts the inputs and outputs per BIP69: inputs by previous
    /// transaction id, as displayed, then output index; outputs by value,
    /// then script bytes.
    public mutating func sortBIP69() {
        inputs.sort { a, b in
            if a.previousOutPoint.hash != b.previousOutPoint.hash { return a.previousOutPoint.hash < b.previousOutPoint.hash }
            return a.previousOutPoint.index < b.previousOutPoint.index
        }
        outputs.sort { a, b in
            if a.value != b.value { return a.value < b.value }
            return a.pkScript.lexicographicallyPrecedes(b.pkScript)
        }
    }
}

/// SigHashes computes BIP143 signature hashes of segwit version 0 inputs,
/// sharing the hashes of all prevouts, sequences and outputs between them.
struct SigHashes {
    static let all: UInt8 = 0x01

    let prevouts: Hash256
    let sequences: Hash256
    let outputs: Hash256

    init(_ tx: Transaction) {
        var p = ByteWriter()
        var s = ByteWriter()
        for input in tx.inputs {
            input.previousOutPoint.write(to: &p)
            s.writeUInt32(input.sequence)
        }
        var o = ByteWriter()
        for output in tx.outputs { output.write(to: &o) }
        prevouts = Hashes.sha256d(p.data)
        sequences = Hashes.sha256d(s.data)
        outputs = Hashes.sha256d(o.data)
    }

    /// The SIGHASH_ALL hash of the input spending a P2WPKH output: its
    /// script code is the P2PKH script of the key hash.
    func p2wpkh(_ tx: Transaction, input: Int, pkScript: Data, value: Int64) -> Data {
        var w = ByteWriter(capacity: 160)
        w.writeInt32(tx.version)
        w.write(prevouts)
        w.write(sequences)
        tx.inputs[input].previousOutPoint.write(to: &w)
        w.writeVarBytes(Script.p2pkh(pkScript.subdata(in: pkScript.startIndex + 2..<pkScript.endIndex)))
        w.writeInt64(value)
        w.writeUInt32(tx.inputs[input].sequence)
        w.write(outputs)
        w.writeUInt32(tx.lockTime)
        w.writeUInt32(UInt32(SigHashes.all))
        return Hashes.sha256d(w.data).data
    }
}
