import Foundation

/// Network holds the parameters of one Bitcoin network the wallet runs on:
/// its P2P magic and port, genesis block, proof of work rules, address
/// encodings and DNS seeds. The values match btcd's chaincfg.
public struct Network: Sendable, Hashable, Identifiable {
    public enum Kind: String, Sendable, CaseIterable, Hashable {
        case mainnet, testnet3, testnet4, signet, regtest, simnet
    }

    public let kind: Kind
    /// The network's name in btcd: mainnet, testnet3, testnet4, signet,
    /// regtest or simnet.
    public let name: String
    /// The magic number that starts every P2P message, little-endian on the
    /// wire.
    public let magic: UInt32
    public let defaultPort: UInt16
    public let genesis: BlockHeader
    public let powLimit: UInt256
    public let powLimitBits: UInt32
    /// Whether a block more than minDiffReductionTime after its parent may
    /// have the minimum difficulty, as on the test networks.
    public let reduceMinDifficulty: Bool
    public let minDiffReductionTime: Int64
    /// Whether BIP94 is enforced: the timewarp fix and retargeting from the
    /// first block of the period, as on testnet4.
    public let enforceBIP94: Bool
    public let bech32HRP: String
    public let pubKeyHashID: UInt8
    public let scriptHashID: UInt8
    public let hdPublicKeyID: Data
    public let dnsSeeds: [PeerAddress]

    public var id: Kind { kind }
    public var genesisHash: Hash256 { genesis.hash }

    /// Whether the header chain checks the difficulty of every header. The
    /// local test networks mine at the minimum difficulty and are not
    /// checked, as btcd's checks are not.
    public var checksDifficulty: Bool { kind != .regtest && kind != .simnet }

    /// Whether the wallet's recovery phrase is kept in the Keychain. The
    /// local test networks keep it in their database instead: their coins
    /// have no value, and a development build, signed anew at every build,
    /// would otherwise have to ask for Keychain access at every launch.
    public var keepsPhraseInKeychain: Bool { kind != .regtest && kind != .simnet }

    /// The BIP44 coin type of the BIP84 derivation: 0 on mainnet, 1 on every
    /// other network.
    public var coinType: UInt32 { kind == .mainnet ? 0 : 1 }

    /// The name the network is selected by and stored under in the wallet:
    /// mainnet, testnet, testnet4, signet, regtest or simnet.
    public var displayName: String { kind == .testnet3 ? "testnet" : name }

    /// The wallet database file of the network: twotbit.db on mainnet and
    /// twotbit-<network>.db otherwise, so the wallets of different networks
    /// never share a file.
    public var databaseFileName: String { kind == .mainnet ? "twotbit.db" : "twotbit-\(displayName).db" }

    public static func == (a: Network, b: Network) -> Bool { a.kind == b.kind }
    public func hash(into hasher: inout Hasher) { hasher.combine(kind) }

    /// Maps a network name, as given on the command line or stored in the
    /// wallet, to its parameters.
    public static func named(_ name: String) -> Network? {
        switch name.trimmingCharacters(in: .whitespaces).lowercased() {
        case "mainnet", "bitcoin", "main": return .mainnet
        case "testnet", "testnet3", "test": return .testnet3
        case "testnet4": return .testnet4
        case "signet": return .signet
        case "regtest": return .regtest
        case "simnet": return .simnet
        default: return nil
        }
    }

    public static let all: [Network] = [.mainnet, .testnet3, .testnet4, .signet, .regtest, .simnet]

    private static let mainPowLimit = UInt256(hex: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffff")!
    private static let regtestPowLimit = UInt256(hex: "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")!

    private static func genesis(_ hex: String) -> BlockHeader {
        try! BlockHeader(data: Data(hex: hex)!)
    }

    public static let mainnet = Network(
        kind: .mainnet, name: "mainnet", magic: 0xd9b4_bef9, defaultPort: 8333,
        genesis: genesis("0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c"),
        powLimit: mainPowLimit, powLimitBits: 0x1d00_ffff, reduceMinDifficulty: false, minDiffReductionTime: 0, enforceBIP94: false,
        bech32HRP: "bc", pubKeyHashID: 0x00, scriptHashID: 0x05, hdPublicKeyID: Data([0x04, 0x88, 0xb2, 0x1e]),
        dnsSeeds: [
            PeerAddress(host: "seed.bitcoin.sipa.be", port: 8333),
            PeerAddress(host: "dnsseed.bluematt.me", port: 8333),
            PeerAddress(host: "dnsseed.bitcoin.dashjr.org", port: 8333),
            PeerAddress(host: "seed.bitcoin.jonasschnelli.ch", port: 8333),
            PeerAddress(host: "bitcoin.sprovoost.nl", port: 8333),
            PeerAddress(host: "dnsseed.emzy.de", port: 8333),
            PeerAddress(host: "seed.bitcoin.wiz.biz", port: 8333),
            PeerAddress(host: "seed.bitcoinstats.com", port: 8333),
        ])

    public static let testnet3 = Network(
        kind: .testnet3, name: "testnet3", magic: 0x0709_110b, defaultPort: 18333,
        genesis: genesis("0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4adae5494dffff001d1aa4ae18"),
        powLimit: mainPowLimit, powLimitBits: 0x1d00_ffff, reduceMinDifficulty: true, minDiffReductionTime: 1200, enforceBIP94: false,
        bech32HRP: "tb", pubKeyHashID: 0x6f, scriptHashID: 0xc4, hdPublicKeyID: Data([0x04, 0x35, 0x87, 0xcf]),
        dnsSeeds: [
            PeerAddress(host: "testnet-seed.bitcoin.jonasschnelli.ch", port: 18333),
            PeerAddress(host: "seed.tbtc.petertodd.org", port: 18333),
            PeerAddress(host: "testnet-seed.bluematt.me", port: 18333),
            PeerAddress(host: "testnet-seed.bitcoin.sprovoost.nl", port: 18333),
            PeerAddress(host: "testnet-seed.bitcoin.wiz.biz", port: 18333),
        ])

    public static let testnet4 = Network(
        kind: .testnet4, name: "testnet4", magic: 0x283f_161c, defaultPort: 48333,
        genesis: genesis("0100000000000000000000000000000000000000000000000000000000000000000000004e7b2b9128fe0291db0693af2ae418b767e657cd407e80cb1434221eaea7a07a046f3566ffff001dbb0c7817"),
        powLimit: mainPowLimit, powLimitBits: 0x1d00_ffff, reduceMinDifficulty: true, minDiffReductionTime: 1200, enforceBIP94: true,
        bech32HRP: "tb", pubKeyHashID: 0x6f, scriptHashID: 0xc4, hdPublicKeyID: Data([0x04, 0x35, 0x87, 0xcf]),
        dnsSeeds: [
            PeerAddress(host: "seed.testnet4.bitcoin.sprovoost.nl", port: 48333),
            PeerAddress(host: "seed.testnet4.wiz.biz", port: 48333),
        ])

    public static let signet = Network(
        kind: .signet, name: "signet", magic: 0x40cf_030a, defaultPort: 38333,
        genesis: genesis("0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a008f4d5fae77031e8ad22203"),
        powLimit: UInt256(hex: "00000377ae000000000000000000000000000000000000000000000000000000")!, powLimitBits: 0x1e03_77ae,
        reduceMinDifficulty: false, minDiffReductionTime: 1200, enforceBIP94: false,
        bech32HRP: "tb", pubKeyHashID: 0x6f, scriptHashID: 0xc4, hdPublicKeyID: Data([0x04, 0x35, 0x87, 0xcf]),
        dnsSeeds: [
            PeerAddress(host: "seed.signet.bitcoin.sprovoost.nl", port: 38333),
            PeerAddress(host: "seed.signet.achownodes.xyz", port: 38333),
        ])

    public static let regtest = Network(
        kind: .regtest, name: "regtest", magic: 0xdab5_bffa, defaultPort: 18444,
        genesis: genesis("0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4adae5494dffff7f2002000000"),
        powLimit: regtestPowLimit, powLimitBits: 0x207f_ffff, reduceMinDifficulty: true, minDiffReductionTime: 1200, enforceBIP94: false,
        bech32HRP: "bcrt", pubKeyHashID: 0x6f, scriptHashID: 0xc4, hdPublicKeyID: Data([0x04, 0x35, 0x87, 0xcf]),
        dnsSeeds: [])

    public static let simnet = Network(
        kind: .simnet, name: "simnet", magic: 0x1214_1c16, defaultPort: 18555,
        genesis: genesis("0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a45068653ffff7f2002000000"),
        powLimit: regtestPowLimit, powLimitBits: 0x207f_ffff, reduceMinDifficulty: true, minDiffReductionTime: 1200, enforceBIP94: false,
        bech32HRP: "sb", pubKeyHashID: 0x3f, scriptHashID: 0x7b, hdPublicKeyID: Data([0x04, 0x20, 0xbd, 0x3a]),
        dnsSeeds: [])
}
