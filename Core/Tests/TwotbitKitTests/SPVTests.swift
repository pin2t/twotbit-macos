import Foundation
import Testing
@testable import TwotbitKit

struct SPVFixture: Decodable {
    struct Net: Decodable {
        let name: String
        let net: UInt32
        let defaultPort: String
        let genesis: String
        let genesisHash: String
        let powLimit: String
        let powLimitBits: UInt32
        let reduceMinDifficulty: Bool
        let minDiffReductionTime: Int64
        let enforceBIP94: Bool
        let bech32HRP: String
        let pubKeyHashAddrID: UInt8
        let scriptHashAddrID: UInt8
        let hdPublicKeyID: String
    }
    struct CompactV: Decodable { let bits: UInt32; let target: String?; let error: Bool; let back: UInt32 }
    struct RetargetV: Decodable { let network: String; let first: Int64; let last: Int64; let oldBits: UInt32; let bits: UInt32 }
    struct GCSV: Decodable { let key: String; let items: [String]; let filter: String; let hash: String; let queries: [String]; let matches: [Bool] }
    struct BlockFilterV: Decodable {
        let height: Int32
        let blockHash: String
        let filter: String
        let filterHash: String
        let prevHeader: String?
        let header: String?
        let scripts: [String]?
        let absent: [String]?
        let absentMatches: [Bool]?
    }
    struct BlockV: Decodable {
        let name: String
        let hex: String
        let hash: String
        let merkleRoot: String
        let txids: [String]
        let wtxids: [String]
        let valid: Bool
        let error: String?
    }
    let networks: [Net]
    let compact: [CompactV]
    let retarget: [RetargetV]
    let gcs: [GCSV]
    let blockFilters: [BlockFilterV]
    let blocks: [BlockV]
}

/// easyBits is a minimal difficulty, so tests can mine headers at once.
let easyBits: UInt32 = 0x207f_ffff

/// Mines a header on the parent with the bits and time.
func mineHeader(prev: Hash256, bits: UInt32, time: UInt32) -> BlockHeader {
    var header = BlockHeader(version: 1, prevBlock: prev, merkleRoot: .zero, timestamp: time, bits: bits, nonce: 0)
    let target = Compact.target(bits)!
    while UInt256(header.hash) > target { header.nonce += 1 }
    return header
}

extension Network {
    /// The network with its minimum difficulty raised to easyBits, as the
    /// Go chain tests do to mine test headers on it.
    func easy() -> Network {
        Network(kind: kind, name: name, magic: magic, defaultPort: defaultPort, genesis: genesis,
                powLimit: Compact.target(easyBits)!, powLimitBits: easyBits, reduceMinDifficulty: reduceMinDifficulty,
                minDiffReductionTime: minDiffReductionTime, enforceBIP94: enforceBIP94, bech32HRP: bech32HRP,
                pubKeyHashID: pubKeyHashID, scriptHashID: scriptHashID, hdPublicKeyID: hdPublicKeyID, dnsSeeds: [])
    }
}

@Suite struct ChainTests {
    static let fixture = Fixtures.load("spv", as: SPVFixture.self)

    @Test func networkParameters() {
        for v in Self.fixture.networks {
            let n = Network.fixture(v.name)
            #expect(n.name == v.name)
            #expect(n.magic == v.net)
            #expect(String(n.defaultPort) == v.defaultPort)
            #expect(n.genesis.serialized.hex == v.genesis)
            #expect(n.genesisHash.hex == v.genesisHash)
            #expect(n.powLimit == UInt256(hex: v.powLimit))
            #expect(n.powLimitBits == v.powLimitBits)
            #expect(n.reduceMinDifficulty == v.reduceMinDifficulty)
            #expect(!n.reduceMinDifficulty || n.minDiffReductionTime == v.minDiffReductionTime)
            #expect(n.enforceBIP94 == v.enforceBIP94)
            #expect(n.bech32HRP == v.bech32HRP)
            #expect(n.pubKeyHashID == v.pubKeyHashAddrID)
            #expect(n.scriptHashID == v.scriptHashAddrID)
            #expect(n.hdPublicKeyID.hex == v.hdPublicKeyID)
        }
    }

    @Test func compactBits() {
        for v in Self.fixture.compact {
            let target = Compact.target(v.bits)
            if v.error {
                #expect(target == nil, "\(String(v.bits, radix: 16))")
                continue
            }
            guard let want = v.target.flatMap({ UInt256(hex: $0) }) else {
                // btcd decodes targets past 256 bits; Bitcoin Core rejects them.
                #expect(target == nil)
                continue
            }
            #expect(target == want, "\(String(v.bits, radix: 16))")
            #expect(Compact.bits(want) == v.back, "\(String(v.bits, radix: 16))")
        }
    }

    @Test func retargets() {
        for v in Self.fixture.retarget {
            #expect(HeaderChain.nextRetargetBits(first: v.first, last: v.last, oldBits: v.oldBits, network: .fixture(v.network)) == v.bits)
        }
    }

    /// The first 4100 mainnet headers, from btcd's test blocks, validate,
    /// across the retargets at 2016 and 4032.
    @Test func realMainnetHeaders() throws {
        let data = Fixtures.data("mainnet-headers-0-4099", "bin")
        var chain = HeaderChain(network: .mainnet)
        for i in 0..<(data.count / 80) {
            try chain.add(BlockHeader(data: data.subdata(in: i * 80..<(i + 1) * 80)))
        }
        #expect(chain.height == 4099)
        #expect(chain.entry(at: 0)?.hash == Network.mainnet.genesisHash)
        #expect(chain.height(of: chain.entry(at: 2016)!.hash) == 2016)
        var tampered = try BlockHeader(data: data.subdata(in: 4100 * 80 - 80..<4100 * 80))
        tampered.nonce ^= 1
        var short = HeaderChain(network: .mainnet)
        for i in 0..<4099 { try short.appendTrusted(BlockHeader(data: data.subdata(in: i * 80..<(i + 1) * 80))) }
        #expect(throws: ChainError.self) { try short.add(tampered) }
    }

    @Test func chainAdd() throws {
        let network = Network.regtest
        var chain = HeaderChain(network: network)
        try chain.add(network.genesis)
        var time = network.genesis.timestamp + 60
        var prev = network.genesisHash
        for _ in 1...3 {
            let header = mineHeader(prev: prev, bits: easyBits, time: time)
            try chain.add(header)
            prev = header.hash
            time += 60
        }
        #expect(chain.height == 3)
        #expect(chain.tip?.hash == prev)
        #expect(chain.height(of: prev) == 3)
        #expect(chain.locator().count == 4)
        var bad = mineHeader(prev: prev, bits: easyBits, time: time + 60)
        bad.bits = 0x1d00_ffff
        #expect(throws: ChainError.self, "invalid proof of work") { try chain.add(bad) }
        bad = mineHeader(prev: .zero, bits: easyBits, time: time + 60)
        #expect(throws: ChainError.self, "broken linkage") { try chain.add(bad) }
        bad = mineHeader(prev: prev, bits: easyBits, time: time - 3600)
        #expect(throws: ChainError.self, "stale timestamp") { try chain.add(bad) }
        bad = mineHeader(prev: prev, bits: easyBits, time: UInt32(Date().timeIntervalSince1970) + 3 * 3600)
        #expect(throws: ChainError.self, "future timestamp") { try chain.add(bad) }
        chain.truncate(to: 1)
        #expect(chain.height == 1)
        #expect(chain.height(of: prev) == -1)
    }

    /// A header easier than the network's limit is refused even with its
    /// own proof of work met.
    @Test func powLimit() throws {
        var chain = HeaderChain(network: .mainnet)
        try chain.add(Network.mainnet.genesis)
        let easy = mineHeader(prev: Network.mainnet.genesisHash, bits: easyBits, time: Network.mainnet.genesis.timestamp + 600)
        #expect(throws: ChainError.self) { try chain.add(easy) }
    }

    /// Within a difficulty period a mainnet header must keep its parent's
    /// bits.
    @Test func bitsWithinPeriod() throws {
        let network = Network.signet.easy()
        var chain = HeaderChain(network: network)
        try chain.add(network.genesis)
        let harder = Compact.bits(Compact.target(easyBits)! >> 1)
        let header = mineHeader(prev: network.genesisHash, bits: harder, time: network.genesis.timestamp + 600)
        #expect(throws: ChainError.self) { try chain.add(header) }
    }

    @Test func testnetMinDifficulty() throws {
        for base in [Network.testnet3, Network.testnet4] {
            let network = base.easy()
            var chain = HeaderChain(network: network)
            try chain.add(network.genesis)
            let late = network.genesis.timestamp + 21 * 60
            var header = mineHeader(prev: network.genesisHash, bits: easyBits, time: late)
            try chain.add(header)
            header = mineHeader(prev: header.hash, bits: easyBits, time: late + 1)
            #expect(throws: ChainError.self, "\(network.name): min difficulty without the gap") { try chain.add(header) }
        }
    }

    /// trustedChain builds a chain of n headers after genesis, ten minutes
    /// apart, without mining.
    func trustedChain(_ network: Network, _ n: Int, bits: (Int) -> UInt32) throws -> HeaderChain {
        var chain = HeaderChain(network: network)
        try chain.appendTrusted(network.genesis)
        var prev = network.genesisHash
        for height in 1...n {
            let header = BlockHeader(version: 4, prevBlock: prev, merkleRoot: .zero,
                                     timestamp: network.genesis.timestamp + UInt32(height * 600), bits: bits(height), nonce: 0)
            try chain.appendTrusted(header)
            prev = header.hash
        }
        return chain
    }

    @Test func testnetDifficultyAtLimit() throws {
        for base in [Network.testnet3, Network.testnet4] {
            let network = base.easy()
            var chain = try trustedChain(network, Int(HeaderChain.retargetInterval) + 1) { _ in easyBits }
            let parent = chain.tip!
            let header = mineHeader(prev: parent.hash, bits: easyBits, time: parent.time + 60)
            try chain.add(header)
        }
    }

    @Test func retargetBIP94() throws {
        let periodBits: UInt32 = 0x2000_ffff
        let network = Network.testnet4.easy()
        let last = 2 * Int(HeaderChain.retargetInterval) - 1
        var chain = try trustedChain(network, last) { $0 == last ? easyBits : periodBits }
        let first = chain.entry(at: HeaderChain.retargetInterval)!
        let parent = chain.tip!
        let want = HeaderChain.nextRetargetBits(first: Int64(first.time), last: Int64(parent.time), oldBits: periodBits, network: network)
        let testnet3 = HeaderChain.nextRetargetBits(first: Int64(first.time), last: Int64(parent.time), oldBits: easyBits, network: network)
        #expect(want != testnet3)
        let late = parent.time + 21 * 60
        #expect(throws: ChainError.self, "min difficulty at the retarget") { try chain.add(mineHeader(prev: parent.hash, bits: easyBits, time: late)) }
        #expect(throws: ChainError.self, "retarget from the last block") { try chain.add(mineHeader(prev: parent.hash, bits: testnet3, time: late)) }
        #expect(throws: ChainError.self, "time warp") { try chain.add(mineHeader(prev: parent.hash, bits: want, time: parent.time - 11 * 60)) }
        try chain.add(mineHeader(prev: parent.hash, bits: want, time: parent.time - 9 * 60))
    }

    @Test func firstHeightAtOrAfter() throws {
        let network = Network.regtest
        let chain = try trustedChain(network, 30) { _ in easyBits }
        let base = Int64(network.genesis.timestamp)
        #expect(chain.firstHeight(atOrAfter: 0) == 0)
        #expect(chain.firstHeight(atOrAfter: base + 600 * 7) == 7)
        #expect(chain.firstHeight(atOrAfter: base + 600 * 7 - 1) == 7)
        #expect(chain.firstHeight(atOrAfter: base + 600 * 31) == 31)
    }
}

@Suite struct FilterTests {
    @Test func gcsVectors() throws {
        for v in ChainTests.fixture.gcs {
            let blockHash = Hash256(data: Data(h: v.key))!
            let filter = Data(h: v.filter)
            #expect(GCSFilter.hash(filter).hex == v.hash)
            let hits = try GCSFilter.matchScripts(filter, blockHash: blockHash, scripts: v.queries.map { Data(h: $0) })
            #expect(hits == v.matches)
            #expect(GCSFilter.build(items: v.items.map { Data(h: $0) }, blockHash: blockHash) == filter)
        }
    }

    @Test func realBlockFilters() throws {
        for v in ChainTests.fixture.blockFilters {
            let blockHash = Hash256(hex: v.blockHash)!
            let filter = Data(h: v.filter)
            #expect(GCSFilter.hash(filter).hex == v.filterHash)
            let scripts = (v.scripts ?? []).map { Data(h: $0) }
            let hits = try GCSFilter.matchScripts(filter, blockHash: blockHash, scripts: scripts)
            #expect(hits.allSatisfy { $0 }, "block \(v.height)")
            if let absent = v.absent, let want = v.absentMatches {
                #expect(try GCSFilter.matchScripts(filter, blockHash: blockHash, scripts: absent.map { Data(h: $0) }) == want)
            }
            if let prev = v.prevHeader, let header = v.header, !prev.isEmpty {
                #expect(GCSFilter.header(filterHash: Hash256(hex: v.filterHash)!, previous: Hash256(hex: prev)!).hex == header)
            }
            var unique = [Data]()
            for s in scripts where !unique.contains(s) { unique.append(s) }
            #expect(GCSFilter.build(items: unique, blockHash: blockHash) == filter, "block \(v.height)")
        }
    }

    @Test func emptyFilter() throws {
        let filter = GCSFilter.build(items: [], blockHash: .zero)
        #expect(filter == Data([0]))
        #expect(try GCSFilter.matchScripts(filter, blockHash: .zero, scripts: [Data([1])]) == [false])
    }

    @Test func bloomVectors() {
        let fixture = Fixtures.load("sync", as: SyncFixture.self)
        for v in fixture.blooms {
            var filter = BloomFilter(elements: v.elements, tweak: v.tweak, fpRate: v.fpRate)
            for item in v.items { filter.add(Data(h: item)) }
            for op in v.outPoints { filter.add(OutPoint(string: op)!) }
            #expect(Data(filter.data).hex == v.filter, "\(v.elements) at \(v.fpRate)")
            #expect(filter.hashFuncs == v.hashFuncs)
            #expect(Message.filterLoad(filter).payload.hex == v.message)
            for item in v.items { #expect(filter.contains(Data(h: item))) }
        }
    }
}

@Suite struct BlockTests {
    @Test func blocks() throws {
        for v in ChainTests.fixture.blocks {
            let block = try Block(data: Data(h: v.hex))
            #expect(block.serialized.hex == v.hex, "\(v.name)")
            #expect(block.hash.hex == v.hash)
            #expect(block.transactions.map(\.txid.hex) == v.txids)
            #expect(block.transactions.map(\.wtxid.hex) == v.wtxids)
            #expect(block.header.merkleRoot.hex == v.merkleRoot)
            let verified = (try? block.verify(expected: Hash256(hex: v.hash)!)) != nil
            #expect(verified == v.valid, "\(v.name)")
        }
        let first = try Block(data: Data(h: ChainTests.fixture.blocks[0].hex))
        #expect(throws: BlockError.self) { try first.verify(expected: .zero) }
    }
}
