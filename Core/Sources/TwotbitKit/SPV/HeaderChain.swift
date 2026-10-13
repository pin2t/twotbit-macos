import Foundation

/// ChainEntry is what the header chain keeps of each validated header: its
/// hash, time and difficulty bits, all the validation of later headers and
/// the sync need. Mainnet's chain of over 900 000 headers fits in about 40
/// bytes a header this way.
public struct ChainEntry: Sendable, Hashable {
    public let hash: Hash256
    public let time: UInt32
    public let bits: UInt32
}

public struct ChainError: Error, CustomStringConvertible, Sendable {
    public let description: String
    init(_ description: String) { self.description = description }
}

/// HeaderChain is an ordered, validated chain of block headers from the
/// genesis block. Every header added is checked as Bitcoin Core checks
/// headers: proof of work against its target and the network's limit,
/// linkage to the tip, a time after the median of the last eleven and
/// within two hours of now, and the difficulty bits the network's rules
/// require, testnet's minimum difficulty exception and testnet4's BIP94
/// included.
public struct HeaderChain: Sendable {
    /// The most a block time may be ahead of the local clock.
    static let maxFutureDrift: Int64 = 2 * 60 * 60
    /// The number of past blocks whose median time a new block must pass.
    static let medianWindow = 11
    /// The blocks between difficulty adjustments and the time they should
    /// take.
    public static let retargetInterval: Int32 = 2016
    static let retargetTimespan: Int64 = 2016 * 10 * 60
    /// How far before its parent the first block of a difficulty period may
    /// be dated under BIP94.
    static let maxTimeWarp: Int64 = 10 * 60

    public let network: Network
    private var entries: [ChainEntry] = []
    /// Heights by the first eight bytes of the block hash, the random end of
    /// it. A lookup checks the full hash.
    private var index: [UInt64: Int32] = [:]

    public init(network: Network) {
        self.network = network
    }

    /// The tip height, or -1 for an empty chain.
    public var height: Int32 { Int32(entries.count) - 1 }

    public var tip: ChainEntry? { entries.last }

    public func entry(at height: Int32) -> ChainEntry? {
        guard height >= 0, Int(height) < entries.count else { return nil }
        return entries[Int(height)]
    }

    /// The height of the block hash, or -1 when it is not in the chain.
    /// Two hashes sharing their first eight bytes, which takes about 2^32
    /// blocks to happen once, fall back to a scan.
    public func height(of hash: Hash256) -> Int32 {
        guard let h = index[hash.w0] else { return -1 }
        if entries[Int(h)].hash == hash { return h }
        return Int32(entries.lastIndex { $0.hash == hash } ?? -1)
    }

    public func contains(_ hash: Hash256) -> Bool { height(of: hash) >= 0 }

    /// The block locator of a getheaders request: hashes from the tip back
    /// toward genesis, every one for the first eleven, then with
    /// exponentially growing steps.
    public func locator() -> [Hash256] {
        guard !entries.isEmpty else { return [.zero] }
        var out = [Hash256]()
        var step: Int32 = 1
        var h = height
        while h >= 0 {
            out.append(entries[Int(h)].hash)
            if out.count > 10 { step *= 2 }
            h -= step
        }
        return out
    }

    /// Validates the header as the direct successor of the tip and appends
    /// it.
    public mutating func add(_ header: BlockHeader, now: Int64 = Int64(Date().timeIntervalSince1970)) throws {
        let height = Int32(entries.count)
        let hash = header.hash
        do {
            try checkProofOfWork(header, hash: hash)
        } catch let error as ChainError {
            throw ChainError("header \(hash) at height \(height): \(error)")
        }
        if height == 0 {
            guard hash == network.genesisHash else { throw ChainError("first header \(hash), want genesis \(network.genesisHash)") }
        } else {
            let tip = entries[Int(height) - 1]
            guard header.prevBlock == tip.hash else {
                throw ChainError("header \(hash) at height \(height): prev block \(header.prevBlock), want \(tip.hash)")
            }
            let median = medianTime()
            guard header.timestamp > median else {
                throw ChainError("header \(hash) at height \(height): timestamp \(header.timestamp) not after median \(median)")
            }
            guard Int64(header.timestamp) <= now + HeaderChain.maxFutureDrift else {
                throw ChainError("header \(hash) at height \(height): timestamp \(header.timestamp) too far in the future")
            }
            do {
                try checkDifficulty(header, height: height)
            } catch let error as ChainError {
                throw ChainError("header \(hash) at height \(height): \(error)")
            }
        }
        append(hash: hash, header: header)
    }

    /// Appends a header that was validated before it was stored: the
    /// wallet's own database is trusted, so only the linkage is checked
    /// when reloading.
    public mutating func appendTrusted(_ header: BlockHeader) throws {
        let height = Int32(entries.count)
        let hash = header.hash
        if height == 0 {
            guard hash == network.genesisHash else { throw ChainError("first header \(hash), want genesis \(network.genesisHash)") }
        } else if header.prevBlock != entries[Int(height) - 1].hash {
            throw ChainError("stored header \(hash) at height \(height): prev block \(header.prevBlock), want \(entries[Int(height) - 1].hash)")
        }
        append(hash: hash, header: header)
    }

    private mutating func append(hash: Hash256, header: BlockHeader) {
        if index[hash.w0] == nil { index[hash.w0] = Int32(entries.count) }
        entries.append(ChainEntry(hash: hash, time: header.timestamp, bits: header.bits))
    }

    /// Removes every header above the height.
    public mutating func truncate(to height: Int32) {
        let keep = max(Int(height) + 1, 0)
        guard keep < entries.count else { return }
        for h in keep..<entries.count {
            let key = entries[h].hash.w0
            if let indexed = index[key], Int(indexed) >= keep { index[key] = nil }
        }
        entries.removeSubrange(keep...)
    }

    /// Reserves room for the number of headers, to load a stored chain
    /// without regrowing.
    public mutating func reserve(_ count: Int) {
        entries.reserveCapacity(count)
        index.reserveCapacity(count)
    }

    /// The first height whose block time is at or after the unix time, or
    /// the tip height plus one when every block is older.
    public func firstHeight(atOrAfter unix: Int64) -> Int32 {
        guard unix > 0 else { return 0 }
        for (h, entry) in entries.enumerated() where Int64(entry.time) >= unix {
            return Int32(h)
        }
        return height + 1
    }

    /// The proof of work of the blocks above the height: the expected number
    /// of hashes to find them, 2^256 / (target + 1) each, as Bitcoin Core
    /// sums it, in floating point, which is close enough to tell branches
    /// apart.
    public func work(above height: Int32) -> Double {
        let start = max(Int(height) + 1, 0)
        guard start < entries.count else { return 0 }
        return entries[start...].reduce(0) { $0 + ($1.bits).compactWork }
    }

    /// The median time of the last eleven blocks.
    func medianTime() -> UInt32 {
        let times = entries.suffix(HeaderChain.medianWindow).map(\.time).sorted()
        return times[times.count / 2]
    }

    /// Checks the hash against the target of the header's bits, refusing a
    /// negative, zero or overflowing target and one easier than the
    /// network's limit, as Bitcoin Core's CheckProofOfWork does.
    func checkProofOfWork(_ header: BlockHeader, hash: Hash256) throws {
        guard header.bits != 0 else { throw ChainError("zero difficulty bits") }
        guard let target = header.bits.compactTarget, !target.isZero else {
            throw ChainError("invalid difficulty bits \(String(header.bits, radix: 16))")
        }
        guard target <= network.powLimit else {
            throw ChainError("difficulty bits \(String(header.bits, radix: 16)) easier than the network's limit")
        }
        guard UInt256(hash) <= target else { throw ChainError("hash \(hash) exceeds target \(target)") }
    }

    /// Checks the bits against the difficulty the rules require at the
    /// height, as Bitcoin Core's GetNextWorkRequired computes it: the
    /// parent's bits within a difficulty period and the retargeted bits at
    /// its start. On testnet3 and testnet4 a block more than 20 minutes after
    /// its parent has the minimum difficulty, and others in a period that of
    /// the last block not using that exception. Testnet4 also enforces
    /// BIP94: a period's first block may not be dated more than 10 minutes
    /// before its parent, and its difficulty is scaled from the first block
    /// of the previous period instead of the last.
    func checkDifficulty(_ header: BlockHeader, height: Int32) throws {
        guard network.checksDifficulty else { return }
        let parent = entries[Int(height) - 1]
        if height % HeaderChain.retargetInterval != 0 {
            var want = parent.bits
            if network.reduceMinDifficulty {
                if Int64(header.timestamp) - Int64(parent.time) > network.minDiffReductionTime {
                    want = network.powLimitBits
                } else {
                    want = lastRealBits(height - 1)
                }
            }
            guard header.bits == want else {
                throw ChainError("bits \(String(header.bits, radix: 16)), want \(String(want, radix: 16))")
            }
            return
        }
        let first = entries[Int(height - HeaderChain.retargetInterval)]
        var oldBits = parent.bits
        if network.enforceBIP94 {
            guard Int64(header.timestamp) >= Int64(parent.time) - HeaderChain.maxTimeWarp else {
                throw ChainError("timestamp \(header.timestamp) at difficulty retarget is more than 10 minutes before parent \(parent.time)")
            }
            oldBits = first.bits
        }
        let want = HeaderChain.nextRetargetBits(first: Int64(first.time), last: Int64(parent.time), oldBits: oldBits, network: network)
        guard header.bits == want else {
            throw ChainError("bits \(String(header.bits, radix: 16)) at difficulty retarget, want \(String(want, radix: 16))")
        }
    }

    /// The bits of the latest block at or below the height that is not a
    /// minimum difficulty exception: the difficulty of its period.
    func lastRealBits(_ height: Int32) -> UInt32 {
        var h = height
        while h > 0 && h % HeaderChain.retargetInterval != 0 && entries[Int(h)].bits == network.powLimitBits {
            h -= 1
        }
        return entries[Int(h)].bits
    }

    /// The bits of the first block after a difficulty period: the old
    /// target scaled by the time the period took, clamped to a factor of
    /// four either way and to the network's limit.
    public static func nextRetargetBits(first: Int64, last: Int64, oldBits: UInt32, network: Network) -> UInt32 {
        let actual = min(max(last - first, retargetTimespan / 4), retargetTimespan * 4)
        guard let old = oldBits.compactTarget else { return network.powLimitBits }
        var target = old.scaled(by: UInt64(actual), dividedBy: UInt64(retargetTimespan))
        if target > network.powLimit { target = network.powLimit }
        return target.compactBits
    }
}
