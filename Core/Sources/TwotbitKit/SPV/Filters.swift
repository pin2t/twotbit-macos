import Foundation

/// GCSFilter is a BIP158 basic block filter: a Golomb-Rice coded set of the
/// scripts a block creates and spends, mapped into a range with SipHash
/// keyed by the block hash.
public struct GCSFilter: Sendable {
    /// The Golomb-Rice parameter P and the false positive rate M of the
    /// basic filter type.
    public static let p: UInt64 = 19
    public static let m: UInt64 = 784_931

    /// The number of items in the set.
    public let n: UInt64
    /// The Golomb-Rice coded deltas of the sorted mapped items.
    private let bits: [UInt8]

    /// Reads a serialized filter: the item count as a compact size, then
    /// the coded set.
    public init(serialized: Data) throws {
        var reader = ByteReader(serialized)
        n = try reader.readVarInt()
        guard n < 1 << 32 else { throw DecodeError.invalid("filter of \(n) items") }
        bits = try reader.readByteArray(reader.remaining)
    }

    /// The SipHash key of a block's filter: the first half of the block
    /// hash in internal byte order.
    public static func key(blockHash: Hash256) -> (UInt64, UInt64) { (blockHash.w0, blockHash.w1) }

    /// The item mapped into [0, n·M) by the fast range reduction of its
    /// SipHash.
    static func map(_ item: Data, key: (UInt64, UInt64), modulus: UInt64) -> UInt64 {
        SipHash.hash(k0: key.0, k1: key.1, [UInt8](item)).multipliedFullWidth(by: modulus).high
    }

    /// Reports which of the items are in the filter of the block, in one
    /// pass over the coded set.
    public func match(_ items: [Data], blockHash: Hash256) -> [Bool] {
        var hits = [Bool](repeating: false, count: items.count)
        guard n > 0, !items.isEmpty else { return hits }
        let modulus = n * GCSFilter.m
        let key = GCSFilter.key(blockHash: blockHash)
        let targets = items.enumerated().map { (value: GCSFilter.map($0.element, key: key, modulus: modulus), index: $0.offset) }
            .sorted { $0.value < $1.value }
        var reader = BitReader(bits)
        var value: UInt64 = 0
        var t = 0
        for _ in 0..<n {
            guard let delta = reader.readGolombRice(p: GCSFilter.p) else { break }
            value &+= delta
            while t < targets.count && targets[t].value < value { t += 1 }
            if t == targets.count { break }
            while t < targets.count && targets[t].value == value {
                hits[targets[t].index] = true
                t += 1
            }
            if t == targets.count { break }
        }
        return hits
    }

    /// Builds the serialized filter of the items for the block, as btcd's
    /// BuildGCSFilter does: every item mapped, sorted and coded as deltas.
    public static func build(items: [Data], blockHash: Hash256) -> Data {
        var writer = ByteWriter()
        writer.writeVarInt(UInt64(items.count))
        let modulus = UInt64(items.count) * m
        let key = key(blockHash: blockHash)
        let values = items.map { map($0, key: key, modulus: modulus) }.sorted()
        var bitWriter = BitWriter()
        var last: UInt64 = 0
        for v in values {
            let delta = v - last
            last = v
            for _ in 0..<(delta >> p) { bitWriter.write(bit: true) }
            bitWriter.write(bit: false)
            bitWriter.write(delta & ((1 << p) - 1), bits: Int(p))
        }
        writer.write(bitWriter.bytes)
        return writer.data
    }

    /// The double SHA256 of a serialized filter, which cfheaders messages
    /// list and the filter header chain commits to.
    public static func hash(_ serialized: Data) -> Hash256 { Hashes.sha256d(serialized) }

    /// The filter header chaining a filter hash to the previous header:
    /// SHA256d(filter hash || previous header), per BIP157. The genesis
    /// filter chains to the null hash.
    public static func header(filterHash: Hash256, previous: Hash256) -> Hash256 {
        var data = filterHash.data
        previous.append(to: &data)
        return Hashes.sha256d(data)
    }

    /// Decodes a serialized filter and reports which scripts are in it.
    public static func matchScripts(_ serialized: Data, blockHash: Hash256, scripts: [Data]) throws -> [Bool] {
        try GCSFilter(serialized: serialized).match(scripts, blockHash: blockHash)
    }
}

/// BitReader reads a byte string most significant bit first.
struct BitReader {
    private let bytes: [UInt8]
    private var position = 0

    init(_ bytes: [UInt8]) { self.bytes = bytes }

    mutating func readBit() -> Bool? {
        guard position < bytes.count * 8 else { return nil }
        defer { position += 1 }
        return bytes[position >> 3] >> (7 - UInt8(position & 7)) & 1 == 1
    }

    mutating func read(bits count: Int) -> UInt64? {
        var v: UInt64 = 0
        for _ in 0..<count {
            guard let bit = readBit() else { return nil }
            v = v << 1 | (bit ? 1 : 0)
        }
        return v
    }

    /// A Golomb-Rice coded value: the quotient in unary, then P bits of
    /// remainder. Nil at the end of the data.
    mutating func readGolombRice(p: UInt64) -> UInt64? {
        var quotient: UInt64 = 0
        while true {
            guard let bit = readBit() else { return nil }
            if !bit { break }
            quotient += 1
        }
        guard let remainder = read(bits: Int(p)) else { return nil }
        return quotient << p | remainder
    }
}

/// BitWriter writes bits most significant first, padding the last byte
/// with zeros.
struct BitWriter {
    private(set) var bytes: [UInt8] = []
    private var used = 8

    mutating func write(bit: Bool) {
        if used == 8 {
            bytes.append(0)
            used = 0
        }
        if bit { bytes[bytes.count - 1] |= 1 << (7 - UInt8(used)) }
        used += 1
    }

    mutating func write(_ value: UInt64, bits count: Int) {
        for i in stride(from: count - 1, through: 0, by: -1) {
            write(bit: value >> UInt64(i) & 1 == 1)
        }
    }
}

/// BloomFilter is a BIP37 bloom filter as btcutil's bloom package builds
/// it, for peers to relay only the transactions matching the wallet.
public struct BloomFilter: Sendable {
    /// The protocol limits of filterload: filter bytes and hash functions.
    public static let maxFilterSize = 36_000
    public static let maxHashFuncs: UInt32 = 50
    /// BloomUpdateNone: the peer must not add matched outputs itself.
    public static let updateNone: UInt8 = 0

    public private(set) var data: [UInt8]
    public let hashFuncs: UInt32
    public let tweak: UInt32
    public let flags: UInt8

    /// A filter sized for the number of elements at the false positive
    /// rate: m = -n·ln(p)/ln(2)² bits and k = m/n·ln(2) hash functions,
    /// clamped to the protocol limits.
    public init(elements: UInt32, tweak: UInt32, fpRate: Double, flags: UInt8 = BloomFilter.updateNone) {
        let rate = min(max(fpRate, 1e-9), 1.0)
        let n = Double(max(elements, 1))
        let ln2Squared = M_LN2 * M_LN2
        var dataLen = UInt32(-1 * n * log(rate) / ln2Squared)
        dataLen = min(dataLen, UInt32(BloomFilter.maxFilterSize * 8)) / 8
        let funcs = UInt32(Double(dataLen * 8) / n * M_LN2)
        data = [UInt8](repeating: 0, count: Int(dataLen))
        hashFuncs = min(funcs, BloomFilter.maxHashFuncs)
        self.tweak = tweak
        self.flags = flags
    }

    /// A filter of the given bits, as a filterload message carries it.
    public init(raw: [UInt8], hashFuncs: UInt32, tweak: UInt32, flags: UInt8) {
        data = raw
        self.hashFuncs = hashFuncs
        self.tweak = tweak
        self.flags = flags
    }

    private func hash(_ number: UInt32, _ item: [UInt8]) -> Int {
        Int(Murmur3.hash(seed: number &* 0xfba4_c795 &+ tweak, item) % (UInt32(data.count) << 3))
    }

    public mutating func add(_ item: Data) {
        guard !data.isEmpty else { return }
        let bytes = [UInt8](item)
        for i in 0..<hashFuncs {
            let index = hash(i, bytes)
            data[index >> 3] |= 1 << UInt8(index & 7)
        }
    }

    /// Adds an outpoint as BIP37 matches spends of it: its 36-byte
    /// serialization.
    public mutating func add(_ outPoint: OutPoint) { add(outPoint.serialized) }

    public func contains(_ item: Data) -> Bool {
        guard !data.isEmpty else { return true }
        let bytes = [UInt8](item)
        for i in 0..<hashFuncs {
            let index = hash(i, bytes)
            if data[index >> 3] & (1 << UInt8(index & 7)) == 0 { return false }
        }
        return true
    }
}
