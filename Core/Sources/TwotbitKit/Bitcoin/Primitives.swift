import Foundation

/// BlockHeader is the 80-byte header of a block.
public struct BlockHeader: Sendable, Hashable {
    public var version: Int32
    public var prevBlock: Hash256
    public var merkleRoot: Hash256
    public var timestamp: UInt32
    public var bits: UInt32
    public var nonce: UInt32

    public init(version: Int32, prevBlock: Hash256, merkleRoot: Hash256, timestamp: UInt32, bits: UInt32, nonce: UInt32) {
        self.version = version
        self.prevBlock = prevBlock
        self.merkleRoot = merkleRoot
        self.timestamp = timestamp
        self.bits = bits
        self.nonce = nonce
    }

    public init(data: Data) throws {
        var reader = ByteReader(data)
        try self.init(from: &reader)
    }

    public init(from reader: inout ByteReader) throws {
        version = try reader.readInt32()
        prevBlock = try reader.readHash()
        merkleRoot = try reader.readHash()
        timestamp = try reader.readUInt32()
        bits = try reader.readUInt32()
        nonce = try reader.readUInt32()
    }

    public func write(to writer: inout ByteWriter) {
        writer.writeInt32(version)
        writer.write(prevBlock)
        writer.write(merkleRoot)
        writer.writeUInt32(timestamp)
        writer.writeUInt32(bits)
        writer.writeUInt32(nonce)
    }

    public var serialized: Data {
        var writer = ByteWriter(capacity: 80)
        write(to: &writer)
        return writer.data
    }

    /// The block hash: the double SHA256 of the serialized header.
    public var hash: Hash256 { serialized.sha256d() }
}

/// OutPoint names one transaction output: the id of its transaction and its
/// index there.
public struct OutPoint: Hashable, Sendable, CustomStringConvertible {
    public var hash: Hash256
    public var index: UInt32

    public init(hash: Hash256, index: UInt32) {
        self.hash = hash
        self.index = index
    }

    /// The previous output of a coinbase input.
    public static let coinbase = OutPoint(hash: .zero, index: 0xffff_ffff)

    public var isCoinbase: Bool { self == .coinbase }

    /// "txid:index", as btcd writes outpoints.
    public var description: String { "\(hash.hex):\(index)" }

    /// Parses the "txid:index" form.
    public init?(string: String) {
        let parts = string.split(separator: ":")
        guard parts.count == 2, let hash = Hash256(hex: String(parts[0])), let index = UInt32(parts[1]) else { return nil }
        self.init(hash: hash, index: index)
    }

    public func write(to writer: inout ByteWriter) {
        writer.write(hash)
        writer.writeUInt32(index)
    }

    public var serialized: Data {
        var writer = ByteWriter(capacity: 36)
        write(to: &writer)
        return writer.data
    }
}

public struct TxIn: Sendable, Hashable {
    public var previousOutPoint: OutPoint
    public var signatureScript: Data
    public var witness: [Data]
    public var sequence: UInt32

    public init(previousOutPoint: OutPoint, signatureScript: Data = Data(), witness: [Data] = [], sequence: UInt32 = 0xffff_ffff) {
        self.previousOutPoint = previousOutPoint
        self.signatureScript = signatureScript
        self.witness = witness
        self.sequence = sequence
    }
}

public struct TxOut: Sendable, Hashable {
    public var value: Int64
    public var pkScript: Data

    public init(value: Int64, pkScript: Data) {
        self.value = value
        self.pkScript = pkScript
    }

    public func write(to writer: inout ByteWriter) {
        writer.writeInt64(value)
        writer.writeVarBytes(pkScript)
    }
}

/// Transaction is a Bitcoin transaction, read and written with its witness
/// data in the BIP144 encoding when it has any.
public struct Transaction: Sendable, Hashable {
    public var version: Int32
    public var inputs: [TxIn]
    public var outputs: [TxOut]
    public var lockTime: UInt32

    public init(version: Int32 = 2, inputs: [TxIn] = [], outputs: [TxOut] = [], lockTime: UInt32 = 0) {
        self.version = version
        self.inputs = inputs
        self.outputs = outputs
        self.lockTime = lockTime
    }

    public init(data: Data) throws {
        var reader = ByteReader(data)
        try self.init(from: &reader)
        guard reader.isAtEnd else { throw DecodeError.invalid("trailing data after transaction") }
    }

    /// Reads a transaction in either encoding: a zero input count followed
    /// by the flag byte 1 marks the witness encoding.
    public init(from reader: inout ByteReader) throws {
        version = try reader.readInt32()
        var count = try reader.readCount(limit: reader.remaining / 41 + 1)
        var hasWitness = false
        if count == 0 {
            let flag = try reader.readUInt8()
            guard flag == 0x01 else { throw DecodeError.invalid("witness flag \(flag), want 1") }
            hasWitness = true
            count = try reader.readCount(limit: reader.remaining / 41 + 1)
        }
        inputs = []
        inputs.reserveCapacity(count)
        for _ in 0..<count {
            let hash = try reader.readHash()
            let index = try reader.readUInt32()
            let script = try reader.readVarBytes(limit: 10_000_000)
            let sequence = try reader.readUInt32()
            inputs.append(TxIn(previousOutPoint: OutPoint(hash: hash, index: index), signatureScript: script, sequence: sequence))
        }
        let outCount = try reader.readCount(limit: reader.remaining / 9 + 1)
        outputs = []
        outputs.reserveCapacity(outCount)
        for _ in 0..<outCount {
            let value = try reader.readInt64()
            let script = try reader.readVarBytes(limit: 10_000_000)
            outputs.append(TxOut(value: value, pkScript: script))
        }
        if hasWitness {
            for i in 0..<inputs.count {
                let items = try reader.readCount(limit: reader.remaining + 1)
                var witness = [Data]()
                witness.reserveCapacity(items)
                for _ in 0..<items {
                    witness.append(try reader.readVarBytes(limit: 10_000_000))
                }
                inputs[i].witness = witness
            }
        }
        lockTime = try reader.readUInt32()
    }

    /// Whether any input carries witness data.
    public var hasWitness: Bool { inputs.contains { !$0.witness.isEmpty } }

    public func write(to writer: inout ByteWriter, witness: Bool) {
        let withWitness = witness && hasWitness
        writer.writeInt32(version)
        if withWitness {
            writer.writeUInt8(0x00)
            writer.writeUInt8(0x01)
        }
        writer.writeVarInt(UInt64(inputs.count))
        for input in inputs {
            input.previousOutPoint.write(to: &writer)
            writer.writeVarBytes(input.signatureScript)
            writer.writeUInt32(input.sequence)
        }
        writer.writeVarInt(UInt64(outputs.count))
        for output in outputs { output.write(to: &writer) }
        if withWitness {
            for input in inputs {
                writer.writeVarInt(UInt64(input.witness.count))
                for item in input.witness { writer.writeVarBytes(item) }
            }
        }
        writer.writeUInt32(lockTime)
    }

    /// The serialized transaction, with its witness data unless witness is
    /// false.
    public func serialized(witness: Bool = true) -> Data {
        var writer = ByteWriter(capacity: 256)
        write(to: &writer, witness: witness)
        return writer.data
    }

    /// The transaction id: the hash of the serialization without witness.
    public var txid: Hash256 { serialized(witness: false).sha256d() }

    /// The witness transaction id, which commits to the witness data too.
    public var wtxid: Hash256 { serialized(witness: true).sha256d() }

    public var isCoinbase: Bool { inputs.count == 1 && inputs[0].previousOutPoint.isCoinbase }

    /// The weight per BIP141: the stripped size three times plus the full
    /// size.
    public var weight: Int { serialized(witness: false).count * 3 + serialized(witness: true).count }

    /// The virtual size in vbytes: the weight divided by four, rounded up.
    public var vsize: Int { (weight + 3) / 4 }
}

/// Block is a full block: its header and its transactions.
public struct Block: Sendable {
    public var header: BlockHeader
    public var transactions: [Transaction]

    public init(header: BlockHeader, transactions: [Transaction]) {
        self.header = header
        self.transactions = transactions
    }

    public init(data: Data) throws {
        var reader = ByteReader(data)
        try self.init(from: &reader)
    }

    public init(from reader: inout ByteReader) throws {
        header = try BlockHeader(from: &reader)
        let count = try reader.readCount(limit: reader.remaining / 60 + 1)
        transactions = []
        transactions.reserveCapacity(count)
        for _ in 0..<count {
            transactions.append(try Transaction(from: &reader))
        }
    }

    public var hash: Hash256 { header.hash }

    public var serialized: Data {
        var writer = ByteWriter(capacity: 1024)
        header.write(to: &writer)
        writer.writeVarInt(UInt64(transactions.count))
        for tx in transactions { tx.write(to: &writer, witness: true) }
        return writer.data
    }


    /// The witness commitment prefix of a coinbase output: OP_RETURN, a
    /// 36-byte push and the BIP141 magic.
    static let witnessMagic: [UInt8] = [0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed]

    /// Verifies that the block is the one the header chain committed to:
    /// its header hashes to the expected hash, its transactions hash to the
    /// merkle root without duplicates, and its witness data matches the
    /// coinbase witness commitment, as btcd's ValidateWitnessCommitment
    /// checks it.
    public func verify(expected: Hash256) throws {
        let got = hash
        guard got == expected else { throw BlockError("block hash \(got), want \(expected)") }
        guard !transactions.isEmpty else { throw BlockError("block has no transactions") }
        var seen = Set<Hash256>()
        var txids = [Hash256]()
        txids.reserveCapacity(transactions.count)
        for tx in transactions {
            let id = tx.txid
            guard seen.insert(id).inserted else { throw BlockError("duplicate transaction \(id)") }
            txids.append(id)
        }
        let root = txids.merkleRoot()
        guard root == header.merkleRoot else { throw BlockError("merkle root \(root), header commits to \(header.merkleRoot)") }
        try verifyWitnessCommitment()
    }

    func verifyWitnessCommitment() throws {
        let coinbase = transactions[0]
        guard !coinbase.inputs.isEmpty else { throw BlockError("witness commitment: transaction has no inputs") }
        var commitment: Data?
        if coinbase.isCoinbase {
            for output in coinbase.outputs.reversed() where output.pkScript.count >= 38 && output.pkScript.starts(with: Block.witnessMagic) {
                commitment = output.pkScript.subdata(in: output.pkScript.startIndex + 6..<output.pkScript.startIndex + 38)
                break
            }
        }
        guard let commitment else {
            if transactions.contains(where: { $0.hasWitness }) {
                throw BlockError("witness commitment: block contains transaction with witness data, yet no witness commitment present")
            }
            return
        }
        let witness = coinbase.inputs[0].witness
        guard witness.count == 1 else { throw BlockError("witness commitment: the coinbase transaction has \(witness.count) items in its witness stack when only one is allowed") }
        guard witness[0].count == 32 else { throw BlockError("witness commitment: the coinbase witness nonce has \(witness[0].count) bytes when it must be 32") }
        var wtxids = transactions.map { $0.wtxid }
        wtxids[0] = .zero
        var preimage = wtxids.merkleRoot().data
        preimage.append(witness[0])
        guard preimage.sha256d().data == commitment else { throw BlockError("witness commitment does not match") }
    }
}

public struct BlockError: Error, CustomStringConvertible, Sendable {
    public let description: String
    init(_ description: String) { self.description = description }
}

extension [Hash256] {
    /// The merkle root of the hashes: pairs hashed together level by level,
    /// the last hash of an odd level paired with itself.
    public func merkleRoot() -> Hash256 {
        guard !isEmpty else { return .zero }
        var level = self
        var buffer = Data(count: 64)
        while level.count > 1 {
            var next = [Hash256]()
            next.reserveCapacity((level.count + 1) / 2)
            for i in stride(from: 0, to: level.count, by: 2) {
                let left = level[i]
                let right = i + 1 < level.count ? level[i + 1] : left
                buffer.removeAll(keepingCapacity: true)
                left.append(to: &buffer)
                right.append(to: &buffer)
                next.append(buffer.sha256d())
            }
            level = next
        }
        return level[0]
    }
}
