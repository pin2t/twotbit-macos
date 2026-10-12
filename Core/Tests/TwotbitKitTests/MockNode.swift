import Foundation
import Network
import Synchronization
@testable import TwotbitKit

/// MockNode is a regtest Bitcoin node in the test process: it listens on a
/// local port, completes the handshake and serves a mined chain's headers,
/// BIP158 basic filters, filter headers and blocks, relays its mempool and
/// records what the wallet sends it. Behaviour can be bent to test the
/// wallet against failing and lying peers.
final class MockNode: Sendable {
    struct State: Sendable {
        var blocks: [Block] = []
        var filters: [Data] = []
        var filterHeaders: [Hash256] = []
        var utxos: [OutPoint: Data] = [:]
        var mempool: [Hash256: Transaction] = [:]
        var services: ServiceFlags = [.network, .witness, .compactFilters]
        var received: [Transaction] = []
        var bloomLoads = 0
        var connections = 0
        var peers: [TCPStream] = []
        /// Filters served in place of the real ones, by height.
        var wrongFilters: [Int32: Data] = [:]
        /// Whether requests are left unanswered.
        var silent = false
    }

    let network = Network.regtest
    let state = Mutex(State())
    private let listener: NWListener
    let port: UInt16

    var address: String { "127.0.0.1:\(port)" }

    private init(listener: NWListener, port: UInt16) {
        self.listener = listener
        self.port = port
    }

    /// Starts a node with the chain of blocks after the regtest genesis.
    static func start(blocks: [Block] = []) async throws -> MockNode {
        let parameters = NWParameters.tcp
        parameters.requiredLocalEndpoint = NWEndpoint.hostPort(host: "127.0.0.1", port: .any)
        let listener = try NWListener(using: parameters)
        let ready = Mutex<CheckedContinuation<UInt16, Error>?>(nil)
        let port: UInt16 = try await withCheckedThrowingContinuation { continuation in
            ready.withLock { $0 = continuation }
            listener.stateUpdateHandler = { state in
                switch state {
                case .ready: ready.withLock { $0?.resume(returning: listener.port?.rawValue ?? 0); $0 = nil }
                case .failed(let error): ready.withLock { $0?.resume(throwing: error); $0 = nil }
                default: break
                }
            }
            listener.newConnectionHandler = { _ in }
            listener.start(queue: DispatchQueue(label: "mock.listener"))
        }
        let node = MockNode(listener: listener, port: port)
        node.reset(blocks: blocks)
        listener.newConnectionHandler = { connection in
            Task { await node.serve(connection) }
        }
        return node
    }

    func stop() {
        listener.cancel()
        for p in state.withLock({ $0.peers }) { p.close() }
    }

    /// Replaces the chain with genesis and the blocks, rebuilding the
    /// filters and filter headers.
    func reset(blocks: [Block]) {
        state.withLock { s in
            s.blocks = []
            s.filters = []
            s.filterHeaders = []
            s.utxos = [:]
            let genesis = Block(header: network.genesis, transactions: [])
            for block in [genesis] + blocks { MockNode.append(&s, block) }
        }
    }

    func add(_ blocks: [Block]) {
        state.withLock { s in for b in blocks { MockNode.append(&s, b) } }
    }

    private static func append(_ s: inout State, _ block: Block) {
        var scripts = [Data]()
        for tx in block.transactions {
            for out in tx.outputs where !out.pkScript.isEmpty && out.pkScript.first != Script.opReturn { scripts.append(out.pkScript) }
            if !tx.isCoinbase {
                for input in tx.inputs {
                    if let spent = s.utxos[input.previousOutPoint], !spent.isEmpty { scripts.append(spent) }
                }
            }
        }
        var unique = [Data]()
        for script in scripts where !unique.contains(script) { unique.append(script) }
        let filter = GCSFilter.build(items: unique, blockHash: block.hash)
        let prev = s.filterHeaders.last ?? .zero
        s.filterHeaders.append(GCSFilter.header(filterHash: GCSFilter.hash(filter), previous: prev))
        s.filters.append(filter)
        for tx in block.transactions {
            for input in tx.inputs { s.utxos.removeValue(forKey: input.previousOutPoint) }
            for (i, out) in tx.outputs.enumerated() { s.utxos[OutPoint(hash: tx.txid, index: UInt32(i))] = out.pkScript }
            s.mempool.removeValue(forKey: tx.txid)
        }
        s.blocks.append(block)
    }

    var tip: Block { state.withLock { $0.blocks.last! } }
    var height: Int32 { state.withLock { Int32($0.blocks.count - 1) } }
    var received: [Transaction] { state.withLock { $0.received } }

    /// Puts the transaction in the mempool and announces it to every
    /// connected wallet.
    func relay(_ tx: Transaction) {
        let peers = state.withLock { s -> [TCPStream] in
            s.mempool[tx.txid] = tx
            return s.peers
        }
        for p in peers { p.send(Wire.frame(.inv([InvVect(.tx, tx.txid)]), magic: network.magic)) }
    }

    /// Announces the tip to every connected wallet.
    func announceTip() {
        let (peers, hash) = state.withLock { ($0.peers, $0.blocks.last!.hash) }
        for p in peers { p.send(Wire.frame(.inv([InvVect(.block, hash)]), magic: network.magic)) }
    }

    /// Disconnects every connected wallet.
    func dropConnections() {
        let peers = state.withLock { s -> [TCPStream] in
            defer { s.peers = [] }
            return s.peers
        }
        for p in peers { p.close() }
    }

    private func serve(_ connection: NWConnection) async {
        guard let stream = try? await TCPStream.accept(connection) else { return }
        state.withLock {
            $0.connections += 1
            $0.peers.append(stream)
        }
        defer { stream.close() }
        let send: (Message) -> Void = { stream.send(Wire.frame($0, magic: self.network.magic)) }
        while true {
            guard let (command, payload) = try? await PeerConnection.readFrame(stream, network: network),
                  let message = try? Message.decode(command: command, payload: payload) else { return }
            let s = state.withLock { $0 }
            if s.silent, case .version = message {} else if s.silent { continue }
            switch message {
            case .version:
                let me = NetAddress(host: "127.0.0.1", port: port)
                send(.version(VersionMessage(protocolVersion: 70016, services: s.services, timestamp: Int64(Date().timeIntervalSince1970),
                                             addrRecv: me, addrFrom: me, nonce: UInt64.random(in: 1...UInt64.max),
                                             userAgent: "/Mock:1.0/", startHeight: Int32(s.blocks.count - 1), relay: true)))
                send(.verack)
            case .ping(let nonce):
                send(.pong(nonce))
            case .getHeaders(let locator, _):
                let start = locator.lazy.compactMap { hash in s.blocks.firstIndex { $0.hash == hash } }.first ?? 0
                send(.headers(s.blocks[(start + 1)...].prefix(2000).map(\.header)))
            case let .getCFHeaders(start, stop):
                guard let end = s.blocks.firstIndex(where: { $0.hash == stop }), Int(start) <= end else { continue }
                let hashes = (Int(start)...end).map { GCSFilter.hash(s.wrongFilters[Int32($0)] ?? s.filters[$0]) }
                let prev = start == 0 ? Hash256.zero : s.filterHeaders[Int(start) - 1]
                send(.cfHeaders(CFHeaders(filterType: 0, stopHash: stop, prevFilterHeader: prev, filterHashes: hashes)))
            case let .getCFilters(start, stop):
                guard let end = s.blocks.firstIndex(where: { $0.hash == stop }), Int(start) <= end else { continue }
                for h in Int(start)...end {
                    send(.cfilter(CFilter(filterType: 0, blockHash: s.blocks[h].hash, data: s.wrongFilters[Int32(h)] ?? s.filters[h])))
                }
            case .getData(let list):
                var missing = [InvVect]()
                for iv in list {
                    if let block = s.blocks.first(where: { $0.hash == iv.hash }) {
                        send(.block(block))
                    } else if let tx = s.mempool[iv.hash] {
                        send(.tx(tx))
                    } else {
                        missing.append(iv)
                    }
                }
                if !missing.isEmpty { send(.notFound(missing)) }
            case .tx(let tx):
                state.withLock {
                    $0.received.append(tx)
                    $0.mempool[tx.txid] = tx
                }
            case .filterLoad:
                state.withLock { $0.bloomLoads += 1 }
            case .memPool:
                send(.inv(s.mempool.keys.map { InvVect(.tx, $0) }))
            default:
                break
            }
        }
    }
}

/// ChainBuilder mines regtest blocks with valid merkle roots and witness
/// commitments, paying and spending as told.
struct ChainBuilder {
    var tip: BlockHeader
    var time: UInt32
    var height: Int32 = 0

    init(network: Network = .regtest, after: Block? = nil, height: Int32 = 0, time: UInt32? = nil) {
        tip = after?.header ?? network.genesis
        self.time = time ?? (tip.timestamp + 600)
        self.height = height
    }

    /// Mines the next block with a coinbase paying the miner script and the
    /// transactions.
    mutating func mine(_ txs: [Transaction] = [], coinbaseTo script: Data = Data([0x51])) -> Block {
        height += 1
        var coinbase = Transaction(version: 1, inputs: [TxIn(previousOutPoint: .coinbase, signatureScript: Data([0x03, UInt8(height & 0xff), UInt8(height >> 8), 0]))],
                                   outputs: [TxOut(value: 50 * 100_000_000, pkScript: script)])
        if txs.contains(where: \.hasWitness) {
            coinbase.inputs[0].witness = [Data(count: 32)]
            var wtxids = [Hash256.zero] + txs.map(\.wtxid)
            wtxids[0] = .zero
            var preimage = Block.merkleRoot(wtxids).data
            preimage.append(Data(count: 32))
            coinbase.outputs.append(TxOut(value: 0, pkScript: Data(Block.witnessMagic) + Hashes.sha256d(preimage).data))
        }
        let all = [coinbase] + txs
        var header = BlockHeader(version: 0x2000_0000, prevBlock: tip.hash, merkleRoot: Block.merkleRoot(all.map(\.txid)),
                                 timestamp: time, bits: 0x207f_ffff, nonce: 0)
        let target = Compact.target(header.bits)!
        while UInt256(header.hash) > target { header.nonce += 1 }
        tip = header
        time += 600
        return Block(header: header, transactions: all)
    }

    /// Mines n empty blocks.
    mutating func mine(count n: Int) -> [Block] { (0..<n).map { _ in mine() } }
}

/// A transaction paying the outputs from an outside coin, as another
/// wallet's payment to this one looks.
func payment(_ outputs: [TxOut], seed: UInt8 = 1) -> Transaction {
    let prev = OutPoint(hash: Hash256(w0: UInt64(seed), w1: 0xfeed, w2: 0, w3: 0), index: 0)
    return Transaction(version: 2, inputs: [TxIn(previousOutPoint: prev, signatureScript: Data([0x51]))], outputs: outputs)
}

/// Waits until the condition holds, polling, or fails after the timeout.
func eventually(_ timeout: Duration = .seconds(20), _ what: String, _ condition: () -> Bool) async throws {
    let deadline = ContinuousClock.now + timeout
    while !condition() {
        guard ContinuousClock.now < deadline else { throw TimeoutError("waiting for \(what)") }
        try await Task.sleep(for: .milliseconds(50))
    }
}
