import Foundation
import Synchronization
import Testing
@testable import TwotbitKit

/// A regtest wallet in a temporary directory for the sync tests: the BIP84
/// vector wallet with its first receive and change addresses stored.
final class TestWallet: Sendable {
    let dir: URL
    let store: Store
    let wallet: HDWallet

    init(createdAt: Int64 = 0, receive: UInt32 = 4) throws {
        dir = FileManager.default.temporaryDirectory.appendingPathComponent("twotbit-sync-\(UUID().uuidString)")
        store = try Store.open(path: dir.appendingPathComponent("w.db").path)
        wallet = try HDWallet(mnemonic: WalletTests.vectorMnemonic, network: .regtest)
        try store.saveMeta(mnemonic: "", xpub: wallet.accountXPub, network: "regtest", createdAt: createdAt)
        for i in 0..<receive { try store.addAddress(wallet.receiveAddress(i)) }
        try store.addChangeAddress(wallet.changeAddress(0))
    }

    func address(_ i: UInt32) -> DerivedAddress { try! wallet.receiveAddress(i) }

    func addPeer(_ node: MockNode) throws {
        try store.upsertPeer(host: "127.0.0.1", port: node.port, services: ServiceFlags([.network, .witness, .compactFilters]).rawValue, latencyMs: 1)
    }

    deinit {
        store.close()
        try? FileManager.default.removeItem(at: dir)
    }
}

/// The outside script payments go to and come from.
let outside = Script.p2wpkh(Data(repeating: 0x42, count: 20))

@Suite(.serialized) struct SyncTests {
    static let fixture = Fixtures.load("sync", as: SyncFixture.self)

    @Test func spentAddresses() {
        for v in Self.fixture.spent {
            let witness = (v.witness ?? []).map { Data(h: $0) }
            #expect(SyncEngine.spentAddress(Data(h: v.sigScript), witness, .mainnet) == v.address, "\(v.sigScript) \(v.witness ?? [])")
        }
        for v in Self.fixture.scriptAddresses {
            #expect((Address.of(script: Data(h: v.script), network: .mainnet) ?? "") == v.address, "\(v.script)")
        }
        for v in Self.fixture.testnetScriptAddresses {
            #expect((Address.of(script: Data(h: v.script), network: .testnet3) ?? "") == v.address, "\(v.script)")
        }
    }

    /// The history and balances of wallets of four scripts match bitfyn's
    /// for payments, spends, self transfers, coinbases and pending ones.
    @Test func historiesAndBalances() throws {
        for v in Self.fixture.histories {
            var w = WalletState()
            w.initialized = true
            for (script, address) in zip(v.walletScripts, v.walletAddresses) {
                w.scriptIndex[Data(h: script)] = w.scripts.count
                w.scripts.append(WatchScript(address: address, path: "m/84'/0'/0'/0/0", script: Data(h: script)))
            }
            let txs = try v.txs.map { try Transaction(data: Data(h: $0)) }
            let history = SyncEngine.buildHistory(txs, times: v.times, confirmed: v.confirmed, wallet: w, network: .mainnet)
            #expect(history.count == v.history.count)
            for (got, want) in zip(history, v.history) {
                #expect(got.txid.hex == want.txid)
                #expect(got.time == want.time)
                #expect(got.confirmed == want.confirmed)
                #expect(got.net == want.net, "\(want.txid)")
                #expect(got.fee == want.fee, "\(want.txid)")
                #expect(got.inputs == want.inputs.map { TxAddress(address: $0.address, mine: $0.mine) })
                #expect(got.outputs == want.outputs.map { TxAddress(address: $0.address, mine: $0.mine) })
            }
            let index = w.scriptIndex
            let (balance, pending) = SyncEngine.computeBalance(Array(txs[..<v.confirmed]), Array(txs[v.confirmed...])) { index[$0] != nil }
            #expect(balance == v.balance)
            #expect(pending == v.pending)
        }
    }

    @Test func majorityAnchors() throws {
        for v in Self.fixture.majority {
            let votes = (v.votes ?? []).map { Hash256(hex: $0)! }
            if v.error {
                #expect(throws: PeerError.self) { try SyncEngine.majorityAnchor(votes) }
            } else {
                #expect(try SyncEngine.majorityAnchor(votes).hex == v.anchor)
            }
        }
    }

    @Test func statusText() {
        var s = SyncStatus()
        #expect(s.text == "Not connected")
        s.via = "Tor"
        #expect(s.text == "Connecting over Tor...")
        s.peers = 2
        s.height = 1234
        #expect(s.text == "Syncing (1234)...")
        s.synced = true
        #expect(s.text == "Connected over Tor")
        s.via = ""
        #expect(s.text == "Connected")
        s.peers = 9
        #expect(s.bars == 3)
    }

    /// Runs the engine of the wallet until the condition holds.
    func sync(_ w: TestWallet, pinned: String = "", until what: String, timeout: Duration = .seconds(30),
              _ condition: @escaping (SyncEngine) -> Bool) async throws -> SyncEngine {
        let engine = try SyncEngine(network: .regtest, store: w.store)
        try engine.start(pinned: pinned) { _ in }
        do {
            try await eventually(timeout, what) { condition(engine) }
        } catch {
            await engine.stop()
            throw error
        }
        return engine
    }

    func synced(_ height: Int32) -> (SyncEngine) -> Bool {
        { $0.status().synced && $0.chainHeight == height }
    }

    /// The engine syncs headers and filters from a node, downloads the
    /// blocks matching the wallet and finds its payments and spends.
    @Test func fullSync() async throws {
        let w = try TestWallet()
        var chain = ChainBuilder()
        var blocks = chain.mine(count: 5)
        let pay0 = payment([TxOut(value: 100_000, pkScript: w.address(0).script), TxOut(value: 7, pkScript: outside)], seed: 1)
        blocks.append(chain.mine([pay0]))
        let pay1 = payment([TxOut(value: 50_000, pkScript: w.address(1).script)], seed: 2)
        blocks.append(chain.mine([pay1]))
        blocks += chain.mine(count: 3)
        let spend = Transaction(version: 2, inputs: [TxIn(previousOutPoint: OutPoint(hash: pay0.txid, index: 0), signatureScript: Data(), witness: [Data([1]), Data([2])])],
                                outputs: [TxOut(value: 60_000, pkScript: outside), TxOut(value: 39_000, pkScript: w.address(2).script)])
        blocks.append(chain.mine([spend]))
        let node = try await MockNode.start(blocks: blocks)
        defer { node.stop() }
        try w.addPeer(node)
        let engine = try await sync(w, until: "sync to 11", synced(11))
        defer { Task { await engine.stop() } }
        #expect(engine.status().balance == 89_000)
        #expect(engine.status().pending == 0)
        #expect(engine.coins().map(\.value) == [50_000, 39_000])
        #expect(engine.coins().allSatisfy { $0.confirmed })
        let history = engine.history()
        #expect(history.map(\.net) == [-61_000, 50_000, 100_000])
        #expect(history[0].fee == 1_000)
        #expect(engine.isUsed(w.address(0).address) && engine.isUsed(w.address(2).address) && !engine.isUsed(w.address(3).address))
        #expect(try w.store.filterCount() == 12)
        #expect(try w.store.matches().count == 4)
        #expect(try w.store.headerCount() == 12)
        await engine.stop()

        let reopened = try SyncEngine(network: .regtest, store: w.store)
        #expect(reopened.chainHeight == 11)
        #expect(reopened.status().balance == 89_000)
    }

    /// A peer serving a filter that lacks an output script of its block is
    /// outvoted by the full block and dropped; the wallet's payment in that
    /// block is still found.
    @Test func crossCheckAndMismatch() async throws {
        let w = try TestWallet()
        var chain = ChainBuilder()
        var blocks = chain.mine(count: 3)
        let pay = payment([TxOut(value: 21_000, pkScript: w.address(0).script)], seed: 3)
        let paid = chain.mine([pay])
        blocks.append(paid)
        blocks += chain.mine(count: 2)
        var nodes = [MockNode]()
        for _ in 0..<3 { nodes.append(try await MockNode.start(blocks: blocks)) }
        defer { nodes.forEach { $0.stop() } }
        let liar = nodes[2]
        liar.state.withLock { $0.wrongFilters[4] = GCSFilter.build(items: [Data([0x51])], blockHash: paid.hash) }
        for n in nodes { try w.addPeer(n) }
        let engine = try await sync(w, until: "three peers") { $0.status().peers == 3 }
        defer { Task { await engine.stop() } }
        try await eventually(.seconds(30), "sync to 6") { engine.status().synced && engine.chainHeight == 6 }
        #expect(engine.status().balance == 21_000)
        await engine.stop()
    }

    /// Relayed payments count as pending; a broadcast payment reaches the
    /// node, and both confirm once mined.
    @Test func relayBroadcastConfirm() async throws {
        let w = try TestWallet()
        var chain = ChainBuilder()
        var blocks = chain.mine(count: 2)
        let pay = payment([TxOut(value: 80_000, pkScript: w.address(0).script)], seed: 4)
        blocks.append(chain.mine([pay]))
        let node = try await MockNode.start(blocks: blocks)
        defer { node.stop() }
        try w.addPeer(node)
        let engine = try await sync(w, until: "sync to 3", synced(3))
        defer { Task { await engine.stop() } }

        let incoming = payment([TxOut(value: 12_345, pkScript: w.address(1).script)], seed: 5)
        node.relay(incoming)
        try await eventually(.seconds(10), "pending payment") { engine.status().pending == 12_345 }
        #expect(engine.coins().contains { !$0.confirmed && $0.value == 12_345 })

        let coin = engine.coins().first { $0.confirmed }!
        let change = try w.wallet.changeAddress(0)
        let spend = try SpendPlanner.plan(coins: [coin], useAll: true, dest: outside, amount: 30_000, feeRate: 2, change: change.script)
        let tx = try w.wallet.sign(spend, dest: outside, change: change.script)
        #expect(try engine.broadcast(tx) == 1)
        try await eventually(.seconds(10), "node got the payment") { node.received.contains { $0.txid == tx.txid } }
        #expect(engine.status().balance + engine.status().pending == 80_000 + 12_345 - 30_000 - spend.fee)

        node.add([chain.mine([incoming, tx])])
        node.announceTip()
        try await eventually(.seconds(20), "confirmation") { engine.status().synced && engine.chainHeight == 4 && engine.status().pending == 0 }
        #expect(engine.status().balance == 80_000 + 12_345 - 30_000 - spend.fee)
        #expect(engine.coins().allSatisfy { $0.confirmed })
        await engine.stop()
    }

    /// A heavier branch from a fork replaces the blocks after it, with the
    /// wallet payments in them; a lighter one is refused.
    @Test func reorgs() async throws {
        let w = try TestWallet()
        var chain = ChainBuilder()
        var common = chain.mine(count: 6)
        var x = chain
        let payX = payment([TxOut(value: 11_000, pkScript: w.address(0).script)], seed: 6)
        var branchX = [x.mine([payX])] + x.mine(count: 3)
        let node = try await MockNode.start(blocks: common + branchX)
        defer { node.stop() }
        try w.addPeer(node)
        let engine = try await sync(w, until: "sync to 10", synced(10))
        defer { Task { await engine.stop() } }
        #expect(engine.status().balance == 11_000)

        var y = chain
        let payY = payment([TxOut(value: 22_000, pkScript: w.address(1).script)], seed: 7)
        let branchY = y.mine(count: 2) + [y.mine([payY])] + y.mine(count: 2)
        node.reset(blocks: common + branchY)
        node.announceTip()
        try await eventually(.seconds(20), "reorg to 11") { engine.status().synced && engine.chainHeight == 11 }
        #expect(engine.status().balance == 22_000)
        #expect(engine.entry(at: 11)?.hash == branchY.last!.hash)

        var z = chain
        let branchZ = z.mine(count: 3)
        node.reset(blocks: common + branchZ)
        node.announceTip()
        try await eventually(.seconds(20), "lighter fork refused") { node.state.withLock { $0.connections } >= 2 }
        try await Task.sleep(for: .milliseconds(500))
        #expect(engine.chainHeight == 11)
        #expect(engine.entry(at: 11)?.hash == branchY.last!.hash)
        common.removeAll()
        branchX.removeAll()
        await engine.stop()
    }

    /// A wallet created after the start of the chain downloads filters from
    /// its creation on, the first filter header proven by the peers'
    /// majority.
    @Test func filterAnchor() async throws {
        var chain = ChainBuilder(time: UInt32(Date().timeIntervalSince1970) - 40 * 600)
        var blocks = chain.mine(count: 20)
        let created = Int64(blocks[15].header.timestamp)
        let w = try TestWallet(createdAt: created)
        let pay = payment([TxOut(value: 5_000, pkScript: w.address(0).script)], seed: 8)
        blocks.append(chain.mine([pay]))
        var nodes = [MockNode]()
        for _ in 0..<3 { nodes.append(try await MockNode.start(blocks: blocks)) }
        defer { nodes.forEach { $0.stop() } }
        for n in nodes { try w.addPeer(n) }
        let engine = try await sync(w, until: "sync to 21", synced(21))
        defer { Task { await engine.stop() } }
        #expect(engine.filterStart == 16 - SyncEngine.safetyGap)
        #expect(try w.store.filterCount() == 21 - Int(engine.filterStart) + 1)
        #expect(engine.status().balance == 5_000)
        await engine.stop()
    }

    /// Watching an address the wallet's stored transactions already paid,
    /// as when another wallet on the seed used it, queues a rescan that
    /// finds its spend in a block scanned before.
    @Test func watchAndRescan() async throws {
        let w = try TestWallet(receive: 2)
        let late = w.address(3)
        var chain = ChainBuilder()
        var blocks = chain.mine(count: 2)
        let pay = payment([TxOut(value: 30_000, pkScript: w.address(0).script), TxOut(value: 40_000, pkScript: late.script)], seed: 9)
        blocks.append(chain.mine([pay]))
        blocks += chain.mine(count: 2)
        let spendLate = Transaction(version: 2, inputs: [TxIn(previousOutPoint: OutPoint(hash: pay.txid, index: 1))], outputs: [TxOut(value: 39_000, pkScript: outside)])
        blocks.append(chain.mine([spendLate]))
        let node = try await MockNode.start(blocks: blocks)
        defer { node.stop() }
        try w.addPeer(node)
        let engine = try await sync(w, until: "sync to 6", synced(6))
        defer { Task { await engine.stop() } }
        #expect(engine.status().balance == 30_000)
        try w.store.addAddress(late)
        engine.watch(late)
        #expect(engine.isUsed(late.address))
        try await eventually(.seconds(20), "rescan") { (try? w.store.rescans().isEmpty) == true && engine.status().synced }
        #expect(engine.status().balance == 30_000)
        #expect(engine.history().count == 2)
        await engine.stop()
    }

    /// A pinned peer is synced from; a peer without compact filters is
    /// refused.
    @Test func pinnedPeerAndServices() async throws {
        let w = try TestWallet()
        var chain = ChainBuilder()
        let node = try await MockNode.start(blocks: chain.mine(count: 4))
        defer { node.stop() }
        let engine = try await sync(w, pinned: node.address, until: "pinned sync", synced(4))
        #expect(engine.orderedPeers().first?.pinned == true)
        await engine.stop()

        let plain = try await MockNode.start(blocks: [])
        defer { plain.stop() }
        plain.state.withLock { $0.services = [.network, .witness] }
        let w2 = try TestWallet()
        let probe = try SyncEngine(network: .regtest, store: w2.store)
        #expect(await probe.connect(plain.address, pinned: false) == false)
        #expect(probe.status().peers == 0)
        let stored = try w2.store.peers().first { $0.port == plain.port }
        #expect(stored?.services == ServiceFlags([.network, .witness]).rawValue)
    }
}
