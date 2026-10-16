import Foundation
import Testing
@testable import TwotbitKit

/// Builds a demo regtest wallet for screenshots in the directory named by
/// TWOTBIT_DEMO_DIR: synced from a mock node, with payments received over
/// the past weeks, a payment sent with change, and one unconfirmed payment
/// on the way. Its recovery phrase is the BIP84 test vector's, left in the
/// database as bitfyn keeps it, so the app moves it to the Keychain.
@Suite struct DemoWallet {
    @Test(.enabled(if: ProcessInfo.processInfo.environment["TWOTBIT_DEMO_DIR"] != nil))
    func build() async throws {
        let dir = URL(fileURLWithPath: ProcessInfo.processInfo.environment["TWOTBIT_DEMO_DIR"]!)
        try? FileManager.default.removeItem(at: dir)
        let store = try Store.open(path: dir.appendingPathComponent(Network.regtest.databaseFileName).path)
        let wallet = try HDWallet(mnemonic: WalletTests.vectorMnemonic, network: .regtest)
        let now = Int64(Date().timeIntervalSince1970)
        try store.saveMeta(mnemonic: WalletTests.vectorMnemonic, xpub: wallet.accountXPub, network: "regtest", createdAt: now - 47 * 24 * 3600)
        for i: UInt32 in 0..<6 { try store.addAddress(wallet.receiveAddress(i)) }
        try store.addChangeAddress(wallet.changeAddress(0))
        try Rates.seed(store)
        try store.addRate(Rate(time: now, cents: 11_234_567))

        var chain = ChainBuilder(time: UInt32(now - 50 * 24 * 3600))
        var blocks = [Block]()
        func days(_ d: Int) { chain.time = UInt32(now - Int64(d) * 24 * 3600) }
        days(50)
        blocks += chain.mine(count: 3)
        days(44)
        let first = payment([TxOut(value: 25_000_000, pkScript: try wallet.receiveAddress(0).script), TxOut(value: 1_000_000, pkScript: outside)], seed: 11)
        blocks.append(chain.mine([first]))
        days(30)
        let second = payment([TxOut(value: 1_850_000, pkScript: try wallet.receiveAddress(1).script)], seed: 12)
        blocks.append(chain.mine([second]))
        days(9)
        let change = try wallet.changeAddress(0)
        let coin = Coin(outPoint: OutPoint(hash: first.txid, index: 0), value: 25_000_000, pkScript: try wallet.receiveAddress(0).script,
                        address: try wallet.receiveAddress(0).address, path: try wallet.receiveAddress(0).path, confirmed: true, time: 0)
        let spend = try SpendPlanner.plan(coins: [coin], useAll: true, dest: outside, amount: 7_500_000, feeRate: 4, change: change.script)
        blocks.append(chain.mine([try wallet.sign(spend, dest: outside, change: change.script)]))
        days(2)
        let third = payment([TxOut(value: 640_000, pkScript: try wallet.receiveAddress(2).script)], seed: 13)
        blocks.append(chain.mine([third]))
        chain.time = UInt32(now - 3 * 3600)
        blocks += chain.mine(count: 2)

        let node = try await MockNode.start(blocks: blocks)
        defer { node.stop() }
        try store.upsertPeer(host: "127.0.0.1", port: node.port, services: ServiceFlags([.network, .witness, .compactFilters]).rawValue, latencyMs: 1)
        let engine = try SyncEngine(network: .regtest, store: store)
        try engine.start { _ in }
        try await eventually(.seconds(30), "demo sync") { engine.status().synced && engine.chainHeight == Int32(blocks.count) }
        node.relay(payment([TxOut(value: 120_000, pkScript: try wallet.receiveAddress(3).script)], seed: 14))
        try await eventually(.seconds(10), "pending payment") { engine.status().pending == 120_000 }
        await engine.stop()
        try store.updateNextIndex(4)
        store.close()
        print("demo wallet in \(dir.path): balance \(engine.status().balance) sat, pending \(engine.status().pending) sat")
    }
}
