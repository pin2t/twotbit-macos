import Foundation
import Testing
@testable import TwotbitKit

/// Syncs a fresh wallet from the real peers of the network named by
/// TWOTBIT_LIVE, such as signet or testnet4: DNS seeds, the handshake with
/// Bitcoin Core nodes, the whole header chain and the filters since the
/// wallet's creation, its anchor proven by the peers' majority. It needs
/// the internet and takes minutes; set TWOTBIT_LOG_STDERR to watch it.
@Suite struct LiveTests {
    @Test(.enabled(if: ProcessInfo.processInfo.environment["TWOTBIT_LIVE"] != nil))
    func liveSync() async throws {
        let network = try #require(Network.named(ProcessInfo.processInfo.environment["TWOTBIT_LIVE"]!))
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("twotbit-live-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: dir) }
        let store = try Store.open(path: dir.appendingPathComponent(network.databaseFileName).path)
        defer { store.close() }
        let wallet = try HDWallet(mnemonic: try BIP39.generateMnemonic(), network: network)
        try store.saveMeta(mnemonic: "", xpub: wallet.accountXPub, network: network.displayName, createdAt: Int64(Date().timeIntervalSince1970))
        try store.addAddress(wallet.receiveAddress(0))
        let engine = try SyncEngine(network: network, store: store)
        let started = ContinuousClock.now
        try engine.start { _ in }
        var last = ""
        try await eventually(.seconds(900), "live sync of \(network.name)") {
            let s = engine.status()
            if s.text != last {
                last = s.text
                print("\(Int((ContinuousClock.now - started).components.seconds))s: \(s.text), \(s.peers) peers")
            }
            return s.synced && s.height > 1000
        }
        let s = engine.status()
        print("synced \(network.name) to \(s.height) in \((ContinuousClock.now - started).formatted): \(try store.headerCount()) headers, "
              + "\(try store.filterCount()) filters from \(engine.filterStart), \(s.peers) peers")
        #expect(try store.filterCount() == Int(s.height - engine.filterStart + 1))
        await engine.stop()
    }
}
