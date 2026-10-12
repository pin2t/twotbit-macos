import Foundation
import Testing
@testable import TwotbitKit

/// A fresh database file in a temporary directory, removed after the test.
func withTempStore<T>(_ body: (Store, URL) throws -> T) throws -> T {
    let dir = FileManager.default.temporaryDirectory.appendingPathComponent("twotbit-test-\(UUID().uuidString)")
    defer { try? FileManager.default.removeItem(at: dir) }
    let store = try Store.open(path: dir.appendingPathComponent("wallet.db").path)
    defer { store.close() }
    return try body(store, dir)
}

@Suite struct StoreTests {
    @Test func metaAndAddresses() throws {
        try withTempStore { store, _ in
            #expect(try store.meta() == nil)
            try store.saveMeta(mnemonic: "", xpub: "vpub-test", network: "testnet", createdAt: 1_700_000_000)
            try store.saveMeta(mnemonic: "ignored", xpub: "other", network: "mainnet", createdAt: 1)
            var meta = try #require(try store.meta())
            #expect(meta == WalletMeta(mnemonic: "", xpub: "vpub-test", network: "testnet", createdAt: 1_700_000_000, nextIndex: 0))
            try store.updateNextIndex(7)
            meta = try #require(try store.meta())
            #expect(meta.nextIndex == 7)
            let wallet = try HDWallet(mnemonic: WalletTests.vectorMnemonic, network: .testnet3)
            for i: UInt32 in 0..<3 {
                try store.addAddress(wallet.receiveAddress(i))
                try store.addAddress(wallet.receiveAddress(i))
            }
            try store.addChangeAddress(wallet.changeAddress(0))
            #expect(try store.addresses().map(\.address) == (0..<3).map { try! wallet.receiveAddress($0).address })
            #expect(try store.changeAddresses().map(\.path) == ["m/84'/1'/0'/1/0"])
        }
    }

    @Test func headersFiltersAndRewind() throws {
        try withTempStore { store, _ in
            let data = Fixtures.data("mainnet-headers-0-4099", "bin")
            let headers = try (0..<50).map { i in StoredHeader(height: Int32(i), header: try BlockHeader(data: data.subdata(in: i * 80..<(i + 1) * 80))) }
            try store.saveHeaders(headers)
            var loaded = [StoredHeader]()
            try store.forEachHeader { loaded.append($0) }
            #expect(loaded == headers)
            #expect(try store.headerCount() == 50)
            try store.deleteHeaders(above: 39)
            #expect(try store.headerCount() == 40)

            #expect(try store.filterResumeHeight(from: 10) == 10)
            let filters = (10..<20).map { StoredFilter(height: Int32($0), blockHash: headers[$0].header.hash, filterHeader: Hash256(w0: UInt64($0), w1: 0, w2: 0, w3: 0), data: $0 % 2 == 0 ? Data([1, 2]) : nil) }
            try store.saveFilters(filters)
            #expect(try store.filterResumeHeight(from: 10) == 20)
            #expect(try store.filterResumeHeight(from: 25) == 25)
            #expect(try store.filterHeader(at: 15) == Hash256(w0: 15, w1: 0, w2: 0, w3: 0))
            #expect(try store.filterHeader(at: 5) == nil)
            try store.pruneFilterData(from: 0)
            try store.deleteFilters(above: 14)
            #expect(try store.filterCount() == 5)

            try store.saveMatch(FilterMatch(height: 12, blockHash: .zero, address: "a", script: Data([0])))
            try store.saveMatch(FilterMatch(height: 12, blockHash: .zero, address: "a", script: Data([0])))
            try store.saveMatch(FilterMatch(height: 30, blockHash: .zero, address: "b", script: Data([1])))
            try store.deleteMatches(above: 20)
            #expect(try store.matches().map(\.address) == ["a"])
        }
    }

    @Test func transactionsAndPending() throws {
        try withTempStore { store, _ in
            let a = StoredTransaction(txid: Hash256(w0: 1, w1: 0, w2: 0, w3: 0), height: 5, blockHash: .zero, raw: Data([1]))
            let b = StoredTransaction(txid: Hash256(w0: 2, w1: 0, w2: 0, w3: 0), height: 3, blockHash: .zero, raw: Data([2]))
            try store.saveTransaction(a)
            try store.saveTransaction(b)
            try store.saveTransaction(a)
            #expect(try store.transactions().map(\.height) == [3, 5])
            try store.deleteTransactions(above: 4)
            #expect(try store.transactions() == [b])

            try store.savePending(PendingTransaction(txid: a.txid, raw: Data([9]), seenAt: 100))
            try store.savePending(PendingTransaction(txid: a.txid, raw: Data([9]), seenAt: 200))
            try store.savePending(PendingTransaction(txid: b.txid, raw: Data([8]), seenAt: 50))
            #expect(try store.pendingTransactions().map(\.seenAt) == [50, 100])
            #expect(try store.deletePending(before: 60) == 1)
            try store.deletePending(a.txid)
            #expect(try store.pendingTransactions().isEmpty)
        }
    }

    @Test func rescansPeersSettingsRates() throws {
        try withTempStore { store, _ in
            try store.addRescan(RescanJob(address: "x", from: 50))
            try store.addRescan(RescanJob(address: "x", from: 70))
            try store.addRescan(RescanJob(address: "y", from: 10))
            #expect(try store.rescans() == [RescanJob(address: "y", from: 10), RescanJob(address: "x", from: 50)])
            try store.deleteRescan(RescanJob(address: "x", from: 60))
            #expect(try store.rescans().count == 2)
            try store.deleteRescan(RescanJob(address: "x", from: 50))
            #expect(try store.rescans().map(\.address) == ["y"])

            try store.savePeer(host: "1.2.3.4", port: 8333)
            try store.recordPeerResult(host: "1.2.3.4", port: 8333, ok: true, latencyMs: 40)
            try store.recordPeerResult(host: "1.2.3.4", port: 8333, ok: false, latencyMs: 90)
            try store.upsertPeer(host: "1.2.3.4", port: 8333, services: 1097, latencyMs: 30)
            try store.updatePeerServices(host: "abc.onion", port: 8333, services: 64)
            let peers = try store.peers().sorted { $0.host < $1.host }
            #expect(peers == [PeerRecord(host: "1.2.3.4", port: 8333, services: 1097, latencyMs: 30, okCount: 1, failCount: 1),
                              PeerRecord(host: "abc.onion", port: 8333, services: 64, latencyMs: 0, okCount: 0, failCount: 0)])

            #expect(try store.setting(Store.settingTor) == "")
            try store.setSetting(Store.settingTor, "on")
            #expect(try store.setting(Store.settingTor) == "on")
            try store.setSetting(Store.settingTor, "")
            #expect(try store.setting(Store.settingTor) == "")

            #expect(try store.latestRate() == nil)
            #expect(try store.seedRates([Rate(time: 1, cents: 10), Rate(time: 2, cents: 20)]))
            #expect(try !store.seedRates([Rate(time: 3, cents: 30)]))
            try store.addRate(Rate(time: 5, cents: 50))
            #expect(try store.latestRate() == Rate(time: 5, cents: 50))
        }
    }

    @Test func walletLoader() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("twotbit-test-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: dir) }
        let secrets = MemorySecretStore()
        let created = try WalletLoader.open(dataDirectory: dir, network: .signet, secrets: secrets)
        let xpub = created.wallet.accountXPub
        #expect(created.meta.mnemonic == "")
        #expect(created.meta.network == "signet")
        #expect(try secrets.secret(account: xpub) == created.wallet.mnemonic)
        created.store.close()
        #expect(FileManager.default.fileExists(atPath: dir.appendingPathComponent("twotbit-signet.db").path))

        let reopened = try WalletLoader.open(dataDirectory: dir, network: .signet, secrets: secrets)
        #expect(reopened.wallet.accountXPub == xpub)
        reopened.store.close()

        #expect(throws: WalletError.missingRecoveryPhrase) { try WalletLoader.open(dataDirectory: dir, network: .signet, secrets: MemorySecretStore()) }
        let restored = MemorySecretStore()
        #expect(throws: WalletError.recoveryPhraseMismatch) {
            try WalletLoader.restore(mnemonic: WalletTests.vectorMnemonic, dataDirectory: dir, network: .signet, secrets: restored)
        }
        try WalletLoader.restore(mnemonic: "  " + created.wallet.mnemonic.uppercased() + " ", dataDirectory: dir, network: .signet, secrets: restored)
        #expect(try WalletLoader.open(dataDirectory: dir, network: .signet, secrets: restored).wallet.accountXPub == xpub)
    }

    /// A regtest wallet keeps its phrase in the database and never touches
    /// the secret store.
    @Test func localNetworkPhrase() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("twotbit-test-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: dir) }
        let secrets = MemorySecretStore()
        let created = try WalletLoader.open(dataDirectory: dir, network: .regtest, secrets: secrets)
        #expect(created.meta.mnemonic == created.wallet.mnemonic)
        #expect(try secrets.secret(account: created.wallet.accountXPub) == nil)
        created.store.close()
        let reopened = try WalletLoader.open(dataDirectory: dir, network: .regtest, secrets: secrets)
        #expect(reopened.wallet.accountXPub == created.wallet.accountXPub)
        #expect(try secrets.secret(account: created.wallet.accountXPub) == nil)
        reopened.store.close()
    }

    /// A database brought over from bitfyn, its mnemonic in the meta row,
    /// opens and has the mnemonic moved into the secret store.
    @Test func bitfynDatabase() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("twotbit-test-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: dir) }
        let store = try Store.open(path: dir.appendingPathComponent("twotbit-testnet.db").path)
        let wallet = try HDWallet(mnemonic: WalletTests.vectorMnemonic, network: .testnet3)
        try store.saveMeta(mnemonic: WalletTests.vectorMnemonic, xpub: wallet.accountXPub, network: "testnet3", createdAt: 1)
        store.close()
        let secrets = MemorySecretStore()
        try FileManager.default.copyItem(at: dir.appendingPathComponent("twotbit-testnet.db"), to: dir.appendingPathComponent("twotbit-signet.db"))
        #expect(throws: WalletError.wrongNetwork(stored: "testnet3", requested: "signet")) {
            try WalletLoader.open(dataDirectory: dir, network: .signet, secrets: secrets)
        }
        let opened = try WalletLoader.open(dataDirectory: dir, network: .testnet3, secrets: secrets)
        #expect(opened.meta.mnemonic == "")
        #expect(try secrets.secret(account: wallet.accountXPub) == WalletTests.vectorMnemonic)
        opened.store.close()
    }

    /// Validates every header of real chains stored by bitfyn, with the
    /// full rules: TWOTBIT_CHAIN_DB lists network=path pairs, such as
    /// mainnet=$HOME/.bitfyn/bitfyn.db, separated by commas. The databases
    /// are opened immutable and only their headers are read.
    @Test(.enabled(if: ProcessInfo.processInfo.environment["TWOTBIT_CHAIN_DB"] != nil))
    func realChains() throws {
        for pair in ProcessInfo.processInfo.environment["TWOTBIT_CHAIN_DB"]!.split(separator: ",") {
            let parts = pair.split(separator: "=", maxSplits: 1).map(String.init)
            let network = Network.fixture(parts[0])
            let store = try Store.openImmutable(path: parts[1])
            defer { store.close() }
            var chain = HeaderChain(network: network)
            chain.reserve(try store.headerCount())
            let started = Date()
            try store.forEachHeader { stored in
                #expect(stored.height == chain.height + 1)
                try chain.add(stored.header)
            }
            #expect(Int(chain.height) + 1 == (try store.headerCount()))
            print("\(network.name): \(chain.height + 1) headers validated in \(Int(Date().timeIntervalSince(started))) s, tip \(chain.tip!.hash)")
        }
    }
}
