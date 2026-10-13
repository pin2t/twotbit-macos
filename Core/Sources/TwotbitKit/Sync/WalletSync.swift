import Foundation

/// TxAddress is an address a transaction spends from or pays to, and
/// whether it is the wallet's. Address is empty when it cannot be told: an
/// input whose previous output the wallet does not hold, spending a script
/// that leaves no trace of its address. A coinbase input reads "coinbase".
public struct TxAddress: Sendable, Hashable {
    public var address: String
    public var mine: Bool

    public init(address: String, mine: Bool) {
        self.address = address
        self.mine = mine
    }
}

/// WalletTransaction is a wallet transaction as the history shows it: when
/// it was confirmed or first seen, what it did to the balance, the fee the
/// wallet paid, set when every input spends a wallet coin, and the
/// addresses it spends from and pays to.
public struct WalletTransaction: Sendable, Hashable, Identifiable {
    public var txid: Hash256
    public var time: Int64
    public var confirmed: Bool
    public var net: Int64
    public var fee: Int64
    public var inputs: [TxAddress]
    public var outputs: [TxAddress]

    public var id: Hash256 { txid }

    public init(txid: Hash256, time: Int64, confirmed: Bool, net: Int64, fee: Int64, inputs: [TxAddress], outputs: [TxAddress]) {
        self.txid = txid
        self.time = time
        self.confirmed = confirmed
        self.net = net
        self.fee = fee
        self.inputs = inputs
        self.outputs = outputs
    }
}

/// WalletState is the wallet rebuilt from its stored confirmed and
/// unconfirmed transactions.
struct WalletState: Sendable {
    var initialized = false
    var scripts: [WatchScript] = []
    var scriptIndex: [Data: Int] = [:]
    var outpoints: [OutPoint: String] = [:]
    var confirmedIDs: Set<Hash256> = []
    var pendingIDs: Set<Hash256> = []
    var pendingSpends: [OutPoint: Hash256] = [:]
    var seenTxs: Set<Hash256> = []
    var usedAddrs: Set<String> = []
    var firstPaid: [String: Int32] = [:]
    var coins: [Coin] = []
    var pendingTxs: [Transaction] = []
    var history: [WalletTransaction] = []
    var confirmedBalance: Int64 = 0
    var pendingBalance: Int64 = 0
}

extension SyncEngine {
    /// Drops unconfirmed transactions that never confirmed: Bitcoin Core's
    /// default mempool expiry.
    static let pendingExpiry: Int64 = 14 * 24 * 60 * 60
    /// Bounds the set of relayed transaction ids already requested.
    static let seenLimit = 10_000
    /// The false positive rate of the wallet's BIP37 filter: lower rates
    /// leak more about which addresses are the wallet's, higher ones make
    /// peers relay more unrelated transactions. The filter is sized for at
    /// least bloomMinElements, as a filter of one or two is far above its
    /// nominal rate.
    static let bloomFPRate = 0.0001
    static let bloomMinElements: UInt32 = 20
    /// How many checked relayed transactions are counted between two log
    /// lines.
    static let relayLogEvery: Int64 = 1000
    /// The input address of a coinbase transaction.
    static let coinbaseInput = "coinbase"

    /// Rebuilds the wallet state from the database.
    func loadWallet() throws {
        try wallet.withLock { try loadWalletLocked(&$0) }
    }

    /// Rebuilds the coins, the inputs spent by pending transactions, the
    /// history and the balances; the wallet lock is held.
    func loadWalletLocked(_ w: inout WalletState) throws {
        let stored = try store.transactions()
        let pending = try store.pendingTransactions()
        var confirmed = [Transaction]()
        var heights = [Int32]()
        var times = [Int64]()
        w.confirmedIDs = []
        for t in stored {
            let tx: Transaction
            do { tx = try Transaction(data: t.raw) } catch { throw PeerError("decode stored tx \(t.txid): \(error)") }
            confirmed.append(tx)
            heights.append(t.height)
            times.append(blockTime(t.height))
            w.confirmedIDs.insert(t.txid)
        }
        var unconfirmed = [Transaction]()
        w.pendingIDs = []
        w.pendingSpends = [:]
        for p in pending {
            let tx: Transaction
            do { tx = try Transaction(data: p.raw) } catch { throw PeerError("decode pending tx \(p.txid): \(error)") }
            unconfirmed.append(tx)
            times.append(p.seenAt)
            w.pendingIDs.insert(p.txid)
            for input in tx.inputs { w.pendingSpends[input.previousOutPoint] = p.txid }
        }
        let all = confirmed + unconfirmed
        w.outpoints = [:]
        w.usedAddrs = []
        w.firstPaid = [:]
        var unspent = [OutPoint: Coin]()
        for (n, tx) in all.enumerated() {
            let txid = tx.txid
            for (i, out) in tx.outputs.enumerated() {
                guard let idx = w.scriptIndex[out.pkScript] else { continue }
                let script = w.scripts[idx]
                let op = OutPoint(hash: txid, index: UInt32(i))
                w.outpoints[op] = script.address
                w.usedAddrs.insert(script.address)
                if n < confirmed.count, w.firstPaid[script.address].map({ heights[n] < $0 }) ?? true {
                    w.firstPaid[script.address] = heights[n]
                }
                unspent[op] = Coin(outPoint: op, value: out.value, pkScript: out.pkScript, address: script.address, path: script.path,
                                   confirmed: n < confirmed.count, time: times[n])
            }
        }
        for tx in all {
            for input in tx.inputs { unspent.removeValue(forKey: input.previousOutPoint) }
        }
        w.coins = unspent.values.sorted { a, b in
            if a.value != b.value { return a.value > b.value }
            return a.outPoint.description < b.outPoint.description
        }
        w.pendingTxs = unconfirmed
        w.history = SyncEngine.buildHistory(all, times: times, confirmed: confirmed.count, wallet: w, network: network)
        let index = w.scriptIndex
        (w.confirmedBalance, w.pendingBalance) = SyncEngine.computeBalance(confirmed, unconfirmed) { index[$0] != nil }
    }

    /// The unix time of the block at the height, or 0 when it is not in the
    /// chain.
    func blockTime(_ height: Int32) -> Int64 {
        entry(at: height).map { Int64($0.time) } ?? 0
    }

    /// The confirmed balance, the value of the wallet coins the confirmed
    /// transactions leave unspent, and the change the unconfirmed ones make
    /// to it, in satoshis.
    static func computeBalance(_ confirmed: [Transaction], _ unconfirmed: [Transaction], isMine: (Data) -> Bool) -> (Int64, Int64) {
        let settled = unspentValue(confirmed, isMine: isMine)
        return (settled, unspentValue(confirmed + unconfirmed, isMine: isMine) - settled)
    }

    /// The value of the wallet outputs of the transactions that none of
    /// them spends.
    static func unspentValue(_ txs: [Transaction], isMine: (Data) -> Bool) -> Int64 {
        var coins = [OutPoint: Int64]()
        for tx in txs {
            let txid = tx.txid
            for (i, out) in tx.outputs.enumerated() where isMine(out.pkScript) {
                coins[OutPoint(hash: txid, index: UInt32(i))] = out.value
            }
        }
        for tx in txs {
            for input in tx.inputs { coins.removeValue(forKey: input.previousOutPoint) }
        }
        return coins.values.reduce(0, +)
    }

    /// Whether the address received a payment, confirmed or pending.
    public func isUsed(_ address: String) -> Bool { wallet.withLock { $0.usedAddrs.contains(address) } }

    /// The spendable wallet coins, confirmed and unconfirmed, the largest
    /// first.
    public func coins() -> [Coin] { wallet.withLock { $0.coins } }

    /// The wallet transactions, confirmed and unconfirmed, the newest first.
    public func history() -> [WalletTransaction] { wallet.withLock { $0.history } }

    /// The confirmed balance and the pending change.
    func walletBalance() -> (Int64, Int64) { wallet.withLock { ($0.confirmedBalance, $0.pendingBalance) } }

    /// A snapshot of the watched wallet scripts.
    func watchedScripts() -> [WatchScript] { wallet.withLock { $0.scripts } }

    /// Watches a newly derived P2WPKH wallet address, receive or change, so
    /// filters, blocks and relayed transactions are matched against it too,
    /// and refreshes the peers' bloom filters. Stored transactions may pay
    /// the address already, when another wallet on the same seed used it
    /// first: their coins appear at once, and a rescan from the first block
    /// paying it is queued, since spends of them were not looked for in the
    /// blocks scanned before.
    public func watch(_ address: DerivedAddress) {
        let script = address.script
        enum Outcome { case skip, watched(paid: Int32?, error: Error?) }
        let outcome = wallet.withLock { w -> Outcome in
            guard w.initialized, w.scriptIndex[script] == nil else { return .skip }
            w.scriptIndex[script] = w.scripts.count
            w.scripts.append(WatchScript(address: address.address, path: address.path, script: script))
            do {
                try loadWalletLocked(&w)
            } catch {
                return .watched(paid: nil, error: error)
            }
            guard let first = w.firstPaid[address.address] else { return .watched(paid: nil, error: nil) }
            do {
                try store.addRescan(RescanJob(address: address.address, from: first))
            } catch {
                return .watched(paid: first, error: error)
            }
            return .watched(paid: first, error: nil)
        }
        guard case let .watched(paid, error) = outcome else { return }
        Log.info("sync: watching address \(address.address)")
        if let error { Log.info("sync: watch address \(address.address): \(error)") }
        guard let paid else {
            reloadBlooms()
            return
        }
        Log.info("sync: address \(address.address) was paid in block \(paid) before it was watched, rescan queued")
        walletChanged()
        wake.signal()
    }

    /// Logs how a transaction touches the wallet and reports whether it
    /// does; the wallet lock is held.
    func describeTx(_ tx: Transaction, _ w: WalletState, _ place: String) -> Bool {
        let txid = tx.txid
        var relevant = false
        for input in tx.inputs {
            if let address = w.outpoints[input.previousOutPoint] {
                relevant = true
                Log.info("match: tx \(txid) \(place) spends \(input.previousOutPoint) of \(address)")
            }
        }
        for out in tx.outputs {
            guard let idx = w.scriptIndex[out.pkScript] else { continue }
            relevant = true
            Log.info("match: tx \(txid) \(place) pays \(out.value) sat to \(w.scripts[idx].address)")
        }
        return relevant
    }

    /// Stores every transaction of the verified block paying a wallet script
    /// or spending a wallet coin. A pending transaction it confirms leaves
    /// the pending set, and a pending transaction conflicting with one of
    /// its transactions is dropped. It returns the number of wallet
    /// transactions found.
    @discardableResult
    func processBlock(_ height: Int32, _ block: Block) throws -> Int {
        let blockHash = block.hash
        let (found, changed, failure) = wallet.withLock { w -> (Int, Bool, Error?) in
            var found = 0
            var changed = false
            do {
                for tx in block.transactions {
                    let txid = tx.txid
                    for input in tx.inputs {
                        guard let other = w.pendingSpends[input.previousOutPoint], other != txid else { continue }
                        do { try store.deletePending(other) } catch { throw PeerError("drop pending tx \(other): \(error)") }
                        w.pendingSpends.removeValue(forKey: input.previousOutPoint)
                        changed = true
                        Log.info("pending: tx \(other) dropped, it conflicts with tx \(txid) in block \(height)")
                    }
                    guard describeTx(tx, w, "in block \(height)") else { continue }
                    do {
                        try store.saveTransaction(StoredTransaction(txid: txid, height: height, blockHash: blockHash, raw: tx.serialized()))
                    } catch {
                        throw PeerError("store tx \(txid): \(error)")
                    }
                    if w.pendingIDs.contains(txid) {
                        do { try store.deletePending(txid) } catch { throw PeerError("confirm pending tx \(txid): \(error)") }
                        Log.info("pending: tx \(txid) confirmed in block \(height)")
                    }
                    found += 1
                    changed = true
                }
                if changed { try loadWalletLocked(&w) }
            } catch {
                return (found, changed, error)
            }
            return (found, changed, nil)
        }
        if changed { walletChanged() }
        if let failure { throw failure }
        return found
    }

    /// Asks the peer for the announced transactions not seen before,
    /// without witness data: the inputs and outputs are all the wallet
    /// checks.
    func requestTxs(_ c: PeerConnection, _ list: [InvVect]) {
        let wanted = wallet.withLock { w -> [InvVect] in
            var out = [InvVect]()
            for iv in list where iv.kind == .tx || iv.kind == .witnessTx {
                if w.seenTxs.contains(iv.hash) || w.confirmedIDs.contains(iv.hash) || w.pendingIDs.contains(iv.hash) { continue }
                if w.seenTxs.count >= SyncEngine.seenLimit { w.seenTxs = [] }
                w.seenTxs.insert(iv.hash)
                out.append(InvVect(.tx, iv.hash))
            }
            return out
        }
        if !wanted.isEmpty { c.send(.getData(wanted)) }
    }

    /// Stores a relayed unconfirmed transaction when it pays a wallet
    /// script or spends a wallet coin; bloom filter false positives are
    /// ignored.
    func acceptPendingTx(_ c: PeerConnection, _ tx: Transaction) {
        let txid = tx.txid
        let result = wallet.withLock { w -> Result<Bool, Error> in
            if w.confirmedIDs.contains(txid) || w.pendingIDs.contains(txid) || !describeTx(tx, w, "unconfirmed, from \(c.address),") {
                return .success(false)
            }
            do {
                try store.savePending(PendingTransaction(txid: txid, raw: tx.serialized(), seenAt: Int64(Date().timeIntervalSince1970)))
                try loadWalletLocked(&w)
            } catch {
                return .failure(error)
            }
            return .success(true)
        }
        switch result {
        case .success(true): walletChanged()
        case .failure(let error): Log.info("pending: store tx \(txid): \(error)")
        default: break
        }
    }

    /// Drops the unconfirmed transactions older than pendingExpiry.
    func expirePending() throws {
        let n: Int
        do {
            n = try store.deletePending(before: Int64(Date().timeIntervalSince1970) - SyncEngine.pendingExpiry)
        } catch {
            throw PeerError("expire pending transactions: \(error)")
        }
        guard n > 0 else { return }
        Log.info("pending: \(n) unconfirmed transactions expired after 14 days")
        try loadWallet()
        walletChanged()
    }

    /// Reports the new balance and refreshes the bloom filters of the
    /// connected peers with the current wallet coins.
    func walletChanged() {
        let (confirmed, pending) = walletBalance()
        Log.info("balance: \(confirmed) sat confirmed, \(pending >= 0 ? "+" : "")\(pending) sat pending")
        reloadBlooms()
        emit()
    }

    /// Sends a signed wallet transaction to every connected peer and records
    /// it as pending, so the balance reflects it at once. It is sent again to
    /// every peer that connects until it confirms. It returns the number of
    /// peers it was sent to.
    public func broadcast(_ tx: Transaction) throws -> Int {
        let peers = livePeers(poolPeers())
        guard !peers.isEmpty else { throw PeerError("not connected to any peer") }
        let txid = tx.txid
        let failure = wallet.withLock { w -> Error? in
            do {
                try store.savePending(PendingTransaction(txid: txid, raw: tx.serialized(), seenAt: Int64(Date().timeIntervalSince1970)))
                w.seenTxs.insert(txid)
                _ = describeTx(tx, w, "sent,")
                try loadWalletLocked(&w)
            } catch {
                return error
            }
            return nil
        }
        if let failure { throw PeerError("record tx \(txid): \(failure)") }
        for c in peers { c.send(.tx(tx)) }
        Log.info("send: tx \(txid) broadcast to \(peers.count) peers")
        walletChanged()
        return peers.count
    }

    /// Sends the pending transactions spending wallet coins, the wallet's
    /// own unconfirmed payments, to a newly connected peer.
    func rebroadcast(_ c: PeerConnection) {
        let own = wallet.withLock { w in
            w.pendingTxs.filter { tx in tx.inputs.contains { w.outpoints[$0.previousOutPoint] != nil } }
        }
        for tx in own { c.send(.tx(tx)) }
        if !own.isEmpty { Log.info("send: \(own.count) pending transactions sent again to \(c.address)") }
    }

    // MARK: Bloom filters and relay

    /// The BIP37 filter of the wallet: the key hash of every wallet address,
    /// which peers match in output scripts, and every wallet coin, matched
    /// in the inputs spending it. Peers must not add to it themselves: each
    /// false positive would add an unrelated transaction's outputs until
    /// the filter matches everything. The wallet reloads it instead whenever
    /// its coins change.
    func walletBloom() -> BloomFilter {
        wallet.withLock { w in
            let elements = UInt32(w.scripts.count + w.outpoints.count)
            var filter = BloomFilter(elements: max(elements, SyncEngine.bloomMinElements), tweak: UInt32.random(in: 0...UInt32.max),
                                     fpRate: SyncEngine.bloomFPRate, flags: BloomFilter.updateNone)
            for s in w.scripts { filter.add(s.script.dropFirst(2)) }
            for op in w.outpoints.keys { filter.add(op) }
            return filter
        }
    }

    /// Sends the wallet filter to a peer serving BIP37 filters and asks it
    /// for the matching transactions already in its mempool; from then on it
    /// announces every matching transaction it relays.
    @discardableResult
    func loadBloom(_ c: PeerConnection) -> Bool {
        guard c.services.contains(.bloom) else { return false }
        let filter = walletBloom()
        c.send(.filterLoad(filter))
        c.send(.memPool)
        Log.info("peer \(c.address): bloom filter loaded (\(filter.data.count) bytes, \(filter.hashFuncs) hash functions)")
        return true
    }

    /// Refreshes the filter of every connected peer serving BIP37 after the
    /// wallet coins changed.
    func reloadBlooms() {
        for c in livePeers(poolPeers()) where c.services.contains(.bloom) {
            c.send(.filterLoad(walletBloom()))
        }
    }

    /// Counts one relayed transaction checked against the wallet and logs
    /// the running totals now and then.
    func countRelayed(_ c: PeerConnection, _ tx: Transaction) {
        let (n, bytes) = relay.withLock { r -> (Int64, Int64) in
            r.txs += 1
            r.bytes += Int64(tx.serialized().count)
            return (r.txs, r.bytes)
        }
        if n % SyncEngine.relayLogEvery == 0 {
            Log.info("tx relay: \(n) relayed transactions checked (\(bytes / 1024) KB), the latest from \(c.address)")
        }
    }

    /// Whether the transactions the peer announces are fetched, given the
    /// connected peers with the primary first. While any peer serves bloom
    /// filters only those are listened to, as they announce just the
    /// transactions matching the wallet's filter. Without any, every relayed
    /// transaction is downloaded from the primary and checked by the wallet
    /// itself: full transaction bandwidth, but it works with every node and
    /// reveals nothing about the wallet.
    func relaySource(_ c: PeerConnection, _ peers: [PeerConnection]) -> Bool {
        if peers.contains(where: { $0.services.contains(.bloom) }) { return c.services.contains(.bloom) }
        return peers.first === c
    }

    /// Names how unconfirmed transactions are received from the peers.
    func describeRelay(_ peers: [PeerConnection]) -> String {
        let bloom = peers.filter { $0.services.contains(.bloom) }.count
        if bloom > 0 { return "bloom filters on \(bloom) peer\(bloom == 1 ? "" : "s")" }
        if let first = peers.first { return "no peer serves bloom filters, downloading all relayed transactions from \(first.address)" }
        return "no peers"
    }

    /// Logs how unconfirmed transactions are received, when that changed.
    func logRelayMode() {
        let mode = describeRelay(orderedPeers())
        let changed = relay.withLock { r -> Bool in
            defer { r.mode = mode }
            return r.mode != mode
        }
        if changed { Log.info("tx relay: \(mode)") }
    }

    // MARK: History

    /// Describes the wallet transactions, the confirmed ones in block order
    /// followed by the unconfirmed ones, each with its time, and returns
    /// them newest first, the unconfirmed before the confirmed.
    static func buildHistory(_ txs: [Transaction], times: [Int64], confirmed: Int, wallet w: WalletState, network: Network) -> [WalletTransaction] {
        var byID = [Hash256: Transaction]()
        for tx in txs { byID[tx.txid] = tx }
        var out = [WalletTransaction]()
        for (n, tx) in txs.enumerated() {
            var entry = WalletTransaction(txid: tx.txid, time: times[n], confirmed: n < confirmed, net: 0, fee: 0, inputs: [], outputs: [])
            var funded = true
            var fee: Int64 = 0
            for input in tx.inputs {
                let (address, value) = inputAddress(input, byID, w, network)
                entry.inputs.append(address)
                funded = funded && address.mine
                fee += value
                if address.mine { entry.net -= value }
            }
            for output in tx.outputs {
                let address = outputAddress(output.pkScript, w, network)
                entry.outputs.append(address)
                fee -= output.value
                if address.mine { entry.net += output.value }
            }
            if funded { entry.fee = fee }
            out.append(entry)
        }
        return out.stableSorted { a, b in
            if a.confirmed != b.confirmed { return !a.confirmed }
            return a.time > b.time
        }
    }

    /// The address an output script pays, the wallet's own told by its
    /// scripts. A script with no address, such as OP_RETURN data, gets none.
    static func outputAddress(_ script: Data, _ w: WalletState, _ network: Network) -> TxAddress {
        if let idx = w.scriptIndex[script] { return TxAddress(address: w.scripts[idx].address, mine: true) }
        return TxAddress(address: script.address(network: network) ?? "", mine: false)
    }

    /// The address an input spends from, with the value it spends when the
    /// wallet holds the previous transaction; otherwise the address is read
    /// from the signature script and witness.
    static func inputAddress(_ input: TxIn, _ byID: [Hash256: Transaction], _ w: WalletState, _ network: Network) -> (TxAddress, Int64) {
        let prev = input.previousOutPoint
        if prev.isCoinbase { return (TxAddress(address: coinbaseInput, mine: false), 0) }
        if let tx = byID[prev.hash], Int(prev.index) < tx.outputs.count {
            let out = tx.outputs[Int(prev.index)]
            return (outputAddress(out.pkScript, w, network), out.value)
        }
        return (TxAddress(address: spentAddress(input.signatureScript, input.witness, network), mine: false), 0)
    }

    /// The address of the output an input spends, read from its signature
    /// script and witness: P2WPKH and P2WSH, bare or nested in P2SH, P2PKH
    /// and P2SH. Taproot spends do not reveal the output key and give an
    /// empty address, as does anything not recognised.
    static func spentAddress(_ sigScript: Data, _ witness: [Data], _ network: Network) -> String {
        guard let pushes = try? sigScript.pushedData() else { return "" }
        if !witness.isEmpty {
            if pushes.count == 1 { return Address.p2sh(hash: pushes[0].hash160(), network: network) }
            if !sigScript.isEmpty { return "" }
            let last = witness[witness.count - 1]
            if witness.count == 2 && last.isPubKey {
                return Address.segwit(version: 0, program: last.hash160(), network: network)
            }
            if witness.count >= 2 && !last.isControlBlock {
                return Address.segwit(version: 0, program: last.sha256(), network: network)
            }
            return ""
        }
        if pushes.count == 2 && pushes[1].isPubKey {
            return Address.p2pkh(hash: pushes[1].hash160(), network: network)
        }
        if pushes.count >= 2 { return Address.p2sh(hash: pushes[pushes.count - 1].hash160(), network: network) }
        return ""
    }
}
