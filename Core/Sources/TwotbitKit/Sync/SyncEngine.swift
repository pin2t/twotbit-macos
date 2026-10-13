import Foundation
import Synchronization

/// SyncStatus is a snapshot of the sync for display: the connected peers,
/// the current activity and the block height it reached, whether the wallet
/// is synced to the tip, and the balance in satoshis: confirmed, and the
/// change pending unconfirmed transactions make to it.
public struct SyncStatus: Sendable, Equatable {
    public enum Activity: Sendable, Equatable {
        case idle, headers, filters
    }

    public var activity: Activity = .idle
    public var peers = 0
    public var height: Int32 = 0
    public var synced = false
    public var balance: Int64 = 0
    public var pending: Int64 = 0
    /// The anonymity networks peers are reached over, "Tor", "I2P" or "Tor
    /// and I2P", or empty when they are reached directly.
    public var via = ""

    public init() {}

    /// The connectivity level from 0 to the target peer count: one bar per
    /// connected peer.
    public var bars: Int { min(peers, SyncEngine.targetPeers) }

    /// The status line: not connected, syncing with the block reached so
    /// far, or connected once synced to the tip, naming Tor or I2P when they
    /// are on.
    public var text: String {
        switch true {
        case peers == 0 && !via.isEmpty: return "Connecting over \(via)..."
        case peers == 0: return "Not connected"
        case !synced: return "Syncing (\(height))..."
        case !via.isEmpty: return "Connected over \(via)"
        default: return "Connected"
        }
    }
}

/// WatchScript is one wallet output script kept for matching, with its
/// address and the derivation path of its key.
struct WatchScript: Sendable {
    let address: String
    let path: String
    let script: Data
}

/// SyncEngine keeps the wallet synchronised with the Bitcoin network: it
/// holds a small pool of P2P peers, downloads and validates block headers
/// and BIP158 filters, matches the wallet scripts, downloads the matching
/// blocks and follows new blocks and relayed transactions while the pool
/// stays connected.
public final class SyncEngine: Sendable {
    /// The number of peer connections kept open.
    public static let targetPeers = 3
    /// How many candidates are dialed at once while the pool is first
    /// filled.
    static let connectWorkers = 5
    /// How many peers are asked for the first filter header when the anchor
    /// of the filter header chain is proven by majority, and how many of
    /// them are dialed at once.
    static let anchorPeerLimit = 10
    static let anchorDialers = 8
    /// The longest delay between reconnects to the pinned peer; a
    /// connection lasting pinnedStableAfter resets it.
    static let pinnedMaxBackoff: Duration = .seconds(60)
    static let pinnedStableAfter: Duration = .seconds(30)
    /// How long the pinned peer may be away before the sync falls back to
    /// the other peers until it is back.
    static let pinnedFallbackAfter: Duration = .seconds(300)
    /// The pace of reconnects and failed sync rounds.
    static let retryDelay: Duration = .seconds(5)
    /// The fallback re-sync period, in case a block announcement is missed.
    static let pollInterval: Duration = .seconds(600)

    public let network: Network
    let store: Store
    let chain: Mutex<ChainState>
    let wallet = Mutex(WalletState())
    let manager = Mutex(ManagerState())
    /// Serializes status callbacks so they arrive in the order the status
    /// changed.
    let emitLock = Mutex(())
    let wake = Pulse()
    let poolChanged = Pulse()
    let relay = Mutex(RelayState())

    struct ChainState: Sendable {
        var headers: HeaderChain
        var seedTime: Int64 = 0
        var filterStart: Int32 = 0
        var anchorPrev: Hash256 = .zero
        var anchorSet = false
    }

    struct ManagerState: Sendable {
        var pool: [PeerConnection] = []
        var activity: SyncStatus.Activity = .idle
        var height: Int32 = 0
        var stopped = true
        var onStatus: (@Sendable (SyncStatus) -> Void)?
        var pinnedAddr = ""
        var pinnedSeen = ContinuousClock.now
        var pinnedTask: Task<Void, Never>?
        /// The anonymity networks on, each with its client's dialer once it
        /// is ready.
        var overlays: [OverlayNetwork: (any Dialer)?] = [:]
        var refill = false
        var roundOK = false
        var announced = 0
        var syncedThrough = 0
        var candidates: [String] = []
        var candNext = 0
        var anchorTried = false
        /// The background work the engine waits for when it stops, each
        /// task removing itself once done.
        var tasks: [UUID: Task<Void, Never>] = [:]
    }

    struct RelayState: Sendable {
        var mode = ""
        var txs: Int64 = 0
        var bytes: Int64 = 0
    }

    /// Opens the sync state of the wallet database: the stored header chain,
    /// which was validated before it was stored, and the wallet scripts and
    /// transactions. The genesis header is stored on first use.
    public init(network: Network, store: Store) throws {
        self.network = network
        self.store = store
        var headers = HeaderChain(network: network)
        let count = try store.headerCount()
        if count == 0 {
            try headers.add(network.genesis)
            try store.saveHeaders([StoredHeader(height: 0, header: network.genesis)])
        } else {
            headers.reserve(count)
            var next: Int32 = 0
            try store.forEachHeader { stored in
                guard stored.height == next else { throw ChainError("stored chain has no header at height \(next)") }
                try headers.appendTrusted(stored.header)
                next += 1
            }
        }
        chain = Mutex(ChainState(headers: headers))
        let addresses = try store.addresses() + store.changeAddresses()
        wallet.withLock { w in
            w.initialized = true
            for a in addresses {
                let script = Script.p2wpkh(pubkey: a.pubkey)
                w.scriptIndex[script] = w.scripts.count
                w.scripts.append(WatchScript(address: a.address, path: a.path, script: script))
            }
        }
        try loadWallet()
        let seed = try store.meta()?.createdAt ?? 0
        chain.withLock { c in
            c.seedTime = seed
            c.filterStart = SyncEngine.filterStartHeight(c.headers, seed)
        }
        let watched = wallet.withLock { ($0.scripts.count, $0.outpoints.count) }
        Log.info("sync: loaded \(headers.height + 1) headers, tip \(headers.height), watching \(watched.0) addresses and \(watched.1) coins")
    }

    /// The tip height of the validated header chain.
    public var chainHeight: Int32 { chain.withLock { $0.headers.height } }

    func entry(at height: Int32) -> ChainEntry? { chain.withLock { $0.headers.entry(at: height) } }
    func heightOf(_ hash: Hash256) -> Int32 { chain.withLock { $0.headers.height(of: hash) } }

    /// Starts syncing in the background: it keeps targetPeers peers
    /// connected, syncs headers and filters and stays connected to follow
    /// new blocks. Every change of the status is reported through onStatus,
    /// from any thread. pinned is an optional host:port peer assumed to be
    /// always available: it is never dropped or replaced, it is reconnected
    /// whenever the connection is lost, and headers and filters are synced
    /// from it while it is connected. The other peers cross-check its
    /// filters and take over once it has been away for pinnedFallbackAfter.
    public func start(pinned: String = "", onStatus: @escaping @Sendable (SyncStatus) -> Void) throws {
        if !pinned.isEmpty {
            guard (try? pinned.splitHostPort()) != nil else { throw PeerError("peer address \"\(pinned)\" must include a port") }
        }
        let tip = chainHeight
        manager.withLock { m in
            m.pool = []
            m.activity = .idle
            m.height = tip
            m.onStatus = onStatus
            m.stopped = false
            m.pinnedAddr = pinned
            m.pinnedSeen = .now
            m.refill = true
            m.roundOK = false
            m.announced = 0
            m.syncedThrough = 0
            m.candidates = []
            m.candNext = 0
            m.anchorTried = false
        }
        emit()
        spawn { await self.maintain() }
        spawn { await self.syncLoop() }
        if !pinned.isEmpty { startPinned(pinned) }
    }

    /// Runs the work as a task the engine waits for when it stops.
    @discardableResult
    func spawn(_ work: @escaping @Sendable () async -> Void) -> Task<Void, Never> {
        let id = UUID()
        let task = Task {
            await work()
            _ = self.manager.withLock { $0.tasks.removeValue(forKey: id) }
        }
        manager.withLock { m in
            m.tasks[id] = task
            if m.stopped { task.cancel() }
        }
        return task
    }

    private func startPinned(_ addr: String) {
        let task = spawn { await self.keepPinned(addr) }
        manager.withLock { m in
            m.pinnedTask?.cancel()
            m.pinnedTask = task
        }
    }

    /// Ends the sync: it closes every peer connection and waits for the
    /// background work to finish. It is safe to call more than once.
    public func stop() async {
        let (tasks, open) = manager.withLock { m -> ([Task<Void, Never>], [PeerConnection]) in
            guard !m.stopped else { return ([], []) }
            m.stopped = true
            m.pinnedTask?.cancel()
            return (Array(m.tasks.values), m.pool)
        }
        for task in tasks { task.cancel() }
        for c in open { c.disconnect() }
        for task in tasks { await task.value }
    }

    /// Pins the running sync to another peer, as start's pinned does, or
    /// unpins it with "". The pinned peer before is disconnected, and so is
    /// a pool connection to the new one, which is dialed again as pinned.
    public func setPinned(_ addr: String) throws {
        if !addr.isEmpty {
            guard (try? addr.splitHostPort()) != nil else { throw PeerError("peer address \"\(addr)\" must include a port") }
        }
        let change = manager.withLock { m -> (old: String, closing: [PeerConnection])? in
            guard !m.stopped, addr != m.pinnedAddr else { return nil }
            let old = m.pinnedAddr
            m.pinnedTask?.cancel()
            m.pinnedTask = nil
            m.pinnedAddr = addr
            m.pinnedSeen = .now
            return (old, m.pool.filter { $0.pinned || $0.address == addr })
        }
        guard let change else { return }
        switch true {
        case addr.isEmpty: Log.info("sync: pinned peer \(change.old) removed")
        case change.old.isEmpty: Log.info("sync: pinned peer set to \(addr)")
        default: Log.info("sync: pinned peer changed from \(change.old) to \(addr)")
        }
        for c in change.closing { c.disconnect() }
        if !addr.isEmpty { startPinned(addr) }
        poolChanged.signal()
        wake.signal()
        emit()
    }

    /// Turns the anonymity network on or off. With none on, peers are
    /// reached directly; with some on, only peers on those networks are,
    /// each through its network's dialer, and none of a network whose
    /// client is not ready yet, its dialer nil. It may be called before
    /// start. Switching a network disconnects every peer no longer allowed
    /// and refills the pool; the pinned peer is left to setPinned.
    public func setOverlay(_ network: OverlayNetwork, on: Bool, dialer: (any Dialer)?) {
        let (changed, closing, running, via) = manager.withLock { m -> (Bool, [PeerConnection], Bool, String) in
            let was = m.overlays.keys.contains(network)
            if on {
                m.overlays[network] = .some(dialer)
            } else {
                m.overlays.removeValue(forKey: network)
            }
            let changed = was != on
            var closing = [PeerConnection]()
            if changed {
                closing = m.pool.filter { !SyncEngine.allowed(OverlayNetwork.of($0.host), m.overlays) }
                m.candidates = []
                m.candNext = 0
            }
            m.refill = true
            return (changed, closing, !m.stopped, SyncEngine.via(m.overlays))
        }
        switch true {
        case changed && !via.isEmpty: Log.info("sync: \(network) \(on ? "on" : "off"), connecting over \(via) only, \(closing.count) peers disconnected")
        case changed: Log.info("sync: \(network) off, connecting to peers directly, \(closing.count) peers disconnected")
        case on && dialer != nil: Log.info("sync: \(network) ready, dialing its peers")
        default: break
        }
        for c in closing { c.disconnect() }
        if running {
            poolChanged.signal()
            emit()
        }
    }

    /// Whether peers on the network are used: direct peers while no
    /// anonymity network is on, peers of the networks on otherwise.
    static func allowed(_ network: OverlayNetwork, _ overlays: [OverlayNetwork: (any Dialer)?]) -> Bool {
        overlays.isEmpty ? network == .direct : overlays.keys.contains(network)
    }

    /// The anonymity networks on, as the status names them.
    static func via(_ overlays: [OverlayNetwork: (any Dialer)?]) -> String {
        [OverlayNetwork.tor, .i2p].filter { overlays.keys.contains($0) }.map(\.description).joined(separator: " and ")
    }

    /// The networks whose peers are used.
    func allowedNetworks() -> [OverlayNetwork] {
        manager.withLock { m in OverlayNetwork.allCases.filter { SyncEngine.allowed($0, m.overlays) } }
    }

    /// The dialer to reach the peer with, nil for a peer not dialed now.
    func dialer(for addr: String) -> (any Dialer)? {
        guard let (host, _) = try? addr.splitHostPort() else { return nil }
        let network = OverlayNetwork.of(host)
        return manager.withLock { m -> (any Dialer)? in
            guard SyncEngine.allowed(network, m.overlays) else { return nil }
            if network == .direct { return DirectDialer() }
            return m.overlays[network] ?? nil
        }
    }

    func currentPinned() -> String { manager.withLock { $0.pinnedAddr } }

    /// The current status.
    public func status() -> SyncStatus {
        let (confirmed, pending) = walletBalance()
        return manager.withLock { m in
            var s = SyncStatus()
            s.activity = m.activity
            s.peers = m.pool.count
            s.height = m.height
            s.synced = SyncEngine.synced(m)
            s.balance = confirmed
            s.pending = pending
            s.via = SyncEngine.via(m.overlays)
            return s
        }
    }

    /// Reports the current status to the callback, in order.
    func emit() {
        emitLock.withLock { _ in
            let status = self.status()
            let callback = manager.withLock { $0.stopped ? nil : $0.onStatus }
            callback?(status)
        }
    }

    /// Whether the wallet is synced to the tip: idle after a successful
    /// round, no unknown block announced since that round started, and no
    /// connected peer advertising a higher tip.
    static func synced(_ m: ManagerState) -> Bool {
        guard m.activity == .idle, m.roundOK, m.announced == m.syncedThrough else { return false }
        return !m.pool.contains { $0.remote.startHeight > m.height }
    }

    /// Notes that a peer announced a block not in the chain, so the wallet
    /// is behind until the next successful round.
    func blockAnnounced() {
        manager.withLock { $0.announced += 1 }
        emit()
    }

    /// Records the sync activity and the height it reached.
    func report(_ activity: SyncStatus.Activity, _ height: Int32) {
        manager.withLock { m in
            m.activity = activity
            m.height = height
        }
        emit()
    }

    var isStopped: Bool { manager.withLock { $0.stopped } }
}
