import Foundation
import Synchronization

extension SyncEngine {
    /// The least time the other peers get to answer a parallel request
    /// after the primary did; beyond it a peer may take at most as long as
    /// the primary took before it is dropped as too slow.
    static let stragglerGrace: Duration = .seconds(5)

    /// Fills the pool at the start and after the networks changed, then
    /// keeps it filled, dialing as many next candidates at once as peers are
    /// missing. While a pinned peer is set one slot is kept for it;
    /// keepPinned dials it on its own.
    func maintain() async {
        while !Task.isCancelled {
            let again = manager.withLock { m -> Bool in
                defer { m.refill = false }
                return m.refill
            }
            if again { await fillPool() }
            var wait = SyncEngine.retryDelay
            let need = openSlots()
            if need > 0 {
                let addrs = await takeCandidates(need)
                await withTaskGroup(of: Void.self) { group in
                    for addr in addrs {
                        group.addTask { _ = await self.connect(addr, pinned: false) }
                    }
                }
                if !addrs.isEmpty { wait = .seconds(1) }
            }
            _ = await poolChanged.wait(timeout: wait)
        }
    }

    /// Connects the first peers quickly: connectWorkers workers each take
    /// the next candidate of a freshly shuffled list, dial it unless it is
    /// connected already, and repeat until the pool is full or the list runs
    /// out. Handshakes still in flight once the pool is full are abandoned.
    /// The candidates not dialed are left for maintain to continue with.
    func fillPool() async {
        guard openSlots() > 0 else { return }
        let list: [String]
        do {
            list = try await peerCandidates(pinned: currentPinned(), allowed: allowedNetworks())
        } catch {
            Log.info("peer discovery: \(error)")
            return
        }
        let next = Locked(0)
        await withTaskGroup(of: Void.self) { group in
            for _ in 0..<SyncEngine.connectWorkers {
                group.addTask {
                    while !Task.isCancelled && self.openSlots() > 0 {
                        let index = next.withLock { n -> Int? in
                            guard n < list.count else { return nil }
                            defer { n += 1 }
                            return n
                        }
                        guard let index else { return }
                        if self.connected(list[index]) { continue }
                        if await self.connect(list[index], pinned: false) && self.openSlots() <= 0 { return }
                    }
                }
            }
            while await group.next() != nil {
                if openSlots() <= 0 { group.cancelAll() }
            }
        }
        let fed = next.withLock { min($0, list.count) }
        let count = manager.withLock { m -> Int in
            m.candidates = list
            m.candNext = fed
            return m.pool.count
        }
        Log.info("peers: initial connect dialed \(fed) of \(list.count) candidates, \(count) connected")
    }

    /// How many more peers the pool takes: targetPeers less the connected
    /// peers and less one kept for a pinned peer while it is away; none
    /// while no anonymity network on is ready.
    func openSlots() -> Int { manager.withLock { SyncEngine.openSlots($0) } }

    static func openSlots(_ m: ManagerState) -> Int {
        if !m.overlays.isEmpty && !m.overlays.values.contains(where: { $0 != nil }) { return 0 }
        var n = targetPeers - m.pool.count
        if !m.pinnedAddr.isEmpty && !m.pool.contains(where: { $0.pinned }) { n -= 1 }
        return n
    }

    /// Keeps the pinned peer connected until the task is cancelled, as the
    /// sync stops or another peer is pinned: it dials it, waits for the
    /// connection to drop and dials again, backing off while the peer is
    /// unreachable or keeps dropping the connection soon after the
    /// handshake, as a node with full inbound slots evicting its newest peer
    /// does.
    func keepPinned(_ addr: String) async {
        var backoff = SyncEngine.retryDelay
        while !Task.isCancelled {
            if await connect(addr, pinned: true) {
                let since = ContinuousClock.now
                if let c = pinnedConn() { await c.waitForDisconnect() }
                if Task.isCancelled { return }
                let lasted = ContinuousClock.now - since
                if lasted >= SyncEngine.pinnedStableAfter {
                    backoff = SyncEngine.retryDelay
                    continue
                }
                Log.info("pinned peer \(addr) dropped the connection after \(lasted.formatted)")
            }
            if Task.isCancelled { return }
            Log.info("pinned peer \(addr): retrying in \(backoff.formatted)")
            guard await pause(backoff) else { return }
            backoff = min(backoff * 2, SyncEngine.pinnedMaxBackoff)
        }
    }

    func connected(_ addr: String) -> Bool { manager.withLock { $0.pool.contains { $0.address == addr } } }

    /// The connected peers, oldest first.
    func poolPeers() -> [PeerConnection] { manager.withLock { $0.pool } }

    func livePeers(_ peers: [PeerConnection]) -> [PeerConnection] { peers.filter(\.isLive) }

    /// The connected pinned peer, if any.
    func pinnedConn() -> PeerConnection? { livePeers(poolPeers()).first { $0.pinned } }

    /// The connected peers with the primary first: the pinned peer when one
    /// is set, the oldest connection otherwise.
    func orderedPeers() -> [PeerConnection] {
        let peers = livePeers(poolPeers())
        return peers.filter(\.pinned) + peers.filter { !$0.pinned }
    }

    /// The connected peer driving the sync. With a pinned peer set only it
    /// qualifies, nil meaning waiting for it, until it has been away for
    /// pinnedFallbackAfter: then the oldest other peer does.
    func primary() -> PeerConnection? {
        if !currentPinned().isEmpty {
            if let c = pinnedConn() { return c }
            if !pinnedAway() { return nil }
        }
        return orderedPeers().first
    }

    /// Up to targetPeers connected peers to download and cross-check
    /// filters from, the primary first; none while a pinned peer is set but
    /// not connected.
    func filterPeers() -> [PeerConnection] {
        guard primary() != nil else { return [] }
        return Array(orderedPeers().prefix(SyncEngine.targetPeers))
    }

    /// Whether a pinned peer is set but has not been connected for
    /// pinnedFallbackAfter.
    func pinnedAway() -> Bool {
        let (addr, seen) = manager.withLock { ($0.pinnedAddr, $0.pinnedSeen) }
        if addr.isEmpty || pinnedConn() != nil { return false }
        return ContinuousClock.now - seen >= SyncEngine.pinnedFallbackAfter
    }

    /// How long until the sync falls back from the away pinned peer to the
    /// others, nil without a pinned peer or once the fallback is due.
    func fallbackDelay() -> Duration? {
        let (addr, seen) = manager.withLock { ($0.pinnedAddr, $0.pinnedSeen) }
        let left = SyncEngine.pinnedFallbackAfter - (ContinuousClock.now - seen)
        if addr.isEmpty || left <= .zero { return nil }
        return left
    }

    /// Fails when a pinned peer is set but is not among the peers that
    /// answered: headers and filters are synced from it unless it is away.
    func requirePrimary(_ peers: [PeerConnection]) throws {
        let addr = currentPinned()
        if addr.isEmpty || peers.first?.pinned == true || pinnedAway() { return }
        throw PeerError("pinned peer \(addr) did not answer")
    }

    /// Up to n candidates not connected, rebuilding the list from the
    /// stored peers and the seeds when it runs out.
    func takeCandidates(_ n: Int) async -> [String] {
        var taken = [String]()
        for _ in 0..<2 where taken.count < n {
            let exhausted = manager.withLock { m -> Bool in
                let connected = Set(m.pool.map(\.address))
                while m.candNext < m.candidates.count && taken.count < n {
                    let addr = m.candidates[m.candNext]
                    m.candNext += 1
                    if !connected.contains(addr) && !taken.contains(addr) { taken.append(addr) }
                }
                return m.candNext >= m.candidates.count
            }
            if !exhausted || taken.count >= n { break }
            do {
                let fresh = try await peerCandidates(pinned: currentPinned(), allowed: allowedNetworks())
                manager.withLock { m in
                    m.candidates = fresh
                    m.candNext = 0
                }
            } catch {
                Log.info("peer discovery: \(error)")
                break
            }
        }
        return taken
    }

    /// The peers to fill the pool with: stored and freshly discovered peers
    /// on the allowed networks, without the pinned peer, the most valuable
    /// first: those added recently, and those connected to recently that
    /// answer most requests. Seeds not stored yet count as added now, and
    /// peers of equal value come in random order. Stored peers known not to
    /// serve compact filters are skipped. Peers on the internet come from
    /// the store and the DNS seeds, onion and I2P peers from the store and
    /// their built-in seeds, with no DNS lookup. An empty list is an error
    /// only without a pinned peer.
    func peerCandidates(pinned: String, allowed: [OverlayNetwork]) async throws -> [String] {
        let now = Store.unixNow
        let newcomer = PeerRecord(host: "", port: 0, services: 0, latencyMs: 0, okCount: 0, failCount: 0, addedAt: now).value(now: now)
        var list = [(addr: String, value: Double)]()
        var seen: Set<String> = [pinned]
        func add(_ addr: String, _ value: Double) {
            guard !addr.isEmpty, seen.insert(addr).inserted else { return }
            list.append((addr, value))
        }
        for p in try store.peers() {
            if p.services != 0 && !ServiceFlags(rawValue: p.services).contains(.compactFilters) { continue }
            if !allowed.contains(OverlayNetwork.of(p.host)) { continue }
            add(p.host.withPort(p.port), p.value(now: now))
        }
        for n in allowed {
            let seeds: [PeerAddress]
            switch n {
            case .direct: seeds = await DNS.seeds(network)
            case .tor: seeds = Seeds.onion(for: network)
            case .i2p: seeds = Seeds.i2p(for: network)
            }
            for seed in seeds { add(seed.description, newcomer) }
        }
        list.shuffle()
        list = list.stableSorted { $0.value > $1.value }
        if list.isEmpty && pinned.isEmpty {
            if !allowed.contains(.direct) {
                throw PeerError("no \(allowed.map(\.description).joined(separator: " or ")) peer addresses for network \(network.name)")
            }
            throw PeerError("no peer addresses for network \(network.name) (pass -peer or run a local node)")
        }
        return list.map(\.addr)
    }

    /// Dials one candidate and adds it to the pool, reporting whether it
    /// joined. A peer without the compact filters service is dropped after
    /// its services are stored, and so is one completing its handshake after
    /// others filled the pool. A dial abandoned by cancellation is not held
    /// against the peer.
    func connect(_ addr: String, pinned: Bool) async -> Bool {
        guard let dialer = dialer(for: addr), let (host, port) = try? addr.splitHostPort() else { return false }
        let c: PeerConnection
        let handshake: Duration
        do {
            (c, handshake) = try await PeerConnection.connect(network: network, address: addr, dialer: dialer, relay: true, pinned: pinned) { [weak self] c, message in
                self?.handle(c, message)
            }
        } catch {
            if Task.isCancelled { return false }
            Log.info("peer \(addr): connect failed: \(error)")
            try? store.peerConnectFailed(host: host, port: port)
            return false
        }
        do {
            try store.upsertPeer(host: host, port: port, services: c.services.rawValue, latencyMs: handshake.milliseconds)
        } catch {
            Log.info("store peer \(addr): \(error)")
        }
        guard c.services.contains(.compactFilters) else {
            if pinned {
                Log.info("pinned peer \(addr): no compact filter service (\(c.services)), disconnecting; it needs blockfilterindex=1 and peerblockfilters=1")
            } else {
                Log.info("peer \(addr): no compact filter service (\(c.services)), disconnecting")
            }
            c.disconnect()
            return false
        }
        c.send(.getAddr)
        enum Join { case ok(Int), refuse(String?) }
        let join = manager.withLock { m -> Join in
            if m.stopped { return .refuse(nil) }
            if pinned && addr != m.pinnedAddr { return .refuse("no longer the pinned peer, disconnecting") }
            if !SyncEngine.allowed(OverlayNetwork.of(host), m.overlays) { return .refuse("its network was switched off meanwhile, disconnecting") }
            if m.pool.contains(where: { $0.address == addr }) { return .refuse("connected already, disconnecting the second connection") }
            if !pinned && SyncEngine.openSlots(m) <= 0 { return .refuse("pool already full, disconnecting") }
            m.pool.append(c)
            return .ok(m.pool.count)
        }
        guard case .ok(let count) = join else {
            if case .refuse(let why?) = join { Log.info("peer \(addr): \(why)") }
            c.disconnect()
            return false
        }
        let kind = pinned ? "pinned peer" : "peer"
        Log.info("\(kind) \(addr) connected: \(c.remote.userAgent), height \(c.remote.startHeight), services \(c.services), handshake \(handshake.formatted) (\(count) connected)")
        loadBloom(c)
        rebroadcast(c)
        logRelayMode()
        emit()
        wake.signal()
        spawn {
            await c.waitForDisconnect()
            let left = self.manager.withLock { m -> Int in
                m.pool.removeAll { $0 === c }
                if c.pinned { m.pinnedSeen = .now }
                return m.pool.count
            }
            Log.info("\(kind) \(addr) disconnected\(c.disconnectReason.map { ": \($0)" } ?? "") (\(left) connected)")
            self.logRelayMode()
            self.emit()
            self.poolChanged.signal()
        }
        return true
    }

    /// Disconnects a peer that failed or misbehaved and logs why. The
    /// pinned peer stays connected.
    func drop(_ c: PeerConnection, _ reason: String, _ error: Any) {
        if c.pinned {
            Log.info("pinned peer \(c.address): \(reason): \(error); keeping it")
            return
        }
        Log.info("peer \(c.address): \(reason): \(error); disconnecting")
        c.disconnect()
    }

    /// Records the outcome and latency of one request against the peer.
    func record(_ c: PeerConnection, ok: Bool, since started: ContinuousClock.Instant) {
        do {
            try store.recordPeerResult(host: c.host, port: c.port, ok: ok, latencyMs: (ContinuousClock.now - started).milliseconds)
        } catch {
            Log.info("record peer \(c.address): \(error)")
        }
    }

    /// Handles what a peer sends unasked: relayed transactions are checked
    /// against the wallet, transactions announced by the relay source are
    /// fetched, a block announcement wakes the sync, and advertised peer
    /// addresses, onion ones included, are stored.
    func handle(_ c: PeerConnection, _ message: Message) {
        switch message {
        case .tx(let tx):
            countRelayed(c, tx)
            acceptPendingTx(c, tx)
        case .inv(let list):
            if relaySource(c, orderedPeers()) { requestTxs(c, list) }
            if let block = list.first(where: { $0.kind == .block }) {
                if heightOf(block.hash) < 0 {
                    Log.info("peer \(c.address) announced block \(block.hash)")
                    blockAnnounced()
                }
                wake.signal()
            }
        case .addr(let list):
            for a in list { savePeerAddr(a.host, a.port, a.services) }
            prunePeers()
        case .addrV2(let list):
            for a in list {
                guard let host = a.host, host.isOnion || host.isIP else { continue }
                savePeerAddr(host, a.port, a.services)
            }
            prunePeers()
        default:
            break
        }
    }

    /// Stores an advertised peer address with its services, when known.
    func savePeerAddr(_ host: String, _ port: UInt16, _ services: ServiceFlags) {
        guard port != 0 else { return }
        if services.rawValue != 0 {
            try? store.updatePeerServices(host: host, port: port, services: services.rawValue)
        } else {
            try? store.savePeer(host: host, port: port)
        }
    }

    /// Cuts the stored peers back to the most valuable once gossip grew them
    /// past Store.maxPeers, keeping the pinned and connected peers.
    func prunePeers() {
        let kept = manager.withLock { m in Set(m.pool.map(\.address) + [m.pinnedAddr]) }
        do {
            let n = try store.prunePeers(sparing: kept)
            if n > 0 { Log.info("peers: removed \(n) least valuable stored peers") }
        } catch {
            Log.info("prune peers: \(error)")
        }
    }

    /// Runs the request against every peer at once. peers[0] is the
    /// primary: once it answered, the others get as long as it took, and at
    /// least stragglerGrace, to answer too; when the primary fails, the
    /// first successful answer sets that pace. It returns the peers that
    /// answered in time, in their order, with their results; a peer whose
    /// request failed or came too late is dropped.
    func fanOut<T: Sendable>(_ peers: [PeerConnection], _ what: String,
                             _ request: @escaping @Sendable (PeerConnection) async throws -> T) async -> ([PeerConnection], [T]) {
        guard !peers.isEmpty else { return ([], []) }
        let started = ContinuousClock.now
        var results = [Int: Result<T, Error>]()
        var grace: Duration = .zero
        await withTaskGroup(of: (Int, Result<T, Error>)?.self) { group in
            for (i, c) in peers.enumerated() {
                group.addTask {
                    do {
                        return (i, .success(try await request(c)))
                    } catch {
                        return (i, .failure(error))
                    }
                }
            }
            var pending = peers.count
            var paced = false
            var anyOK = false
            while pending > 0, let next = await group.next() {
                guard let (i, result) = next else { break }
                pending -= 1
                results[i] = result
                if case .success = result { anyOK = true }
                let primaryDone = results[0] != nil
                let primaryOK = results[0].map { if case .success = $0 { return true } else { return false } } ?? false
                if !paced && primaryDone && (primaryOK || anyOK) && pending > 0 {
                    paced = true
                    grace = max(SyncEngine.stragglerGrace, ContinuousClock.now - started)
                    let wait = grace
                    group.addTask {
                        try? await Task.sleep(for: wait)
                        return nil
                    }
                }
            }
            group.cancelAll()
        }
        var okPeers = [PeerConnection]()
        var okResults = [T]()
        for (i, c) in peers.enumerated() {
            switch results[i] {
            case .none:
                drop(c, what, "too slow, no answer within \(grace.formatted) after the primary")
            case .failure(let error):
                drop(c, what, error)
            case .success(let value):
                okPeers.append(c)
                okResults.append(value)
            }
        }
        return (okPeers, okResults)
    }
}
