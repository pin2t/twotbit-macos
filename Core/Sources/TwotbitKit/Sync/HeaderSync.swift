import Foundation
import Synchronization

extension SyncEngine {
    /// The size limits of one request: headers and filter headers per batch,
    /// and the smaller limit for full filters.
    static let headerBatch = 2000
    static let filterHeaderBatch: Int32 = 2000
    static let filterBatch: Int32 = 1000
    /// Filters start this many blocks before the wallet's creation, so no
    /// relevant transaction is missed by timestamp jitter.
    static let safetyGap: Int32 = 10
    /// Bounds one peer's answer while the filter header anchor is proven;
    /// ten peers are asked, so it is shorter than a normal request.
    static let anchorRequestTimeout: Duration = .seconds(20)

    /// The height filters start at: safetyGap blocks before the first block
    /// at or after the wallet's creation time, clamped to genesis.
    static func filterStartHeight(_ chain: HeaderChain, _ seedTime: Int64) -> Int32 {
        let first = chain.firstHeight(atOrAfter: seedTime)
        return first > safetyGap ? first - safetyGap : 0
    }

    /// The height filter download begins at.
    public var filterStart: Int32 { chain.withLock { $0.filterStart } }

    /// Recomputes the filter start height after the header sync: the chain
    /// may have grown past the wallet's creation time, which moves it.
    func refreshFilterStart() {
        chain.withLock { $0.filterStart = SyncEngine.filterStartHeight($0.headers, $0.seedTime) }
    }

    /// Whether the first filter header must be majority proven before the
    /// filter download starts.
    func needsAnchor() -> Bool {
        chain.withLock { $0.filterStart > 0 && $0.filterStart <= $0.headers.height }
    }

    /// Whether the filter download starts at the filter start height and so
    /// needs the anchor proven first. Once filters are stored from there on,
    /// the stored filter headers link the chain.
    func anchorPending() throws -> Bool {
        guard needsAnchor() else { return false }
        let start = filterStart
        return try store.filterResumeHeight(from: start) == start
    }

    /// Stores the majority proven anchor of the filter header chain; the
    /// first cfheaders batch must then match it.
    func setFilterAnchor(_ anchor: Hash256) {
        chain.withLock { c in
            c.anchorPrev = anchor
            c.anchorSet = true
        }
    }

    /// Asks one peer for the cfheaders batch starting at the filter start
    /// height and returns the previous filter header it reports: its
    /// candidate anchor.
    func requestFilterAnchor(_ c: PeerConnection) async throws -> Hash256 {
        let start = filterStart
        guard let entry = entry(at: start) else { throw PeerError("filter start header \(start) not in chain") }
        return try await getCFHeaders(c, start: start, stop: entry.hash, timeout: SyncEngine.anchorRequestTimeout).prevFilterHeader
    }

    /// Requests headers from the peer until its tip is reached, validating
    /// and storing every batch, and returns the new tip height.
    @discardableResult
    func syncHeaders(_ c: PeerConnection) async throws -> Int32 {
        while true {
            let locator = chain.withLock { $0.headers.locator() }
            let batch = try await getHeaders(c, locator: locator)
            if batch.isEmpty { break }
            let from = chainHeight + 1
            do {
                try extendHeaders(batch)
            } catch {
                throw PeerError("extend headers: \(error)")
            }
            let tip = chainHeight
            Log.info("sync: headers \(min(from, tip))-\(tip) from \(c.address)")
            report(.headers, tip)
            if batch.count < SyncEngine.headerBatch { break }
        }
        return chainHeight
    }

    /// Appends a peer's batch to the chain, storing the validated headers in
    /// one transaction, those before an invalid one included. A batch
    /// forking below the tip is a reorg: it is taken only when its branch
    /// has more proof of work than the blocks it replaces, and then the
    /// headers, filters, matches and wallet transactions above the fork are
    /// dropped.
    func extendHeaders(_ batch: [BlockHeader]) throws {
        let first = batch[0].prevBlock
        let (fork, tip) = chain.withLock { ($0.headers.height(of: first), $0.headers.height) }
        guard fork >= 0 else { throw ChainError("peer chain continues from unknown block \(first)") }
        if fork < tip {
            var candidate = chain.withLock { $0.headers }
            candidate.truncate(to: fork)
            for header in batch {
                do { try candidate.add(header) } catch { break }
            }
            let (current, branch) = chain.withLock { ($0.headers.work(above: fork), candidate.work(above: fork)) }
            guard branch > current else {
                throw ChainError("peer chain forks at height \(fork) with less proof of work than the \(tip - fork) blocks after it")
            }
            Log.info("sync: reorg, rewinding from height \(tip) to \(fork)")
            try rewind(to: fork)
        }
        var rows = [StoredHeader]()
        var failure: Error?
        chain.withLock { c in
            for header in batch {
                do {
                    try c.headers.add(header)
                } catch {
                    failure = error
                    break
                }
                rows.append(StoredHeader(height: c.headers.height, header: header))
            }
        }
        do {
            try store.saveHeaders(rows)
        } catch {
            chain.withLock { $0.headers.truncate(to: $0.headers.height - Int32(rows.count)) }
            throw ChainError("store headers: \(error)")
        }
        if let failure { throw failure }
    }

    /// Drops every header and every row derived from blocks above the
    /// height.
    func rewind(to fork: Int32) throws {
        chain.withLock { $0.headers.truncate(to: fork) }
        try store.deleteHeaders(above: fork)
        try store.deleteFilters(above: fork)
        try store.deleteMatches(above: fork)
        try store.deleteTransactions(above: fork)
        try loadWallet()
    }

    /// Syncs from the primary peer whenever a new block is announced, a peer
    /// connects, the pinned peer has been away long enough to fall back to
    /// the others, or the poll interval elapses. A failing peer is
    /// disconnected so the next round uses another one.
    func syncLoop() async {
        var fellBack = false
        while !Task.isCancelled {
            guard let c = primary() else {
                _ = await wake.wait(timeout: fallbackDelay())
                continue
            }
            let pinned = currentPinned()
            if !pinned.isEmpty && c.pinned == fellBack {
                fellBack = !c.pinned
                Log.info(fellBack ? "sync: pinned peer \(pinned) away for \(SyncEngine.pinnedFallbackAfter.formatted), syncing from \(c.address)"
                                  : "sync: syncing from pinned peer \(pinned)")
            }
            let seen = manager.withLock { $0.announced }
            var failure: Error?
            do {
                try await syncOnce(c)
            } catch {
                failure = error
            }
            if Task.isCancelled { return }
            manager.withLock { m in
                m.roundOK = failure == nil
                if failure == nil { m.syncedThrough = seen }
            }
            report(.idle, chainHeight)
            if let failure {
                Log.info("sync: round failed: \(failure)")
                guard await pause(SyncEngine.retryDelay) else { return }
                continue
            }
            _ = await wake.wait(timeout: SyncEngine.pollInterval)
        }
    }

    /// Brings the headers up to the primary peer's tip, then the filters and
    /// wallet transactions up to the header tip, and runs the queued
    /// rescans. The first filter header is majority proven once per run
    /// before the filter download starts. A primary failing the header sync
    /// is disconnected so the next round uses another.
    func syncOnce(_ c: PeerConnection) async throws {
        try expirePending()
        let before = chainHeight
        report(.headers, before)
        do {
            try await syncHeaders(c)
        } catch {
            drop(c, "headers", error)
            throw PeerError("headers: \(error)")
        }
        if chainHeight != before { Log.info("sync: headers synced to \(chainHeight) from \(c.address)") }
        refreshFilterStart()
        if try anchorPending(), !manager.withLock({ $0.anchorTried }) {
            report(.filters, filterStart)
            let anchor: Hash256?
            do {
                anchor = try await proveFilterAnchor()
            } catch {
                throw PeerError("prove filter header anchor: \(error)")
            }
            manager.withLock { $0.anchorTried = true }
            if let anchor {
                setFilterAnchor(anchor)
                Log.info("sync: filter header anchor at height \(filterStart) proven by peer majority: \(anchor)")
            } else {
                Log.info("sync: no peer answered the filter header anchor request; the filter peers will be trusted")
            }
        }
        let stored: Int32
        do {
            stored = try await syncFilters()
        } catch {
            throw PeerError("filters: \(error)")
        }
        do {
            try await rescan()
        } catch {
            throw PeerError("rescan: \(error)")
        }
        if stored > 0 || chainHeight != before {
            Log.info("sync: wallet synced to tip \(chainHeight) (\(stored) new filters)")
        }
    }

    /// Asks up to anchorPeerLimit peers for the first filter header and
    /// returns the value a strict majority reports: the connected peers all
    /// at once, then further candidates dialed anchorDialers at a time until
    /// enough votes are in. Nil when no peer answered; peers disagreeing
    /// without a majority are an error.
    func proveFilterAnchor() async throws -> Hash256? {
        let (answered, initial) = await fanOut(filterPeers(), "filter header anchor") { try await self.requestFilterAnchor($0) }
        let inPool = Set(poolPeers().map(\.address))
        let list = manager.withLock { $0.candidates.filter { !inPool.contains($0) } }
        let votes = Locked(initial)
        let dialed = Locked(0)
        let next = Locked(0)
        let limit = SyncEngine.anchorPeerLimit
        await withTaskGroup(of: Void.self) { group in
            for _ in 0..<SyncEngine.anchorDialers {
                group.addTask {
                    while !Task.isCancelled {
                        if votes.withLock({ $0.count >= limit }) { return }
                        let index = next.withLock { n -> Int? in
                            guard n < list.count else { return nil }
                            defer { n += 1 }
                            return n
                        }
                        guard let index else { return }
                        guard let anchor = try? await self.dialAnchor(list[index]) else { continue }
                        votes.withLock { $0.append(anchor) }
                        dialed.withLock { $0 += 1 }
                    }
                }
            }
        }
        if Task.isCancelled { throw CancellationError() }
        let all = votes.withLock { $0 }
        Log.info("sync: filter header anchor votes: \(answered.count) from connected peers, \(dialed.withLock { $0 }) from dialed peers")
        guard !all.isEmpty else { return nil }
        return try all.majorityAnchor()
    }

    /// Connects to one candidate just long enough to ask it for the filter
    /// header anchor.
    func dialAnchor(_ addr: String) async throws -> Hash256 {
        guard let dialer = dialer(for: addr) else { throw PeerError("peer \(addr) not dialed on the networks on") }
        let (host, port) = try addr.splitHostPort()
        let c: PeerConnection
        do {
            (c, _) = try await PeerConnection.connect(network: network, address: addr, dialer: dialer, relay: false) { [weak self] c, message in
                if case .addr = message { self?.handle(c, message) }
                if case .addrV2 = message { self?.handle(c, message) }
            }
        } catch {
            try? store.recordPeerResult(host: host, port: port, ok: false, latencyMs: 0)
            throw error
        }
        defer { c.disconnect() }
        do {
            try store.updatePeerServices(host: host, port: port, services: c.services.rawValue)
        } catch {
            Log.info("store peer \(addr): \(error)")
        }
        guard c.services.contains(.compactFilters) else { throw PeerError("no compact filter service") }
        do {
            return try await requestFilterAnchor(c)
        } catch {
            Log.info("peer \(addr): filter header anchor: \(error)")
            throw error
        }
    }
}

extension [Hash256] {
    /// The filter header anchor a strict majority of the votes report. No votes, and ties
    /// without a majority, are errors.
    public func majorityAnchor() throws -> Hash256 {
        guard let first = first else { throw PeerError("no anchor votes") }
        var counts = [Hash256: Int]()
        for vote in self { counts[vote, default: 0] += 1 }
        var best = first
        for (vote, n) in counts where n > counts[best]! { best = vote }
        guard counts[best]! * 2 > count else {
            throw PeerError("no majority anchor: \(counts[best]!) of \(count) peers agree")
        }
        return best
    }
}
