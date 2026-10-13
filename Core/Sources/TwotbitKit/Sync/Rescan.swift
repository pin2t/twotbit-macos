import Foundation

extension SyncEngine {
    /// RescanTarget is one queued address with the height its rescan
    /// starts at.
    struct RescanTarget: Sendable {
        let job: RescanJob
        let from: Int32
        let script: WatchScript
    }

    /// MatchKey identifies a recorded filter match of an address in a block.
    struct MatchKey: Hashable {
        let height: Int32
        let address: String
    }

    /// Matches the synced blocks again for the queued addresses: those
    /// watched after blocks paying them were scanned, such as a change
    /// address another wallet on the same seed used first. Their coins were
    /// found late, from the stored transactions, so spends of them in the
    /// blocks scanned before were missed. Each address is rescanned from the
    /// first stored block paying it up to the last synced filter: the
    /// pruned filters are downloaded again and checked against the stored
    /// filter header chain, and every block matching an address it was not
    /// matched for before is processed.
    func rescan() async throws {
        let jobs: [RescanJob]
        do { jobs = try store.rescans() } catch { throw PeerError("load rescans: \(error)") }
        guard !jobs.isEmpty else { return }
        let resume: Int32
        do { resume = try store.filterResumeHeight(from: filterStart) } catch { throw PeerError("filter resume height: \(error)") }
        let end = resume - 1
        let (targets, idle) = rescanTargets(jobs, end: end)
        for job in idle {
            do { try store.deleteRescan(job) } catch { throw PeerError("drop rescan of \(job.address): \(error)") }
        }
        guard let start = targets.first?.from else { return }
        var matched: Set<MatchKey>
        do {
            matched = Set(try store.matches().map { MatchKey(height: $0.height, address: $0.address) })
        } catch {
            throw PeerError("load matches: \(error)")
        }
        Log.info("sync: rescanning blocks \(start)-\(end) for \(targets.count) addresses watched after they were paid")
        var fStart = start
        while fStart <= end {
            let fEnd = min(fStart + SyncEngine.filterBatch - 1, end)
            report(.filters, fStart)
            let filters: [Data]
            do {
                filters = try await refetchFilters(fStart, fEnd)
            } catch {
                throw PeerError("filters \(fStart)-\(fEnd): \(error)")
            }
            for (i, data) in filters.enumerated() {
                try await rescanBlock(fStart + Int32(i), data, targets, &matched) { try await self.fetchBlock($0) }
            }
            fStart += SyncEngine.filterBatch
        }
        for t in targets {
            do { try store.deleteRescan(t.job) } catch { throw PeerError("finish rescan of \(t.job.address): \(error)") }
        }
        Log.info("sync: rescan of blocks \(start)-\(end) done")
    }

    /// Splits the queued rescans into the targets to scan up to the end
    /// height, the lowest start first, and those with nothing to scan. A
    /// target starts at the first stored block paying its address, and not
    /// below its queued height or the filter start.
    func rescanTargets(_ jobs: [RescanJob], end: Int32) -> ([RescanTarget], [RescanJob]) {
        let start = filterStart
        return wallet.withLock { w in
            var byAddress = [String: WatchScript]()
            for s in w.scripts { byAddress[s.address] = s }
            var targets = [RescanTarget]()
            var idle = [RescanJob]()
            for job in jobs {
                guard let script = byAddress[job.address], let first = w.firstPaid[job.address] else {
                    idle.append(job)
                    continue
                }
                let from = max(job.from, first, start)
                if from > end {
                    idle.append(job)
                    continue
                }
                targets.append(RescanTarget(job: job, from: from, script: script))
            }
            return (targets.stableSorted { $0.from < $1.from }, idle)
        }
    }

    /// Matches the filter of the block at the height against the targets
    /// started at or below it. A block matched for an address before was
    /// processed while the address was watched and is skipped for it; when
    /// any other target matches, the block is downloaded with getBlock and
    /// its wallet transactions are stored.
    func rescanBlock(_ height: Int32, _ data: Data, _ targets: [RescanTarget], _ matched: inout Set<MatchKey>,
                     getBlock: (Int32) async throws -> Block) async throws {
        guard let entry = entry(at: height) else { throw PeerError("no header at height \(height)") }
        let active = targets.filter { $0.from <= height }.map(\.script)
        guard !active.isEmpty else { return }
        let hits: [Bool]
        do {
            hits = try GCSFilter.matchScripts(data, blockHash: entry.hash, scripts: active.map(\.script))
        } catch {
            throw PeerError("match filter at height \(height): \(error)")
        }
        let fresh = zip(active, hits).filter { $0.1 && !matched.contains(MatchKey(height: height, address: $0.0.address)) }.map(\.0)
        guard !fresh.isEmpty else { return }
        for s in fresh { Log.info("match: rescanned filter of block \(height) (\(entry.hash)) matches address \(s.address)") }
        let block: Block
        do {
            block = try await getBlock(height)
        } catch {
            throw PeerError("download matched block \(height): \(error)")
        }
        if try processBlock(height, block) == 0 {
            Log.info("match: block \(height) holds no wallet transaction (filter false positive)")
        }
        for s in fresh {
            do {
                try store.saveMatch(FilterMatch(height: height, blockHash: entry.hash, address: s.address, script: s.script))
            } catch {
                throw PeerError("store match at height \(height): \(error)")
            }
            matched.insert(MatchKey(height: height, address: s.address))
        }
    }

    /// Downloads the filters of the synced blocks start...end again from the
    /// peers in turn, the primary first, and returns the first set whose
    /// chained headers reproduce the stored filter header chain. Below the
    /// first stored header the peer's cfheaders supply the previous header;
    /// a wrong one cannot link to the stored chain either. A peer serving
    /// filters that do not link is disconnected.
    func refetchFilters(_ start: Int32, _ end: Int32) async throws -> [Data] {
        guard let stop = entry(at: end)?.hash else { throw PeerError("no header at height \(end)") }
        var prev = Hash256.zero
        var known = start == 0
        if !known, let stored = try store.filterHeader(at: start - 1) {
            prev = stored
            known = true
        }
        let peers = orderedPeers()
        guard !peers.isEmpty else { throw PeerError("no connected peers") }
        var lastError: Error = PeerError("no peer answered")
        for c in peers {
            var from = prev
            do {
                if !known {
                    from = try await getCFHeaders(c, start: start, stop: stop, timeout: SyncEngine.requestTimeout).prevFilterHeader
                }
                let filters = try await getCFilters(c, start: start, stop: stop)
                do {
                    try checkStoredChain(start, from, filters)
                } catch {
                    drop(c, "rescan filters", error)
                    throw error
                }
                return filters
            } catch {
                lastError = error
                if Task.isCancelled { throw error }
            }
        }
        throw PeerError("no peer served filters linking to the stored headers: \(lastError)")
    }

    /// Verifies that the filters from the height on, chained from prev,
    /// reproduce the stored filter headers.
    func checkStoredChain(_ start: Int32, _ prev: Hash256, _ filters: [Data]) throws {
        var prev = prev
        for (i, data) in filters.enumerated() {
            let height = start + Int32(i)
            guard let stored = try store.filterHeader(at: height) else { throw PeerError("filter header at height \(height) not stored") }
            prev = data.filterHash.filterHeader(previous: prev)
            guard prev == stored else { throw PeerError("filter at height \(height) chains to header \(prev), stored \(stored)") }
        }
    }
}
