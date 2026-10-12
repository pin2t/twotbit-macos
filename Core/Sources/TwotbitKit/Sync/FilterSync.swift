import Foundation

extension SyncEngine {
    /// FilterSource is a peer serving filters with the filter hashes it
    /// committed to in its cfheaders, indexed by height less the batch base.
    struct FilterSource: Sendable {
        let peer: PeerConnection
        let hashes: [Hash256]
    }

    /// Variant is one version of a block's filter with the peers serving it.
    struct Variant {
        let data: Data
        let hash: Hash256
        var peers: [PeerConnection]
    }

    /// Downloads and verifies the BIP158 filters from the wallet's start
    /// height, matching each against the wallet scripts. Filter hashes and
    /// filters come from up to targetPeers peers at once and are compared
    /// block by block, following the BIP157 client guidance: a filter every
    /// peer agrees on is accepted, a disagreement is settled against the
    /// full block. Every stored filter is pruned right after matching; only
    /// its chained header is kept. It returns the number of new filters.
    func syncFilters() async throws -> Int32 {
        refreshFilterStart()
        let first = filterStart
        try store.pruneFilterData(from: first)
        var start = try store.filterResumeHeight(from: first)
        let tip = chainHeight
        var stored: Int32 = 0
        if start <= tip { report(.filters, start) }
        while start <= tip {
            let end = min(start + SyncEngine.filterHeaderBatch - 1, tip)
            var sources: [FilterSource]
            do {
                sources = try await filterHashes(start, end)
            } catch {
                throw PeerError("filter headers \(start)-\(end): \(error)")
            }
            var fStart = start
            while fStart <= end {
                let fEnd = min(fStart + SyncEngine.filterBatch - 1, end)
                do {
                    stored += try await syncFilterBatch(sources, base: start, fStart, fEnd)
                } catch {
                    throw PeerError("filters \(fStart)-\(fEnd): \(error)")
                }
                sources = sources.filter { $0.peer.isLive }
                report(.filters, fEnd)
                fStart += SyncEngine.filterBatch
            }
            start = end + 1
        }
        return stored
    }

    /// Fetches the cfheaders batch start...end from the filter peers and
    /// keeps those whose batch links to the stored filter header chain.
    func filterHashes(_ start: Int32, _ end: Int32) async throws -> [FilterSource] {
        let peers = filterPeers()
        guard !peers.isEmpty else { throw PeerError("no connected peers") }
        guard let stop = entry(at: end)?.hash else { throw PeerError("no header at height \(end)") }
        let (answered, responses) = await fanOut(peers, "cfheaders") { c in
            try await self.getCFHeaders(c, start: start, stop: stop, timeout: SyncEngine.requestTimeout)
        }
        guard !answered.isEmpty else { throw PeerError("every peer failed the cfheaders request") }
        let (filterStart, anchorSet) = chain.withLock { ($0.filterStart, $0.anchorSet) }
        if start == filterStart && filterStart > 0 && !anchorSet {
            let votes = responses.map(\.prevFilterHeader)
            var anchor: Hash256
            do {
                anchor = try SyncEngine.majorityAnchor(votes)
            } catch {
                anchor = votes[0]
                Log.info("sync: filter peers disagree on the filter header anchor (\(error)); trusting \(answered[0].address)")
            }
            setFilterAnchor(anchor)
        }
        var sources = [FilterSource]()
        for (c, response) in zip(answered, responses) {
            do {
                try checkFilterPrev(start, response.prevFilterHeader)
            } catch {
                drop(c, "cfheaders", error)
                continue
            }
            sources.append(FilterSource(peer: c, hashes: response.filterHashes))
        }
        guard !sources.isEmpty else { throw PeerError("no peer served a filter header chain linking to height \(start - 1)") }
        try requirePrimary(sources.map(\.peer))
        return sources
    }

    /// Downloads the filters fStart...fEnd from every source, checks each
    /// against the filter hashes its peer committed to, then accepts the
    /// filters block by block. It returns the number of filters stored.
    func syncFilterBatch(_ sources: [FilterSource], base: Int32, _ fStart: Int32, _ fEnd: Int32) async throws -> Int32 {
        guard let stop = entry(at: fEnd)?.hash else { throw PeerError("no header at height \(fEnd)") }
        var committed = [ObjectIdentifier: [Hash256]]()
        for s in sources { committed[ObjectIdentifier(s.peer)] = s.hashes }
        let live = sources.map(\.peer).filter(\.isLive)
        let (peers, got) = await fanOut(live, "cfilters") { [committed] c in
            let data = try await self.getCFilters(c, start: fStart, stop: stop)
            let hashes = committed[ObjectIdentifier(c)] ?? []
            for (i, d) in data.enumerated() {
                let index = Int(fStart - base) + i
                let raw = GCSFilter.hash(d)
                guard index < hashes.count, raw == hashes[index] else {
                    throw PeerError("filter at height \(fStart + Int32(i)) hashes to \(raw), peer committed to \(index < hashes.count ? hashes[index].hex : "none")")
                }
            }
            return data
        }
        guard !peers.isEmpty else { throw PeerError("every peer failed the cfilters request") }
        try requirePrimary(peers)
        if peers.count == 1 && fStart == base {
            Log.info("sync: filters \(fStart)-\(fEnd) from \(peers[0].address) alone, no second peer to cross-check")
        }
        var mismatches = 0
        let count = fEnd - fStart + 1
        try await storeFilters(fStart, count) { i in
            let variants = SyncEngine.groupVariants(peers, got, Int(i))
            if variants.count > 1 { mismatches += 1 }
            return try await self.chooseFilter(fStart + i, variants)
        }
        if peers.count > 1 {
            Log.info("sync: filters \(fStart)-\(fEnd) cross-checked with \(peers.count) peers, \(mismatches) mismatches")
        }
        return count
    }

    /// Groups the filters the peers served for one block by their hash, in
    /// the order the peers are listed.
    static func groupVariants(_ peers: [PeerConnection], _ got: [[Data]], _ index: Int) -> [Variant] {
        var variants = [Variant]()
        for (i, c) in peers.enumerated() {
            let data = got[i][index]
            let hash = GCSFilter.hash(data)
            if let v = variants.firstIndex(where: { $0.hash == hash }) {
                variants[v].peers.append(c)
            } else {
                variants.append(Variant(data: data, hash: hash, peers: [c]))
            }
        }
        return variants
    }

    /// Picks the filter of the block at the height. When peers disagree,
    /// the full block is downloaded and verified, every variant is checked
    /// to contain all of the block's output scripts, and the peers that
    /// served an invalid or outvoted filter are disconnected. The verified
    /// block is returned too when it had to be downloaded.
    func chooseFilter(_ height: Int32, _ variants: [Variant]) async throws -> (Data, Block?) {
        guard variants.count > 1 else { return (variants[0].data, nil) }
        let hash = entry(at: height)?.hash ?? .zero
        Log.info("sync: filter mismatch at height \(height) (block \(hash)): \(SyncEngine.describe(variants))")
        let block: Block
        do {
            block = try await fetchBlock(height)
        } catch {
            throw PeerError("resolve filter mismatch at height \(height): \(error)")
        }
        let (winner, valid): (Int, [Bool])
        do {
            (winner, valid) = try SyncEngine.resolveVariants(variants, block)
        } catch {
            for v in variants {
                for c in v.peers { drop(c, "filter at height \(height)", error) }
            }
            throw PeerError("height \(height): \(error)")
        }
        let chosen = variants[winner]
        Log.info("sync: filter mismatch at height \(height) resolved against the full block: using \(chosen.hash) from \(chosen.peers.map(\.address).joined(separator: " "))")
        for (i, v) in variants.enumerated() where i != winner {
            let reason = valid[i] ? "filter \(v.hash) outvoted by \(chosen.hash)" : "filter \(v.hash) is missing output scripts of block \(hash)"
            for c in v.peers { drop(c, "filter at height \(height)", reason) }
        }
        return (chosen.data, block)
    }

    /// Checks every filter variant against the verified block. A valid
    /// filter contains every output script of the block; the winner is the
    /// valid variant served by the most peers, the earliest listed on a tie.
    static func resolveVariants(_ variants: [Variant], _ block: Block) throws -> (Int, [Bool]) {
        let blockHash = block.hash
        var winner = -1
        var valid = [Bool](repeating: false, count: variants.count)
        for (i, v) in variants.enumerated() {
            do {
                valid[i] = try filterHasOutputs(v.data, blockHash, block)
            } catch {
                Log.info("sync: filter \(v.hash) from \(v.peers.map(\.address).joined(separator: " ")) cannot be decoded: \(error)")
                continue
            }
            if valid[i] && (winner < 0 || v.peers.count > variants[winner].peers.count) { winner = i }
        }
        guard winner >= 0 else { throw PeerError("no peer served a filter containing all output scripts of block \(blockHash)") }
        return (winner, valid)
    }

    /// Whether the filter contains every output script BIP158 requires: all
    /// of them but empty and OP_RETURN scripts. The scripts the block's
    /// inputs spend cannot be checked without their previous transactions.
    static func filterHasOutputs(_ data: Data, _ blockHash: Hash256, _ block: Block) throws -> Bool {
        var seen = Set<Data>()
        var outputs = [Data]()
        for tx in block.transactions {
            for out in tx.outputs where !out.pkScript.isEmpty && out.pkScript.first != Script.opReturn {
                if seen.insert(out.pkScript).inserted { outputs.append(out.pkScript) }
            }
        }
        return try GCSFilter.matchScripts(data, blockHash: blockHash, scripts: outputs).allSatisfy { $0 }
    }

    /// Accepts count consecutive filters from fStart, as picked one by one,
    /// and stores their rows in one transaction, chained in memory from the
    /// stored predecessor of fStart. Rows accepted before an error are
    /// still stored. It returns the number stored.
    @discardableResult
    func storeFilters(_ fStart: Int32, _ count: Int32, pick: (Int32) async throws -> (Data, Block?)) async throws -> Int32 {
        var prev = try prevFilterHeader(fStart)
        var rows = [StoredFilter]()
        var failure: Error?
        for i in 0..<count {
            do {
                let (data, block) = try await pick(i)
                let row = try await applyFilter(fStart + i, data, block, prev)
                rows.append(row)
                prev = row.filterHeader
            } catch {
                failure = error
                break
            }
        }
        if !rows.isEmpty {
            do {
                try store.saveFilters(rows)
            } catch {
                throw PeerError("store filters \(fStart)-\(fStart + Int32(rows.count) - 1): \(error)")
            }
        }
        if let failure { throw failure }
        return Int32(rows.count)
    }

    /// Verifies the prev_filter_header of a cfheaders batch against the
    /// stored chain of filter headers. Bitcoin Core and btcd send the null
    /// hash for the first batch at height 0; the genesis hash is accepted
    /// there too. The first batch at the wallet's start height has no stored
    /// predecessor: it must match the majority proven anchor when one is
    /// set, and is otherwise trusted as the anchor.
    func checkFilterPrev(_ start: Int32, _ got: Hash256) throws {
        let (filterStart, anchorSet, anchorPrev) = chain.withLock { ($0.filterStart, $0.anchorSet, $0.anchorPrev) }
        if start == filterStart && filterStart > 0 {
            if anchorSet {
                guard got == anchorPrev else { throw PeerError("filter header anchor \(got), want majority-proven \(anchorPrev)") }
                return
            }
            chain.withLock { $0.anchorPrev = got }
            return
        }
        var want = Hash256.zero
        if start > 0 {
            guard let stored = try store.filterHeader(at: start - 1) else { throw PeerError("filter header at height \(start - 1) not stored") }
            want = stored
        }
        if got == want || (start == 0 && got == network.genesisHash) { return }
        throw PeerError("filter header chain break at \(start): prev \(got), want \(want)")
    }

    /// The filter header the filter at the height links to: the anchor at
    /// the wallet's start height, the null hash at genesis and the stored
    /// header of the previous block otherwise.
    func prevFilterHeader(_ height: Int32) throws -> Hash256 {
        if height == 0 { return .zero }
        let (filterStart, anchorPrev) = chain.withLock { ($0.filterStart, $0.anchorPrev) }
        if height == filterStart { return anchorPrev }
        guard let stored = try store.filterHeader(at: height - 1) else { throw PeerError("filter header at height \(height - 1) not stored") }
        return stored
    }

    /// Matches the accepted filter of the block at the height against the
    /// wallet scripts and returns its row, chained to prev. On a match the
    /// block is downloaded, unless it is at hand already, and the wallet
    /// transactions in it are stored. The row carries no filter data:
    /// filters are pruned right after matching.
    func applyFilter(_ height: Int32, _ data: Data, _ block: Block?, _ prev: Hash256) async throws -> StoredFilter {
        guard let entry = entry(at: height) else { throw PeerError("no header at height \(height)") }
        let row = StoredFilter(height: height, blockHash: entry.hash,
                               filterHeader: GCSFilter.header(filterHash: GCSFilter.hash(data), previous: prev), data: nil)
        let watched = watchedScripts()
        let hits: [Bool]
        do {
            hits = try GCSFilter.matchScripts(data, blockHash: entry.hash, scripts: watched.map(\.script))
        } catch {
            throw PeerError("match filter at height \(height): \(error)")
        }
        let matched = zip(watched, hits).filter(\.1).map(\.0)
        for w in matched { Log.info("match: filter of block \(height) (\(entry.hash)) matches address \(w.address)") }
        var block = block
        if !matched.isEmpty && block == nil {
            do {
                block = try await fetchBlock(height)
            } catch {
                throw PeerError("download matched block \(height): \(error)")
            }
        }
        if let block {
            let found = try processBlock(height, block)
            if !matched.isEmpty && found == 0 { Log.info("match: block \(height) holds no wallet transaction (filter false positive)") }
        }
        for w in matched {
            do {
                try store.saveMatch(FilterMatch(height: height, blockHash: entry.hash, address: w.address, script: w.script))
            } catch {
                throw PeerError("store match at height \(height): \(error)")
            }
        }
        return row
    }

    /// Downloads the block at the height from the connected peers in turn,
    /// the primary first, and returns the first copy that verifies against
    /// the header chain. A peer serving a block that fails verification is
    /// disconnected.
    func fetchBlock(_ height: Int32) async throws -> Block {
        guard let hash = entry(at: height)?.hash else { throw PeerError("no header at height \(height)") }
        let peers = orderedPeers()
        guard !peers.isEmpty else { throw PeerError("no connected peers") }
        var lastError: Error = PeerError("no peer answered")
        for c in peers {
            let block: Block
            do {
                block = try await getBlock(c, hash: hash)
            } catch {
                Log.info("peer \(c.address): block \(height): \(error)")
                lastError = error
                if Task.isCancelled { throw error }
                continue
            }
            do {
                try block.verify(expected: hash)
            } catch {
                drop(c, "block \(height)", error)
                lastError = error
                continue
            }
            Log.info("sync: downloaded block \(height) (\(hash), \(block.transactions.count) transactions) from \(c.address)")
            return block
        }
        throw PeerError("no peer served block \(hash): \(lastError)")
    }

    static func describe(_ variants: [Variant]) -> String {
        variants.map { "\($0.hash) from \($0.peers.map(\.address).joined(separator: " "))" }.joined(separator: ", ")
    }
}
