import Foundation

extension SyncEngine {
    /// How long a request may wait for its response.
    static let requestTimeout: Duration = .seconds(90)

    /// Requests the headers following the block locator.
    func getHeaders(_ c: PeerConnection, locator: [Hash256]) async throws -> [BlockHeader] {
        c.headers.drain()
        let started = ContinuousClock.now
        c.send(.getHeaders(locator: locator, stop: .zero))
        do {
            let headers = try await c.headers.receive(timeout: SyncEngine.requestTimeout, what: "headers")
            record(c, ok: true, since: started)
            return headers
        } catch {
            record(c, ok: false, since: started)
            throw error
        }
    }

    /// Sends one getcfheaders request and checks the response's filter
    /// type, stop hash and number of filter hashes.
    func getCFHeaders(_ c: PeerConnection, start: Int32, stop: Hash256, timeout: Duration) async throws -> CFHeaders {
        c.cfHeaders.drain()
        let started = ContinuousClock.now
        c.send(.getCFHeaders(startHeight: UInt32(start), stop: stop))
        let response: CFHeaders
        do {
            response = try await c.cfHeaders.receive(timeout: timeout, what: "cfheaders")
            record(c, ok: true, since: started)
        } catch {
            record(c, ok: false, since: started)
            throw error
        }
        guard response.filterType == Message.basicFilter else { throw PeerError("unexpected filter type \(response.filterType)") }
        guard response.stopHash == stop else { throw PeerError("stop hash \(response.stopHash), want \(stop)") }
        let want = Int(heightOf(stop) - start + 1)
        guard response.filterHashes.count == want else {
            throw PeerError("got \(response.filterHashes.count) filter headers for \(want) blocks")
        }
        return response
    }

    /// Downloads the filters of the blocks start...stop in height order.
    /// Every filter must belong to a block of the range and arrive once.
    func getCFilters(_ c: PeerConnection, start: Int32, stop: Hash256) async throws -> [Data] {
        c.cfilters.drain()
        let end = heightOf(stop)
        guard end >= start else { throw PeerError("stop block \(stop) not in the chain") }
        let started = ContinuousClock.now
        c.send(.getCFilters(startHeight: UInt32(start), stop: stop))
        var out = [Data?](repeating: nil, count: Int(end - start + 1))
        do {
            for _ in out.indices {
                let response = try await c.cfilters.receive(timeout: SyncEngine.requestTimeout, what: "cfilter")
                guard response.filterType == Message.basicFilter else { throw PeerError("unexpected filter type \(response.filterType)") }
                let height = heightOf(response.blockHash)
                guard height >= start, height <= end, out[Int(height - start)] == nil else {
                    throw PeerError("unexpected cfilter for block \(response.blockHash)")
                }
                out[Int(height - start)] = response.data
            }
        } catch {
            record(c, ok: false, since: started)
            throw error
        }
        record(c, ok: true, since: started)
        return out.map { $0 ?? Data() }
    }

    /// Downloads the full block, with its witness data when the peer serves
    /// it. The block is not verified here.
    func getBlock(_ c: PeerConnection, hash: Hash256) async throws -> Block {
        c.blockReplies.drain()
        let kind: InvType = c.services.contains(.witness) ? .witnessBlock : .block
        let started = ContinuousClock.now
        c.send(.getData([InvVect(kind, hash)]))
        let deadline = started + SyncEngine.requestTimeout
        while true {
            let left = deadline - .now
            do {
                guard left > .zero else { throw TimeoutError() }
                switch try await c.blockReplies.receive(timeout: left, what: "block") {
                case .block(let block) where block.hash == hash:
                    record(c, ok: true, since: started)
                    return block
                case .notFound(let list) where list.contains(where: { $0.hash == hash }):
                    record(c, ok: false, since: started)
                    throw PeerError("block \(hash) not found")
                default:
                    continue
                }
            } catch is TimeoutError {
                record(c, ok: false, since: started)
                throw TimeoutError("no block response within \(SyncEngine.requestTimeout.formatted)")
            }
        }
    }
}
