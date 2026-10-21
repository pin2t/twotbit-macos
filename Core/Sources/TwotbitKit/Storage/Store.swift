import Foundation
import Synchronization

/// WalletMeta is the single wallet metadata row: the network, the account
/// xpub, when the wallet was created and the next receive index. The
/// recovery phrase lives in the Keychain; the mnemonic column holds it only
/// in an older database, until it is moved there.
public struct WalletMeta: Sendable, Equatable {
    public var mnemonic: String
    public var xpub: String
    public var network: String
    public var createdAt: Int64
    public var nextIndex: UInt32
}

/// StoredHeader is one validated block header at its height.
public struct StoredHeader: Sendable, Equatable {
    public var height: Int32
    public var header: BlockHeader
}

/// StoredFilter is the BIP158 filter row of one block: its chained filter
/// header and, until it is pruned after matching, the filter itself.
public struct StoredFilter: Sendable, Equatable {
    public var height: Int32
    public var blockHash: Hash256
    public var filterHeader: Hash256
    public var data: Data?
}

/// FilterMatch records one wallet script that matched a block filter.
public struct FilterMatch: Sendable, Equatable {
    public var height: Int32
    public var blockHash: Hash256
    public var address: String
    public var script: Data
}

/// StoredTransaction is one confirmed wallet transaction in its serialized
/// form.
public struct StoredTransaction: Sendable, Equatable {
    public var txid: Hash256
    public var height: Int32
    public var blockHash: Hash256
    public var raw: Data
}

/// PendingTransaction is one unconfirmed wallet transaction with the unix
/// time it was first seen.
public struct PendingTransaction: Sendable, Equatable {
    public var txid: Hash256
    public var raw: Data
    public var seenAt: Int64
}

/// StoredAddress is one derived address with its derivation path and public
/// key.
public struct StoredAddress: Sendable, Equatable {
    public var index: UInt32
    public var path: String
    public var address: String
    public var pubkey: Data
}

/// RescanJob is a queued rescan of the blocks from a height on for a wallet
/// address that was watched after blocks paying it were scanned.
public struct RescanJob: Sendable, Equatable {
    public var address: String
    public var from: Int32
}

/// PeerRecord is one known peer with its connection statistics.
public struct PeerRecord: Sendable, Equatable {
    public var host: String
    public var port: UInt16
    public var services: UInt64
    public var latencyMs: Int64
    public var okCount: Int64
    public var failCount: Int64
}

/// Rate is the price of one bitcoin in US cents at a unix time.
public struct Rate: Sendable, Equatable {
    public var time: Int64
    public var cents: Int64

    public init(time: Int64, cents: Int64) {
        self.time = time
        self.cents = cents
    }
}

/// Store keeps the wallet in an SQLite database: the wallet metadata and
/// addresses, the validated header chain, filter headers and matches, wallet
/// transactions, known peers, rates and settings. Calls are serialized; it is safe to use from any thread.
public final class Store: Sendable {
    /// The settings keys: the pinned peer's host:port, and "on" while Tor or
    /// I2P is on.
    public static let settingPinnedPeer = "pinnedPeer"
    public static let settingTor = "tor"
    public static let settingI2P = "i2p"
    /// The SOCKS5 proxy of the Tor client, host:port.
    public static let settingTorProxy = "torProxy"

    static let schema = """
    create table if not exists meta (
        id        integer primary key check (id = 1),
        mnemonic  blob    not null,
        xpub      text    not null,
        network   text    not null,
        createdAt integer not null,
        nextIndex integer not null default 0
    );
    create table if not exists addresses (
        type           text    not null check (type in ('receive', 'change')),
        idx            integer not null,
        derivationPath text    not null unique,
        address        text    not null unique,
        pubkey         blob    not null,
        createdAt      integer not null,
        primary key (type, idx)
    );
    create table if not exists headers (
        height     integer primary key,
        hash       blob not null unique,
        prevHash   blob not null,
        merkleRoot blob not null,
        version    integer not null,
        timestamp  integer not null,
        bits       integer not null,
        nonce      integer not null
    );
    create table if not exists cfilters (
        height       integer primary key,
        blockHash    blob not null,
        filterHeader blob not null,
        filterData   blob
    );
    create table if not exists matches (
        height    integer not null,
        blockHash blob    not null,
        address   text    not null,
        script    blob    not null,
        primary key (height, address)
    );
    create table if not exists transactions (
        txid      blob    primary key,
        height    integer not null,
        blockHash blob    not null,
        raw       blob    not null
    );
    create table if not exists pending (
        txid   blob    primary key,
        raw    blob    not null,
        seenAt integer not null
    );
    create table if not exists peers (
        host      text    not null,
        port      integer not null,
        services  integer not null default 0,
        latencyMs integer not null default 0,
        okCount   integer not null default 0,
        failCount integer not null default 0,
        primary key (host, port)
    );
    create table if not exists rates (
        ts    integer primary key,
        cents integer not null
    );
    create table if not exists rescans (
        address    text    primary key,
        fromHeight integer not null
    );
    create table if not exists settings (
        key   text primary key,
        value text not null
    );
    """

    private let db: Mutex<SQLiteDatabase>
    public let path: String

    private init(db: SQLiteDatabase, path: String) {
        self.db = Mutex(db)
        self.path = path
    }

    /// Opens the database at the path, creating it and its directory as
    /// needed.
    public static func open(path: String) throws -> Store {
        let dir = (path as NSString).deletingLastPathComponent
        if !dir.isEmpty {
            try FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        }
        let db = try SQLiteDatabase(path: path)
        do {
            try db.execute("pragma journal_mode = wal; pragma synchronous = normal;")
            try db.execute(schema)
        } catch let error as SQLiteError where error.code == 26 {
            throw SQLiteError(code: 26, message: "cannot read the wallet database (encrypted or not a database): \(error.message)")
        }
        chmod(path, 0o600)
        return Store(db: db, path: path)
    }

    /// Opens an existing database only to read it, changing nothing of the
    /// file, as to read the headers of another wallet's database.
    public static func openImmutable(path: String) throws -> Store {
        Store(db: try SQLiteDatabase(path: path, immutable: true), path: path)
    }

    /// Closes the database; the store is not used afterwards.
    public func close() {
        db.withLock { $0.close() }
    }

    private func with<T>(_ body: (SQLiteDatabase) throws -> T) throws -> T {
        try db.withLock { db throws -> T in try body(db) }
    }

    // MARK: Wallet metadata and addresses

    /// Inserts the wallet metadata row unless a wallet is stored already.
    public func saveMeta(mnemonic: String, xpub: String, network: String, createdAt: Int64) throws {
        try with { db in
            try db.run("insert or ignore into meta (id, mnemonic, xpub, network, createdAt, nextIndex) values (1, ?, ?, ?, ?, 0)",
                       [.blob(Data(mnemonic.utf8)), .text(xpub), .text(network), .int(createdAt)])
        }
    }

    /// The wallet metadata, or nil when no wallet is stored yet.
    public func meta() throws -> WalletMeta? {
        try with { db in
            var meta: WalletMeta?
            try db.run("select mnemonic, xpub, network, createdAt, nextIndex from meta where id = 1") { row in
                meta = WalletMeta(mnemonic: String(decoding: row.blob(0) ?? Data(), as: UTF8.self), xpub: row.text(1), network: row.text(2),
                                  createdAt: row.int(3), nextIndex: UInt32(truncatingIfNeeded: row.int(4)))
            }
            return meta
        }
    }

    /// Replaces the stored mnemonic, empty once it moved to the Keychain.
    public func setMnemonic(_ mnemonic: String) throws {
        try with { db in try db.run("update meta set mnemonic = ? where id = 1", [.blob(Data(mnemonic.utf8))]) }
    }

    public func updateNextIndex(_ index: UInt32) throws {
        try with { db in try db.run("update meta set nextIndex = ? where id = 1", [.int(Int64(index))]) }
    }

    /// Stores a derived receive address. Idempotent per index.
    public func addAddress(_ a: DerivedAddress) throws { try addAddress(kind: "receive", a) }

    /// Stores a derived change address. Idempotent per index.
    public func addChangeAddress(_ a: DerivedAddress) throws { try addAddress(kind: "change", a) }

    private func addAddress(kind: String, _ a: DerivedAddress) throws {
        try with { db in
            try db.run("insert or ignore into addresses (type, idx, derivationPath, address, pubkey, createdAt) values (?, ?, ?, ?, ?, ?)",
                       [.text(kind), .int(Int64(a.index)), .text(a.path), .text(a.address), .blob(a.pubkey), .int(Int64(Date().timeIntervalSince1970))])
        }
    }

    public func addresses() throws -> [StoredAddress] { try addresses(kind: "receive") }
    public func changeAddresses() throws -> [StoredAddress] { try addresses(kind: "change") }

    private func addresses(kind: String) throws -> [StoredAddress] {
        try with { db in
            var out = [StoredAddress]()
            try db.run("select idx, derivationPath, address, pubkey from addresses where type = ? order by idx", [.text(kind)]) { row in
                out.append(StoredAddress(index: UInt32(truncatingIfNeeded: row.int(0)), path: row.text(1), address: row.text(2), pubkey: row.blob(3) ?? Data()))
            }
            return out
        }
    }

    // MARK: Headers

    private static let insertHeader = "insert or replace into headers (height, hash, prevHash, merkleRoot, version, timestamp, bits, nonce) values (?, ?, ?, ?, ?, ?, ?, ?)"

    private static func headerValues(_ h: StoredHeader) -> [SQLValue] {
        [.int(Int64(h.height)), .blob(h.header.hash.data), .blob(h.header.prevBlock.data), .blob(h.header.merkleRoot.data),
         .int(Int64(h.header.version)), .int(Int64(h.header.timestamp)), .int(Int64(h.header.bits)), .int(Int64(h.header.nonce))]
    }

    /// Stores headers in one transaction, replacing rows at the same
    /// heights.
    public func saveHeaders(_ headers: [StoredHeader]) throws {
        guard !headers.isEmpty else { return }
        try with { db in
            try db.transaction {
                for h in headers { try db.run(Store.insertHeader, Store.headerValues(h)) }
            }
        }
    }

    /// Streams every stored header in height order.
    public func forEachHeader(_ body: (StoredHeader) throws -> Void) throws {
        try with { db in
            try db.run("select height, prevHash, merkleRoot, version, timestamp, bits, nonce from headers order by height") { row in
                let header = BlockHeader(version: Int32(truncatingIfNeeded: row.int(3)), prevBlock: row.hash(1), merkleRoot: row.hash(2),
                                         timestamp: UInt32(truncatingIfNeeded: row.int(4)), bits: UInt32(truncatingIfNeeded: row.int(5)),
                                         nonce: UInt32(truncatingIfNeeded: row.int(6)))
                try body(StoredHeader(height: Int32(truncatingIfNeeded: row.int(0)), header: header))
            }
        }
    }

    public func headerCount() throws -> Int {
        try with { db in Int(try db.scalar("select count(*) from headers") ?? 0) }
    }

    /// Removes every header above the height.
    public func deleteHeaders(above height: Int32) throws {
        try with { db in try db.run("delete from headers where height > ?", [.int(Int64(height))]) }
    }

    // MARK: Filters

    private static let insertFilter = "insert or replace into cfilters (height, blockHash, filterHeader, filterData) values (?, ?, ?, ?)"

    /// Stores filter rows in one transaction.
    public func saveFilters(_ filters: [StoredFilter]) throws {
        guard !filters.isEmpty else { return }
        try with { db in
            try db.transaction {
                for f in filters {
                    try db.run(Store.insertFilter, [.int(Int64(f.height)), .blob(f.blockHash.data), .blob(f.filterHeader.data), f.data.map { .blob($0) } ?? .null])
                }
            }
        }
    }

    /// Removes every filter row above the height, as a fork is rewound.
    public func deleteFilters(above height: Int32) throws {
        try with { db in try db.run("delete from cfilters where height > ?", [.int(Int64(height))]) }
    }

    /// Drops filter data kept at or above the height, left behind by a
    /// crash before pruning; the chained headers stay.
    public func pruneFilterData(from height: Int32) throws {
        try with { db in try db.run("update cfilters set filterData = null where height >= ? and filterData is not null", [.int(Int64(height))]) }
    }

    /// The height the next filter download starts at: one past the highest
    /// stored filter row at or after from. Rows are contiguous from the
    /// wallet's start height, so that is the first one missing.
    public func filterResumeHeight(from: Int32) throws -> Int32 {
        try with { db in
            guard let highest = try db.scalar("select max(height) from cfilters where height >= ?", [.int(Int64(from))]), Int32(highest) >= from else {
                return from
            }
            return Int32(highest) + 1
        }
    }

    /// The stored filter header at the height, if any.
    public func filterHeader(at height: Int32) throws -> Hash256? {
        try with { db in
            var out: Hash256?
            try db.run("select filterHeader from cfilters where height = ?", [.int(Int64(height))]) { row in out = row.hash(0) }
            return out
        }
    }

    public func filterCount() throws -> Int {
        try with { db in Int(try db.scalar("select count(*) from cfilters") ?? 0) }
    }

    // MARK: Matches

    public func saveMatch(_ m: FilterMatch) throws {
        try with { db in
            try db.run("insert or ignore into matches (height, blockHash, address, script) values (?, ?, ?, ?)",
                       [.int(Int64(m.height)), .blob(m.blockHash.data), .text(m.address), .blob(m.script)])
        }
    }

    public func matches() throws -> [FilterMatch] {
        try with { db in
            var out = [FilterMatch]()
            try db.run("select height, blockHash, address, script from matches order by height, address") { row in
                out.append(FilterMatch(height: Int32(truncatingIfNeeded: row.int(0)), blockHash: row.hash(1), address: row.text(2), script: row.blob(3) ?? Data()))
            }
            return out
        }
    }

    public func deleteMatches(above height: Int32) throws {
        try with { db in try db.run("delete from matches where height > ?", [.int(Int64(height))]) }
    }

    // MARK: Transactions

    /// Stores a confirmed wallet transaction, replacing an earlier copy.
    public func saveTransaction(_ t: StoredTransaction) throws {
        try with { db in
            try db.run("insert or replace into transactions (txid, height, blockHash, raw) values (?, ?, ?, ?)",
                       [.blob(t.txid.data), .int(Int64(t.height)), .blob(t.blockHash.data), .blob(t.raw)])
        }
    }

    /// Every confirmed wallet transaction in block order.
    public func transactions() throws -> [StoredTransaction] {
        try with { db in
            var out = [StoredTransaction]()
            try db.run("select txid, height, blockHash, raw from transactions order by height, rowid") { row in
                out.append(StoredTransaction(txid: row.hash(0), height: Int32(truncatingIfNeeded: row.int(1)), blockHash: row.hash(2), raw: row.blob(3) ?? Data()))
            }
            return out
        }
    }

    public func deleteTransactions(above height: Int32) throws {
        try with { db in try db.run("delete from transactions where height > ?", [.int(Int64(height))]) }
    }

    /// Stores an unconfirmed transaction; one seen before keeps its first
    /// seen time.
    public func savePending(_ p: PendingTransaction) throws {
        try with { db in
            try db.run("insert or ignore into pending (txid, raw, seenAt) values (?, ?, ?)", [.blob(p.txid.data), .blob(p.raw), .int(p.seenAt)])
        }
    }

    /// Every unconfirmed wallet transaction, oldest first.
    public func pendingTransactions() throws -> [PendingTransaction] {
        try with { db in
            var out = [PendingTransaction]()
            try db.run("select txid, raw, seenAt from pending order by seenAt, rowid") { row in
                out.append(PendingTransaction(txid: row.hash(0), raw: row.blob(1) ?? Data(), seenAt: row.int(2)))
            }
            return out
        }
    }

    public func deletePending(_ txid: Hash256) throws {
        try with { db in try db.run("delete from pending where txid = ?", [.blob(txid.data)]) }
    }

    /// Removes the unconfirmed transactions first seen before the unix time
    /// and returns how many were removed.
    public func deletePending(before unix: Int64) throws -> Int {
        try with { db in
            try db.run("delete from pending where seenAt < ?", [.int(unix)])
            return db.changes
        }
    }

    // MARK: Rescans

    /// Queues a rescan of the address; one queued already keeps the lower
    /// height.
    public func addRescan(_ r: RescanJob) throws {
        try with { db in
            try db.run("""
                insert into rescans (address, fromHeight) values (?, ?)
                on conflict (address) do update set fromHeight = min(fromHeight, excluded.fromHeight)
                """, [.text(r.address), .int(Int64(r.from))])
        }
    }

    public func rescans() throws -> [RescanJob] {
        try with { db in
            var out = [RescanJob]()
            try db.run("select address, fromHeight from rescans order by fromHeight, address") { row in
                out.append(RescanJob(address: row.text(0), from: Int32(truncatingIfNeeded: row.int(1))))
            }
            return out
        }
    }

    /// Removes a finished rescan, unless it was queued again from a lower
    /// height meanwhile.
    public func deleteRescan(_ r: RescanJob) throws {
        try with { db in try db.run("delete from rescans where address = ? and fromHeight >= ?", [.text(r.address), .int(Int64(r.from))]) }
    }

    // MARK: Peers

    /// Records a known peer address. Idempotent.
    public func savePeer(host: String, port: UInt16) throws {
        try with { db in try db.run("insert or ignore into peers (host, port) values (?, ?)", [.text(host), .int(Int64(port))]) }
    }

    /// Stores the services and handshake latency of a connected peer.
    public func upsertPeer(host: String, port: UInt16, services: UInt64, latencyMs: Int64) throws {
        try with { db in
            try db.run("""
                insert into peers (host, port, services, latencyMs, okCount, failCount) values (?, ?, ?, ?, 0, 0)
                on conflict(host, port) do update set services = excluded.services, latencyMs = excluded.latencyMs
                """, [.text(host), .int(Int64(port)), .int(Int64(bitPattern: services)), .int(latencyMs)])
        }
    }

    /// Stores the advertised services of a gossiped peer.
    public func updatePeerServices(host: String, port: UInt16, services: UInt64) throws {
        try with { db in
            try db.run("""
                insert into peers (host, port, services) values (?, ?, ?)
                on conflict(host, port) do update set services = excluded.services
                """, [.text(host), .int(Int64(port)), .int(Int64(bitPattern: services))])
        }
    }

    /// Counts one successful or failed request against a peer and stores
    /// its latency.
    public func recordPeerResult(host: String, port: UInt16, ok: Bool, latencyMs: Int64) throws {
        try with { db in
            try db.run("""
                insert into peers (host, port, latencyMs, okCount, failCount) values (?, ?, ?, ?, ?)
                on conflict(host, port) do update set latencyMs = excluded.latencyMs,
                okCount = okCount + excluded.okCount, failCount = failCount + excluded.failCount
                """, [.text(host), .int(Int64(port)), .int(latencyMs), .int(ok ? 1 : 0), .int(ok ? 0 : 1)])
        }
    }

    public func peers() throws -> [PeerRecord] {
        try with { db in
            var out = [PeerRecord]()
            try db.run("select host, port, services, latencyMs, okCount, failCount from peers") { row in
                out.append(PeerRecord(host: row.text(0), port: UInt16(truncatingIfNeeded: row.int(1)), services: UInt64(bitPattern: row.int(2)),
                                      latencyMs: row.int(3), okCount: row.int(4), failCount: row.int(5)))
            }
            return out
        }
    }

    // MARK: Settings

    /// The value stored for the key, or "" when it is not set.
    public func setting(_ key: String) throws -> String {
        try with { db in
            var value = ""
            try db.run("select value from settings where key = ?", [.text(key)]) { row in value = row.text(0) }
            return value
        }
    }

    /// Stores the value for the key; an empty value removes the setting.
    public func setSetting(_ key: String, _ value: String) throws {
        try with { db in
            if value.isEmpty {
                try db.run("delete from settings where key = ?", [.text(key)])
            } else {
                try db.run("insert or replace into settings (key, value) values (?, ?)", [.text(key), .text(value)])
            }
        }
    }

    // MARK: Rates

    /// Fills the rates table with the rates, only while it is empty, so
    /// rates recorded since are never overwritten. It reports whether they
    /// were inserted.
    public func seedRates(_ rates: [Rate]) throws -> Bool {
        try with { db in
            try db.transaction {
                guard try db.scalar("select exists(select 1 from rates)") == 0 else { return false }
                for r in rates { try db.run("insert or replace into rates (ts, cents) values (?, ?)", [.int(r.time), .int(r.cents)]) }
                return true
            }
        }
    }

    public func addRate(_ r: Rate) throws {
        try with { db in try db.run("insert or replace into rates (ts, cents) values (?, ?)", [.int(r.time), .int(r.cents)]) }
    }

    /// The most recent rate, or nil while none is stored.
    public func latestRate() throws -> Rate? {
        try with { db in
            var rate: Rate?
            try db.run("select ts, cents from rates order by ts desc limit 1") { row in rate = Rate(time: row.int(0), cents: row.int(1)) }
            return rate
        }
    }
}
