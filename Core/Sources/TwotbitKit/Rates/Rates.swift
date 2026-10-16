import Foundation
import Synchronization

/// Rates keeps the BTC/USD rate table up to date. The table is seeded
/// from the history shipped with the app, and while the app runs a
/// background loop records a fresh rate from public exchange APIs whenever
/// the latest stored one gets old.
public final class Rates: Sendable {
    /// How often the loop looks at the age of the latest rate, and the age
    /// from which it is refreshed.
    static let checkInterval: Duration = .seconds(600)
    static let maxAge: Int64 = 30 * 60
    /// The relative distance between the lowest and highest source rate
    /// above which they are not averaged: the highest is stored instead.
    static let maxSpread = 0.10
    /// Bounds one request to a rate source.
    static let fetchTimeout: TimeInterval = 20

    /// RateSource is a public API quoting the BTC/USD price.
    struct Source: Sendable {
        let name: String
        let url: URL
        let parse: @Sendable (Data) throws -> String
    }

    static let sources: [Source] = [
        Source(name: "coinbase", url: URL(string: "https://api.coinbase.com/v2/prices/BTC-USD/spot")!, parse: parseCoinbase),
        Source(name: "kraken", url: URL(string: "https://api.kraken.com/0/public/Ticker?pair=XBTUSD")!, parse: parseKraken),
        Source(name: "bitstamp", url: URL(string: "https://www.bitstamp.net/api/v2/ticker/btcusd/")!, parse: parseBitstamp),
    ]

    private let store: Store
    private let task = Mutex<Task<Void, Never>?>(nil)

    public init(store: Store) { self.store = store }

    /// The rate history shipped with the app: daily BTC/USD rates since
    /// 2010 and finer ones of late.
    public static func embeddedHistory() throws -> [Rate] {
        guard let url = Bundle.module.url(forResource: "rates", withExtension: "csv") else { throw RateError("rates.csv is missing") }
        return try parseCSV(String(decoding: try Data(contentsOf: url), as: UTF8.self))
    }

    /// Fills an empty rates table with the shipped rate history.
    public static func seed(_ store: Store) throws {
        let history = try embeddedHistory()
        if try store.seedRates(history) { Log.info("rates: seeded \(history.count) historical rates") }
    }

    /// Reads "ts,cents" rows after their header line.
    static func parseCSV(_ text: String) throws -> [Rate] {
        var lines = text.split(whereSeparator: \.isNewline).makeIterator()
        guard lines.next() == "ts,cents" else { throw RateError("missing \"ts,cents\" header") }
        var rates = [Rate]()
        var n = 1
        while let line = lines.next() {
            n += 1
            let parts = line.split(separator: ",")
            guard parts.count == 2, let ts = Int64(parts[0]), let cents = Int64(parts[1]), cents > 0 else {
                throw RateError("line \(n): bad rate \"\(line)\"")
            }
            rates.append(Rate(time: ts, cents: cents))
        }
        return rates
    }

    /// Starts the refresh loop: it checks the latest rate at once and then
    /// every ten minutes, fetching a new one when it is thirty minutes old or
    /// more. onRate is called with every rate stored.
    public func start(onRate: @escaping @Sendable (Rate) -> Void) {
        let store = self.store
        let task = Task.detached {
            while !Task.isCancelled {
                if let rate = await Rates.refresh(store, now: Int64(Date().timeIntervalSince1970)) { onRate(rate) }
                guard await pause(Rates.checkInterval) else { return }
            }
        }
        self.task.withLock { $0 = task }
    }

    /// Ends the refresh loop, aborting a fetch in flight, and waits for it.
    public func stop() async {
        let task = self.task.withLock { t -> Task<Void, Never>? in
            defer { t = nil }
            return t
        }
        task?.cancel()
        await task?.value
    }

    /// Fetches and stores a new rate when the latest stored one is older
    /// than maxAge, returning it.
    static func refresh(_ store: Store, now: Int64) async -> Rate? {
        do {
            if let latest = try store.latestRate(), now - latest.time < maxAge { return nil }
        } catch {
            Log.info("rates: read latest rate: \(error)")
            return nil
        }
        let cents: Int64
        do {
            cents = try await fetchRate()
        } catch {
            if !Task.isCancelled { Log.info("rates: \(error)") }
            return nil
        }
        let rate = Rate(time: now, cents: cents)
        do {
            try store.addRate(rate)
        } catch {
            Log.info("rates: store rate: \(error)")
            return nil
        }
        Log.info("rates: stored \(cents / 100).\(String(format: "%02d", cents % 100)) USD")
        return rate
    }

    /// Asks every source at once and combines the rates of those that
    /// answered; it fails only when none did.
    static func fetchRate() async throws -> Int64 {
        let results = await withTaskGroup(of: (String, Result<Int64, Error>).self) { group in
            for source in sources {
                group.addTask { (source.name, await Result { try await fetch(source) }) }
            }
            var out = [(String, Result<Int64, Error>)]()
            for await r in group { out.append(r) }
            return out
        }
        let rates = results.compactMap { try? $0.1.get() }
        let errors = results.compactMap { name, result -> String? in
            if case .failure(let error) = result { return "\(name): \(error)" }
            return nil
        }
        guard !rates.isEmpty else { throw RateError("no rate source answered: \(errors.joined(separator: "; "))") }
        if !errors.isEmpty { Log.info("rates: using \(rates.count) of \(sources.count) sources: \(errors.joined(separator: "; "))") }
        return combine(rates)
    }

    /// The price one source quotes, in US cents.
    static func fetch(_ source: Source) async throws -> Int64 {
        var request = URLRequest(url: source.url, timeoutInterval: fetchTimeout)
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        let (body, response) = try await URLSession.shared.data(for: request)
        guard let http = response as? HTTPURLResponse, http.statusCode == 200 else {
            throw RateError("HTTP \((response as? HTTPURLResponse)?.statusCode ?? 0)")
        }
        return try toCents(try source.parse(body.prefix(1 << 20)))
    }

    /// The decimal USD price in whole cents, rounded.
    static func toCents(_ price: String) throws -> Int64 {
        guard let usd = Double(price.trimmingCharacters(in: .whitespaces)), usd > 0, usd.isFinite else {
            throw RateError("bad price \"\(price)\"")
        }
        return Int64((usd * 100).rounded())
    }

    /// The rate to store from the source rates: their average, or the
    /// highest when the lowest is more than maxSpread below it.
    static func combine(_ cents: [Int64]) -> Int64 {
        let lo = cents.min()!, hi = cents.max()!
        if Double(hi - lo) > maxSpread * Double(hi) { return hi }
        let n = Int64(cents.count)
        return (cents.reduce(0, +) + n / 2) / n
    }

    /// {"data":{"amount":"65000.12",...}}
    static func parseCoinbase(_ body: Data) throws -> String {
        struct Response: Decodable { struct Inner: Decodable { let amount: String }; let data: Inner }
        return try JSONDecoder().decode(Response.self, from: body).data.amount
    }

    /// The last trade price of {"error":[],"result":{"XXBTZUSD":{"c":["65000.1","0.01"],...}}}.
    static func parseKraken(_ body: Data) throws -> String {
        struct Ticker: Decodable { let c: [String] }
        struct Response: Decodable { let error: [String]; let result: [String: Ticker]? }
        let r = try JSONDecoder().decode(Response.self, from: body)
        if !r.error.isEmpty { throw RateError(r.error.joined(separator: "; ")) }
        guard let last = r.result?.values.first?.c.first else { throw RateError("no ticker in response") }
        return last
    }

    /// {"last":"65000",...}
    static func parseBitstamp(_ body: Data) throws -> String {
        struct Response: Decodable { let last: String }
        return try JSONDecoder().decode(Response.self, from: body).last
    }
}

public struct RateError: Error, CustomStringConvertible, Sendable {
    public let description: String
    init(_ description: String) { self.description = description }
}

extension Result where Failure == Error {
    init(catching body: () async throws -> Success) async {
        do { self = .success(try await body()) } catch { self = .failure(error) }
    }
}
