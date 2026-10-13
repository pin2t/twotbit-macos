import Foundation

/// AmountUnit is a unit amounts are entered in.
public enum AmountUnit: String, CaseIterable, Sendable, Identifiable {
    case sats
    case btc = "BTC"

    public var id: String { rawValue }
}

public struct AmountError: Error, Equatable, Sendable, CustomStringConvertible {
    public let description: String
    init(_ description: String) { self.description = description }
}

/// Format renders and reads the amounts, times and texts the wallet shows,
/// as bitfyn's GUI does.
public enum Format {
    public static let satsPerBTC: Int64 = 100_000_000
    /// The amount from which balances are shown in BTC instead of sats:
    /// 0.05 BTC.
    public static let btcThreshold: Int64 = 5_000_000
    /// The 21 million BTC supply cap in satoshis.
    public static let maxSats: Int64 = 21_000_000 * satsPerBTC

    /// An amount for display: in sats below 0.05 BTC and in BTC otherwise,
    /// the whole part grouped by threes, as in "1 234 567 sats" or
    /// "1 234.456789 BTC". Trailing zeros of the BTC fraction are dropped.
    public static func amount(_ sats: Int64) -> String {
        let sign = sats < 0 ? "-" : ""
        let abs = sats.magnitude
        if abs < UInt64(btcThreshold) { return sign + group(String(abs)) + " sats" }
        let whole = group(String(abs / UInt64(satsPerBTC)))
        let frac = trimZeros(String(format: "%08llu", abs % UInt64(satsPerBTC)))
        return frac.isEmpty ? "\(sign)\(whole) BTC" : "\(sign)\(whole).\(frac) BTC"
    }

    /// Groups a string of digits by threes from the right with spaces.
    public static func group(_ digits: String) -> String {
        var out = ""
        for (i, d) in digits.enumerated() {
            if i > 0 && (digits.count - i) % 3 == 0 { out.append(" ") }
            out.append(d)
        }
        return out
    }

    private static func trimZeros(_ s: String) -> String {
        String(s.reversed().drop { $0 == "0" }.reversed())
    }

    /// The main balance line: the spendable balance, which counts
    /// unconfirmed transactions too.
    public static func balance(confirmed: Int64, pending: Int64) -> String { amount(confirmed + pending) }

    /// The note next to the balance naming its incoming unconfirmed part;
    /// empty when nothing is incoming: pending spends get no note.
    public static func pendingNote(_ pending: Int64) -> String {
        pending <= 0 ? "" : "(\(amount(pending)) pending)"
    }

    /// The worth of an amount in US cents at a rate in cents per bitcoin,
    /// rounded half up to the cent, the whole bitcoins and the rest valued
    /// apart so the product cannot overflow.
    public static func usdValue(_ sats: Int64, centsPerBTC: Int64) -> Int64 {
        let sign: Int64 = sats < 0 ? -1 : 1
        let abs = sats.magnitude
        let whole = Int64(abs / UInt64(satsPerBTC)) * centsPerBTC
        let frac = (Int64(abs % UInt64(satsPerBTC)) * centsPerBTC + satsPerBTC / 2) / satsPerBTC
        return sign * (whole + frac)
    }

    /// US cents as dollars, grouped by threes with two decimals, as in
    /// "12 345.67 USD".
    public static func usd(_ cents: Int64) -> String {
        let sign = cents < 0 ? "-" : ""
        let abs = cents.magnitude
        return "\(sign)\(group(String(abs / 100))).\(String(format: "%02llu", abs % 100)) USD"
    }

    /// Reads an entered amount in the unit: whole sats, or BTC with at most
    /// eight decimals. Spaces grouping digits are ignored and an empty entry
    /// is zero.
    public static func parseAmount(_ text: String, unit: AmountUnit) throws -> Int64 {
        let clean = text.trimmingCharacters(in: .whitespaces).replacingOccurrences(of: " ", with: "")
        if clean.isEmpty { return 0 }
        var sats: Int64
        switch unit {
        case .sats:
            guard clean.allSatisfy(\.isASCIIDigit) || (clean.first == "+" && clean.dropFirst().allSatisfy(\.isASCIIDigit) && clean.count > 1),
                  let n = Int64(clean), n >= 0 else { throw AmountError("enter a whole number of sats") }
            sats = n
        case .btc:
            let parts = clean.split(separator: ".", maxSplits: 1, omittingEmptySubsequences: false)
            let whole = String(parts[0])
            let frac = parts.count > 1 ? String(parts[1]) : ""
            if frac.count > 8 { throw AmountError("BTC amounts have at most 8 decimals") }
            guard !clean.contains(where: { $0 == "+" || $0 == "-" }), whole.allSatisfy(\.isASCIIDigit), frac.allSatisfy(\.isASCIIDigit),
                  !(whole.isEmpty && frac.isEmpty), let w = Int64(whole.isEmpty ? "0" : whole), w <= Int64.max / satsPerBTC,
                  let f = Int64(frac + String(repeating: "0", count: 8 - frac.count)) else {
                throw AmountError("enter an amount like 0.0015")
            }
            sats = w * satsPerBTC + f
        }
        if sats > maxSats { throw AmountError("amount exceeds 21 million BTC") }
        return sats
    }

    /// Sats in the unit without grouping, for an entry field.
    public static func unitText(_ sats: Int64, unit: AmountUnit) -> String {
        unit == .sats ? String(sats) : btcDecimal(sats)
    }

    /// Sats as a plain BTC decimal with trailing zeros dropped, as BIP21
    /// amounts are written.
    public static func btcDecimal(_ sats: Int64) -> String {
        let frac = trimZeros(String(format: "%08lld", sats % satsPerBTC))
        let whole = String(sats / satsPerBTC)
        return frac.isEmpty ? whole : "\(whole).\(frac)"
    }

    /// The BIP21 payment request for the address, with the amount when one
    /// is given.
    public static func invoiceURI(_ address: String, sats: Int64) -> String {
        sats > 0 ? "bitcoin:\(address)?amount=\(btcDecimal(sats))" : "bitcoin:\(address)"
    }

    /// What a transaction did to the balance, signed: "+ 1 000 sats" or
    /// "- 0.5 BTC".
    public static func netAmount(_ net: Int64) -> String {
        if net > 0 { return "+ " + amount(net) }
        if net < 0 { return "- " + amount(-net) }
        return amount(0)
    }

    /// The units ages are told in, the largest first.
    static let timeUnits: [(seconds: Int64, name: String)] = [
        (365 * 24 * 3600, "year"), (30 * 24 * 3600, "month"), (24 * 3600, "day"), (3600, "hour"), (60, "minute"),
    ]

    /// n of the unit: "1 day", "3 days".
    static func count(_ n: Int64, _ unit: String) -> String { n == 1 ? "1 \(unit)" : "\(n) \(unit)s" }

    /// How long ago the unix time was, in its largest whole unit: "just
    /// now", "5 minutes ago", "1 day ago", up to years. An unknown time
    /// reads "—" and a future one, as block times may be slightly ahead,
    /// "just now".
    public static func relativeTime(_ unix: Int64, now: Date) -> String {
        if unix == 0 { return "—" }
        let age = Int64(now.timeIntervalSince1970.rounded(.down)) - unix
        for u in timeUnits where age / u.seconds >= 1 {
            return count(age / u.seconds, u.name) + " ago"
        }
        return "just now"
    }

    /// How long the wallet has existed since its creation, in at most that
    /// many of its largest units: "1 year 2 months", "3 days", "less than a
    /// minute".
    public static func lifetime(created: Int64, now: Date, units: Int) -> String {
        if created == 0 { return "—" }
        let age = Int64(now.timeIntervalSince1970.rounded(.down)) - created
        for (i, u) in timeUnits.enumerated() {
            let n = age / u.seconds
            guard n >= 1 else { continue }
            var text = count(n, u.name)
            if units > 1 && i + 1 < timeUnits.count {
                let next = timeUnits[i + 1]
                let rest = age % u.seconds / next.seconds
                if rest >= 1 { text += " " + count(rest, next.name) }
            }
            return text
        }
        return "less than a minute"
    }

    /// The address in groups of four characters counted from its end, for
    /// reading it out: the characters left over join the first group, so
    /// it alone may be longer, as in "bc1q0r 80j3 88qf … t4xl".
    public static func groupAddress(_ address: String) -> String {
        let chars = Array(address)
        guard chars.count > 4 else { return address }
        let rest = chars.count % 4
        var groups = [String(chars[..<(rest == 0 ? 4 : rest + 4)])]
        var i = groups[0].count
        while i < chars.count {
            groups.append(String(chars[i..<i + 4]))
            i += 4
        }
        return groups.joined(separator: " ")
    }

    /// The address shortened to its start and its last six characters
    /// around an ellipsis when longer than the room: the start as long as
    /// fits, at least five characters, "bc1q" and one more, or else
    /// dropped: "…ryt4xl". fits tells whether a text fits.
    public static func fitAddress(_ address: String, fits: (String) -> Bool) -> String {
        let tail = 6
        if address.count <= tail + 1 || fits(address) { return address }
        let end = String(address.suffix(tail))
        var lo = 5, hi = address.count - tail - 1
        var best = -1
        while lo <= hi {
            let mid = (lo + hi) / 2
            if fits(String(address.prefix(mid)) + "…" + end) {
                best = mid
                lo = mid + 1
            } else {
                hi = mid - 1
            }
        }
        return best < 0 ? "…" + end : String(address.prefix(best)) + "…" + end
    }
}

/// WalletStats sums up the wallet's lifetime, unconfirmed transactions
/// included as in the balance: the value received from others and sent to
/// others and the fees paid, in satoshis, the transactions, the coins ever
/// received and those still unspent.
public struct WalletStats: Sendable, Equatable {
    public var received: Int64 = 0
    public var sent: Int64 = 0
    public var fees: Int64 = 0
    public var transactions = 0
    public var coins = 0
    public var unspent = 0

    public init(received: Int64 = 0, sent: Int64 = 0, fees: Int64 = 0, transactions: Int = 0, coins: Int = 0, unspent: Int = 0) {
        self.received = received
        self.sent = sent
        self.fees = fees
        self.transactions = transactions
        self.coins = coins
        self.unspent = unspent
    }

    /// Sums the transactions. One the wallet paid for, every input its own,
    /// counts its fee and the outputs to others as sent: a payment between
    /// the wallet's own addresses sends nothing. Any other counts what it
    /// added to the balance as received, or what it took as sent.
    public init(_ txs: [WalletTransaction], unspent: Int) {
        self.init(transactions: txs.count, unspent: unspent)
        for t in txs {
            coins += t.outputs.filter(\.mine).count
            if t.fee > 0 {
                fees += t.fee
                sent += -t.net - t.fee
            } else if t.net > 0 {
                received += t.net
            } else {
                sent -= t.net
            }
        }
    }
}
