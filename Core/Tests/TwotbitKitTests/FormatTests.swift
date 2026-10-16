import CoreImage
import Foundation
import Testing
@testable import TwotbitKit

/// The tables of bitfyn's GUI and rates tests.
@Suite struct FormatTests {
    @Test func amounts() {
        let cases: [(Int64, String)] = [
            (0, "0 sats"), (999, "999 sats"), (1000, "1 000 sats"), (1_234_567, "1 234 567 sats"), (4_999_999, "4 999 999 sats"),
            (5_000_000, "0.05 BTC"), (100_000_000, "1 BTC"), (123_445_678_900, "1 234.456789 BTC"), (210_000_000_000_000, "2 100 000 BTC"),
            (12_345_678, "0.12345678 BTC"), (-1_500, "-1 500 sats"), (-250_000_000, "-2.5 BTC"),
        ]
        for (sats, want) in cases { #expect(Format.amount(sats) == want) }
    }

    @Test func balanceAndPending() {
        #expect(Format.balance(confirmed: 1_234_567, pending: 0) == "1 234 567 sats")
        #expect(Format.pendingNote(0) == "")
        #expect(Format.balance(confirmed: 0, pending: 25_000_000) == "0.25 BTC")
        #expect(Format.pendingNote(25_000_000) == "(0.25 BTC pending)")
        #expect(Format.balance(confirmed: 10_000_000, pending: -2_000) == "0.09998 BTC")
        #expect(Format.pendingNote(-2_000) == "")
    }

    @Test func parseAmounts() {
        let cases: [(String, AmountUnit, Int64, Bool)] = [
            ("", .sats, 0, true), ("1 234 567", .sats, 1_234_567, true), ("12.5", .sats, 0, false), ("-5", .sats, 0, false),
            ("0.0015", .btc, 150_000, true), (".5", .btc, 50_000_000, true), ("1 234.456789", .btc, 123_445_678_900, true),
            ("2", .btc, 200_000_000, true), ("0.000000001", .btc, 0, false), ("-0.1", .btc, 0, false), ("abc", .btc, 0, false),
            ("21000001", .btc, 0, false), ("+42", .sats, 42, true), ("1.2.3", .btc, 0, false), ("99999999999999999999", .btc, 0, false),
        ]
        for (text, unit, want, ok) in cases {
            let got = try? Format.parseAmount(text, unit: unit)
            #expect((got != nil) == ok, "\(text) \(unit)")
            if ok { #expect(got == want, "\(text)") }
        }
    }

    @Test func invoices() {
        #expect(Format.invoiceURI("bc1qexample", sats: 0) == "bitcoin:bc1qexample")
        #expect(Format.invoiceURI("bc1qexample", sats: 150_000) == "bitcoin:bc1qexample?amount=0.0015")
        #expect(Format.unitText(150_000, unit: .sats) + " " + Format.unitText(150_000, unit: .btc) == "150000 0.0015")
        #expect(Format.btcDecimal(210_000_000_000_000) == "2100000")
    }

    @Test func usd() {
        let values: [(Int64, Int64, Int64)] = [
            (0, 8_376_587, 0), (100_000_000, 8_376_587, 8_376_587), (1_250_000, 8_376_587, 104_707), (1, 8_376_587, 0), (6, 8_376_587, 1),
            (150_000_000, 8_376_587, 12_564_881), (Format.maxSats, 100_000_000_000, 2_100_000_000_000_000_000), (-1_250_000, 8_376_587, -104_707),
        ]
        for (sats, rate, want) in values { #expect(Format.usdValue(sats, centsPerBTC: rate) == want) }
        let texts: [(Int64, String)] = [(0, "0.00 USD"), (5, "0.05 USD"), (1_234_567, "12 345.67 USD"), (100_000_000, "1 000 000.00 USD"), (-1_234_567, "-12 345.67 USD")]
        for (cents, want) in texts { #expect(Format.usd(cents) == want) }
    }

    @Test func netAmounts() {
        #expect(Format.netAmount(1000) == "+ 1 000 sats")
        #expect(Format.netAmount(-50_000_000) == "- 0.5 BTC")
        #expect(Format.netAmount(0) == "0 sats")
    }

    @Test func relativeTimes() {
        let now = Date(timeIntervalSince1970: 1_800_000_000)
        let hour: Int64 = 3600, day: Int64 = 24 * 3600
        let cases: [(Int64, String)] = [
            (0, "just now"), (59, "just now"), (-hour, "just now"), (60, "1 minute ago"), (59 * 60, "59 minutes ago"), (hour, "1 hour ago"),
            (23 * hour, "23 hours ago"), (day, "1 day ago"), (29 * day, "29 days ago"), (30 * day, "1 month ago"), (364 * day, "12 months ago"),
            (365 * day, "1 year ago"), (3 * 365 * day, "3 years ago"),
        ]
        for (age, want) in cases { #expect(Format.relativeTime(1_800_000_000 - age, now: now) == want, "\(age)") }
        #expect(Format.relativeTime(0, now: now) == "—")
    }

    @Test func lifetimes() {
        let now = Date(timeIntervalSince1970: 1_800_000_000)
        let day: Int64 = 24 * 3600
        let cases: [(Int64, String, String)] = [
            (0, "less than a minute", "less than a minute"), (300, "5 minutes", "5 minutes"), (3660, "1 hour 1 minute", "1 hour"),
            (3 * day, "3 days", "3 days"), (3 * day + 7200, "3 days 2 hours", "3 days"), (45 * day, "1 month 15 days", "1 month"),
            (435 * day, "1 year 2 months", "1 year"), (730 * day, "2 years", "2 years"),
        ]
        for (age, two, one) in cases {
            #expect(Format.lifetime(created: 1_800_000_000 - age, now: now, units: 2) == two)
            #expect(Format.lifetime(created: 1_800_000_000 - age, now: now, units: 1) == one)
        }
        #expect(Format.lifetime(created: 0, now: now, units: 2) == "—")
    }

    @Test func fitAddresses() {
        let address = "bc1q0r80j388qfu32q67u6zjx3lhm9wsf07gryt4xl"
        let cases: [(Int, String)] = [(100, address), (address.count, address), (20, "bc1q0r80j388q…ryt4xl"), (12, "bc1q0…ryt4xl"), (11, "…ryt4xl"), (3, "…ryt4xl")]
        for (room, want) in cases { #expect(Format.fitAddress(address) { $0.count <= room } == want, "room \(room)") }
    }

    @Test func groupAddresses() {
        #expect(Format.groupAddress("bc1q0r80j388qfu32q67u6zjx3lhm9wsf07gryt4xl") == "bc1q0r 80j3 88qf u32q 67u6 zjx3 lhm9 wsf0 7gry t4xl")
        #expect(Format.groupAddress("abcdefgh") == "abcd efgh")
        #expect(Format.groupAddress("abcdefghi") == "abcde fghi")
        #expect(Format.groupAddress("abcd") == "abcd")
        #expect(Format.groupAddress("") == "")
    }

    /// A receive, a payment with change, a payment between the wallet's own
    /// addresses, and a spend of wallet coins the wallet did not pay alone.
    @Test func stats() {
        let mine = TxAddress(address: "m", mine: true), other = TxAddress(address: "o", mine: false)
        func tx(_ net: Int64, _ fee: Int64, _ inputs: [TxAddress], _ outputs: [TxAddress]) -> WalletTransaction {
            WalletTransaction(txid: .zero, time: 0, confirmed: true, net: net, fee: fee, inputs: inputs, outputs: outputs)
        }
        let txs = [tx(100_000, 0, [other], [mine, other]), tx(-30_500, 500, [mine], [other, mine]), tx(-300, 300, [mine, mine], [mine]), tx(-2_000, 0, [mine, other], [other])]
        #expect(WalletStats(txs, unspent: 2) == WalletStats(received: 100_000, sent: 32_000, fees: 800, transactions: 4, coins: 3, unspent: 2))
        #expect(WalletStats([], unspent: 0) == WalletStats())
    }

    @Test func peers() {
        let cases: [(String, String?)] = [
            ("192.0.2.1", "192.0.2.1:8333"), ("192.0.2.1:18444", "192.0.2.1:18444"), ("192.0.2.1:08333", "192.0.2.1:8333"),
            ("2001:db8::1", "[2001:db8::1]:8333"), ("[2001:db8::1]", "[2001:db8::1]:8333"), ("[2001:db8::1]:8334", "[2001:db8::1]:8334"),
            ("192.0.2", nil), ("192.0.2.1:", nil), ("192.0.2.1:0", nil), ("192.0.2.1:65536", nil), ("example.com:8333", nil), ("[2001:db8::1", nil),
        ]
        for (text, want) in cases { #expect(text.peerAddress(defaultPort: 8333) == want, "\(text)") }
        #expect(PeerProbe.reason(PeerProbe.NoCompactFilters(address: "x")) == "no compact filters (needs blockfilterindex=1 and peerblockfilters=1)")
        #expect(PeerProbe.reason(PeerError("dial", underlying: NetError(.refused, "connection refused"))) == "connection refused")
        #expect(PeerProbe.reason(PeerError("dial", underlying: NetError(.timeout, "i/o timeout"))) == "no answer")
        #expect(PeerProbe.reason(PeerError("handshake with 192.0.2.1:8333 timed out")) == "no handshake")
    }

    /// A closed port refuses, a node without filters is named, and a
    /// serving node passes the probe.
    @Test func probes() async throws {
        let node = try await MockNode.start()
        defer { node.stop() }
        try await PeerProbe.probe(network: .regtest, address: node.address)
        node.state.withLock { $0.services = [.network] }
        await #expect(throws: PeerProbe.NoCompactFilters.self) { try await PeerProbe.probe(network: .regtest, address: node.address) }
        do {
            try await PeerProbe.probe(network: .regtest, address: "127.0.0.1:1")
            Issue.record("closed port accepted")
        } catch {
            #expect(PeerProbe.reason(error) == "connection refused")
        }
    }

    @Test func rates() throws {
        let embedded = try Rates.embeddedHistory()
        #expect(embedded.count > 20_000)
        #expect(embedded.first == Rate(time: 1_282_089_600, cents: 7))
        for bad in ["", "time,usd\n1,2\n", "ts,cents\n1,x\n", "ts,cents\n1,0\n", "ts,cents\n1\n"] {
            #expect(throws: RateError.self, "\(bad)") { try Rates.parseCSV(bad) }
        }
        let combine: [([Int64], Int64)] = [([100, 101, 103], 101), ([100, 101, 102], 101), ([90, 95, 100], 95), ([89, 95, 100], 100), ([100, 100, 50], 100), ([6_500_012], 6_500_012), ([3, 4], 4)]
        for (input, want) in combine { #expect(Rates.combine(input) == want, "\(input)") }
        #expect(try Rates.toCents(Rates.parseCoinbase(Data(#"{"data":{"amount":"65000.126","base":"BTC","currency":"USD"}}"#.utf8))) == 6_500_013)
        #expect(try Rates.toCents(Rates.parseKraken(Data(#"{"error":[],"result":{"XXBTZUSD":{"a":["1"],"c":["64999.9","0.1"]}}}"#.utf8))) == 6_499_990)
        #expect(try Rates.toCents(Rates.parseBitstamp(Data(#"{"last":"65001","bid":"65000"}"#.utf8))) == 6_500_100)
        #expect(throws: RateError.self) { try Rates.parseKraken(Data(#"{"error":["EQuery:Unknown asset pair"]}"#.utf8)) }
        #expect(throws: RateError.self) { try Rates.toCents("") }
        try withTempStore { store, _ in
            try Rates.seed(store)
            #expect(try store.latestRate() == embedded.last)
        }
    }
}

/// The QR codes of receive invoices decode back to the invoice with
/// CoreImage's detector, upright.
@Suite struct QRCodeTests {
    @Test func decodesBack() throws {
        let texts = [
            "bitcoin:bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu",
            "bitcoin:bcrt1q6rz28mcfaxtmd6v789l9rrlrusdprr9pz3cppk?amount=0.0015",
            "bitcoin:tb1q6rz28mcfaxtmd6v789l9rrlrusdprr9pqcpvkl?amount=21000000",
            "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu",
        ]
        let detector = try #require(CIDetector(ofType: CIDetectorTypeQRCode, context: nil, options: [CIDetectorAccuracy: CIDetectorAccuracyHigh]))
        for text in texts {
            let code = try #require(QRCode(text))
            #expect(code.isUpright, "\(text)")
            let image = try #require(code.image(scale: 8))
            let found = detector.features(in: CIImage(cgImage: image)).compactMap { ($0 as? CIQRCodeFeature)?.messageString }
            #expect(found == [text])
        }
    }

    /// Codes at level Q still read with their middle cleared for the logo.
    @Test func decodesUnderLogo() throws {
        let texts = [
            "bitcoin:bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu",
            "bitcoin:tb1q6rz28mcfaxtmd6v789l9rrlrusdprr9pqcpvkl?amount=21000000",
        ]
        let detector = try #require(CIDetector(ofType: CIDetectorTypeQRCode, context: nil, options: [CIDetectorAccuracy: CIDetectorAccuracyHigh]))
        for text in texts {
            let code = try #require(QRCode(text, correction: "Q"))
            let hole = code.center(0.24)
            #expect(hole.count >= 7 && (code.size - hole.count) % 2 == 0, "\(text)")
            let image = try #require(code.image(scale: 8, hole: hole))
            let found = detector.features(in: CIImage(cgImage: image)).compactMap { ($0 as? CIQRCodeFeature)?.messageString }
            #expect(found == [text])
        }
    }
}
