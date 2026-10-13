import SwiftUI
import TwotbitKit

/// HomeView is the wallet at a glance: the QR code of the current receive
/// address with the address under it, grouped by fours, and a copy button
/// after it, the balance with the incoming pending part next to it and its
/// worth in US dollars under it, the Receive and Send buttons, and the wallet
/// statistics at the bottom. In a wide window the transactions list
/// alongside it at the right.
struct HomeView: View {
    @Environment(AppModel.self) private var model
    /// Whether the window is wide enough to list the transactions too.
    var wide = false

    var body: some View {
        if wide {
            HStack(spacing: 0) {
                main.frame(width: 640)
                Divider()
                TransactionsView()
            }
        } else {
            main
        }
    }

    /// The side of the QR code, and the room it takes in the layout: the
    /// code grows up past that room, into the space above it, so it does
    /// not push what is under it down.
    static let qrSide: CGFloat = 300
    static let qrRoom: CGFloat = 240

    private var main: some View {
        VStack(spacing: 0) {
            Spacer(minLength: 16 + HomeView.qrSide - HomeView.qrRoom)
            QRCodeView(text: model.address, side: HomeView.qrSide)
                .frame(height: HomeView.qrRoom, alignment: .bottom)
            HStack(spacing: 6) {
                Text(Format.groupAddress(model.address))
                    .font(.system(.title3, design: .monospaced))
                    .textSelection(.enabled)
                CopyButton(help: "Copy the address") { model.copy(model.address, "Address") }
            }
            .padding(.top, 14)
            BalanceView()
                .padding(.top, 22)
            HStack(spacing: 14) {
                Button {
                    model.showReceive = true
                } label: {
                    Label("Receive", systemImage: "arrow.down.to.line").frame(width: 130)
                }
                Button {
                    model.openSend()
                } label: {
                    Label("Send", systemImage: "arrow.up.to.line").frame(width: 130)
                }
                .disabled(model.coins.isEmpty)
            }
            .controlSize(.large)
            .padding(.top, 22)
            Spacer(minLength: 24)
            StatsView()
                .padding(.horizontal, 28)
                .padding(.bottom, 24)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}

/// BalanceView shows the spendable balance, the incoming unconfirmed part
/// of it, and its worth in US dollars once a rate is known.
struct BalanceView: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        let note = Format.pendingNote(model.status.pending)
        VStack(spacing: 2) {
            HStack(alignment: .firstTextBaseline, spacing: 6) {
                Text(Format.balance(confirmed: model.status.balance, pending: model.status.pending))
                    .font(.system(size: 34, weight: .bold))
                    .monospacedDigit()
                    .contentTransition(.numericText())
                if !note.isEmpty {
                    Text(note)
                        .font(.callout)
                        .foregroundStyle(.secondary)
                }
            }
            if let usd = model.usdBalance {
                Text(usd)
                    .font(.title3)
                    .foregroundStyle(.secondary)
                    .monospacedDigit()
            }
        }
        .animation(.default, value: model.status.balance + model.status.pending)
    }
}

/// StatsView sums up the wallet's lifetime in two columns: the amounts
/// received, sent and paid in fees with their worth in US dollars at the
/// left, the transactions, coins and the wallet's age at the right. The
/// rows of both columns line up, with separator lines between the rows
/// and between the columns.
struct StatsView: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        let s = model.stats
        Grid(alignment: .topLeading, horizontalSpacing: 20, verticalSpacing: 0) {
            GridRow {
                StatRow(name: "Received", value: Format.amount(s.received), usd: usd(s.received))
                separator
                StatRow(name: "Transactions", value: "\(s.transactions)")
            }
            Divider()
            GridRow {
                StatRow(name: "Sent", value: Format.amount(s.sent), usd: usd(s.sent))
                separator
                StatRow(name: "Coins", value: "\(s.coins) (\(s.unspent) unspent)")
            }
            Divider()
            GridRow {
                StatRow(name: "Fees", value: Format.amount(s.fees), usd: usd(s.fees))
                separator
                StatRow(name: "Lifetime", value: Format.lifetime(created: model.createdAt, now: model.now, units: 2),
                        short: Format.lifetime(created: model.createdAt, now: model.now, units: 1))
            }
        }
        .padding(.horizontal, 18)
        .padding(.vertical, 8)
        .background(.background.secondary, in: RoundedRectangle(cornerRadius: 12))
        .fixedSize()
    }

    /// separator is the vertical line between the columns, as tall as its row.
    private var separator: some View {
        Rectangle()
            .fill(.separator)
            .frame(width: 1)
            .gridCellUnsizedAxes(.vertical)
    }

    private func usd(_ sats: Int64) -> String? {
        model.rate > 0 ? Format.usd(Format.usdValue(sats, centsPerBTC: model.rate)) : nil
    }
}

/// StatRow is one statistic: its name at the left, its value at the right,
/// and for an amount its worth in US dollars under the value. A value may
/// come in a shorter form for when the long one does not fit.
struct StatRow: View {
    let name: String
    let value: String
    var short: String?
    var usd: String?

    var body: some View {
        HStack(alignment: .firstTextBaseline) {
            Text(name).foregroundStyle(.secondary)
            Spacer(minLength: 12)
            VStack(alignment: .trailing, spacing: 1) {
                ViewThatFits(in: .horizontal) {
                    Text(value)
                    Text(short ?? value)
                }
                .monospacedDigit()
                if let usd {
                    Text(usd).font(.caption).foregroundStyle(.secondary).monospacedDigit()
                }
            }
        }
        .font(.system(size: 14))
        .frame(minWidth: 220)
        .padding(.vertical, 10)
    }
}
