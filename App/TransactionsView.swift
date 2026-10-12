import SwiftUI
import TwotbitKit

/// TransactionsView lists the wallet transactions as cards, sortable by time
/// and amount: when each was confirmed or seen, its id with a copy button,
/// what it did to the balance, and the addresses it spends from and pays
/// to, the wallet's own in bold. Unconfirmed ones are grey.
struct TransactionsView: View {
    @Environment(AppModel.self) private var model
    @State private var byAmount = false
    @State private var ascending = false

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                SortControl(title: "Time", active: !byAmount, ascending: ascending) { sort(amount: false, $0) }
                Spacer()
                SortControl(title: "Amount", active: byAmount, ascending: ascending) { sort(amount: true, $0) }
            }
            .padding(.horizontal, 26)
            .padding(.vertical, 10)
            Divider()
            if model.history.isEmpty {
                ContentUnavailableView("No transactions yet", systemImage: "clock.arrow.circlepath",
                                       description: Text("Payments to and from the wallet appear here."))
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                ScrollView {
                    LazyVStack(spacing: 10) {
                        ForEach(sorted) { tx in
                            TransactionCard(tx: tx)
                        }
                    }
                    .padding(16)
                }
            }
        }
    }

    private func sort(amount: Bool, _ up: Bool) {
        byAmount = amount
        ascending = up
    }

    /// The transactions by time or net amount, ties broken by the id so the
    /// order stays put across updates.
    private var sorted: [WalletTransaction] {
        model.history.sorted { a, b in
            let (x, y) = ascending ? (a, b) : (b, a)
            let (kx, ky) = byAmount ? (x.net, y.net) : (x.time, y.time)
            if kx != ky { return kx < ky }
            return x.txid.hex < y.txid.hex
        }
    }
}

/// TransactionCard is one transaction.
struct TransactionCard: View {
    @Environment(AppModel.self) private var model
    let tx: WalletTransaction
    /// The most addresses a card lists on either side; past it the last
    /// row counts the ones left out.
    static let rows = 6

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 12) {
                Text(Format.relativeTime(tx.time, now: model.now))
                    .frame(width: 110, alignment: .leading)
                    .help(tx.time == 0 ? "" : Date(timeIntervalSince1970: TimeInterval(tx.time)).formatted(date: .abbreviated, time: .shortened))
                HStack(spacing: 4) {
                    Text(tx.txid.hex)
                        .font(.system(.callout, design: .monospaced))
                        .lineLimit(1)
                        .truncationMode(.middle)
                    CopyButton(help: "Copy the transaction id") { model.copy(tx.txid.hex, "Transaction id") }
                }
                Spacer(minLength: 8)
                Text(Format.netAmount(tx.net))
                    .monospacedDigit()
                    .fontWeight(.medium)
            }
            HStack(alignment: .center, spacing: 10) {
                AddressList(addresses: tx.inputs, trailing: false)
                Image(systemName: "arrow.right").foregroundStyle(.secondary)
                AddressList(addresses: tx.outputs, trailing: true)
            }
            if !tx.confirmed {
                Text("Unconfirmed").font(.caption).foregroundStyle(.secondary)
            }
        }
        .foregroundStyle(tx.confirmed ? .primary : .secondary)
        .padding(12)
        .background(.background.secondary, in: RoundedRectangle(cornerRadius: 10))
        .contextMenu {
            Button("Copy Transaction ID") { model.copy(tx.txid.hex, "Transaction id") }
        }
    }
}

/// AddressList stacks addresses closely, each shortened to fit, the
/// wallet's own in bold and unknown ones in italics, aligned right when
/// trailing.
struct AddressList: View {
    let addresses: [TxAddress]
    let trailing: Bool

    var body: some View {
        VStack(alignment: trailing ? .trailing : .leading, spacing: 2) {
            ForEach(Array(shown.enumerated()), id: \.offset) { _, row in
                row
            }
        }
        .frame(maxWidth: .infinity, alignment: trailing ? .trailing : .leading)
    }

    private var shown: [AnyView] {
        var rows = [AnyView]()
        for (i, a) in addresses.enumerated() {
            if i == TransactionCard.rows - 1 && addresses.count > TransactionCard.rows {
                rows.append(AnyView(Text("\(addresses.count - i) more").italic().font(.callout)))
                break
            }
            let text = a.address.isEmpty ? "unknown" : a.address
            rows.append(AnyView(
                Text(text)
                    .font(.system(.callout, design: .monospaced))
                    .fontWeight(a.mine ? .bold : .regular)
                    .italic(a.address.isEmpty)
                    .lineLimit(1)
                    .truncationMode(.middle)
                    .textSelection(.enabled)
            ))
        }
        return rows
    }
}
