import SwiftUI
import TwotbitKit

/// CoinsView lists the spendable coins: when each appeared, its address with
/// a copy button, and its value, unconfirmed ones in grey, sortable by time
/// and amount, the newest first. Selected coins are what Send spends; Merge
/// and Split will merge coins into one and split one into many.
struct CoinsView: View {
    @Environment(AppModel.self) private var model
    @State private var sortOrder = [KeyPathComparator(\Coin.time, order: .reverse)]

    var body: some View {
        @Bindable var model = model
        VStack(spacing: 0) {
            if model.coins.isEmpty {
                ContentUnavailableView("No coins yet", systemImage: "circle.circle",
                                       description: Text("Coins appear here once the wallet receives a payment."))
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                Table(sorted, selection: $model.selectedCoins, sortOrder: $sortOrder) {
                    TableColumn("Time", value: \.time) { coin in
                        Text(Format.relativeTime(coin.time, now: model.now))
                            .foregroundStyle(coin.confirmed ? .primary : .secondary)
                            .help(coin.time == 0 ? "" : Date(timeIntervalSince1970: TimeInterval(coin.time)).formatted(date: .abbreviated, time: .shortened))
                    }
                    .width(min: 100, ideal: 120, max: 150)
                    TableColumn("Address") { coin in
                        HStack(spacing: 4) {
                            Text(coin.address)
                                .font(.system(.body, design: .monospaced))
                                .lineLimit(1)
                                .truncationMode(.middle)
                                .foregroundStyle(coin.confirmed ? .primary : .secondary)
                            CopyButton(help: "Copy the address") { model.copy(coin.address, "Address") }
                        }
                    }
                    TableColumn("Amount", value: \.value) { coin in
                        Text(Format.amount(coin.value))
                            .monospacedDigit()
                            .frame(maxWidth: .infinity, alignment: .trailing)
                            .foregroundStyle(coin.confirmed ? .primary : .secondary)
                    }
                    .width(min: 110, ideal: 150, max: 200)
                }
                .contextMenu(forSelectionType: OutPoint.self) { selection in
                    Button("Send Selected…") { model.openSend(with: selection) }.disabled(selection.isEmpty)
                    if let op = selection.first, selection.count == 1, let coin = model.coins.first(where: { $0.outPoint == op }) {
                        Button("Copy Address") { model.copy(coin.address, "Address") }
                        Button("Copy Outpoint") { model.copy(op.description, "Outpoint") }
                    }
                }
            }
            Divider()
            HStack(spacing: 10) {
                Text(selectionText).foregroundStyle(.secondary).monospacedDigit()
                Spacer()
                Button("Merge", systemImage: "arrow.triangle.merge") {}
                    .disabled(true)
                    .help("Merge the selected coins to one address — coming in a later version")
                Button("Split", systemImage: "arrow.triangle.branch") {}
                    .disabled(true)
                    .help("Split one coin to many — coming in a later version")
                Button("Send", systemImage: "arrow.up.to.line") { model.openSend(with: model.selectedCoins) }
                    .keyboardShortcut(.defaultAction)
                    .disabled(model.coins.isEmpty)
            }
            .padding(12)
        }
    }

    private var sorted: [Coin] {
        model.coins.sorted { a, b in
            for comparator in sortOrder {
                switch comparator.compare(a, b) {
                case .orderedAscending: return true
                case .orderedDescending: return false
                case .orderedSame: continue
                }
            }
            return a.outPoint.description < b.outPoint.description
        }
    }

    private var selectionText: String {
        let chosen = model.coins.filter { model.selectedCoins.contains($0.outPoint) }
        if chosen.isEmpty {
            return "\(model.coins.count) coin\(model.coins.count == 1 ? "" : "s"), \(Format.amount(model.coins.reduce(0) { $0 + $1.value }))"
        }
        return "\(chosen.count) selected, \(Format.amount(chosen.reduce(0) { $0 + $1.value }))"
    }
}
