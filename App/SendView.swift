import SwiftUI
import TwotbitKit

/// SendView is the payment form: the destination, the amount in sats or
/// BTC with a Max button, the fee rate, and the coins to spend, none ticked
/// meaning chosen automatically. It shows the fee and change as entered, or
/// what is missing or wrong; Review asks for confirmation before the
/// payment is signed and broadcast.
struct SendView: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    /// The fee rate the form starts with, in sat/vB: the wallet has no fee
    /// estimator yet, so it is up to the user.
    static let defaultFeeRate: Int64 = 2

    @State private var address = ""
    @State private var amount = ""
    @State private var unit = AmountUnit.sats
    @State private var feeRate = String(SendView.defaultFeeRate)
    @State private var chosen: Set<OutPoint>
    @State private var confirming: AppModel.PlannedSend?
    @State private var sent: (Hash256, Int)?
    @State private var failure: String?

    init(preselected: Set<OutPoint>) {
        _chosen = State(initialValue: preselected)
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("Send").font(.title2.bold())
            Grid(alignment: .leadingFirstTextBaseline, horizontalSpacing: 10, verticalSpacing: 10) {
                GridRow {
                    Text("To").gridColumnAlignment(.trailing)
                    TextField("Destination address", text: $address)
                        .font(.system(.body, design: .monospaced))
                        .textFieldStyle(.roundedBorder)
                }
                GridRow {
                    Text("Amount")
                    HStack {
                        TextField("Amount", text: $amount).textFieldStyle(.roundedBorder)
                        Picker("Unit", selection: Binding(get: { unit }, set: convert)) {
                            ForEach(AmountUnit.allCases) { Text($0.rawValue).tag($0) }
                        }
                        .pickerStyle(.segmented)
                        .labelsHidden()
                        .fixedSize()
                        Button("Max", action: fillMax)
                    }
                }
                GridRow {
                    Text("Fee rate")
                    HStack {
                        TextField("Fee rate", text: $feeRate).textFieldStyle(.roundedBorder).frame(width: 80)
                        Text("sat/vB").foregroundStyle(.secondary)
                    }
                }
            }
            Text("Coins to spend (none ticked: chosen automatically)")
                .foregroundStyle(.secondary)
            List(model.coins) { coin in
                Toggle(isOn: Binding(get: { chosen.contains(coin.outPoint) }, set: { on in
                    if on { chosen.insert(coin.outPoint) } else { chosen.remove(coin.outPoint) }
                })) {
                    HStack {
                        Text(Format.amount(coin.value)).monospacedDigit().frame(width: 140, alignment: .trailing)
                        Text(coin.address).font(.system(.callout, design: .monospaced)).lineLimit(1).truncationMode(.middle)
                        if !coin.confirmed { Text("unconfirmed").font(.caption).foregroundStyle(.secondary) }
                    }
                }
                .toggleStyle(.checkbox)
            }
            .listStyle(.bordered)
            .frame(minHeight: 150)
            summary
                .frame(maxWidth: .infinity, minHeight: 36, alignment: .topLeading)
            HStack {
                Button("Cancel") { dismiss() }
                    .keyboardShortcut(.cancelAction)
                Spacer()
                Button("Review", action: review)
                    .keyboardShortcut(.defaultAction)
                    .buttonStyle(.borderedProminent)
            }
        }
        .padding(22)
        .frame(width: 640, height: 600)
        .alert("Confirm payment", isPresented: Binding(get: { confirming != nil }, set: { if !$0 { confirming = nil } }), presenting: confirming) { plan in
            Button("Sign & Send") { send(plan) }
            Button("Back", role: .cancel) {}
        } message: { plan in
            Text(AppModel.confirmText(plan))
        }
        .alert("Payment sent", isPresented: Binding(get: { sent != nil }, set: { if !$0 { sent = nil; dismiss() } }), presenting: sent) { _ in
            Button("OK") { dismiss() }
        } message: { result in
            Text("Transaction \(result.0.hex)\nbroadcast to \(result.1) peer\(result.1 == 1 ? "" : "s").")
        }
        .alert("Payment not sent", isPresented: Binding(get: { failure != nil }, set: { if !$0 { failure = nil } }), presenting: failure) { _ in
            Button("OK") {}
        } message: { text in
            Text(text)
        }
    }

    /// The fee and change of the payment as entered, what is missing or
    /// wrong, or a plain hint while the form is untouched.
    @ViewBuilder private var summary: some View {
        if address.trimmingCharacters(in: .whitespaces).isEmpty && amount.trimmingCharacters(in: .whitespaces).isEmpty {
            Text("Enter the destination address and the amount.").foregroundStyle(.secondary)
        } else {
            switch Result(plan) {
            case .success(let p):
                VStack(alignment: .leading, spacing: 2) {
                    Text("Fee: \(AppModel.feeText(p))")
                    if p.spend.change > 0 { Text("Change: \(Format.amount(p.spend.change))") }
                }
            case .failure(let error):
                Text(verbatim: String(describing: error)).foregroundStyle(.red)
            }
        }
    }

    private var selectedCoins: [Coin] { model.coins.filter { chosen.contains($0.outPoint) } }

    private func plan() throws -> AppModel.PlannedSend {
        let sats = try Format.parseAmount(amount, unit: unit)
        guard let rate = Int64(feeRate.trimmingCharacters(in: .whitespaces)), rate >= 1 else {
            throw AppModel.SendError(description: "enter a fee rate of at least 1 sat/vB")
        }
        return try model.planSend(address: address, amount: sats, feeRate: rate, coins: selectedCoins)
    }

    /// Rewrites the entered amount in the newly chosen unit.
    private func convert(_ next: AmountUnit) {
        if let sats = try? Format.parseAmount(amount, unit: unit), sats > 0 {
            amount = Format.unitText(sats, unit: next)
        }
        unit = next
    }

    /// Enters the most the chosen coins, or all coins, can pay at the fee
    /// rate.
    private func fillMax() {
        let rate = Int64(feeRate.trimmingCharacters(in: .whitespaces)).flatMap { $0 >= 1 ? $0 : nil } ?? SendView.defaultFeeRate
        amount = Format.unitText(model.maxAmount(address: address, feeRate: rate, coins: selectedCoins), unit: unit)
    }

    private func review() {
        do {
            confirming = try plan()
        } catch {
            failure = "\(error)"
        }
    }

    private func send(_ plan: AppModel.PlannedSend) {
        do {
            sent = try model.sendPlanned(plan)
        } catch {
            failure = "payment not sent: \(error)"
        }
    }
}
