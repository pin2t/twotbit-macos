import SwiftUI
import TwotbitKit

/// ReceiveView is the invoice for the current address: an optional amount
/// and the BIP21 payment request as a QR code and as text.
struct ReceiveView: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    @State private var amount = ""
    @State private var unit = AmountUnit.sats

    var body: some View {
        let parsed = Result { try Format.parseAmount(amount, unit: unit) }
        let sats = (try? parsed.get()) ?? 0
        let uri = Format.invoiceURI(model.address, sats: sats)
        VStack(spacing: 14) {
            Text("Receive").font(.title2.bold())
            HStack {
                TextField("Amount (optional)", text: $amount)
                    .textFieldStyle(.roundedBorder)
                Picker("Unit", selection: $unit) {
                    ForEach(AmountUnit.allCases) { Text($0.rawValue).tag($0) }
                }
                .pickerStyle(.segmented)
                .labelsHidden()
                .fixedSize()
            }
            Text(problem(parsed))
                .font(.callout)
                .foregroundStyle(.red)
                .frame(maxWidth: .infinity, alignment: .leading)
                .frame(height: 16)
            QRCodeView(text: uri, side: 280)
            Text(uri)
                .font(.system(.callout, design: .monospaced))
                .multilineTextAlignment(.center)
                .textSelection(.enabled)
                .fixedSize(horizontal: false, vertical: true)
            HStack {
                Button("Copy Invoice", systemImage: "doc.on.doc") { model.copy(uri, "Invoice") }
                Spacer()
                Button("Close") { dismiss() }
                    .keyboardShortcut(.cancelAction)
            }
            .padding(.top, 6)
        }
        .padding(24)
        .frame(width: 460)
    }

    private func problem(_ parsed: Result<Int64, Error>) -> String {
        if case .failure(let error) = parsed { return "\(error)" }
        return ""
    }
}

extension Result where Failure == Error {
    init(_ body: () throws -> Success) {
        do { self = .success(try body()) } catch { self = .failure(error) }
    }
}
