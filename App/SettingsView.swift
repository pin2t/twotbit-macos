import SwiftUI
import TwotbitKit

/// SettingsView is the pinned peer, the Tor and I2P switches, and the
/// wallet: its network, data folder, account key and recovery phrase.
struct SettingsView: View {
    @Environment(AppModel.self) private var model
    @State private var phrase: RecoveryPhrase?
    @State private var nextNetwork: Network?

    var body: some View {
        @Bindable var model = model
        Form {
            SwiftUI.Section {
                TextField("Pinned peer", text: $model.peerText, prompt: Text("IP address or IP:port"))
                    .disabled(model.overlayOn)
                    .onChange(of: model.peerText) { _, text in model.peerEdited(text) }
                if !model.peerStatus.isEmpty && !model.overlayOn {
                    Text(model.peerStatus)
                        .foregroundStyle(model.peerConnected ? .green : .secondary)
                }
                ForEach(model.peerNote, id: \.self) { line in
                    Text(line).font(.caption).foregroundStyle(.secondary)
                }
            } header: {
                Text("Pinned peer")
            }

            SwiftUI.Section {
                overlayToggle(.tor, "Tor", isOn: Binding(get: { model.tor.on }, set: { model.setOverlay(.tor, $0) }))
                overlayToggle(.i2p, "I2P", isOn: Binding(get: { model.i2p.on }, set: { model.setOverlay(.i2p, $0) }))
            } header: {
                Text("Privacy networks")
            } footer: {
                Text("With Tor or I2P on, the wallet connects only to peers on those networks, through the Tor client or I2P router running on this Mac.")
                    .font(.caption).foregroundStyle(.secondary)
            }

            SwiftUI.Section("Wallet") {
                Picker("Network", selection: Binding(get: { model.network }, set: { if $0 != model.network { nextNetwork = $0 } })) {
                    ForEach([Network.mainnet, .testnet3, .testnet4, .signet, .regtest]) { n in
                        Text(n.displayName).tag(n)
                    }
                }
                LabeledContent("Data folder") {
                    HStack {
                        Text(model.options.dataDirectory.path).lineLimit(1).truncationMode(.middle).textSelection(.enabled)
                        Button("Show in Finder") { NSWorkspace.shared.activateFileViewerSelecting([model.options.dataDirectory]) }
                    }
                }
                if let xpub = model.wallet?.accountXPub {
                    LabeledContent("Account public key") {
                        HStack(spacing: 4) {
                            Text(xpub).font(.system(.callout, design: .monospaced)).lineLimit(1).truncationMode(.middle).textSelection(.enabled)
                            CopyButton(help: "Copy the account public key, for watching the wallet elsewhere") { model.copy(xpub, "Account public key") }
                        }
                    }
                }
                LabeledContent("Recovery phrase") {
                    Button("Show…") { reveal() }
                }
            }
        }
        .formStyle(.grouped)
        .sheet(item: $phrase) { RecoveryPhraseView(words: $0.words) }
        .confirmationDialog("Switch to \(nextNetwork?.displayName ?? "")?", isPresented: Binding(get: { nextNetwork != nil }, set: { if !$0 { nextNetwork = nil } })) {
            Button("Switch and Relaunch") {
                if let next = nextNetwork { model.switchNetwork(next) }
            }
        } message: {
            Text("Twotbit relaunches on \(nextNetwork?.displayName ?? ""). Every network has its own wallet; this one stays as it is.")
        }
    }

    private func overlayToggle(_ network: OverlayNetwork, _ name: String, isOn: Binding<Bool>) -> some View {
        let (text, ready) = model.overlayText(network)
        return VStack(alignment: .leading, spacing: 4) {
            Toggle(name, isOn: isOn)
            Text(text).font(.caption).foregroundStyle(ready ? .green : .secondary)
        }
    }

    private func reveal() {
        Task {
            guard await model.authenticate(reason: "show the wallet's recovery phrase") else { return }
            guard let mnemonic = model.wallet?.mnemonic else { return }
            phrase = RecoveryPhrase(words: mnemonic.split(separator: " ").map(String.init))
        }
    }
}

/// RecoveryPhrase is the revealed phrase; presenting the sheet by item hands
/// the words to it, where isPresented would build it with the stale empty list.
struct RecoveryPhrase: Identifiable {
    let id = UUID()
    let words: [String]
}

/// RecoveryPhraseView shows the 12 words that restore the wallet.
struct RecoveryPhraseView: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    let words: [String]

    var body: some View {
        VStack(spacing: 18) {
            Text("Recovery phrase").font(.title2.bold())
            Text("These words restore the wallet and everything in it. Write them down in order and keep them offline; anyone who sees them can take the funds.")
                .multilineTextAlignment(.center)
                .foregroundStyle(.secondary)
                .frame(maxWidth: 420)
            LazyVGrid(columns: Array(repeating: GridItem(.fixed(120), alignment: .leading), count: 3), alignment: .leading, spacing: 10) {
                ForEach(Array(words.enumerated()), id: \.offset) { i, word in
                    HStack(spacing: 6) {
                        Text("\(i + 1).").foregroundStyle(.secondary).monospacedDigit().frame(width: 24, alignment: .trailing)
                        Text(word).font(.system(.body, design: .monospaced))
                    }
                }
            }
            .padding(16)
            .background(.background.secondary, in: RoundedRectangle(cornerRadius: 10))
            HStack {
                Button("Copy") { model.copySecret(words.joined(separator: " "), "Recovery phrase") }
                Button("Done") { dismiss() }
                    .keyboardShortcut(.defaultAction)
            }
        }
        .padding(28)
        .frame(width: 520)
    }
}
