import SwiftUI
import TwotbitKit

/// RootView is the window: the sections in a sidebar, the connectivity in
/// the toolbar, and the Receive and Send sheets.
struct RootView: View {
    @Environment(AppModel.self) private var model
    @State private var width: CGFloat = 0
    /// The window width past which Home lists the transactions too.
    static let wideWidth: CGFloat = 1200

    var body: some View {
        @Bindable var model = model
        Group {
            switch model.phase {
            case .loading:
                ProgressView("Opening the wallet…")
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            case .failed(let message):
                FailureView(message: message)
            case .missingPhrase:
                RestoreView()
            case .ready:
                NavigationSplitView {
                    List(Section.allCases, selection: $model.selection) { section in
                        Label(section.title, systemImage: section.icon).tag(section)
                    }
                    .navigationSplitViewColumnWidth(min: 170, ideal: 190, max: 240)
                } detail: {
                    detail
                        .navigationTitle(model.selection.title)
                        .navigationSubtitle(model.network.kind == .mainnet ? "" : "net: \(model.network.displayName)")
                        .toolbar {
                            ToolbarItem(placement: .primaryAction) {
                                ConnectionStatus(status: model.status)
                            }
                        }
                }
                .sheet(isPresented: $model.showReceive) { ReceiveView() }
                .sheet(isPresented: $model.showSend) { SendView(preselected: model.sendPreselection) }
                .onChange(of: model.selection) { _, section in
                    if section == .settings { model.recheckPeer() }
                }
            }
        }
        .overlay(alignment: .bottom) {
            if let toast = model.toast {
                Toast(message: toast)
                    .padding(.bottom, 28)
                    .transition(.move(edge: .bottom).combined(with: .opacity))
            }
        }
        .animation(.easeInOut(duration: 0.2), value: model.toast)
        .onGeometryChange(for: CGFloat.self) { $0.size.width } action: { width = $0 }
    }

    @ViewBuilder private var detail: some View {
        switch model.selection {
        case .home: HomeView(wide: width > Self.wideWidth)
        case .coins: CoinsView()
        case .transactions: TransactionsView()
        case .settings: SettingsView()
        }
    }
}

/// FailureView tells why the wallet could not start.
struct FailureView: View {
    let message: String

    var body: some View {
        ContentUnavailableView {
            Label("Twotbit failed to start", systemImage: "exclamationmark.triangle")
        } description: {
            Text(message).font(.body.monospaced()).textSelection(.enabled)
        }
    }
}

/// RestoreView asks for the recovery phrase of a wallet whose phrase is no
/// longer in the Keychain.
struct RestoreView: View {
    @Environment(AppModel.self) private var model
    @State private var phrase = ""
    @State private var problem = ""

    var body: some View {
        VStack(spacing: 16) {
            Image(systemName: "key.slash").font(.system(size: 44)).foregroundStyle(.secondary)
            Text("Recovery phrase not found").font(.title2.bold())
            Text("The wallet's recovery phrase is not in the Keychain any more. Enter its 12 words to restore access to this wallet.")
                .multilineTextAlignment(.center)
                .foregroundStyle(.secondary)
                .frame(maxWidth: 440)
            TextEditor(text: $phrase)
                .font(.body.monospaced())
                .frame(width: 440, height: 90)
                .scrollContentBackground(.hidden)
                .padding(6)
                .background(.background.secondary, in: RoundedRectangle(cornerRadius: 8))
            if !problem.isEmpty {
                Text(problem).foregroundStyle(.red)
            }
            Button("Restore") {
                do {
                    try model.restore(phrase: phrase)
                } catch {
                    problem = "\(error)"
                }
            }
            .keyboardShortcut(.defaultAction)
            .disabled(phrase.split(separator: " ").count < 12)
        }
        .padding(40)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}
