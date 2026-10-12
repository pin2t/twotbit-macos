import SwiftUI
import TwotbitKit

/// Twotbit is an SPV Bitcoin wallet: BIP84 keys, a validated header chain,
/// BIP157/158 compact block filters and a small pool of P2P peers, reached
/// directly or over Tor and I2P.
@main
struct TwotbitApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var delegate
    @State private var model = AppModel()

    var body: some Scene {
        Window("Twotbit", id: "main") {
            RootView()
                .environment(model)
                .frame(minWidth: 760, minHeight: 760)
                .onAppear {
                    delegate.model = model
                    model.start()
                    #if DEBUG
                    Snapshot.run(model: model)
                    #endif
                }
        }
        .defaultSize(width: 860, height: 860)
        .commands {
            CommandGroup(replacing: .appSettings) {
                Button("Settings…") { model.selection = .settings }
                    .keyboardShortcut(",", modifiers: .command)
            }
            CommandGroup(replacing: .newItem) {}
            CommandMenu("Wallet") {
                Button("Receive…") { model.showReceive = true }
                    .keyboardShortcut("r", modifiers: [.command, .shift])
                    .disabled(model.phase != .ready)
                Button("Send…") { model.openSend() }
                    .keyboardShortcut("s", modifiers: [.command, .shift])
                    .disabled(model.phase != .ready)
                Divider()
                Button("Copy Address") { model.copy(model.address, "Address") }
                    .keyboardShortcut("c", modifiers: [.command, .shift])
                    .disabled(model.address.isEmpty)
            }
        }
    }
}

/// AppDelegate stops the sync and closes the wallet before the app quits,
/// and quits it when its window closes. The first request to quit is put
/// off until the wallet is shut down, then made again: replying later
/// would hold the main thread in AppKit's nested event loop, where the
/// shutdown could not run when the request came from a task.
final class AppDelegate: NSObject, NSApplicationDelegate {
    @MainActor var model: AppModel?

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { true }

    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        MainActor.assumeIsolated {
            guard let model, !model.isShutDown else { return .terminateNow }
            Task { @MainActor in
                await model.shutdown()
                NSApp.terminate(nil)
            }
            return .terminateCancel
        }
    }
}
