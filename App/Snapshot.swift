#if DEBUG
import AppKit
import SwiftUI

/// Snapshot renders the window's sections and sheets to PNG files and quits,
/// when the app is launched with -snapshot <directory>: a quick look at the
/// interface, in debug builds only.
@MainActor
enum Snapshot {
    static func run(model: AppModel) {
        guard let path = UserDefaults.standard.string(forKey: "snapshot") else { return }
        let dir = URL(fileURLWithPath: (path as NSString).expandingTildeInPath)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        Task { @MainActor in
            try? await Task.sleep(for: .seconds(2))
            for appearance in [NSAppearance.Name.aqua, .darkAqua] {
                NSApp.appearance = NSAppearance(named: appearance)
                let suffix = appearance == .aqua ? "" : "-dark"
                for section in Section.allCases {
                    model.selection = section
                    try? await Task.sleep(for: .milliseconds(900))
                    save(mainWindow, to: dir.appendingPathComponent("\(section.rawValue)\(suffix).png"))
                }
                model.selection = .home
                model.showReceive = true
                try? await Task.sleep(for: .milliseconds(900))
                save(mainWindow?.attachedSheet, to: dir.appendingPathComponent("receive\(suffix).png"))
                model.showReceive = false
                try? await Task.sleep(for: .milliseconds(600))
                model.openSend()
                try? await Task.sleep(for: .milliseconds(900))
                save(mainWindow?.attachedSheet, to: dir.appendingPathComponent("send\(suffix).png"))
                model.showSend = false
                try? await Task.sleep(for: .milliseconds(600))
            }
            NSApp.terminate(nil)
        }
    }

    private static var mainWindow: NSWindow? {
        NSApp.windows.first { $0.isVisible && $0.sheetParent == nil && $0.contentView != nil }
    }

    /// Writes the window as drawn, title bar and toolbar included.
    private static func save(_ window: NSWindow?, to url: URL) {
        guard let view = window?.contentView?.superview ?? window?.contentView,
              let rep = view.bitmapImageRepForCachingDisplay(in: view.bounds) else { return }
        view.cacheDisplay(in: view.bounds, to: rep)
        try? rep.representation(using: .png, properties: [:])?.write(to: url)
    }
}
#endif
