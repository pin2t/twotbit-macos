import SwiftUI
import TwotbitKit

/// SignalBars draws the connectivity as three ascending bars: one solid bar
/// per connected peer, the others outlined.
struct SignalBars: View {
    let level: Int
    static let count = 3
    static let width: CGFloat = 6
    static let gap: CGFloat = 3

    var body: some View {
        HStack(alignment: .bottom, spacing: SignalBars.gap) {
            ForEach(0..<SignalBars.count, id: \.self) { i in
                let height = CGFloat(8 + 6 * i)
                RoundedRectangle(cornerRadius: 1.5)
                    .strokeBorder(.primary, lineWidth: 1)
                    .background(RoundedRectangle(cornerRadius: 1.5).fill(i < level ? Color.primary : .clear))
                    .frame(width: SignalBars.width, height: height)
            }
        }
        .frame(height: 20, alignment: .bottom)
        .accessibilityElement()
        .accessibilityLabel("\(level) of \(SignalBars.count) peers connected")
    }
}

/// ConnectionStatus is the status line with the bars, in the toolbar.
struct ConnectionStatus: View {
    let status: SyncStatus

    var body: some View {
        HStack(spacing: 10) {
            Text(status.text)
                .font(.callout)
                .foregroundStyle(.secondary)
                .monospacedDigit()
            SignalBars(level: status.bars)
        }
        .padding(.horizontal, 6)
        .help("\(status.peers) peer\(status.peers == 1 ? "" : "s") connected, block \(status.height)")
    }
}

/// QRCodeView draws the QR code of a text dark on a light card with the
/// quiet zone scanners need around it, its square modules aligned to
/// whole points so the code stays crisp.
struct QRCodeView: View {
    let text: String
    var side: CGFloat = 240

    /// The codes of the texts shown last, as views redraw on every sync
    /// status while the text stays the same.
    @MainActor private static var cache: [String: QRCode] = [:]

    @MainActor private static func code(_ text: String) -> QRCode? {
        if let code = cache[text] { return code }
        guard let code = QRCode(text) else { return nil }
        if cache.count > 16 { cache.removeAll() }
        cache[text] = code
        return code
    }

    var body: some View {
        let code = QRCodeView.code(text)
        Canvas { context, size in
            guard let code else { return }
            let quiet = 2
            let total = code.size + 2 * quiet
            let cell = floor(min(size.width, size.height) / CGFloat(total))
            let origin = floor((min(size.width, size.height) - cell * CGFloat(total)) / 2) + cell * CGFloat(quiet)
            var path = Path()
            for y in 0..<code.size {
                for x in 0..<code.size where code.isDark(x: x, y: y) {
                    path.addRect(CGRect(x: origin + CGFloat(x) * cell, y: origin + CGFloat(y) * cell, width: cell, height: cell))
                }
            }
            context.fill(path, with: .color(.black))
        }
        .frame(width: side, height: side)
        .background(.white, in: RoundedRectangle(cornerRadius: 12))
        .accessibilityLabel("QR code of \(text)")
    }
}

/// Toast is a short note that fades away, as after copying, or an error.
struct Toast: View {
    let message: ToastMessage

    var body: some View {
        Label(message.text, systemImage: message.error ? "exclamationmark.triangle.fill" : "checkmark.circle.fill")
            .symbolRenderingMode(.multicolor)
            .lineLimit(3)
            .frame(maxWidth: 520)
            .font(.callout.weight(.medium))
            .padding(.horizontal, 14)
            .padding(.vertical, 8)
            .background(.regularMaterial, in: Capsule())
            .shadow(color: .black.opacity(0.15), radius: 8, y: 2)
    }
}

/// CopyButton is a small borderless copy icon.
struct CopyButton: View {
    let help: String
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            Image(systemName: "doc.on.doc")
        }
        .buttonStyle(.borderless)
        .help(help)
    }
}

/// SortControl is a pair of small arrows, up for ascending over down for
/// descending: clicking one sorts by its column in that order, and the
/// arrow of the order in use is highlighted.
struct SortControl: View {
    let title: String
    let active: Bool
    let ascending: Bool
    let sort: (Bool) -> Void

    var body: some View {
        Button {
            sort(active ? !ascending : false)
        } label: {
            HStack(spacing: 4) {
                Text(title).fontWeight(.semibold)
                VStack(spacing: 1) {
                    Image(systemName: "arrowtriangle.up.fill")
                        .foregroundStyle(active && ascending ? Color.accentColor : .secondary)
                    Image(systemName: "arrowtriangle.down.fill")
                        .foregroundStyle(active && !ascending ? Color.accentColor : .secondary)
                }
                .font(.system(size: 6))
            }
        }
        .buttonStyle(.plain)
        .help("Sort by \(title.lowercased())")
    }
}
