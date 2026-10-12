// Draws the Twotbit app icon at every size macOS asks for into the
// AppIcon set of the asset catalog:
//
//     swift Scripts/make-icon.swift App/Assets.xcassets/AppIcon.appiconset
import AppKit

let output = URL(fileURLWithPath: CommandLine.arguments.count > 1 ? CommandLine.arguments[1] : ".")

/// The icon on a canvas of the side: an orange squircle on the macOS icon
/// grid with a white bitcoin sign and two small bits orbiting it.
func icon(side: CGFloat) -> NSBitmapImageRep {
    let rep = NSBitmapImageRep(bitmapDataPlanes: nil, pixelsWide: Int(side), pixelsHigh: Int(side), bitsPerSample: 8, samplesPerPixel: 4,
                               hasAlpha: true, isPlanar: false, colorSpaceName: .deviceRGB, bytesPerRow: 0, bitsPerPixel: 0)!
    NSGraphicsContext.saveGraphicsState()
    NSGraphicsContext.current = NSGraphicsContext(bitmapImageRep: rep)
    let scale = side / 1024
    let body = NSRect(x: 100 * scale, y: 100 * scale, width: 824 * scale, height: 824 * scale)
    let shape = NSBezierPath(roundedRect: body, xRadius: 185 * scale, yRadius: 185 * scale)
    let shadow = NSShadow()
    shadow.shadowColor = NSColor.black.withAlphaComponent(0.28)
    shadow.shadowOffset = NSSize(width: 0, height: -10 * scale)
    shadow.shadowBlurRadius = 24 * scale
    NSGraphicsContext.saveGraphicsState()
    shadow.set()
    NSColor(red: 0.95, green: 0.55, blue: 0.10, alpha: 1).setFill()
    shape.fill()
    NSGraphicsContext.restoreGraphicsState()
    let gradient = NSGradient(colors: [NSColor(red: 1.0, green: 0.68, blue: 0.22, alpha: 1), NSColor(red: 0.91, green: 0.45, blue: 0.06, alpha: 1)])!
    gradient.draw(in: shape, angle: -90)
    NSColor.white.withAlphaComponent(0.22).setStroke()
    shape.lineWidth = 3 * scale
    shape.stroke()

    let config = NSImage.SymbolConfiguration(pointSize: 470 * scale, weight: .bold)
    if let sign = NSImage(systemSymbolName: "bitcoinsign", accessibilityDescription: nil)?.withSymbolConfiguration(config) {
        let tinted = NSImage(size: sign.size, flipped: false) { rect in
            sign.draw(in: rect)
            NSColor.white.set()
            rect.fill(using: .sourceAtop)
            return true
        }
        let size = tinted.size
        let rect = NSRect(x: (side - size.width) / 2, y: (side - size.height) / 2, width: size.width, height: size.height)
        let glyphShadow = NSShadow()
        glyphShadow.shadowColor = NSColor.black.withAlphaComponent(0.18)
        glyphShadow.shadowOffset = NSSize(width: 0, height: -6 * scale)
        glyphShadow.shadowBlurRadius = 10 * scale
        NSGraphicsContext.saveGraphicsState()
        glyphShadow.set()
        tinted.draw(in: rect)
        NSGraphicsContext.restoreGraphicsState()
    }
    for (x, y, r) in [(760.0, 744.0, 34.0), (282.0, 300.0, 24.0)] {
        NSColor.white.withAlphaComponent(0.9).setFill()
        NSBezierPath(ovalIn: NSRect(x: (x - r) * scale, y: (y - r) * scale, width: 2 * r * scale, height: 2 * r * scale)).fill()
    }
    NSGraphicsContext.restoreGraphicsState()
    return rep
}

var images = [[String: String]]()
for (points, scales) in [(16, [1, 2]), (32, [1, 2]), (128, [1, 2]), (256, [1, 2]), (512, [1, 2])] {
    for scale in scales {
        let pixels = points * scale
        let name = "icon_\(points)x\(points)\(scale == 2 ? "@2x" : "").png"
        let data = icon(side: CGFloat(pixels)).representation(using: .png, properties: [:])!
        try! data.write(to: output.appendingPathComponent(name))
        images.append(["idiom": "mac", "size": "\(points)x\(points)", "scale": "\(scale)x", "filename": name])
    }
}
let contents: [String: Any] = ["images": images, "info": ["author": "xcode", "version": 1]]
let json = try! JSONSerialization.data(withJSONObject: contents, options: [.prettyPrinted, .sortedKeys])
try! json.write(to: output.appendingPathComponent("Contents.json"))
print("wrote \(images.count) icons to \(output.path)")
