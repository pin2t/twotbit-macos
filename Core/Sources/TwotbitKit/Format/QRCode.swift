import CoreGraphics
import CoreImage
import CoreImage.CIFilterBuiltins
import Foundation

/// QRCode is the module matrix of the QR code of a text at an error
/// correction level, M as bitfyn's receive codes use unless told, read
/// from CoreImage's encoder and set upright.
public struct QRCode: Equatable, Sendable {
    /// One CoreImage context for every code: contexts are costly to make
    /// and safe to share.
    private static let context = CIContext(options: [.useSoftwareRenderer: true])

    /// The number of modules on a side.
    public let size: Int
    /// The modules row by row from the top left, true where dark.
    public let modules: [Bool]

    /// The code of the text at the correction level: L, M, Q or H, which
    /// restore about 7, 15, 25 and 30% of the code.
    public init?(_ text: String, correction: String = "M") {
        let filter = CIFilter.qrCodeGenerator()
        filter.message = Data(text.utf8)
        filter.correctionLevel = correction
        guard let image = filter.outputImage else { return nil }
        let extent = image.extent.integral
        let width = Int(extent.width), height = Int(extent.height)
        guard width > 0, height > 0 else { return nil }
        var pixels = [UInt8](repeating: 255, count: width * height)
        QRCode.context.render(image, toBitmap: &pixels, rowBytes: width, bounds: extent, format: .L8, colorSpace: CGColorSpaceCreateDeviceGray())
        var minX = width, minY = height, maxX = -1, maxY = -1
        for y in 0..<height {
            for x in 0..<width where pixels[y * width + x] < 128 {
                minX = min(minX, x)
                maxX = max(maxX, x)
                minY = min(minY, y)
                maxY = max(maxY, y)
            }
        }
        guard maxX >= minX, maxX - minX == maxY - minY else { return nil }
        let n = maxX - minX + 1
        var m = [Bool](repeating: false, count: n * n)
        for y in 0..<n {
            for x in 0..<n { m[y * n + x] = pixels[(minY + y) * width + minX + x] < 128 }
        }
        // The corner without a finder pattern must be the bottom right; a
        // bitmap read bottom up has it at the top right.
        if !QRCode.isFinder(m, n, x: 0, y: 0) || QRCode.isFinder(m, n, x: n - 7, y: n - 7) {
            var flipped = m
            for y in 0..<n {
                for x in 0..<n { flipped[y * n + x] = m[(n - 1 - y) * n + x] }
            }
            m = flipped
        }
        size = n
        modules = m
    }

    public func isDark(x: Int, y: Int) -> Bool { modules[y * size + x] }

    /// The rows and columns of the centered square about that fraction of
    /// the side across, for a logo over the code: as many modules as the
    /// side has odd or even, so it sits exactly in the middle.
    public func center(_ fraction: Double) -> Range<Int> {
        var n = Int((Double(size) * fraction).rounded())
        if (size - n) % 2 != 0 { n += 1 }
        let start = (size - n) / 2
        return start..<start + n
    }

    /// Whether the 7×7 block at x, y is a finder pattern: a dark ring, a
    /// light ring and a dark 3×3 core.
    static func isFinder(_ m: [Bool], _ size: Int, x: Int, y: Int) -> Bool {
        for dy in 0..<7 {
            for dx in 0..<7 {
                let ring = min(dx, dy, 6 - dx, 6 - dy)
                if m[(y + dy) * size + x + dx] != (ring != 1) { return false }
            }
        }
        return true
    }

    /// Whether the code stands upright: finder patterns at the top left,
    /// top right and bottom left corners and none at the bottom right.
    public var isUpright: Bool {
        QRCode.isFinder(modules, size, x: 0, y: 0) && QRCode.isFinder(modules, size, x: size - 7, y: 0)
            && QRCode.isFinder(modules, size, x: 0, y: size - 7) && !QRCode.isFinder(modules, size, x: size - 7, y: size - 7)
    }

    /// The code drawn black on white, scale pixels a module, with a quiet
    /// zone of that many modules around it and the modules in the hole's
    /// rows and columns left out.
    public func image(scale: Int, quietZone: Int = 4, hole: Range<Int> = 0..<0) -> CGImage? {
        let side = (size + 2 * quietZone) * scale
        guard let context = CGContext(data: nil, width: side, height: side, bitsPerComponent: 8, bytesPerRow: 0,
                                      space: CGColorSpaceCreateDeviceGray(), bitmapInfo: CGImageAlphaInfo.none.rawValue) else { return nil }
        context.setFillColor(gray: 1, alpha: 1)
        context.fill(CGRect(x: 0, y: 0, width: side, height: side))
        context.setFillColor(gray: 0, alpha: 1)
        for y in 0..<size {
            for x in 0..<size where isDark(x: x, y: y) && !(hole.contains(x) && hole.contains(y)) {
                context.fill(CGRect(x: (quietZone + x) * scale, y: side - (quietZone + y + 1) * scale, width: scale, height: scale))
            }
        }
        return context.makeImage()
    }
}
