import Foundation

/// UInt256 is an unsigned 256-bit integer for proof of work: block hashes
/// read as numbers and the difficulty targets they must not exceed.
public struct UInt256: Comparable, Hashable, Sendable, CustomStringConvertible {
    /// Little-endian 64-bit limbs: l0 is the least significant.
    public var l0: UInt64
    public var l1: UInt64
    public var l2: UInt64
    public var l3: UInt64

    public static let zero = UInt256(l0: 0, l1: 0, l2: 0, l3: 0)

    public init(l0: UInt64, l1: UInt64, l2: UInt64, l3: UInt64) {
        self.l0 = l0
        self.l1 = l1
        self.l2 = l2
        self.l3 = l3
    }

    public init(_ v: UInt64) { self.init(l0: v, l1: 0, l2: 0, l3: 0) }

    /// The hash read as a little-endian number, as proof of work compares
    /// it against the target.
    public init(_ hash: Hash256) { self.init(l0: hash.w0, l1: hash.w1, l2: hash.w2, l3: hash.w3) }

    /// Parses big-endian hex of up to 64 digits.
    public init?(hex: String) {
        guard hex.utf8.count <= 64 else { return nil }
        let padded = String(repeating: "0", count: 64 - hex.utf8.count) + hex
        guard let bytes = Data(hex: padded) else { return nil }
        var limbs = [UInt64](repeating: 0, count: 4)
        for (i, byte) in bytes.enumerated() {
            let limb = 3 - i / 8
            limbs[limb] = limbs[limb] << 8 | UInt64(byte)
        }
        self.init(l0: limbs[0], l1: limbs[1], l2: limbs[2], l3: limbs[3])
    }

    var limbs: [UInt64] { [l0, l1, l2, l3] }

    init(limbs: [UInt64]) { self.init(l0: limbs[0], l1: limbs[1], l2: limbs[2], l3: limbs[3]) }

    public var isZero: Bool { l0 | l1 | l2 | l3 == 0 }

    /// The number of significant bits.
    public var bitLength: Int {
        if l3 != 0 { return 192 + 64 - l3.leadingZeroBitCount }
        if l2 != 0 { return 128 + 64 - l2.leadingZeroBitCount }
        if l1 != 0 { return 64 + 64 - l1.leadingZeroBitCount }
        return 64 - l0.leadingZeroBitCount
    }

    public static func < (a: UInt256, b: UInt256) -> Bool {
        if a.l3 != b.l3 { return a.l3 < b.l3 }
        if a.l2 != b.l2 { return a.l2 < b.l2 }
        if a.l1 != b.l1 { return a.l1 < b.l1 }
        return a.l0 < b.l0
    }

    public static func >> (v: UInt256, shift: Int) -> UInt256 {
        if shift >= 256 { return .zero }
        if shift <= 0 { return v }
        let words = shift / 64
        let bits = shift % 64
        let src = v.limbs
        var out = [UInt64](repeating: 0, count: 4)
        for i in 0..<4 where i + words < 4 {
            out[i] = src[i + words] >> bits
            if bits > 0 && i + words + 1 < 4 {
                out[i] |= src[i + words + 1] << (64 - bits)
            }
        }
        return UInt256(limbs: out)
    }

    /// Shifts left, reporting whether any set bit was shifted out.
    public func shiftedLeft(_ shift: Int) -> (value: UInt256, overflow: Bool) {
        if shift <= 0 { return (self, false) }
        if shift >= 256 { return (.zero, !isZero) }
        let overflow = bitLength + shift > 256
        let words = shift / 64
        let bits = shift % 64
        let src = limbs
        var out = [UInt64](repeating: 0, count: 4)
        for i in stride(from: 3, through: 0, by: -1) where i - words >= 0 {
            out[i] = src[i - words] << bits
            if bits > 0 && i - words - 1 >= 0 {
                out[i] |= src[i - words - 1] >> (64 - bits)
            }
        }
        return (UInt256(limbs: out), overflow)
    }

    /// Multiplies by a small factor and divides by a small divisor, with an
    /// intermediate wide enough that the product never overflows, as the
    /// difficulty retarget does: target × actual timespan / expected
    /// timespan. A quotient beyond 256 bits saturates to the maximum.
    public func scaled(by factor: UInt64, dividedBy divisor: UInt64) -> UInt256 {
        precondition(divisor > 0, "division by zero")
        var wide = [UInt64](repeating: 0, count: 5)
        var carry: UInt64 = 0
        for (i, limb) in limbs.enumerated() {
            let (hi, lo) = limb.multipliedFullWidth(by: factor)
            let (sum, over) = lo.addingReportingOverflow(carry)
            wide[i] = sum
            carry = hi &+ (over ? 1 : 0)
        }
        wide[4] = carry
        var remainder: UInt64 = 0
        for i in stride(from: 4, through: 0, by: -1) {
            let (q, r) = divisor.dividingFullWidth((high: remainder, low: wide[i]))
            wide[i] = q
            remainder = r
        }
        if wide[4] != 0 { return UInt256(l0: .max, l1: .max, l2: .max, l3: .max) }
        return UInt256(limbs: Array(wide[0..<4]))
    }

    /// The low 64 bits.
    public var low64: UInt64 { l0 }

    /// Big-endian hex, 64 digits.
    public var hex: String {
        limbs.reversed().map { String(format: "%016llx", $0) }.joined()
    }

    public var description: String { hex }
}

/// Compact bits are the 32-bit floating point encoding of a difficulty
/// target in the bits field of a block header: an exponent byte and a
/// 23-bit mantissa with a sign bit.
extension UInt32 {
    /// The target the compact bits encode. Negative and overflowing
    /// encodings give nil: Bitcoin Core rejects their blocks, and no valid
    /// target needs them.
    public var compactTarget: UInt256? {
        let exponent = Int(self >> 24)
        let mantissa = UInt64(self & 0x007f_ffff)
        let negative = self & 0x0080_0000 != 0
        if mantissa != 0 && exponent == 0 { return nil }
        var target: UInt256
        if exponent <= 3 {
            target = UInt256(mantissa >> (8 * UInt64(3 - exponent)))
        } else {
            let shifted = UInt256(mantissa).shiftedLeft(8 * (exponent - 3))
            if shifted.overflow { return nil }
            target = shifted.value
        }
        if negative && !target.isZero { return nil }
        return target
    }

    /// The proof of work of one block of the compact bits.
    public var compactWork: Double {
        guard let target = compactTarget else { return 0 }
        let t = Double(target.l3) * 0x1p192 + Double(target.l2) * 0x1p128 + Double(target.l1) * 0x1p64 + Double(target.l0)
        return 0x1p256 / (t + 1)
    }
}

extension UInt256 {
    /// The target in compact bits, rounding the mantissa down to 23
    /// bits, as btcd's BigToCompact does.
    public var compactBits: UInt32 {
        if isZero { return 0 }
        var exponent = UInt32((bitLength + 7) / 8)
        var mantissa: UInt64
        if exponent > 3 {
            mantissa = (self >> (8 * Int(exponent - 3))).low64
        } else {
            mantissa = low64
            exponent = 3
        }
        if mantissa & 0x0080_0000 != 0 || mantissa >> 24 != 0 {
            mantissa >>= 8
            exponent += 1
        }
        return exponent << 24 | UInt32(mantissa & 0x007f_ffff)
    }
}
