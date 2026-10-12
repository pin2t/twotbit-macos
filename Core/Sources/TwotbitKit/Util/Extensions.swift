import Foundation

extension Character {
    var isASCIIDigit: Bool { isASCII && isNumber }
}

extension Array {
    /// The elements sorted by the predicate, keeping the original order of
    /// elements it considers equal, as Go's sort.SliceStable does.
    func stableSorted(by areInIncreasingOrder: (Element, Element) -> Bool) -> [Element] {
        enumerated().sorted { a, b in
            if areInIncreasingOrder(a.element, b.element) { return true }
            if areInIncreasingOrder(b.element, a.element) { return false }
            return a.offset < b.offset
        }.map(\.element)
    }
}

extension Data {
    /// Compares the bytes lexicographically, as Go's bytes.Compare does.
    static func lexicographicallyPrecedes(_ a: Data, _ b: Data) -> Bool {
        a.lexicographicallyPrecedes(b)
    }
}
