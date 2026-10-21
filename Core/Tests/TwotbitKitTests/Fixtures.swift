import Foundation
@testable import TwotbitKit

/// Fixtures loads the test vectors generated from the Go reference and
/// btcd code (see Fixtures/README.md).
enum Fixtures {
    static func url(_ name: String, _ ext: String) -> URL {
        guard let url = Bundle.module.url(forResource: name, withExtension: ext, subdirectory: "Fixtures") else {
            fatalError("missing fixture \(name).\(ext)")
        }
        return url
    }

    static func load<T: Decodable>(_ name: String, as type: T.Type = T.self) -> T {
        do {
            return try JSONDecoder().decode(T.self, from: Data(contentsOf: url(name, "json")))
        } catch {
            fatalError("fixture \(name): \(error)")
        }
    }

    static func data(_ name: String, _ ext: String) -> Data {
        try! Data(contentsOf: url(name, ext))
    }
}

extension Data {
    /// Hex test data; it must be valid.
    init(h: String) {
        guard let data = Data(hex: h) else { fatalError("bad hex \(h)") }
        self = data
    }
}

extension Network {
    /// The network of a name used in the fixtures, btcd's or the user's.
    static func fixture(_ name: String) -> Network {
        guard let network = Network.named(name) else { fatalError("unknown network \(name)") }
        return network
    }
}
