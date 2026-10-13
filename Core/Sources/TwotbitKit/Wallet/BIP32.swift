import Foundation

/// ExtendedKey is a BIP32 extended private key: a private key, its chain
/// code and its place in the tree.
public struct ExtendedKey: Sendable {
    public static let hardened: UInt32 = 0x8000_0000

    public let privateKey: Data
    public let chainCode: Data
    public let depth: UInt8
    public let parentFingerprint: UInt32
    public let childNumber: UInt32

    /// The master key of a seed of 16 to 64 bytes: HMAC-SHA512 keyed with
    /// "Bitcoin seed".
    public static func master(seed: Data) throws -> ExtendedKey {
        guard seed.count >= 16, seed.count <= 64 else { throw KeyError.invalidSeed }
        let i = seed.hmacSHA512(key: Data("Bitcoin seed".utf8))
        let key = i.prefix(32)
        guard Secp256k1.isValidPrivateKey(Data(key)) else { throw KeyError.invalidSeed }
        return ExtendedKey(privateKey: Data(key), chainCode: Data(i.suffix(32)), depth: 0, parentFingerprint: 0, childNumber: 0)
    }

    /// The compressed public key.
    public var publicKey: Data {
        // A valid extended key always holds a valid private key.
        try! Secp256k1.publicKey(of: privateKey)
    }

    /// The first four bytes of the public key's HASH160, which children
    /// name their parent by.
    public var fingerprint: UInt32 {
        let h = publicKey.hash160()
        return h.prefix(4).reduce(0) { $0 << 8 | UInt32($1) }
    }

    /// Derives the child at the index, hardened from 2^31 on, per BIP32
    /// CKDpriv.
    public func derive(_ index: UInt32) throws -> ExtendedKey {
        var data = Data(capacity: 37)
        if index >= ExtendedKey.hardened {
            data.append(0)
            data.append(privateKey)
        } else {
            data.append(publicKey)
        }
        withUnsafeBytes(of: index.bigEndian) { data.append(contentsOf: $0) }
        let i = data.hmacSHA512(key: chainCode)
        let child = try Secp256k1.tweakAdd(privateKey: privateKey, tweak: Data(i.prefix(32)))
        return ExtendedKey(privateKey: child, chainCode: Data(i.suffix(32)), depth: depth &+ 1, parentFingerprint: fingerprint, childNumber: index)
    }

    /// Derives along the path, one index per step.
    public func derive(path: [UInt32]) throws -> ExtendedKey {
        try path.reduce(self) { try $0.derive($1) }
    }

    /// The neutered key serialized with the version bytes in Base58Check:
    /// the extended public key.
    public func publicString(version: Data) -> String {
        var data = Data(capacity: 78)
        data.append(version)
        data.append(depth)
        withUnsafeBytes(of: parentFingerprint.bigEndian) { data.append(contentsOf: $0) }
        withUnsafeBytes(of: childNumber.bigEndian) { data.append(contentsOf: $0) }
        data.append(chainCode)
        data.append(publicKey)
        return data.base58ChecksumEncoded()
    }
}

extension String {
    /// The indexes of a derivation path such as m/84'/0'/0'/1/3,
    /// each below 2^31 before hardening.
    public func derivationPath() throws -> [UInt32] {
        let parts = split(separator: "/", omittingEmptySubsequences: false)
        guard parts.count >= 2, parts[0] == "m" else { throw KeyError.invalidPath(self) }
        return try parts.dropFirst().map { part in
            let isHardened = part.hasSuffix("'")
            let digits = isHardened ? part.dropLast() : part
            guard !digits.isEmpty, digits.allSatisfy(\.isASCIIDigit), let n = UInt32(digits), n < ExtendedKey.hardened else {
                throw KeyError.invalidPath(self)
            }
            return isHardened ? n + ExtendedKey.hardened : n
        }
    }
}
