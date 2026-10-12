import CSecp256k1
import Foundation

/// Secp256k1 wraps the vendored libsecp256k1 for the operations the wallet
/// needs: public keys of private keys, the BIP32 private key tweak, and
/// ECDSA signatures, deterministic per RFC6979 and with low S.
public enum Secp256k1 {
    /// One context for the process, randomized against side channels once.
    /// libsecp256k1 allows a context to be used from several threads at
    /// once by every function the wallet calls on it.
    nonisolated(unsafe) private static let context: OpaquePointer = {
        guard let ctx = secp256k1_context_create(UInt32(SECP256K1_CONTEXT_NONE)) else {
            fatalError("secp256k1 context")
        }
        let seed = [UInt8](Hashes.randomBytes(32))
        precondition(secp256k1_context_randomize(ctx, seed) == 1, "secp256k1 randomize")
        return ctx
    }()

    /// Whether the 32 bytes are a valid private key: not zero and below the
    /// curve order.
    public static func isValidPrivateKey(_ key: Data) -> Bool {
        guard key.count == 32 else { return false }
        let bytes = [UInt8](key)
        return secp256k1_ec_seckey_verify(context, bytes) == 1
    }

    /// The 33-byte compressed public key of the private key.
    public static func publicKey(of privateKey: Data) throws -> Data {
        guard privateKey.count == 32 else { throw KeyError.invalidPrivateKey }
        var pubkey = secp256k1_pubkey()
        let key = [UInt8](privateKey)
        guard secp256k1_ec_pubkey_create(context, &pubkey, key) == 1 else { throw KeyError.invalidPrivateKey }
        var out = [UInt8](repeating: 0, count: 33)
        var length = 33
        secp256k1_ec_pubkey_serialize(context, &out, &length, &pubkey, UInt32(SECP256K1_EC_COMPRESSED))
        return Data(out[0..<length])
    }

    /// Whether the bytes parse as a compressed or uncompressed public key on
    /// the curve.
    public static func isValidPublicKey(_ key: Data) -> Bool {
        var pubkey = secp256k1_pubkey()
        let bytes = [UInt8](key)
        return secp256k1_ec_pubkey_parse(context, &pubkey, bytes, bytes.count) == 1
    }

    /// The private key plus the tweak modulo the curve order, as BIP32
    /// derives child keys. It fails when the tweak is not below the order or
    /// the sum is zero: BIP32 then skips to the next index.
    public static func tweakAdd(privateKey: Data, tweak: Data) throws -> Data {
        guard privateKey.count == 32, tweak.count == 32 else { throw KeyError.invalidPrivateKey }
        var key = [UInt8](privateKey)
        let t = [UInt8](tweak)
        guard secp256k1_ec_seckey_tweak_add(context, &key, t) == 1 else { throw KeyError.invalidChild }
        return Data(key)
    }

    /// Signs the 32-byte hash with the private key and returns the DER
    /// encoded signature. The nonce is derived per RFC6979, so the same key
    /// and hash always give the same signature, and S is always the low one.
    public static func sign(hash: Data, privateKey: Data) throws -> Data {
        guard hash.count == 32, privateKey.count == 32 else { throw KeyError.invalidPrivateKey }
        var signature = secp256k1_ecdsa_signature()
        let msg = [UInt8](hash)
        let key = [UInt8](privateKey)
        guard secp256k1_ecdsa_sign(context, &signature, msg, key, nil, nil) == 1 else {
            throw KeyError.invalidPrivateKey
        }
        var der = [UInt8](repeating: 0, count: 72)
        var length = 72
        guard secp256k1_ecdsa_signature_serialize_der(context, &der, &length, &signature) == 1 else {
            throw KeyError.invalidPrivateKey
        }
        return Data(der[0..<length])
    }

    /// Verifies a DER signature with a low S over the hash.
    public static func verify(signature: Data, hash: Data, publicKey: Data) -> Bool {
        var sig = secp256k1_ecdsa_signature()
        var pubkey = secp256k1_pubkey()
        let der = [UInt8](signature)
        let pub = [UInt8](publicKey)
        let msg = [UInt8](hash)
        guard hash.count == 32,
              secp256k1_ecdsa_signature_parse_der(context, &sig, der, der.count) == 1,
              secp256k1_ec_pubkey_parse(context, &pubkey, pub, pub.count) == 1 else { return false }
        return secp256k1_ecdsa_verify(context, &sig, msg, &pubkey) == 1
    }
}

/// KeyError is a failure of key derivation or signing.
public enum KeyError: Error, Equatable, Sendable, CustomStringConvertible {
    case invalidPrivateKey
    case invalidChild
    case invalidPath(String)
    case invalidSeed

    public var description: String {
        switch self {
        case .invalidPrivateKey: return "invalid private key"
        case .invalidChild: return "invalid child key, use the next index"
        case .invalidPath(let path): return "invalid derivation path \"\(path)\""
        case .invalidSeed: return "invalid seed"
        }
    }
}
