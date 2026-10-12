import Foundation

/// AddressError is a destination address that cannot be paid on the
/// network.
public struct AddressError: Error, Equatable, Sendable, CustomStringConvertible {
    public let description: String
    init(_ description: String) { self.description = description }
}

/// Address encodes and decodes Bitcoin addresses: Base58Check P2PKH and
/// P2SH, Bech32 segwit version 0 and Bech32m taproot.
public enum Address {
    /// The segwit address prefixes of every network.
    private static let segwitHRPs: Set<String> = Set(Network.all.map(\.bech32HRP))

    /// Decodes an address of the network into the output script paying it,
    /// accepting what btcutil's DecodeAddress accepts for the network:
    /// P2PKH, P2SH, P2WPKH, P2WSH, P2TR and hex public keys. Surrounding
    /// whitespace is ignored.
    public static func script(for text: String, network: Network) throws -> Data {
        let address = text.trimmingCharacters(in: .whitespacesAndNewlines)
        if let one = address.lastIndex(of: "1"), address.distance(from: address.startIndex, to: one) > 1 {
            let hrp = address[..<one].lowercased()
            if segwitHRPs.contains(hrp) {
                guard let decoded = Bech32.decodeSegwit(hrp: hrp, address) else {
                    throw AddressError("invalid address: not a valid segwit address")
                }
                guard decoded.version <= 1 else { throw AddressError("invalid address: unsupported witness version \(decoded.version)") }
                guard decoded.version == 0 || decoded.program.count == 32 else {
                    throw AddressError("invalid address: unsupported witness program of \(decoded.program.count) bytes")
                }
                guard hrp == network.bech32HRP else { throw AddressError("address is not for \(network.name)") }
                return Script.witnessProgram(version: decoded.version, program: decoded.program)
            }
        }
        if address.utf8.count == 66 || address.utf8.count == 130, let pubkey = Data(hex: address) {
            guard Secp256k1.isValidPublicKey(pubkey) else { throw AddressError("invalid address: not a valid public key") }
            return Script.p2pk(pubkey)
        }
        guard let payload = Base58.decodeCheck(address) else {
            throw AddressError("invalid address: decoded address is of unknown format")
        }
        guard payload.count == 21 else { throw AddressError("invalid address: decoded address is of unknown size") }
        let version = payload[payload.startIndex]
        let hash = payload.dropFirst()
        switch version {
        case network.pubKeyHashID: return Script.p2pkh(Data(hash))
        case network.scriptHashID: return Script.p2sh(Data(hash))
        default: throw AddressError("invalid address: unknown address type")
        }
    }

    /// Whether the text is an address payable on the network.
    public static func isValid(_ text: String, network: Network) -> Bool {
        (try? script(for: text, network: network)) != nil
    }

    public static func p2pkh(hash: Data, network: Network) -> String {
        Base58.encodeCheck(Data([network.pubKeyHashID]) + hash)
    }

    public static func p2sh(hash: Data, network: Network) -> String {
        Base58.encodeCheck(Data([network.scriptHashID]) + hash)
    }

    public static func segwit(version: UInt8, program: Data, network: Network) -> String {
        Bech32.encodeSegwit(hrp: network.bech32HRP, version: version, program: program)
    }

    /// The P2WPKH address of a compressed public key, as the wallet's BIP84
    /// addresses are.
    public static func p2wpkh(pubkey: Data, network: Network) -> String {
        segwit(version: 0, program: Hashes.hash160(pubkey), network: network)
    }

    /// The single address an output script pays, as btcd's
    /// ExtractPkScriptAddrs finds it, or nil for a script without one, such
    /// as OP_RETURN data or bare multisig.
    public static func of(script: Data, network: Network) -> String? {
        let s = [UInt8](script)
        switch s.count {
        case 25 where s[0] == Script.opDup && s[1] == Script.opHash160 && s[2] == 0x14 && s[23] == Script.opEqualVerify && s[24] == Script.opCheckSig:
            return p2pkh(hash: Data(s[3..<23]), network: network)
        case 23 where s[0] == Script.opHash160 && s[1] == 0x14 && s[22] == Script.opEqual:
            return p2sh(hash: Data(s[2..<22]), network: network)
        case 22 where s[0] == 0x00 && s[1] == 0x14:
            return segwit(version: 0, program: Data(s[2..<22]), network: network)
        case 34 where s[0] == 0x00 && s[1] == 0x20:
            return segwit(version: 0, program: Data(s[2..<34]), network: network)
        case 34 where s[0] == Script.op1 && s[1] == 0x20:
            return segwit(version: 1, program: Data(s[2..<34]), network: network)
        case 35 where s[0] == 0x21 && s[34] == Script.opCheckSig && (s[1] == 0x02 || s[1] == 0x03):
            return pubkeyAddress(Data(s[1..<34]), network: network)
        case 67 where s[0] == 0x41 && s[66] == Script.opCheckSig && (s[1] == 0x04 || s[1] == 0x06 || s[1] == 0x07):
            return pubkeyAddress(Data(s[1..<66]), network: network)
        default:
            return nil
        }
    }

    /// The P2PKH address of a pay-to-pubkey output, of the key as it is
    /// serialized there, when the key is valid.
    private static func pubkeyAddress(_ pubkey: Data, network: Network) -> String? {
        guard Secp256k1.isValidPublicKey(pubkey) else { return nil }
        return p2pkh(hash: Hashes.hash160(pubkey), network: network)
    }
}
