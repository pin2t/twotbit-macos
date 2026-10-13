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
    static let segwitHRPs: Set<String> = Set(Network.all.map(\.bech32HRP))

    public static func p2pkh(hash: Data, network: Network) -> String {
        (Data([network.pubKeyHashID]) + hash).base58ChecksumEncoded()
    }

    public static func p2sh(hash: Data, network: Network) -> String {
        (Data([network.scriptHashID]) + hash).base58ChecksumEncoded()
    }

    public static func segwit(version: UInt8, program: Data, network: Network) -> String {
        program.segwitEncoded(hrp: network.bech32HRP, version: version)
    }

    /// The P2WPKH address of a compressed public key, as the wallet's BIP84
    /// addresses are.
    public static func p2wpkh(pubkey: Data, network: Network) -> String {
        segwit(version: 0, program: pubkey.hash160(), network: network)
    }

    /// The P2PKH address of a pay-to-pubkey output, of the key as it is
    /// serialized there, when the key is valid.
    static func pubkeyAddress(_ pubkey: Data, network: Network) -> String? {
        guard Secp256k1.isValidPublicKey(pubkey) else { return nil }
        return p2pkh(hash: pubkey.hash160(), network: network)
    }
}

extension String {
    /// The output script paying the text as an address of the network,
    /// accepting what btcutil's DecodeAddress accepts for the network:
    /// P2PKH, P2SH, P2WPKH, P2WSH, P2TR and hex public keys. Surrounding
    /// whitespace is ignored.
    public func addressScript(network: Network) throws -> Data {
        let address = trimmingCharacters(in: .whitespacesAndNewlines)
        if let one = address.lastIndex(of: "1"), address.distance(from: address.startIndex, to: one) > 1 {
            let hrp = address[..<one].lowercased()
            if Address.segwitHRPs.contains(hrp) {
                guard let decoded = address.segwitDecoded(hrp: hrp) else {
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
        guard let payload = address.base58ChecksumDecoded() else {
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
    public func isValidAddress(network: Network) -> Bool {
        (try? addressScript(network: network)) != nil
    }
}

extension Data {
    /// The single address the output script pays, as btcd's
    /// ExtractPkScriptAddrs finds it, or nil for a script without one, such
    /// as OP_RETURN data or bare multisig.
    public func address(network: Network) -> String? {
        let s = [UInt8](self)
        switch s.count {
        case 25 where s[0] == Script.opDup && s[1] == Script.opHash160 && s[2] == 0x14 && s[23] == Script.opEqualVerify && s[24] == Script.opCheckSig:
            return Address.p2pkh(hash: Data(s[3..<23]), network: network)
        case 23 where s[0] == Script.opHash160 && s[1] == 0x14 && s[22] == Script.opEqual:
            return Address.p2sh(hash: Data(s[2..<22]), network: network)
        case 22 where s[0] == 0x00 && s[1] == 0x14:
            return Address.segwit(version: 0, program: Data(s[2..<22]), network: network)
        case 34 where s[0] == 0x00 && s[1] == 0x20:
            return Address.segwit(version: 0, program: Data(s[2..<34]), network: network)
        case 34 where s[0] == Script.op1 && s[1] == 0x20:
            return Address.segwit(version: 1, program: Data(s[2..<34]), network: network)
        case 35 where s[0] == 0x21 && s[34] == Script.opCheckSig && (s[1] == 0x02 || s[1] == 0x03):
            return Address.pubkeyAddress(Data(s[1..<34]), network: network)
        case 67 where s[0] == 0x41 && s[66] == Script.opCheckSig && (s[1] == 0x04 || s[1] == 0x06 || s[1] == 0x07):
            return Address.pubkeyAddress(Data(s[1..<66]), network: network)
        default:
            return nil
        }
    }
}
