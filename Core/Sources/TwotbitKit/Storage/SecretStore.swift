import Foundation
import Security
import Synchronization

/// SecretStore keeps the wallet's recovery phrase, under an account name:
/// the wallet's account xpub.
public protocol SecretStore: Sendable {
    func secret(account: String) throws -> String?
    func setSecret(_ secret: String, account: String, label: String) throws
    func deleteSecret(account: String) throws
}

public struct KeychainError: Error, CustomStringConvertible, Sendable {
    public let status: OSStatus
    public var description: String {
        let message = SecCopyErrorMessageString(status, nil) as String? ?? "unknown error"
        return "Keychain: \(message) (\(status))"
    }
}

/// KeychainSecretStore keeps secrets as generic passwords in the user's
/// login keychain, readable only by this app without the user's consent.
public struct KeychainSecretStore: SecretStore {
    public let service: String

    public init(service: String) { self.service = service }

    private func query(_ account: String) -> [String: Any] {
        [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service, kSecAttrAccount as String: account]
    }

    public func secret(account: String) throws -> String? {
        var q = query(account)
        q[kSecReturnData as String] = true
        q[kSecMatchLimit as String] = kSecMatchLimitOne
        var item: CFTypeRef?
        let status = SecItemCopyMatching(q as CFDictionary, &item)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess, let data = item as? Data else { throw KeychainError(status: status) }
        return String(decoding: data, as: UTF8.self)
    }

    public func setSecret(_ secret: String, account: String, label: String) throws {
        let data = Data(secret.utf8)
        let update = SecItemUpdate(query(account) as CFDictionary, [kSecValueData as String: data] as CFDictionary)
        if update == errSecSuccess { return }
        guard update == errSecItemNotFound else { throw KeychainError(status: update) }
        var q = query(account)
        q[kSecValueData as String] = data
        q[kSecAttrLabel as String] = label
        q[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        let status = SecItemAdd(q as CFDictionary, nil)
        guard status == errSecSuccess else { throw KeychainError(status: status) }
    }

    public func deleteSecret(account: String) throws {
        let status = SecItemDelete(query(account) as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else { throw KeychainError(status: status) }
    }
}

/// MemorySecretStore keeps secrets in memory, for tests.
public final class MemorySecretStore: SecretStore {
    private let secrets = Mutex<[String: String]>([:])

    public init() {}

    public func secret(account: String) throws -> String? { secrets.withLock { $0[account] } }
    public func setSecret(_ secret: String, account: String, label: String) throws { secrets.withLock { $0[account] = secret } }
    public func deleteSecret(account: String) throws { _ = secrets.withLock { $0.removeValue(forKey: account) } }
}

public enum WalletError: Error, Equatable, Sendable, CustomStringConvertible {
    case wrongNetwork(stored: String, requested: String)
    case missingRecoveryPhrase
    case recoveryPhraseMismatch

    public var description: String {
        switch self {
        case let .wrongNetwork(stored, requested): return "wallet database is for network \"\(stored)\", not \"\(requested)\""
        case .missingRecoveryPhrase: return "the wallet's recovery phrase is not in the Keychain"
        case .recoveryPhraseMismatch: return "the recovery phrase belongs to another wallet"
        }
    }
}

/// OpenedWallet is the wallet database with the wallet it holds.
public struct OpenedWallet: Sendable {
    public let store: Store
    public let wallet: HDWallet
    public let meta: WalletMeta
}

/// WalletLoader opens the wallet database of a network in the data
/// directory, creating the wallet on first run with a fresh 12-word
/// recovery phrase kept in the secret store.
public enum WalletLoader {
    /// The label of the Keychain item of the network's recovery phrase.
    static func label(_ network: Network) -> String { "Twotbit recovery phrase (\(network.displayName))" }

    public static func open(dataDirectory: URL, network: Network, secrets: any SecretStore, now: Date = Date()) throws -> OpenedWallet {
        let store = try Store.open(path: dataDirectory.appendingPathComponent(network.databaseFileName).path)
        do {
            return try open(store: store, network: network, secrets: secrets, now: now)
        } catch {
            store.close()
            throw error
        }
    }

    static func open(store: Store, network: Network, secrets: any SecretStore, now: Date) throws -> OpenedWallet {
        let keychain = network.keepsPhraseInKeychain
        guard let meta = try store.meta() else {
            let mnemonic = try BIP39.generateMnemonic()
            let wallet = try HDWallet(mnemonic: mnemonic, network: network)
            if keychain { try secrets.setSecret(mnemonic, account: wallet.accountXPub, label: label(network)) }
            try store.saveMeta(mnemonic: keychain ? "" : mnemonic, xpub: wallet.accountXPub, network: network.displayName,
                               createdAt: Int64(now.timeIntervalSince1970))
            Log.info("wallet created on \(network.displayName), account \(wallet.accountXPub)")
            return OpenedWallet(store: store, wallet: wallet, meta: try store.meta()!)
        }
        guard Network.named(meta.network) == network else {
            throw WalletError.wrongNetwork(stored: meta.network, requested: network.displayName)
        }
        if !meta.mnemonic.isEmpty {
            let wallet = try HDWallet(mnemonic: meta.mnemonic, network: network)
            guard keychain else { return OpenedWallet(store: store, wallet: wallet, meta: meta) }
            try secrets.setSecret(meta.mnemonic, account: meta.xpub, label: label(network))
            try store.setMnemonic("")
            Log.info("wallet recovery phrase moved from the database to the Keychain")
            return OpenedWallet(store: store, wallet: wallet, meta: try store.meta()!)
        }
        guard let mnemonic = try secrets.secret(account: meta.xpub) else { throw WalletError.missingRecoveryPhrase }
        let wallet = try HDWallet(mnemonic: mnemonic, network: network)
        guard wallet.accountXPub == meta.xpub else { throw WalletError.recoveryPhraseMismatch }
        return OpenedWallet(store: store, wallet: wallet, meta: meta)
    }

    /// Restores the recovery phrase of the wallet in the database to the
    /// secret store, after the Keychain lost it: the phrase must derive the
    /// stored account xpub.
    public static func restore(mnemonic: String, dataDirectory: URL, network: Network, secrets: any SecretStore) throws {
        let store = try Store.open(path: dataDirectory.appendingPathComponent(network.databaseFileName).path)
        defer { store.close() }
        guard let meta = try store.meta() else { return }
        let normalized = mnemonic.split(whereSeparator: { $0.isWhitespace }).joined(separator: " ").lowercased()
        let wallet = try HDWallet(mnemonic: normalized, network: network)
        guard wallet.accountXPub == meta.xpub else { throw WalletError.recoveryPhraseMismatch }
        try secrets.setSecret(normalized, account: meta.xpub, label: label(network))
    }
}
