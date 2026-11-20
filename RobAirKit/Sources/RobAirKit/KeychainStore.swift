// KeychainStore.swift
// Rôle : lecture/écriture d'éléments dans le Keychain avec la bonne protection (J1 §3.1, MASVS-STORAGE).
//   .afterFirstUnlock : accessible en arrière-plan après le 1er déverrouillage (K_balise, files, compteurs)
//   .biometry         : WhenUnlockedThisDeviceOnly + Face ID à chaque lecture, invalidé si les visages changent (K_vault)
//   .userPresence     : Touch ID ou mot de passe (Mac : clé maîtresse en repli logiciel)
// Tout est ThisDeviceOnly : jamais dans les sauvegardes. Aucun secret dans UserDefaults.

#if os(iOS) || os(macOS)
import Foundation
import Security
import LocalAuthentication

public struct KeychainStore {
    public enum Protection {
        case afterFirstUnlock
        case biometry
        case userPresence
    }

    public let service: String

    public init(service: String) { self.service = service }

    private func baseQuery(account: String?) -> [String: Any] {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service
        ]
        if let account { query[kSecAttrAccount as String] = account }
        #if os(macOS)
        // Keychain « moderne » (mêmes protections que sur iOS). Repli automatique si l'app n'a pas le droit.
        if KeychainStore.useDataProtectionKeychain {
            query[kSecUseDataProtectionKeychain as String] = true
        }
        #endif
        return query
    }

    #if os(macOS)
    nonisolated(unsafe) static var useDataProtectionKeychain = true
    #endif

    public func save(_ data: Data, account: String, protection: Protection = .afterFirstUnlock) throws {
        delete(account: account)
        var query = baseQuery(account: account)
        query[kSecValueData as String] = data
        switch protection {
        case .afterFirstUnlock:
            query[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        case .biometry, .userPresence:
            let flags: SecAccessControlCreateFlags = protection == .biometry ? .biometryCurrentSet : .userPresence
            guard let access = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, flags, nil) else {
                throw RobAirError.keychain(errSecParam)
            }
            query[kSecAttrAccessControl as String] = access
        }
        var status = SecItemAdd(query as CFDictionary, nil)
        #if os(macOS)
        if status == errSecMissingEntitlement, KeychainStore.useDataProtectionKeychain {
            KeychainStore.useDataProtectionKeychain = false
            try save(data, account: account, protection: protection)
            return
        }
        #endif
        if status == errSecDuplicateItem {
            delete(account: account)
            status = SecItemAdd(query as CFDictionary, nil)
        }
        guard status == errSecSuccess else { throw RobAirError.keychain(status) }
    }

    /// Lit un élément. Pour un élément protégé, passer un LAContext déjà validé.
    public func load(account: String, context: LAContext? = nil) throws -> Data? {
        var query = baseQuery(account: account)
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        if let context { query[kSecUseAuthenticationContext as String] = context }
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        switch status {
        case errSecSuccess: return result as? Data
        case errSecItemNotFound: return nil
        default: throw RobAirError.keychain(status)
        }
    }

    public func delete(account: String) {
        SecItemDelete(baseQuery(account: account) as CFDictionary)
    }

    /// Supprime tous les éléments de ce service (réinitialisation, réappairage).
    public func deleteAll() {
        SecItemDelete(baseQuery(account: nil) as CFDictionary)
    }

    // Petits utilitaires JSON pour les données non secrètes mais dont l'INTÉGRITÉ compte (clés épinglées…).
    public func saveJSON<T: Encodable>(_ value: T, account: String) throws {
        try save(try JSONEncoder().encode(value), account: account)
    }

    public func loadJSON<T: Decodable>(_ type: T.Type, account: String) -> T? {
        guard let data = try? load(account: account) else { return nil }
        return try? JSONDecoder().decode(T.self, from: data)
    }
}
#endif
