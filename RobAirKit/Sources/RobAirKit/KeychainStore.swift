// KeychainStore.swift
// Rôle : lecture/écriture d'éléments dans le Keychain avec la bonne protection (J2 §8).
//   .afterFirstUnlock : accessible en arrière-plan après le 1er déverrouillage, jamais sauvegardé (ThisDeviceOnly)
//   .biometry         : exige Face ID à chaque lecture, invalidé si les visages changent (biometryCurrentSet)
// Menaces : I3 (vol de l'appareil), E1/E2 (contournement de Face ID).

#if os(iOS) || os(macOS)
import Foundation
import Security
import LocalAuthentication

public struct KeychainStore {
    public enum Protection {
        case afterFirstUnlock
        case biometry
    }

    public let service: String

    public init(service: String) { self.service = service }

    private func baseQuery(account: String) -> [String: Any] {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account
        ]
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
        case .biometry:
            var error: Unmanaged<CFError>?
            guard let access = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
                                                               .biometryCurrentSet, &error) else {
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

    /// Lit un élément. Pour un élément biométrique, passer un LAContext déjà validé par Face ID.
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

    /// Supprime tous les éléments de ce service (réinitialisation).
    public func deleteAll() {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service
        ]
        #if os(macOS)
        if KeychainStore.useDataProtectionKeychain { query[kSecUseDataProtectionKeychain as String] = true }
        #endif
        SecItemDelete(query as CFDictionary)
    }
}
#endif
