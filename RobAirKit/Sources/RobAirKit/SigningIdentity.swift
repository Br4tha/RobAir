// SigningIdentity.swift
// Rôle : abstraction « quelque chose qui sait signer » (clé Secure Enclave ou clé logicielle).
// Le reste du code ne sait pas où est la clé : il appelle seulement signature(for:).
// Inventaire des clés (J1 §3.1) :
//   K_id_iPhone  : Secure Enclave, WhenUnlockedThisDeviceOnly + biometryCurrentSet (Face ID)
//   K_tel_iPhone : Secure Enclave, AfterFirstUnlockThisDeviceOnly, sans biométrie, TÉLÉMÉTRIE SEULEMENT
//   K_id_Mac     : Secure Enclave du Mac, Touch ID ou mot de passe de session à chaque signature
// Menaces : S, R (signatures), I (clés non exportables), E (Face ID contourné / visage ajouté).

import Foundation
import CryptoKit
#if os(iOS) || os(macOS)
import Security
import LocalAuthentication
#endif

public protocol SigningIdentity {
    var publicKey: P256.Signing.PublicKey { get }
    func signature(for message: Data) throws -> P256.Signing.ECDSASignature
}

/// Clé logicielle : tests, simulateur, et repli sur un Mac sans Secure Enclave utilisable.
public struct SoftwareSigningIdentity: SigningIdentity {
    public let privateKey: P256.Signing.PrivateKey

    public init(privateKey: P256.Signing.PrivateKey = P256.Signing.PrivateKey()) {
        self.privateKey = privateKey
    }

    public var publicKey: P256.Signing.PublicKey { privateKey.publicKey }

    public func signature(for message: Data) throws -> P256.Signing.ECDSASignature {
        try privateKey.signature(for: message)
    }
}

/// Politique d'accès d'une clé de signature.
public enum KeyPolicy {
    /// K_id_iPhone : chaque usage exige Face ID ; ajouter un visage invalide la clé (E2).
    case biometric
    /// K_tel_iPhone : utilisable téléphone verrouillé (après le 1er déverrouillage), pour la télémétrie.
    case background
    /// K_id_Mac : Touch ID ou mot de passe de session de l'opérateur.
    case userPresence
}

#if os(iOS) || os(macOS)
extension KeyPolicy {
    var accessControl: SecAccessControl? {
        let protection: CFString
        let flags: SecAccessControlCreateFlags
        switch self {
        case .biometric:
            protection = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
            flags = [.privateKeyUsage, .biometryCurrentSet]
        case .background:
            protection = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
            flags = [.privateKeyUsage]
        case .userPresence:
            protection = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
            flags = [.privateKeyUsage, .userPresence]
        }
        // SÉCURITÉ : ThisDeviceOnly = jamais dans les sauvegardes ni sur un autre appareil.
        return SecAccessControlCreateWithFlags(nil, protection, flags, nil)
    }
}

/// Clé dans la Secure Enclave : la clé privée ne quitte JAMAIS la puce.
/// `dataRepresentation` est un blob chiffré par la puce, inutilisable sur un autre appareil.
public struct SecureEnclaveSigningIdentity: SigningIdentity {
    public let privateKey: SecureEnclave.P256.Signing.PrivateKey

    public var publicKey: P256.Signing.PublicKey { privateKey.publicKey }

    /// ATTENTION : pour une clé .biometric ou .userPresence, cet appel peut afficher Face ID / Touch ID
    /// et bloquer : ne jamais l'appeler sur le thread principal.
    public func signature(for message: Data) throws -> P256.Signing.ECDSASignature {
        try privateKey.signature(for: message)
    }

    public static func create(_ policy: KeyPolicy) throws -> SecureEnclaveSigningIdentity {
        guard SecureEnclave.isAvailable, let access = policy.accessControl else { throw RobAirError.secureEnclaveUnavailable }
        let key = try SecureEnclave.P256.Signing.PrivateKey(compactRepresentable: false, accessControl: access)
        return SecureEnclaveSigningIdentity(privateKey: key)
    }

    /// Recharge une clé à partir de son blob. `context` : LAContext déjà validé (Face ID / Touch ID),
    /// pour ne pas redemander l'authentification à chaque signature.
    public static func load(_ blob: Data, context: LAContext? = nil) throws -> SecureEnclaveSigningIdentity {
        let key = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: blob, authenticationContext: context)
        return SecureEnclaveSigningIdentity(privateKey: key)
    }
}
#endif
