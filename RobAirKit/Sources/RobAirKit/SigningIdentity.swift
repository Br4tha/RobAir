// SigningIdentity.swift
// Rôle : abstraction « quelque chose qui sait signer » (clé Secure Enclave ou clé logicielle).
// Le reste du code ne sait pas où est la clé : il appelle seulement signature(for:).
// Menaces : S1, S3, R1 (signatures), I3 (clés non exportables).

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

/// Clé logicielle : utilisée pour les tests, le simulateur, et en repli sur un Mac sans Secure Enclave.
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

#if os(iOS) || os(macOS)
/// Clé dans la Secure Enclave : la clé privée ne quitte JAMAIS la puce.
/// `dataRepresentation` est un blob chiffré par la puce, inutilisable sur un autre appareil.
public struct SecureEnclaveSigningIdentity: SigningIdentity {
    public let privateKey: SecureEnclave.P256.Signing.PrivateKey

    public var publicKey: P256.Signing.PublicKey { privateKey.publicKey }

    public func signature(for message: Data) throws -> P256.Signing.ECDSASignature {
        try privateKey.signature(for: message)
    }

    /// Crée une nouvelle clé dans la Secure Enclave.
    /// - biometric = false : clé de routine (K_id), utilisable en arrière-plan après le premier déverrouillage.
    /// - biometric = true  : clé sensible (K_bio), chaque usage exige Face ID ; invalidée si les visages enregistrés changent.
    public static func create(biometric: Bool) throws -> SecureEnclaveSigningIdentity {
        guard SecureEnclave.isAvailable else { throw RobAirError.secureEnclaveUnavailable }
        // SÉCURITÉ : ThisDeviceOnly = jamais dans les sauvegardes ni sur un autre appareil.
        let protection = biometric
            ? kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly
            : kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        // SÉCURITÉ : biometryCurrentSet = ajouter un visage invalide la clé (menace E2).
        let flags: SecAccessControlCreateFlags = biometric
            ? [.privateKeyUsage, .biometryCurrentSet]
            : [.privateKeyUsage]
        var error: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(nil, protection, flags, &error) else {
            throw RobAirError.secureEnclaveUnavailable
        }
        let key = try SecureEnclave.P256.Signing.PrivateKey(compactRepresentable: false, accessControl: access)
        return SecureEnclaveSigningIdentity(privateKey: key)
    }

    /// Recharge une clé à partir de son blob. Pour une clé biométrique, passer un LAContext déjà validé par Face ID.
    public static func load(_ blob: Data, context: LAContext? = nil) throws -> SecureEnclaveSigningIdentity {
        let key = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: blob, authenticationContext: context)
        return SecureEnclaveSigningIdentity(privateKey: key)
    }
}
#endif
