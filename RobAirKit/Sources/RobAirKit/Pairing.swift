// Pairing.swift
// Rôle : appairage iPhone ↔ Mac par QR code. Voir docs/J2-architecture.md §3.
//
// 1. Le Mac affiche un QR : {version, nom Bonjour, clé publique du Mac, jeton T, expiration}
// 2. L'iPhone épingle la clé du Mac (canal visuel = de confiance)
// 3. L'iPhone envoie ses 2 clés publiques + HMAC_T(...) : preuve qu'il a vu le QR
// 4. Les deux écrans affichent un code SAS à 6 chiffres ; l'utilisateur compare et confirme sur le Mac
// 5. Le Mac renvoie une confirmation signée
//
// Menaces : S1 (homme du milieu à l'appairage), S3 (faux iPhone).
// Points de relecture : jeton à usage unique, expiration, comparaison HMAC en temps constant.

import Foundation
import CryptoKit

public struct PairingInvitation: Codable, Equatable {
    public let version: UInt8
    public let serviceName: String
    public let macIdentityKey: Data
    public let token: Data
    public let expiresAtMs: UInt64

    public func encodedForQRCode() throws -> String {
        String(decoding: try RobAirJSON.encode(self), as: UTF8.self)
    }

    /// Décode ET valide le contenu d'un QR code (il vient de l'extérieur : on ne lui fait pas confiance).
    public static func decode(qrCode: String, now: Date = Date()) throws -> PairingInvitation {
        guard qrCode.utf8.count <= 1024 else { throw RobAirError.frameTooLarge }
        let invitation = try RobAirJSON.decode(PairingInvitation.self, from: Data(qrCode.utf8))
        guard invitation.version == RobAirConstants.protocolVersion else { throw RobAirError.unsupportedVersion }
        guard !invitation.serviceName.isEmpty, invitation.serviceName.utf8.count <= 63 else {
            throw RobAirError.malformed("serviceName")
        }
        try requireLength(invitation.token, RobAirConstants.pairingTokenSize, "token")
        _ = try invitation.macPublicKey()
        guard now.millisecondsSince1970 <= invitation.expiresAtMs else { throw RobAirError.expired }
        return invitation
    }

    public func macPublicKey() throws -> P256.Signing.PublicKey {
        try requireLength(macIdentityKey, RobAirConstants.p256PublicKeySize, "macIdentityKey")
        return try P256.Signing.PublicKey(x963Representation: macIdentityKey)
    }
}

public struct PairingRequest: Codable, Equatable {
    public let identityKey: Data     // K_id_I (publique)
    public let biometricKey: Data    // K_bio_I (publique)
    public let proof: Data           // HMAC-SHA256(T, ...)
}

public struct PairingResult: Codable, Equatable {
    public let accepted: Bool
    public let signature: Data       // signature du Mac sur la confirmation (vide si refus)
}

public enum PairingCrypto {
    static func proofMessage(identityKey: Data, biometricKey: Data, macKey: Data) -> Data {
        concat(Data(label: Label.pairingProof), identityKey, biometricKey, macKey)
    }

    public static func makeRequest(invitation: PairingInvitation,
                                   identityKey: P256.Signing.PublicKey,
                                   biometricKey: P256.Signing.PublicKey) -> PairingRequest {
        let id = identityKey.x963Representation
        let bio = biometricKey.x963Representation
        let mac = HMAC<SHA256>.authenticationCode(
            for: proofMessage(identityKey: id, biometricKey: bio, macKey: invitation.macIdentityKey),
            using: SymmetricKey(data: invitation.token))
        return PairingRequest(identityKey: id, biometricKey: bio, proof: Data(mac))
    }

    /// Code de vérification à 6 chiffres affiché des deux côtés (Short Authentication String).
    public static func sas(macKey: Data, identityKey: Data, biometricKey: Data) -> String {
        let digest = Array(SHA256.hash(data: concat(Data(label: Label.sas), macKey, identityKey, biometricKey)))
        let value = (UInt32(digest[0]) << 24 | UInt32(digest[1]) << 16 | UInt32(digest[2]) << 8 | UInt32(digest[3])) % 1_000_000
        let digits = String(format: "%06u", value)
        return String(digits.prefix(3)) + " " + String(digits.suffix(3))
    }

    static func confirmationMessage(identityKey: Data, biometricKey: Data) -> Data {
        concat(Data(label: Label.pairingConfirm), identityKey, biometricKey)
    }

    /// Côté Mac : signature envoyée à l'iPhone une fois le SAS confirmé par l'utilisateur.
    public static func makeResult(accepted: Bool, request: PairingRequest, macIdentity: SigningIdentity) throws -> PairingResult {
        guard accepted else { return PairingResult(accepted: false, signature: Data()) }
        let sig = try macIdentity.signature(for: confirmationMessage(identityKey: request.identityKey,
                                                                     biometricKey: request.biometricKey))
        return PairingResult(accepted: true, signature: sig.rawRepresentation)
    }

    /// Côté iPhone : vérifie que la confirmation vient bien du Mac dont on a scanné le QR.
    public static func verify(result: PairingResult, request: PairingRequest, macKey: P256.Signing.PublicKey) -> Bool {
        result.accepted && macKey.isValidSignature(raw: result.signature,
                                                   for: confirmationMessage(identityKey: request.identityKey,
                                                                            biometricKey: request.biometricKey))
    }
}

/// Côté Mac : une invitation en cours. Usage unique, durée de vie limitée, 3 essais maximum.
public final class PairingSession {
    public let invitation: PairingInvitation
    public private(set) var isConsumed = false
    private var attempts = 0

    public init(serviceName: String, macIdentityKey: P256.Signing.PublicKey, now: Date = Date()) {
        invitation = PairingInvitation(
            version: RobAirConstants.protocolVersion,
            serviceName: serviceName,
            macIdentityKey: macIdentityKey.x963Representation,
            token: SecureRandom.bytes(RobAirConstants.pairingTokenSize),
            expiresAtMs: now.addingTimeInterval(RobAirConstants.pairingTokenLifetime).millisecondsSince1970)
    }

    public func isExpired(now: Date = Date()) -> Bool {
        now.millisecondsSince1970 > invitation.expiresAtMs
    }

    /// Valide une demande d'appairage. En cas de succès, l'invitation est consommée.
    public func validate(_ request: PairingRequest, now: Date = Date())
        throws -> (identityKey: P256.Signing.PublicKey, biometricKey: P256.Signing.PublicKey) {
        guard !isConsumed else { throw RobAirError.tokenAlreadyUsed }
        guard !isExpired(now: now) else { throw RobAirError.expired }
        attempts += 1
        if attempts >= RobAirConstants.pairingMaxAttempts { isConsumed = true }

        try requireLength(request.identityKey, RobAirConstants.p256PublicKeySize, "identityKey")
        try requireLength(request.biometricKey, RobAirConstants.p256PublicKeySize, "biometricKey")
        let identity = try P256.Signing.PublicKey(x963Representation: request.identityKey)
        let biometric = try P256.Signing.PublicKey(x963Representation: request.biometricKey)

        // SÉCURITÉ : comparaison en temps constant (pas de ==).
        let valid = HMAC<SHA256>.isValidAuthenticationCode(
            request.proof,
            authenticating: PairingCrypto.proofMessage(identityKey: request.identityKey,
                                                       biometricKey: request.biometricKey,
                                                       macKey: invitation.macIdentityKey),
            using: SymmetricKey(data: invitation.token))
        guard valid else { throw RobAirError.authenticationFailed }
        isConsumed = true
        return (identity, biometric)
    }
}
