// EncryptionKey.swift
// Rôle : clé publique HPKE du Mac (K_enc_Mac, X25519), qui sert à chiffrer la télémétrie (J1 §3.1, §3.5).
// Rotation hebdomadaire : chaque nouvelle clé publique est SIGNÉE par K_id_Mac, et l'iPhone vérifie
// la signature avec la clé du Mac épinglée à l'appairage. Un attaquant ne peut donc pas lui faire
// chiffrer la télémétrie pour sa propre clé.
// `epoch` numérote les clés : l'enveloppe de télémétrie l'indique, le Mac sait quelle clé privée utiliser.

import Foundation
import CryptoKit

public struct SignedEncryptionKey: WireMessage, Equatable {
    public let epoch: UInt32
    public let publicKey: Data          // X25519, 32 octets
    public let notBeforeMs: UInt64
    public let signature: Data          // Sig_K_id_Mac(étiquette ‖ epoch ‖ clé ‖ notBefore)

    static func signedMessage(epoch: UInt32, publicKey: Data, notBeforeMs: UInt64) -> Data {
        var message = Data(label: Label.encryptionKey)
        message.appendUInt32BE(epoch)
        message.append(publicKey)
        message.appendUInt64BE(notBeforeMs)
        return message
    }

    public static func make(epoch: UInt32, key: Curve25519.KeyAgreement.PublicKey, signer: SigningIdentity,
                            now: Date = Date()) throws -> SignedEncryptionKey {
        let ms = now.millisecondsSince1970
        let raw = key.rawRepresentation
        let sig = try signer.signature(for: signedMessage(epoch: epoch, publicKey: raw, notBeforeMs: ms))
        return SignedEncryptionKey(epoch: epoch, publicKey: raw, notBeforeMs: ms, signature: sig.rawRepresentation)
    }

    public func validate() throws {
        try requireLength(publicKey, RobAirConstants.x25519KeySize, "publicKey")
        try requireLength(signature, RobAirConstants.p256SignatureSize, "signature")
    }

    /// Côté iPhone : vérifie la signature du Mac et renvoie la clé utilisable.
    public func verified(by macKey: P256.Signing.PublicKey) throws -> Curve25519.KeyAgreement.PublicKey {
        try validate()
        guard macKey.isValidSignature(raw: signature, for: Self.signedMessage(epoch: epoch, publicKey: publicKey, notBeforeMs: notBeforeMs)) else {
            throw RobAirError.invalidSignature
        }
        return try HandshakeMath.x25519(publicKey)
    }

    /// Une clé plus récente (epoch supérieur) remplace l'ancienne ; jamais l'inverse (pas de retour en arrière).
    public func isNewer(than other: SignedEncryptionKey?) -> Bool {
        guard let other else { return true }
        return epoch > other.epoch
    }
}
