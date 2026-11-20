// BLEProof.swift
// Rôle : preuve de proximité par défi-réponse BLE. Voir docs/J2-architecture.md §6.
//   iPhone → Mac : défi (16 octets aléatoires) ‖ empreinte de l'iPhone (32 octets)
//   Mac → iPhone : Sig_K_id_M(étiquette ‖ défi ‖ empreinte)
// Menace S2 : un clone de l'annonce BLE ne sait pas produire cette signature.
// Risque résiduel : relais BLE (voir J1 §6).

import Foundation
import CryptoKit

public enum BLEProof {
    /// UUID de la caractéristique GATT (écriture du défi + notification de la réponse).
    public static let characteristicUUID = "B8E4C3A2-5D1F-4E7A-9C3B-2F6D8A1E0C47"

    /// UUID de service propre à chaque Mac, dérivé de sa clé publique.
    /// Dans une salle où plusieurs groupes testent, chaque iPhone ne cherche que SON Mac.
    /// (Un attaquant peut copier cet UUID : c'est la signature qui protège, pas l'UUID.)
    public static func serviceUUID(for macKey: P256.Signing.PublicKey) -> String {
        var bytes = Array(SHA256.hash(data: concat(Data(label: Label.bleServiceUUID), macKey.x963Representation)).prefix(16))
        bytes[6] = (bytes[6] & 0x0F) | 0x40   // format UUID version 4
        bytes[8] = (bytes[8] & 0x3F) | 0x80   // variante RFC 4122
        let hex = bytes.map { String(format: "%02X", $0) }.joined()
        let chars = Array(hex)
        let groups = [0..<8, 8..<12, 12..<16, 16..<20, 20..<32].map { String(chars[$0]) }
        return groups.joined(separator: "-")
    }

    public static func makeChallenge() -> Data {
        SecureRandom.bytes(RobAirConstants.challengeSize)
    }

    public static func request(challenge: Data, fingerprint: Data) -> Data {
        concat(challenge, fingerprint)
    }

    static func parse(request: Data) throws -> (challenge: Data, fingerprint: Data) {
        try requireLength(request, RobAirConstants.challengeSize + RobAirConstants.fingerprintSize, "bleRequest")
        return (request.bytes(0..<RobAirConstants.challengeSize),
                request.bytes(RobAirConstants.challengeSize..<request.count))
    }

    static func message(challenge: Data, fingerprint: Data) -> Data {
        concat(Data(label: Label.bleProof), challenge, fingerprint)
    }

    /// Côté Mac : signe le défi, uniquement pour l'iPhone appairé.
    public static func respond(to request: Data, identity: SigningIdentity, allowedFingerprint: Data) throws -> Data {
        let parsed = try parse(request: request)
        guard parsed.fingerprint == allowedFingerprint else { throw RobAirError.unknownDevice }
        return try identity.signature(for: message(challenge: parsed.challenge, fingerprint: parsed.fingerprint)).rawRepresentation
    }

    /// Côté iPhone : vérifie la réponse avec la clé du Mac épinglée.
    public static func verify(response: Data, challenge: Data, fingerprint: Data, macKey: P256.Signing.PublicKey) -> Bool {
        macKey.isValidSignature(raw: response, for: message(challenge: challenge, fingerprint: fingerprint))
    }
}
