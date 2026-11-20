// Challenges.swift
// Rôle : les deux défis-réponses du projet.
//
// A. Authentification forte Mac → iPhone (J1 §3.7, sujet p.18) — actions sensibles vues depuis le Mac :
//    1. le Mac envoie un défi aléatoire de 32 octets, à usage unique, valable 30 s ;
//    2. l'iPhone demande Face ID, ce qui débloque K_id_iPhone dans la Secure Enclave, et signe
//       {défi, mac_id, iphone_id, action} ;
//    3. le Mac vérifie avec la clé enregistrée à l'appairage, puis CONSOMME le défi.
//
// B. Déverrouillage de secours iPhone → Mac → iPhone (J1 §3.8) — fausse alerte + échecs Face ID :
//    1. l'iPhone génère un défi c (32 octets, 120 s, usage unique), l'envoie au Mac ET l'affiche en QR ;
//    2. l'opérateur du Mac s'authentifie (Touch ID / mot de passe) et le Mac signe
//       {EMERGENCY_UNLOCK, c, iphone_id, timestamp} avec K_id_Mac ;
//    3. la réponse revient par le réseau local ou par QR code ;
//    4. l'iPhone vérifie signature, défi en attente, expiration, puis CONSOMME c.
//    Périmètre : lève le verrouillage de RobAir, pas celui d'iOS. Le coffre exige toujours Face ID.
//
// Menaces : S (faux Mac envoyant un faux déverrouillage), rejeu, E (contourner l'écran d'alerte).

import Foundation
import CryptoKit

// MARK: - A. Défi Mac → iPhone

public enum ChallengeAction: String, Codable, CaseIterable {
    case endAlert       // « j'ai retrouvé mon téléphone »
    case disarm         // désarmement de la surveillance
    case configChange   // changement de configuration
}

public struct MacChallenge: WireMessage, Equatable {
    public let challenge: Data
    public let action: ChallengeAction
    public let expiresAtMs: UInt64

    public func validate() throws {
        try requireLength(challenge, RobAirConstants.macChallengeSize, "challenge")
    }
}

public struct ChallengeResponse: WireMessage, Equatable {
    public let challenge: Data
    public let action: ChallengeAction
    public let signature: Data

    public func validate() throws {
        try requireLength(challenge, RobAirConstants.macChallengeSize, "challenge")
        try requireLength(signature, RobAirConstants.p256SignatureSize, "signature")
    }
}

public enum ChallengeCrypto {
    static func signedMessage(challenge: Data, macID: Data, iphoneID: Data, action: ChallengeAction) -> Data {
        var message = concat(Data(label: Label.macChallenge), challenge, macID, iphoneID)
        message.appendLengthPrefixed(Data(action.rawValue.utf8))
        return message
    }

    /// Côté iPhone, APRÈS Face ID : `signer` = K_id_iPhone chargée avec le LAContext validé.
    public static func respond(to challenge: MacChallenge, signer: SigningIdentity, macID: Data,
                               now: Date = Date()) throws -> ChallengeResponse {
        try challenge.validate()
        guard now.millisecondsSince1970 <= challenge.expiresAtMs else { throw RobAirError.expired }
        let sig = try signer.signature(for: signedMessage(challenge: challenge.challenge, macID: macID,
                                                          iphoneID: DeviceID.of(signer.publicKey), action: challenge.action))
        return ChallengeResponse(challenge: challenge.challenge, action: challenge.action, signature: sig.rawRepresentation)
    }
}

/// Côté Mac : émet les défis et les consomme. Un défi ne peut être présenté qu'UNE fois, même faux.
public final class ChallengeIssuer {
    private var pending: [Data: (action: ChallengeAction, expiresAtMs: UInt64)] = [:]

    public init() {}

    public func issue(_ action: ChallengeAction, now: Date = Date()) -> MacChallenge {
        purge(now: now)
        let challenge = MacChallenge(challenge: SecureRandom.bytes(RobAirConstants.macChallengeSize), action: action,
                                     expiresAtMs: now.addingTimeInterval(RobAirConstants.macChallengeLifetime).millisecondsSince1970)
        pending[challenge.challenge] = (action, challenge.expiresAtMs)
        return challenge
    }

    /// Renvoie l'action autorisée. Toute erreur laisse le défi consommé (fail-safe).
    public func verify(_ response: ChallengeResponse, iphoneKey: P256.Signing.PublicKey, macID: Data,
                       now: Date = Date()) throws -> ChallengeAction {
        try response.validate()
        guard let entry = pending.removeValue(forKey: response.challenge) else { throw RobAirError.tokenAlreadyUsed }
        guard now.millisecondsSince1970 <= entry.expiresAtMs else { throw RobAirError.expired }
        // L'action signée doit être celle du défi : on ne peut pas transformer un « désarmer » en « fin d'alerte ».
        guard entry.action == response.action else { throw RobAirError.invalidSignature }
        let message = ChallengeCrypto.signedMessage(challenge: response.challenge, macID: macID,
                                                    iphoneID: DeviceID.of(iphoneKey), action: response.action)
        guard iphoneKey.isValidSignature(raw: response.signature, for: message) else { throw RobAirError.invalidSignature }
        return entry.action
    }

    public var pendingCount: Int { pending.count }

    private func purge(now: Date) {
        let nowMs = now.millisecondsSince1970
        pending = pending.filter { $0.value.expiresAtMs >= nowMs }
    }
}

// MARK: - B. Déverrouillage de secours

public struct EmergencyRequest: WireMessage, Equatable {
    public let iphoneID: Data
    public let challenge: Data
    public let expiresAtMs: UInt64

    public func validate() throws {
        try requireLength(iphoneID, RobAirConstants.deviceIDSize, "iphoneID")
        try requireLength(challenge, RobAirConstants.emergencyChallengeSize, "challenge")
    }

    /// Code à 6 chiffres affiché sur l'iPhone ET sur le Mac : l'opérateur vérifie que la demande
    /// vient bien de l'iPhone qu'il a sous les yeux (une demande réseau peut être forgée).
    public var shortCode: String { EmergencyCrypto.shortCode(challenge) }
}

public struct EmergencyGrant: WireMessage, Equatable {
    public let iphoneID: Data
    public let challenge: Data
    public let timestampMs: UInt64
    public let signature: Data

    public func validate() throws {
        try requireLength(iphoneID, RobAirConstants.deviceIDSize, "iphoneID")
        try requireLength(challenge, RobAirConstants.emergencyChallengeSize, "challenge")
        try requireLength(signature, RobAirConstants.p256SignatureSize, "signature")
    }
}

public enum EmergencyCrypto {
    static let action = "EMERGENCY_UNLOCK"

    static func signedMessage(challenge: Data, iphoneID: Data, timestampMs: UInt64) -> Data {
        var message = Data(label: Label.emergencyUnlock)
        message.appendLengthPrefixed(Data(action.utf8))
        message.append(challenge)
        message.append(iphoneID)
        message.appendUInt64BE(timestampMs)
        return message
    }

    static func shortCode(_ challenge: Data) -> String {
        let d = Array(SHA256.hash(data: challenge))
        let value = (UInt32(d[0]) << 16 | UInt32(d[1]) << 8 | UInt32(d[2])) % 1_000_000
        let digits = String(format: "%06u", value)
        return String(digits.prefix(3)) + " " + String(digits.suffix(3))
    }

    /// Côté Mac, APRÈS authentification de l'opérateur (Touch ID / mot de passe exigé par K_id_Mac).
    public static func grant(_ request: EmergencyRequest, pairedIPhoneID: Data, signer: SigningIdentity,
                             now: Date = Date()) throws -> EmergencyGrant {
        try request.validate()
        guard request.iphoneID == pairedIPhoneID else { throw RobAirError.unknownDevice }
        guard now.millisecondsSince1970 <= request.expiresAtMs else { throw RobAirError.expired }
        let ts = now.millisecondsSince1970
        let sig = try signer.signature(for: signedMessage(challenge: request.challenge, iphoneID: request.iphoneID, timestampMs: ts))
        return EmergencyGrant(iphoneID: request.iphoneID, challenge: request.challenge, timestampMs: ts, signature: sig.rawRepresentation)
    }
}

/// Côté iPhone : un défi de secours en attente. Un seul à la fois, consommé à la première réponse valide.
public final class EmergencyUnlockSession {
    public let request: EmergencyRequest
    public private(set) var isConsumed = false

    public init(iphoneID: Data, now: Date = Date()) {
        request = EmergencyRequest(iphoneID: iphoneID,
                                   challenge: SecureRandom.bytes(RobAirConstants.emergencyChallengeSize),
                                   expiresAtMs: now.addingTimeInterval(RobAirConstants.emergencyChallengeLifetime).millisecondsSince1970)
    }

    public func isExpired(now: Date = Date()) -> Bool { now.millisecondsSince1970 > request.expiresAtMs }

    /// Vérifie la réponse du Mac. Succès → défi consommé : un ordre capturé ne sert à rien (rejeu).
    public func verify(_ grant: EmergencyGrant, macKey: P256.Signing.PublicKey, now: Date = Date()) throws {
        try grant.validate()
        guard !isConsumed else { throw RobAirError.tokenAlreadyUsed }
        guard !isExpired(now: now) else { throw RobAirError.expired }
        guard grant.challenge == request.challenge, grant.iphoneID == request.iphoneID else { throw RobAirError.unexpectedMessage }
        try Freshness.check(timestampMs: grant.timestampMs, now: now, window: RobAirConstants.emergencyChallengeLifetime)
        let message = EmergencyCrypto.signedMessage(challenge: grant.challenge, iphoneID: grant.iphoneID, timestampMs: grant.timestampMs)
        guard macKey.isValidSignature(raw: grant.signature, for: message) else { throw RobAirError.invalidSignature }
        isConsumed = true
    }
}

// MARK: - Transport par QR code (quand le réseau local ne passe pas)

public enum QRPayload {
    public static let emergencyRequestPrefix = "robair-sos-req:"
    public static let emergencyGrantPrefix = "robair-sos-ok:"

    public static func encode<T: WireMessage>(_ value: T, prefix: String) throws -> String {
        prefix + (try StrictJSON.encode(value)).base64EncodedString()
    }

    public static func decode<T: WireMessage>(_ text: String, prefix: String, as type: T.Type) throws -> T {
        guard text.utf8.count <= 1500, text.hasPrefix(prefix),
              let data = Data(base64Encoded: String(text.dropFirst(prefix.count))) else {
            throw RobAirError.malformed("qr")
        }
        return try StrictJSON.decode(T.self, from: data)
    }
}
