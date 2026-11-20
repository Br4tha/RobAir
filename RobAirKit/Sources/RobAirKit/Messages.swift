// Messages.swift
// Rôle : contenu des messages chiffrés (états, alertes, événements sensibles signés).
// Menaces : R1 (non-répudiation des actions sensibles), rejeu (horodatage + identifiant unique).
// RGPD : aucun RSSI, aucune position, aucun nom n'est transmis. Seulement des états.

import Foundation
import CryptoKit

public enum ProximityState: String, Codable {
    case near, away, unknown
}

public enum LockStatus: String, Codable {
    case locked, unlocked
}

public enum AlertReason: String, Codable {
    case bleDisconnected, proofFailed, signalWeak, appBackgrounded
}

public enum SensitiveAction: String, Codable {
    case unlock
}

/// Heartbeat / changement d'état, envoyé par l'iPhone.
public struct StatusPayload: Codable, Equatable {
    public let timestampMs: UInt64
    public let proximity: ProximityState
    public let lock: LockStatus

    public init(proximity: ProximityState, lock: LockStatus, now: Date = Date()) {
        self.timestampMs = now.millisecondsSince1970
        self.proximity = proximity
        self.lock = lock
    }
}

public struct AlertPayload: Codable, Equatable {
    public let timestampMs: UInt64
    public let reason: AlertReason

    public init(reason: AlertReason, now: Date = Date()) {
        self.timestampMs = now.millisecondsSince1970
        self.reason = reason
    }
}

public struct AckPayload: Codable, Equatable {
    public let timestampMs: UInt64
    public let acknowledgedType: UInt8

    public init(acknowledging type: MessageType, now: Date = Date()) {
        self.timestampMs = now.millisecondsSince1970
        self.acknowledgedType = type.rawValue
    }
}

/// Action sensible signée par la clé biométrique (K_bio) de l'iPhone.
/// AES-GCM prouve seulement « quelqu'un qui a la clé de session » (le Mac l'a aussi) ;
/// cette signature prouve « l'iPhone, après Face ID » → preuve opposable (non-répudiation).
public struct SensitiveEventPayload: Codable, Equatable {
    public let timestampMs: UInt64
    public let action: SensitiveAction
    public let eventID: Data
    public let signature: Data

    static func signedMessage(action: SensitiveAction, timestampMs: UInt64, eventID: Data) -> Data {
        var message = Data(label: Label.sensitiveEvent)
        message.appendLengthPrefixed(Data(action.rawValue.utf8))   // champ de taille variable → préfixé
        message.appendUInt64BE(timestampMs)
        message.append(eventID)
        return message
    }

    public static func make(action: SensitiveAction, signer: SigningIdentity, now: Date = Date()) throws -> SensitiveEventPayload {
        let ts = now.millisecondsSince1970
        let id = SecureRandom.bytes(RobAirConstants.eventIDSize)
        let signature = try signer.signature(for: signedMessage(action: action, timestampMs: ts, eventID: id))
        return SensitiveEventPayload(timestampMs: ts, action: action, eventID: id, signature: signature.rawRepresentation)
    }

    public func isValid(for biometricKey: P256.Signing.PublicKey) -> Bool {
        guard eventID.count == RobAirConstants.eventIDSize else { return false }
        return biometricKey.isValidSignature(raw: signature,
                                             for: Self.signedMessage(action: action, timestampMs: timestampMs, eventID: eventID))
    }
}

public enum Freshness {
    /// Rejette un message dont l'horodatage est trop loin de l'horloge locale (rejeu différé).
    public static func check(timestampMs: UInt64,
                             now: Date = Date(),
                             window: TimeInterval = RobAirConstants.timestampWindow) throws {
        let sent = Date(millisecondsSince1970: timestampMs)
        guard abs(sent.timeIntervalSince(now)) <= window else { throw RobAirError.staleTimestamp }
    }
}
