// AlertState.swift
// Rôle : état de surveillance de l'iPhone (désarmé / armé / alerte) et messages d'état de la session.
// Logique pure → testable.
//
// Règles (J1 §1.2, §3.5, §3.8 ; J2 §8) :
//   - armer exige une balise PRÉSENTE (preuve HMAC récente) ;
//   - armé + rupture (ou toute anomalie : fail-safe) → ALERTE : coffre fermé, écran d'alerte, télémétrie ;
//   - sortir de l'alerte : Face ID du propriétaire, déverrouillage de secours signé par le Mac,
//     ou action « fin d'alerte » autorisée par défi-réponse ;
//   - le coffre ne s'ouvre JAMAIS en alerte, et toujours avec Face ID.

import Foundation

public enum ProtectionState: Equatable {
    case disarmed
    case armed
    case alert(TelemetryTrigger)

    public var isAlert: Bool { if case .alert = self { return true } else { return false } }
}

public struct AlertStateMachine {
    public enum Event: Equatable {
        case arm(beacon: RuptureDetector.State)
        case beaconChanged(RuptureDetector.State)
        case failure                                   // erreur inattendue, état incohérent
        case ownerAuthenticated                        // Face ID réussi sur l'iPhone
        case emergencyUnlocked                         // réponse de secours du Mac vérifiée
        case macAuthorized(ChallengeAction)            // défi-réponse §3.7 vérifié par le Mac puis confirmé
    }

    public private(set) var state: ProtectionState

    /// `state` : état restauré au relancement de l'app. Une alerte survit donc à un redémarrage (fail-safe).
    public init(state: ProtectionState = .disarmed) { self.state = state }

    @discardableResult
    public mutating func handle(_ event: Event) -> ProtectionState {
        switch (state, event) {
        case (.disarmed, .arm(let beacon)):
            if beacon == .present { state = .armed }
        case (.armed, .beaconChanged(.ruptured(let reason))):
            state = .alert(reason)
        case (.armed, .failure):
            state = .alert(.failSafe)
        case (_, .ownerAuthenticated), (.alert, .emergencyUnlocked):
            state = .disarmed
        case (_, .macAuthorized(.endAlert)), (_, .macAuthorized(.disarm)):
            state = .disarmed
        default:
            break   // tout le reste ne change rien (notamment : rien ne fait passer d'alerte à armé)
        }
        return state
    }

    /// Le coffre ne peut s'ouvrir qu'hors alerte (Face ID reste exigé en plus, par le Keychain).
    public var canOpenVault: Bool { !state.isAlert }
}

// MARK: - Messages de session (chiffrés)

public enum BeaconStatus: String, Codable {
    case present, absent, unknown, unpaired
}

public struct StatusPayload: WireMessage, Equatable {
    public let state: String          // "disarmed" | "armed" | "alert"
    public let trigger: TelemetryTrigger?
    public let vaultOpen: Bool
    public let beacon: BeaconStatus

    public init(state: ProtectionState, vaultOpen: Bool, beacon: BeaconStatus) {
        switch state {
        case .disarmed: self.state = "disarmed"; trigger = nil
        case .armed: self.state = "armed"; trigger = nil
        case .alert(let reason): self.state = "alert"; trigger = reason
        }
        self.vaultOpen = vaultOpen
        self.beacon = beacon
    }

    public func validate() throws {
        guard ["disarmed", "armed", "alert"].contains(state) else { throw RobAirError.malformed("state") }
        guard (state == "alert") == (trigger != nil) else { throw RobAirError.malformed("trigger") }
    }

    public var protectionState: ProtectionState {
        switch state {
        case "armed": return .armed
        case "alert": return .alert(trigger ?? .failSafe)
        default: return .disarmed
        }
    }
}

/// Accès en écriture à la boîte du relais, transmis par le Mac DANS la session chiffrée (§3.2, étape 4).
public struct MailboxConfig: WireMessage, Equatable {
    public let mailboxID: String
    public let writeToken: String

    public init(mailboxID: String, writeToken: String) {
        self.mailboxID = mailboxID
        self.writeToken = writeToken
    }

    public func validate() throws {
        try RelayAPI.validateIdentifier(mailboxID, field: "mailboxID")
        try RelayAPI.validateIdentifier(writeToken, field: "writeToken")
    }
}
