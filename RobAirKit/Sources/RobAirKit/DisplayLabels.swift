// DisplayLabels.swift
// Rôle : libellés français partagés par les deux interfaces (aucune logique de sécurité ici).

import Foundation

public extension ProtectionState {
    var label: String {
        switch self {
        case .disarmed: return "Désarmé"
        case .armed: return "Armé"
        case .alert: return "ALERTE"
        }
    }
}

public extension TelemetryTrigger {
    var label: String {
        switch self {
        case .bleDisconnected: return "liaison avec la balise perdue"
        case .signalLow: return "signal de la balise trop faible"
        case .beaconProofFailed: return "preuve de la balise invalide ou absente"
        case .failSafe: return "anomalie (verrouillage de sécurité)"
        case .periodic: return "position de suivi"
        case .test: return "envoi de test"
        }
    }
}

public extension BeaconStatus {
    var label: String {
        switch self {
        case .present: return "Présente"
        case .absent: return "Absente"
        case .unknown: return "Vérification…"
        case .unpaired: return "Non appairée"
        }
    }
}

public extension ChallengeAction {
    var label: String {
        switch self {
        case .endAlert: return "Fin d'alerte (téléphone retrouvé)"
        case .disarm: return "Désarmer la surveillance"
        case .configChange: return "Modifier la configuration"
        }
    }
}

public extension RuptureDetector.State {
    var beaconStatus: BeaconStatus {
        switch self {
        case .present: return .present
        case .unknown: return .unknown
        case .ruptured: return .absent
        }
    }
}
