// DisplayLabels.swift
// Rôle : libellés français partagés par les deux interfaces (aucune logique de sécurité ici).

import Foundation

public extension ProximityState {
    var label: String {
        switch self {
        case .near: return "Proche"
        case .away: return "Éloigné"
        case .unknown: return "Inconnue"
        }
    }
}

public extension LockStatus {
    var label: String { self == .locked ? "Verrouillé" : "Déverrouillé" }
}

public extension AlertReason {
    var label: String {
        switch self {
        case .bleDisconnected: return "liaison Bluetooth perdue"
        case .proofFailed: return "preuve BLE invalide ou absente"
        case .signalWeak: return "signal trop faible"
        case .appBackgrounded: return "app en arrière-plan"
        }
    }
}
