// Errors.swift
// Rôle : erreurs du protocole. Règle fail-safe : toute erreur = verrouillage / fermeture de la connexion.
// Relecture : les messages d'erreur ne doivent jamais contenir de donnée secrète.

import Foundation

public enum RobAirError: Error, Equatable {
    case malformed(String)
    case unsupportedVersion
    case unexpectedMessage
    case frameTooLarge
    case replayDetected
    case authenticationFailed
    case invalidSignature
    case unknownDevice
    case expired
    case tokenAlreadyUsed
    case staleTimestamp
    case counterExhausted
    case keychain(Int32)
    case secureEnclaveUnavailable
}

extension RobAirError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .malformed(let field): return "Message invalide (\(field))."
        case .unsupportedVersion: return "Version de protocole non supportée."
        case .unexpectedMessage: return "Message inattendu à cette étape."
        case .frameTooLarge: return "Trame trop grande."
        case .replayDetected: return "Rejeu détecté."
        case .authenticationFailed: return "Échec d'authentification du message."
        case .invalidSignature: return "Signature invalide."
        case .unknownDevice: return "Appareil inconnu (non appairé)."
        case .expired: return "Invitation expirée."
        case .tokenAlreadyUsed: return "Invitation déjà utilisée."
        case .staleTimestamp: return "Horodatage hors fenêtre."
        case .counterExhausted: return "Compteur épuisé : nouvelle session requise."
        case .keychain(let status): return "Erreur Keychain (\(status))."
        case .secureEnclaveUnavailable: return "Secure Enclave indisponible."
        }
    }
}
