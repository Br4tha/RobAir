// Errors.swift
// Rôle : erreurs du protocole. Règle fail-safe : toute erreur = rejet silencieux / fermeture / verrouillage.
// Règle §3.4 : on ne renvoie JAMAIS le détail d'une erreur à l'émetteur ; ces textes servent
// uniquement à l'interface locale et au journal. Ils ne contiennent jamais de donnée secrète.

import Foundation

public enum RobAirError: Error, Equatable {
    case malformed(String)
    case unknownField(String)
    case outOfBounds(String)
    case unsupportedVersion
    case unexpectedMessage
    case messageTooLarge
    case replayDetected
    case authenticationFailed
    case invalidSignature
    case unknownDevice
    case unknownKeyEpoch
    case expired
    case tokenAlreadyUsed
    case staleTimestamp
    case counterExhausted
    case keychain(Int32)
    case secureEnclaveUnavailable
    case relay(Int)
}

extension RobAirError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .malformed(let field): return "Message invalide (\(field))."
        case .unknownField(let field): return "Champ inconnu refusé (\(field))."
        case .outOfBounds(let field): return "Valeur hors bornes (\(field))."
        case .unsupportedVersion: return "Version de protocole non supportée."
        case .unexpectedMessage: return "Message inattendu à cette étape."
        case .messageTooLarge: return "Message trop grand."
        case .replayDetected: return "Rejeu détecté."
        case .authenticationFailed: return "Échec d'authentification du message."
        case .invalidSignature: return "Signature invalide."
        case .unknownDevice: return "Appareil inconnu (non appairé)."
        case .unknownKeyEpoch: return "Clé de chiffrement inconnue ou expirée."
        case .expired: return "Défi ou invitation expiré."
        case .tokenAlreadyUsed: return "Défi ou invitation déjà utilisé."
        case .staleTimestamp: return "Horodatage hors fenêtre."
        case .counterExhausted: return "Compteur épuisé : nouvelle session requise."
        case .keychain(let status): return "Erreur Keychain (\(status))."
        case .secureEnclaveUnavailable: return "Secure Enclave indisponible."
        case .relay(let status): return "Relais : réponse HTTP \(status)."
        }
    }
}
