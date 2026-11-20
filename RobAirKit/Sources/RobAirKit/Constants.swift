// Constants.swift
// Rôle : tous les paramètres du protocole au même endroit.
// Relecture : chaque valeur doit correspondre à docs/J2-architecture.md.

import Foundation

public enum RobAirConstants {
    /// Version du protocole, présente dans chaque trame (premier octet).
    public static let protocolVersion: UInt8 = 1

    /// Type de service Bonjour (déclaré aussi dans les Info.plist : NSBonjourServices).
    public static let bonjourServiceType = "_robair._tcp"

    // MARK: Limites réseau (menaces T3 et D2)
    /// Taille maximale d'une trame, en octets. Au-delà : rejet immédiat.
    public static let maxFrameSize = 4096
    /// Durée maximale du handshake, en secondes.
    public static let handshakeTimeout: TimeInterval = 5
    /// Écart maximal accepté entre l'horodatage d'un message et l'horloge locale (anti-rejeu).
    public static let timestampWindow: TimeInterval = 60

    // MARK: Supervision
    /// Intervalle d'envoi de l'état de l'iPhone vers le Mac.
    public static let heartbeatInterval: TimeInterval = 10
    /// Sans message valide depuis ce délai, le Mac passe en « NON VÉRIFIÉ ».
    public static let macStaleAfter: TimeInterval = 30

    // MARK: Proximité BLE (menace S2)
    /// Intervalle entre deux défis BLE.
    public static let challengeInterval: TimeInterval = 10
    /// Délai maximal de réponse à un défi.
    public static let challengeTimeout: TimeInterval = 2
    /// Âge maximal d'une preuve BLE valide pour rester « proche ».
    public static let proofMaxAge: TimeInterval = challengeInterval + challengeTimeout + 3
    /// Nombre de mesures RSSI moyennées.
    public static let rssiWindow = 5
    /// Sous ce RSSI moyen (dBm), on passe « éloigné ».
    public static let rssiLeaveThreshold = -80
    /// Au-dessus de ce RSSI moyen (dBm), on redevient « proche » (hystérésis).
    public static let rssiEnterThreshold = -70

    // MARK: Verrouillage (fail-safe)
    /// Au-delà de ce temps passé en arrière-plan, l'app se verrouille.
    public static let backgroundLockDelay: TimeInterval = 30

    // MARK: Appairage (menace S3)
    public static let pairingTokenLifetime: TimeInterval = 120
    public static let pairingMaxAttempts = 3

    // MARK: Tailles des champs (en octets)
    public static let nonceSize = 32
    public static let challengeSize = 16
    public static let pairingTokenSize = 32
    public static let eventIDSize = 16
    public static let fingerprintSize = 32
    public static let p256PublicKeySize = 65   // format X9.63 non compressé
    public static let p256SignatureSize = 64   // format brut r ‖ s
}

/// Étiquettes de « séparation de domaine ».
/// Chaque usage d'une clé signe un message qui commence par une étiquette différente :
/// une signature produite pour le BLE ne peut donc jamais être réutilisée comme signature de handshake.
enum Label {
    static let pairingProof = "robair-pair-proof-v1"
    static let pairingConfirm = "robair-pair-confirm-v1"
    static let sas = "robair-sas-v1"
    static let transcript = "robair-hs-transcript-v1"
    static let serverSignature = "robair-hs-server-v1"
    static let clientSignature = "robair-hs-client-v1"
    static let keyClientToServer = "robair-key-c2s-v1"
    static let keyServerToClient = "robair-key-s2c-v1"
    static let bleProof = "robair-ble-proof-v1"
    static let bleServiceUUID = "robair-ble-uuid-v1"
    static let sensitiveEvent = "robair-event-v1"
    static let journalEncryption = "robair-journal-enc-v1"
    static let journalSeal = "robair-journal-seal-v1"
}
