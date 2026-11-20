// Constants.swift
// Rôle : tous les paramètres du protocole au même endroit.
// Relecture : chaque valeur doit correspondre à docs/J1-cadrage.md (§ indiqués) et docs/J2-architecture.md.

import Foundation

public enum RobAirConstants {
    /// Version du protocole, présente dans chaque message (premier octet ou champ `v`).
    public static let protocolVersion: UInt8 = 1

    /// Type de service Bonjour (déclaré aussi dans les Info.plist : NSBonjourServices).
    public static let bonjourServiceType = "_robair._tcp"

    // MARK: Limites réseau (§3.4 : validation stricte)
    /// Taille maximale d'un message, en octets. Au-delà : rejet immédiat.
    public static let maxMessageSize = 4096
    /// Durée maximale du handshake, en secondes.
    public static let handshakeTimeout: TimeInterval = 5
    /// Écart d'horloge toléré pour un message de session (canal local).
    public static let timestampWindowLocal: TimeInterval = 30
    /// Écart d'horloge toléré pour la télémétrie (différée : file d'attente, relais).
    public static let timestampWindowDeferred: TimeInterval = 300

    // MARK: Session locale (§3.3)
    /// Renouvellement des clés de session (nouvel échange X25519 dans la session).
    public static let sessionRekeyInterval: TimeInterval = 15 * 60
    /// Intervalle d'envoi de l'état de l'iPhone au Mac quand une session est ouverte.
    public static let statusInterval: TimeInterval = 10

    // MARK: Appairage (§3.2)
    public static let pairingTokenLifetime: TimeInterval = 5 * 60
    public static let pairingMaxAttempts = 3

    // MARK: Défis (§3.7, §3.8)
    /// Défi Mac → iPhone (fin d'alerte, désarmement…) : valable 30 s, usage unique.
    public static let macChallengeLifetime: TimeInterval = 30
    /// Défi de déverrouillage de secours (émis par l'iPhone) : valable 120 s, usage unique.
    public static let emergencyChallengeLifetime: TimeInterval = 120
    /// Nombre d'échecs Face ID avant de proposer le déverrouillage de secours.
    public static let faceIDFailuresBeforeEmergency = 3

    // MARK: Balise BLE et détection de rupture (§3.9)
    public static let beaconChallengeInterval: TimeInterval = 10
    public static let beaconChallengeTimeout: TimeInterval = 2
    /// Sans preuve HMAC valide depuis ce délai, la balise est considérée absente.
    public static let beaconProofMaxAge: TimeInterval = beaconChallengeInterval + beaconChallengeTimeout + 3
    public static let rssiSampleInterval: TimeInterval = 1
    /// Fenêtre de la moyenne glissante du RSSI.
    public static let rssiAverageWindow: TimeInterval = 5
    /// Moyenne sous ce seuil pendant `rssiLowDuration` → rupture. À calibrer en démo.
    public static let rssiLowThreshold = -85
    /// Pour sortir de l'état « signal faible », la moyenne doit remonter au-dessus (hystérésis).
    public static let rssiRecoverThreshold = -75
    public static let rssiLowDuration: TimeInterval = 3

    // MARK: Télémétrie (§3.5)
    public static let telemetryInterval: TimeInterval = 15
    public static let telemetryQueueMax = 100
    /// Le Mac interroge le relais à cet intervalle pendant une alerte (§2.2).
    public static let relayPollInterval: TimeInterval = 30
    /// Rotation de la clé de chiffrement HPKE du Mac (K_enc_Mac).
    public static let encryptionKeyRotation: TimeInterval = 7 * 24 * 3600
    /// Les anciennes clés privées K_enc restent utilisables ce temps-là (messages en retard).
    public static let encryptionKeyGrace: TimeInterval = 14 * 24 * 3600

    // MARK: Tailles des champs (en octets)
    public static let deviceIDSize = 16
    public static let nonceSize = 32
    public static let macChallengeSize = 32
    public static let emergencyChallengeSize = 32
    public static let beaconChallengeSize = 16
    public static let beaconKeySize = 32
    public static let pairingTokenSize = 32
    public static let ackSecretSize = 16
    public static let x25519KeySize = 32
    public static let p256PublicKeySize = 65   // format X9.63 non compressé
    public static let p256SignatureSize = 64   // format brut r ‖ s
}

/// Étiquettes de « séparation de domaine ».
/// Chaque usage d'une clé porte sur un message qui commence par une étiquette différente :
/// une signature produite pour un usage ne peut jamais être réutilisée pour un autre.
enum Label {
    static let deviceID = "robair-device-id-v1"
    static let pairingProof = "robair-pair-proof-v1"
    static let pairingConfirm = "robair-pair-confirm-v1"
    static let sas = "robair-sas-v1"
    static let transcript = "robair-hs-transcript-v1"
    static let serverSignature = "robair-hs-server-v1"
    static let clientSignature = "robair-hs-client-v1"
    static let keyClientToServer = "robair-key-c2s-v1"
    static let keyServerToClient = "robair-key-s2c-v1"
    static let rekey = "robair-rekey-v1"
    static let encryptionKey = "robair-enc-key-v1"
    static let telemetrySignature = "robair-telemetry-v1"
    static let telemetryHPKE = "robair-telemetry-hpke-v1"
    static let macChallenge = "robair-mac-challenge-v1"
    static let emergencyUnlock = "robair-emergency-unlock-v1"
    static let beaconProof = "robair-beacon-proof-v1"
    static let journalEntry = "robair-journal-entry-v1"
}
