// Beacon.swift
// Rôle : balise BLE de confiance = 2e iPhone en mode « Balise » (J1 §1.3, §3.9 ; J2 §6).
//
// Appairage capteur ↔ balise : la balise génère K_balise (32 octets) et un UUID de service aléatoire,
// et les affiche en QR code ; le capteur le scanne (canal visuel = de confiance, comme pour le Mac).
// Anti-clonage : toutes les 10 s, le capteur envoie un défi ; la balise répond
// HMAC-SHA256(K_balise, étiquette ‖ défi). Réponse invalide ou absente = rupture.
// Détection de rupture : déconnexion confirmée, OU RSSI moyen (fenêtre glissante de 5 s) sous le seuil
// pendant plus de 3 s, avec hystérésis pour en sortir.
// Risque résiduel : le relais BLE (un complice retransmet la radio) n'est pas détectable ici.

import Foundation
import CryptoKit

/// Contenu du QR code affiché par la balise. Contient un SECRET (K_balise) : affichage bref, à l'abri des regards.
public struct BeaconPairingCode: WireMessage, Equatable {
    public let v: UInt8
    public let serviceUUID: String
    public let key: Data

    public static let qrPrefix = "robair-beacon:"

    /// Nouvelle balise : UUID de service et clé tirés au hasard (aucun lien avec l'identité de l'utilisateur).
    public static func generate() -> BeaconPairingCode {
        var bytes = Array(SecureRandom.bytes(16))
        bytes[6] = (bytes[6] & 0x0F) | 0x40   // UUID version 4
        bytes[8] = (bytes[8] & 0x3F) | 0x80   // variante RFC 4122
        let hex = bytes.map { String(format: "%02X", $0) }.joined()
        let chars = Array(hex)
        let uuid = [0..<8, 8..<12, 12..<16, 16..<20, 20..<32].map { String(chars[$0]) }.joined(separator: "-")
        return BeaconPairingCode(v: RobAirConstants.protocolVersion, serviceUUID: uuid,
                                 key: SecureRandom.bytes(RobAirConstants.beaconKeySize))
    }

    public func validate() throws {
        guard v == RobAirConstants.protocolVersion else { throw RobAirError.unsupportedVersion }
        guard UUID(uuidString: serviceUUID) != nil else { throw RobAirError.malformed("serviceUUID") }
        try requireLength(key, RobAirConstants.beaconKeySize, "key")
    }

    public func qrText() throws -> String { try QRPayload.encode(self, prefix: Self.qrPrefix) }

    public static func parse(qrText: String) throws -> BeaconPairingCode {
        try QRPayload.decode(qrText, prefix: qrPrefix, as: BeaconPairingCode.self)
    }
}

public enum BeaconProof {
    /// UUID de la caractéristique GATT (écriture du défi + notification de la réponse).
    public static let characteristicUUID = "B8E4C3A2-5D1F-4E7A-9C3B-2F6D8A1E0C47"

    public static func makeChallenge() -> Data { SecureRandom.bytes(RobAirConstants.beaconChallengeSize) }

    static func message(_ challenge: Data) -> Data { concat(Data(label: Label.beaconProof), challenge) }

    /// Côté balise.
    public static func respond(to challenge: Data, key: SymmetricKey) throws -> Data {
        try requireLength(challenge, RobAirConstants.beaconChallengeSize, "beaconChallenge")
        return Data(HMAC<SHA256>.authenticationCode(for: message(challenge), using: key))
    }

    /// Côté capteur. Comparaison en temps constant.
    public static func verify(response: Data, challenge: Data, key: SymmetricKey) -> Bool {
        guard response.count == 32 else { return false }
        return HMAC<SHA256>.isValidAuthenticationCode(response, authenticating: message(challenge), using: key)
    }
}

/// Décide « balise présente / rupture ». Logique pure, sans CoreBluetooth → testable.
/// Fail-safe : sans preuve HMAC valide récente, la balise n'est JAMAIS « présente ».
public struct RuptureDetector {
    public enum State: Equatable {
        case unknown                       // pas encore de preuve (démarrage)
        case present
        case ruptured(TelemetryTrigger)    // .bleDisconnected, .beaconProofFailed ou .signalLow
    }

    public struct Config {
        public var averageWindow = RobAirConstants.rssiAverageWindow
        public var lowThreshold = RobAirConstants.rssiLowThreshold
        public var recoverThreshold = RobAirConstants.rssiRecoverThreshold
        public var lowDuration = RobAirConstants.rssiLowDuration
        public var proofMaxAge = RobAirConstants.beaconProofMaxAge
        public var challengeTimeout = RobAirConstants.beaconChallengeTimeout
        public init() {}
    }

    public private(set) var state: State = .unknown
    private let config: Config
    private var connected = false
    private var everConnected = false
    private var samples: [(at: Date, rssi: Int)] = []
    private var lowSince: Date?
    private var signalLow = false
    private var lastValidProof: Date?
    private var proofFailed = false

    public init(config: Config = Config()) { self.config = config }

    @discardableResult
    public mutating func connectionChanged(_ isConnected: Bool, now: Date) -> State {
        connected = isConnected
        if isConnected {
            everConnected = true
        } else {
            samples.removeAll()
            lowSince = nil
            signalLow = false
            lastValidProof = nil
        }
        return evaluate(now: now)
    }

    @discardableResult
    public mutating func recordRSSI(_ rssi: Int, now: Date) -> State {
        guard rssi < 0 else { return state }   // CoreBluetooth renvoie 127 quand la mesure est indisponible
        samples.append((now, rssi))
        samples.removeAll { now.timeIntervalSince($0.at) > config.averageWindow }
        let average = samples.map(\.rssi).reduce(0, +) / samples.count
        if average < config.lowThreshold {
            lowSince = lowSince ?? now
            if now.timeIntervalSince(lowSince!) >= config.lowDuration { signalLow = true }
        } else if average >= config.recoverThreshold {
            lowSince = nil
            signalLow = false        // hystérésis : il faut remonter nettement pour sortir
        } else if !signalLow {
            lowSince = nil           // entre les deux seuils : on ne bascule pas
        }
        return evaluate(now: now)
    }

    @discardableResult
    public mutating func recordProof(valid: Bool, latency: TimeInterval, now: Date) -> State {
        if valid, latency <= config.challengeTimeout {
            lastValidProof = now
            proofFailed = false
        } else {
            lastValidProof = nil
            proofFailed = true
        }
        return evaluate(now: now)
    }

    /// À appeler régulièrement : fait expirer une preuve trop ancienne.
    @discardableResult
    public mutating func tick(now: Date) -> State { evaluate(now: now) }

    private mutating func evaluate(now: Date) -> State {
        if !connected {
            state = everConnected ? .ruptured(.bleDisconnected) : .unknown
        } else if proofFailed {
            state = .ruptured(.beaconProofFailed)
        } else if let proof = lastValidProof, now.timeIntervalSince(proof) <= config.proofMaxAge {
            state = signalLow ? .ruptured(.signalLow) : .present
        } else if lastValidProof != nil || state == .present {
            state = .ruptured(.beaconProofFailed)   // preuve expirée : plus de réponse de la balise
        } else {
            state = .unknown                         // connecté, première preuve en attente
        }
        return state
    }
}
