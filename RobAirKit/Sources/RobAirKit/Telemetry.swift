// Telemetry.swift
// Rôle : protocole d'urgence et télémétrie (J1 §3.5, J2 §7).
//
//   1. Contenu : {type: TELEMETRY, iphone_id, seq, timestamp, lat, lon, accuracy, battery, trigger, ack_secret}
//   2. Signature : K_tel_iPhone (Secure Enclave, SANS biométrie : le voleur tient le téléphone verrouillé)
//   3. Chiffrement : HPKE (X25519, HKDF-SHA256, AES-256-GCM) pour la clé K_enc_Mac en vigueur.
//      Fonctionne SANS session ouverte, donc aussi via le relais. Le champ `info` lie le message
//      à iphone_id et mac_id ; l'en-tête de l'enveloppe est authentifié (AAD).
//   4. Réception (Mac) : déchiffrement, vérification de la signature, seq, horodatage (72 h dans le passé, 300 s dans le futur), journal, accusé.
//
// Accusé de réception : le contenu chiffré porte un secret aléatoire `ackSecret` que seul le Mac peut lire.
// Le Mac le renvoie pour prouver la réception ; un attaquant réseau ne peut donc pas forger d'accusé
// pour faire effacer la file d'attente de l'iPhone. (Ajout au §3.5, justifié dans J2.)
//
// Menaces : T (positions modifiées), I (écoute), S (fausse télémétrie), R (« ce n'est jamais arrivé »).

import Foundation
import CryptoKit

public enum TelemetryTrigger: String, Codable {
    case bleDisconnected      // rupture de la connexion à la balise
    case signalLow            // RSSI moyen sous le seuil (§3.9)
    case beaconProofFailed    // réponse HMAC invalide ou absente (balise clonée ?)
    case failSafe             // erreur ou état incohérent pendant la surveillance (« dans le doute, on verrouille »)
    case periodic             // position suivante pendant l'alerte
    case test                 // envoi de test depuis l'interface (démo)
}

public struct TelemetryPayload: WireMessage, Equatable {
    public let type: String
    public let iphoneID: Data
    public let seq: UInt64
    public let timestampMs: UInt64
    public let lat: Double?
    public let lon: Double?
    public let accuracy: Double?
    public let battery: Double?
    public let trigger: TelemetryTrigger
    public let ackSecret: Data

    public static let typeTag = "TELEMETRY"

    public init(iphoneID: Data, seq: UInt64, lat: Double?, lon: Double?, accuracy: Double?, battery: Double?,
                trigger: TelemetryTrigger, now: Date = Date()) {
        self.type = Self.typeTag
        self.iphoneID = iphoneID
        self.seq = seq
        self.timestampMs = now.millisecondsSince1970
        self.lat = lat
        self.lon = lon
        self.accuracy = accuracy
        self.battery = battery
        self.trigger = trigger
        self.ackSecret = SecureRandom.bytes(RobAirConstants.ackSecretSize)
    }

    /// Bornes vérifiées (§3.4) : latitude dans [−90, 90], etc. Une valeur absente est permise
    /// (première alerte envoyée avant le premier point GPS).
    public func validate() throws {
        guard type == Self.typeTag else { throw RobAirError.malformed("type") }
        try requireLength(iphoneID, RobAirConstants.deviceIDSize, "iphoneID")
        try requireLength(ackSecret, RobAirConstants.ackSecretSize, "ackSecret")
        guard seq > 0 else { throw RobAirError.outOfBounds("seq") }
        guard (lat == nil) == (lon == nil) else { throw RobAirError.malformed("lat/lon") }
        if let lat { guard lat.isFinite, (-90...90).contains(lat) else { throw RobAirError.outOfBounds("lat") } }
        if let lon { guard lon.isFinite, (-180...180).contains(lon) else { throw RobAirError.outOfBounds("lon") } }
        if let accuracy { guard accuracy.isFinite, (0...100_000).contains(accuracy) else { throw RobAirError.outOfBounds("accuracy") } }
        if let battery { guard battery.isFinite, (0...1).contains(battery) else { throw RobAirError.outOfBounds("battery") } }
    }
}

/// Contenu signé, placé DANS le chiffrement HPKE.
struct SignedTelemetry: WireMessage {
    let payload: Data
    let signature: Data

    func validate() throws {
        try requireLength(signature, RobAirConstants.p256SignatureSize, "signature")
    }
}

/// Ce qui circule (canal local en clair, ou relais) : rien n'y est lisible sans K_enc_Mac.
public struct TelemetryEnvelope: WireMessage, Equatable {
    public let v: UInt8
    public let iphoneID: Data
    public let epoch: UInt32
    public let encapsulatedKey: Data
    public let ciphertext: Data

    public func validate() throws {
        guard v == RobAirConstants.protocolVersion else { throw RobAirError.unsupportedVersion }
        try requireLength(iphoneID, RobAirConstants.deviceIDSize, "iphoneID")
        try requireLength(encapsulatedKey, RobAirConstants.x25519KeySize, "encapsulatedKey")
        guard !ciphertext.isEmpty, ciphertext.count <= 2048 else { throw RobAirError.messageTooLarge }
    }

    var associatedData: Data {
        var aad = Data([v])
        aad.append(iphoneID)
        aad.appendUInt32BE(epoch)
        return aad
    }

    /// Forme sérialisée (JSON) envoyée telle quelle au relais ou dans une trame `telemetry`.
    public func serialized() throws -> Data { try StrictJSON.encode(self) }

    public static func parse(_ data: Data) throws -> TelemetryEnvelope {
        try StrictJSON.decode(TelemetryEnvelope.self, from: data)
    }
}

public struct TelemetryAck: WireMessage, Equatable {
    public let ackSecret: Data

    public init(ackSecret: Data) { self.ackSecret = ackSecret }

    public func validate() throws {
        try requireLength(ackSecret, RobAirConstants.ackSecretSize, "ackSecret")
    }
}

public enum TelemetryCrypto {
    /// HPKE : X25519 + HKDF-SHA256 + AES-256-GCM, mode « base » (RFC 9180).
    static let suite = HPKE.Ciphersuite(kem: .Curve25519_HKDF_SHA256, kdf: .HKDF_SHA256, aead: .AES_GCM_256)

    static func info(iphoneID: Data, macID: Data) -> Data {
        concat(Data(label: Label.telemetryHPKE), iphoneID, macID)
    }

    static func signedBytes(_ payload: Data) -> Data {
        concat(Data(label: Label.telemetrySignature), payload)
    }

    /// Côté iPhone : signe avec K_tel puis chiffre pour la clé publique du Mac (déjà vérifiée).
    public static func seal(_ payload: TelemetryPayload, signer: SigningIdentity,
                            macKey: Curve25519.KeyAgreement.PublicKey, epoch: UInt32, macID: Data) throws -> TelemetryEnvelope {
        try payload.validate()
        let payloadBytes = try StrictJSON.encode(payload)
        let signature = try signer.signature(for: signedBytes(payloadBytes))
        let inner = try StrictJSON.encode(SignedTelemetry(payload: payloadBytes, signature: signature.rawRepresentation))

        var sender = try HPKE.Sender(recipientKey: macKey, ciphersuite: suite,
                                     info: info(iphoneID: payload.iphoneID, macID: macID))
        let header = TelemetryEnvelope(v: RobAirConstants.protocolVersion, iphoneID: payload.iphoneID, epoch: epoch,
                                       encapsulatedKey: sender.encapsulatedKey, ciphertext: Data([0]))
        let ciphertext = try sender.seal(inner, authenticating: header.associatedData)
        let envelope = TelemetryEnvelope(v: header.v, iphoneID: header.iphoneID, epoch: epoch,
                                         encapsulatedKey: header.encapsulatedKey, ciphertext: ciphertext)
        try envelope.validate()
        return envelope
    }

    /// Côté Mac : déchiffre, vérifie la signature K_tel et la cohérence des identifiants.
    /// Le contrôle de seq et d'horodatage est fait ensuite par `TelemetryReceiver`.
    public static func open(_ envelope: TelemetryEnvelope, privateKey: Curve25519.KeyAgreement.PrivateKey,
                            macID: Data, telemetryKey: P256.Signing.PublicKey) throws -> TelemetryPayload {
        try envelope.validate()
        let inner: Data
        do {
            var recipient = try HPKE.Recipient(privateKey: privateKey, ciphersuite: suite,
                                               info: info(iphoneID: envelope.iphoneID, macID: macID),
                                               encapsulatedKey: envelope.encapsulatedKey)
            inner = try recipient.open(envelope.ciphertext, authenticating: envelope.associatedData)
        } catch {
            throw RobAirError.authenticationFailed
        }
        let signed = try StrictJSON.decode(SignedTelemetry.self, from: inner)
        // SÉCURITÉ : la signature est vérifiée AVANT d'interpréter le contenu.
        guard telemetryKey.isValidSignature(raw: signed.signature, for: signedBytes(signed.payload)) else {
            throw RobAirError.invalidSignature
        }
        let payload = try StrictJSON.decode(TelemetryPayload.self, from: signed.payload)
        // L'expéditeur annoncé en clair doit être celui qui a signé.
        guard payload.iphoneID == envelope.iphoneID else { throw RobAirError.unknownDevice }
        return payload
    }
}

/// Côté Mac : anti-rejeu de la télémétrie, APRÈS déchiffrement et vérification de la signature K_tel.
///   - seq strictement croissant : un message déjà vu (rejeu, ou reçu par le local ET le relais) est ignoré ;
///   - fenêtre asymétrique (J2 écart 4) : 72 h dans le passé (file d'attente, relais), 300 s dans le futur.
/// Audit Red Team (faille RT-1) : un message authentique mais hors fenêtre n'est PLUS une erreur.
/// Avant, il n'était jamais acquitté : il restait en tête de la file de l'iPhone et BLOQUAIT toutes
/// les positions suivantes. Désormais il est acquitté (le Mac a pu le déchiffrer) mais n'est ni affiché
/// ni compté comme position actuelle.
public struct TelemetryReceiver: Codable, Equatable {
    public enum Outcome: Equatable {
        case accepted       // nouveau, dans la fenêtre : affiché et journalisé
        case duplicate      // seq déjà vu : ignoré (accusé renvoyé quand même)
        case outOfWindow    // authentique mais trop vieux / trop en avance : journalisé, non affiché
    }

    public private(set) var lastSeq: UInt64

    public init(lastSeq: UInt64 = 0) { self.lastSeq = lastSeq }

    public mutating func accept(_ payload: TelemetryPayload, now: Date = Date()) -> Outcome {
        guard payload.seq > lastSeq else { return .duplicate }
        guard Freshness.isWithin(timestampMs: payload.timestampMs, now: now,
                                 maxAge: RobAirConstants.telemetryMaxAge,
                                 maxAhead: RobAirConstants.timestampWindowDeferred) else { return .outOfWindow }
        lastSeq = payload.seq
        return .accepted
    }
}
