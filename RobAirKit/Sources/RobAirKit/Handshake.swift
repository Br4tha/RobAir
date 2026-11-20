// Handshake.swift
// Rôle : session locale iPhone ↔ Mac avec forward secrecy (J1 §3.3, J2 §5).
//
//   iPhone (client)                                       Mac (serveur)
//   ClientHello {iphone_id, ePub_I (X25519), N_I}   ─────►
//                                                   ◄─────  ServerHello {mac_id, ePub_M, N_M, Sig_K_id_Mac(H)}
//   ClientFinish {Sig_K_id_iPhone(H)}               ─────►
//   H = SHA-256(étiquette ‖ iphone_id ‖ mac_id ‖ ePub_I ‖ N_I ‖ ePub_M ‖ N_M)   (« transcription »)
//   Clés : HKDF-SHA256(ECDH(éphémères), salt = H, info = sens) → une clé AES-256-GCM par sens.
//
// Renouvellement toutes les 15 min (§3.3, point 5) : nouvel échange X25519 DANS la session
// (messages rekey / rekeyAck chiffrés), sel = hash de l'ancienne transcription + nouvelles valeurs.
// Il garde la forward secrecy sans redemander Face ID (iPhone) ni Touch ID (Mac).
// Une reconnexion ou une levée de verrouillage impose, elle, un handshake complet signé.
//
// Menaces : S1 (faux Mac), S3 (faux iPhone), I1 (écoute), forward secrecy.
// Points de relecture :
//   1. Les signatures couvrent TOUTE la transcription (sinon homme du milieu possible).
//   2. Étiquettes différentes client/serveur (une signature ne peut pas être « renvoyée en miroir »).
//   3. Le serveur ne livre les clés qu'APRÈS avoir vérifié ClientFinish.
//   4. Les clés éphémères sont oubliées après usage (objets à usage unique).

import Foundation
import CryptoKit

public struct ClientHello: WireMessage, Equatable {
    public let iphoneID: Data
    public let ephemeralKey: Data
    public let nonce: Data

    public func validate() throws {
        try requireLength(iphoneID, RobAirConstants.deviceIDSize, "iphoneID")
        try requireLength(ephemeralKey, RobAirConstants.x25519KeySize, "ephemeralKey")
        try requireLength(nonce, RobAirConstants.nonceSize, "nonce")
    }
}

public struct ServerHello: WireMessage, Equatable {
    public let macID: Data
    public let ephemeralKey: Data
    public let nonce: Data
    public let signature: Data

    public func validate() throws {
        try requireLength(macID, RobAirConstants.deviceIDSize, "macID")
        try requireLength(ephemeralKey, RobAirConstants.x25519KeySize, "ephemeralKey")
        try requireLength(nonce, RobAirConstants.nonceSize, "nonce")
        try requireLength(signature, RobAirConstants.p256SignatureSize, "signature")
    }
}

public struct ClientFinish: WireMessage, Equatable {
    public let signature: Data

    public func validate() throws {
        try requireLength(signature, RobAirConstants.p256SignatureSize, "signature")
    }
}

/// Clés d'une session, du point de vue de celui qui les détient.
public struct SessionKeys {
    public let sending: SymmetricKey
    public let receiving: SymmetricKey
    public let transcriptHash: Data
}

enum HandshakeMath {
    static func transcriptHash(iphoneID: Data, macID: Data, clientEphemeral: Data, clientNonce: Data,
                               serverEphemeral: Data, serverNonce: Data) -> Data {
        // Tous les champs sont de taille fixe : la concaténation est sans ambiguïté.
        var hasher = SHA256()
        for part in [Data(label: Label.transcript), iphoneID, macID, clientEphemeral, clientNonce, serverEphemeral, serverNonce] {
            hasher.update(data: part)
        }
        return Data(hasher.finalize())
    }

    static func deriveKeys(shared: SharedSecret, salt: Data) -> (clientToServer: SymmetricKey, serverToClient: SymmetricKey) {
        // SÉCURITÉ : une clé par sens → le même couple (clé, nonce) n'est jamais utilisé des deux côtés.
        let c2s = shared.hkdfDerivedSymmetricKey(using: SHA256.self, salt: salt,
                                                 sharedInfo: Data(label: Label.keyClientToServer), outputByteCount: 32)
        let s2c = shared.hkdfDerivedSymmetricKey(using: SHA256.self, salt: salt,
                                                 sharedInfo: Data(label: Label.keyServerToClient), outputByteCount: 32)
        return (c2s, s2c)
    }

    static func x25519(_ data: Data) throws -> Curve25519.KeyAgreement.PublicKey {
        do { return try Curve25519.KeyAgreement.PublicKey(rawRepresentation: data) } catch { throw RobAirError.malformed("x25519") }
    }

    static func agree(_ priv: Curve25519.KeyAgreement.PrivateKey, _ pub: Curve25519.KeyAgreement.PublicKey) throws -> SharedSecret {
        let shared: SharedSecret
        do { shared = try priv.sharedSecretFromKeyAgreement(with: pub) } catch { throw RobAirError.authenticationFailed }
        // SÉCURITÉ : une clé publique X25519 « de faible ordre » (ex. tout à zéro) donne un secret NUL,
        // connu de l'attaquant. Toutes les implémentations ne le refusent pas (trouvé par
        // testLowOrderEphemeralIsRejected) : on vérifie nous-mêmes (RFC 7748 §6.1).
        let isAllZero = shared.withUnsafeBytes { $0.allSatisfy { $0 == 0 } }
        guard !isAllZero else { throw RobAirError.authenticationFailed }
        return shared
    }
}

/// Côté iPhone. Un objet = une tentative de handshake.
/// `identity` = K_id_iPhone : la Secure Enclave exige un LAContext déjà validé par Face ID.
public final class HandshakeClient {
    private let identity: SigningIdentity
    private let macKey: P256.Signing.PublicKey   // épinglée à l'appairage (QR code)
    private var ephemeral: Curve25519.KeyAgreement.PrivateKey?
    private var sentHello: ClientHello?

    public init(identity: SigningIdentity, macKey: P256.Signing.PublicKey) {
        self.identity = identity
        self.macKey = macKey
    }

    public func makeHello() -> ClientHello {
        let eph = Curve25519.KeyAgreement.PrivateKey()
        ephemeral = eph
        let hello = ClientHello(iphoneID: DeviceID.of(identity.publicKey),
                                ephemeralKey: eph.publicKey.rawRepresentation,
                                nonce: SecureRandom.bytes(RobAirConstants.nonceSize))
        sentHello = hello
        return hello
    }

    public func handle(_ reply: ServerHello) throws -> (finish: ClientFinish, keys: SessionKeys) {
        guard let eph = ephemeral, let hello = sentHello else { throw RobAirError.unexpectedMessage }
        // SÉCURITÉ : usage unique, la clé éphémère est oubliée quoi qu'il arrive.
        defer { ephemeral = nil; sentHello = nil }

        try reply.validate()
        guard reply.macID == DeviceID.of(macKey) else { throw RobAirError.unknownDevice }
        let transcript = HandshakeMath.transcriptHash(iphoneID: hello.iphoneID, macID: reply.macID,
                                                      clientEphemeral: hello.ephemeralKey, clientNonce: hello.nonce,
                                                      serverEphemeral: reply.ephemeralKey, serverNonce: reply.nonce)
        // SÉCURITÉ : c'est CETTE vérification qui bloque le faux Mac (S1).
        guard macKey.isValidSignature(raw: reply.signature, for: concat(Data(label: Label.serverSignature), transcript)) else {
            throw RobAirError.invalidSignature
        }
        let shared = try HandshakeMath.agree(eph, HandshakeMath.x25519(reply.ephemeralKey))
        let keys = HandshakeMath.deriveKeys(shared: shared, salt: transcript)
        let signature = try identity.signature(for: concat(Data(label: Label.clientSignature), transcript))
        return (ClientFinish(signature: signature.rawRepresentation),
                SessionKeys(sending: keys.clientToServer, receiving: keys.serverToClient, transcriptHash: transcript))
    }
}

/// Côté Mac. Un objet = une connexion entrante.
/// `identity` = K_id_Mac : sa signature peut déclencher Touch ID → appeler hors du thread principal.
public final class HandshakeServer {
    private enum Phase {
        case awaitingHello
        case awaitingFinish(transcript: Data, clientToServer: SymmetricKey, serverToClient: SymmetricKey)
        case finished
    }

    private let identity: SigningIdentity
    private let iphoneKey: P256.Signing.PublicKey   // K_id_iPhone épinglée à l'appairage
    private var phase = Phase.awaitingHello

    public init(identity: SigningIdentity, iphoneKey: P256.Signing.PublicKey) {
        self.identity = identity
        self.iphoneKey = iphoneKey
    }

    public func handle(_ hello: ClientHello) throws -> ServerHello {
        guard case .awaitingHello = phase else { throw RobAirError.unexpectedMessage }
        phase = .finished   // en cas d'erreur ci-dessous, l'objet devient inutilisable (fail-safe)

        try hello.validate()
        guard hello.iphoneID == DeviceID.of(iphoneKey) else { throw RobAirError.unknownDevice }
        let clientEphemeral = try HandshakeMath.x25519(hello.ephemeralKey)

        let eph = Curve25519.KeyAgreement.PrivateKey()
        let nonce = SecureRandom.bytes(RobAirConstants.nonceSize)
        let macID = DeviceID.of(identity.publicKey)
        let transcript = HandshakeMath.transcriptHash(iphoneID: hello.iphoneID, macID: macID,
                                                      clientEphemeral: hello.ephemeralKey, clientNonce: hello.nonce,
                                                      serverEphemeral: eph.publicKey.rawRepresentation, serverNonce: nonce)
        let signature = try identity.signature(for: concat(Data(label: Label.serverSignature), transcript))
        let keys = HandshakeMath.deriveKeys(shared: try HandshakeMath.agree(eph, clientEphemeral), salt: transcript)
        phase = .awaitingFinish(transcript: transcript, clientToServer: keys.clientToServer, serverToClient: keys.serverToClient)
        return ServerHello(macID: macID, ephemeralKey: eph.publicKey.rawRepresentation,
                           nonce: nonce, signature: signature.rawRepresentation)
    }

    public func handle(_ finish: ClientFinish) throws -> SessionKeys {
        guard case let .awaitingFinish(transcript, c2s, s2c) = phase else { throw RobAirError.unexpectedMessage }
        phase = .finished
        try finish.validate()
        // SÉCURITÉ : c'est CETTE vérification qui bloque le faux iPhone (S3).
        guard iphoneKey.isValidSignature(raw: finish.signature, for: concat(Data(label: Label.clientSignature), transcript)) else {
            throw RobAirError.invalidSignature
        }
        return SessionKeys(sending: s2c, receiving: c2s, transcriptHash: transcript)
    }
}

// MARK: - Renouvellement des clés dans la session (toutes les 15 min)

public struct RekeyMessage: WireMessage, Equatable {
    public let ephemeralKey: Data
    public let nonce: Data

    public func validate() throws {
        try requireLength(ephemeralKey, RobAirConstants.x25519KeySize, "ephemeralKey")
        try requireLength(nonce, RobAirConstants.nonceSize, "nonce")
    }
}

/// Résultat d'un renouvellement : nouvelles clés par sens + nouvelle transcription (base du suivant).
public struct RekeyedKeys {
    public let clientToServer: SymmetricKey
    public let serverToClient: SymmetricKey
    public let transcriptHash: Data
}

enum RekeyMath {
    static func transcript(previous: Data, initiator: RekeyMessage, responder: RekeyMessage) -> Data {
        var hasher = SHA256()
        for part in [Data(label: Label.rekey), previous, initiator.ephemeralKey, initiator.nonce,
                     responder.ephemeralKey, responder.nonce] {
            hasher.update(data: part)
        }
        return Data(hasher.finalize())
    }

    static func keys(shared: SharedSecret, transcript: Data) -> RekeyedKeys {
        let k = HandshakeMath.deriveKeys(shared: shared, salt: transcript)
        return RekeyedKeys(clientToServer: k.clientToServer, serverToClient: k.serverToClient, transcriptHash: transcript)
    }
}

/// L'iPhone lance le renouvellement. Protocole : l'initiateur n'envoie RIEN d'autre entre rekey et rekeyAck,
/// le répondeur bascule ses deux clés juste après avoir envoyé rekeyAck (sous l'ancienne clé).
public final class RekeyInitiator {
    private var ephemeral: Curve25519.KeyAgreement.PrivateKey?
    public let message: RekeyMessage

    public init() {
        let eph = Curve25519.KeyAgreement.PrivateKey()
        ephemeral = eph
        message = RekeyMessage(ephemeralKey: eph.publicKey.rawRepresentation, nonce: SecureRandom.bytes(RobAirConstants.nonceSize))
    }

    public func finish(ack: RekeyMessage, previousTranscript: Data) throws -> RekeyedKeys {
        guard let eph = ephemeral else { throw RobAirError.unexpectedMessage }
        defer { ephemeral = nil }
        try ack.validate()
        let shared = try HandshakeMath.agree(eph, HandshakeMath.x25519(ack.ephemeralKey))
        return RekeyMath.keys(shared: shared, transcript: RekeyMath.transcript(previous: previousTranscript, initiator: message, responder: ack))
    }
}

public enum RekeyResponder {
    public static func respond(to request: RekeyMessage, previousTranscript: Data) throws -> (ack: RekeyMessage, keys: RekeyedKeys) {
        try request.validate()
        let eph = Curve25519.KeyAgreement.PrivateKey()
        let ack = RekeyMessage(ephemeralKey: eph.publicKey.rawRepresentation, nonce: SecureRandom.bytes(RobAirConstants.nonceSize))
        let shared = try HandshakeMath.agree(eph, HandshakeMath.x25519(request.ephemeralKey))
        return (ack, RekeyMath.keys(shared: shared, transcript: RekeyMath.transcript(previous: previousTranscript, initiator: request, responder: ack)))
    }
}
