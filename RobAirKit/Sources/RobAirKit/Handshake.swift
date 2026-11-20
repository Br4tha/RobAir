// Handshake.swift
// Rôle : ouverture d'une session chiffrée = Diffie-Hellman ÉPHÉMÈRE SIGNÉ (même schéma que TLS 1.3 / SIGMA).
// Voir docs/J2-architecture.md §4.
//
//   iPhone (client)                                   Mac (serveur)
//   ClientHello {empreinte, ePub_I, N_I}      ─────►
//                                             ◄─────  ServerHello {ePub_M, N_M, Sig_M(transcript)}
//   ClientFinish {Sig_I(transcript)}          ─────►
//   Les deux : HKDF(ECDH(eph), sel = N_I‖N_M, info = étiquette‖transcript) → clé c2s + clé s2c
//
// Menaces : S1 (faux Mac), S3 (faux iPhone), I1 (écoute), confidentialité persistante.
// Points de relecture :
//   1. Les signatures couvrent TOUT le transcript (sinon homme du milieu possible).
//   2. Étiquettes différentes client/serveur (une signature ne peut pas être « renvoyée en miroir »).
//   3. Le serveur ne livre les clés qu'APRÈS avoir vérifié ClientFinish.
//   4. Les clés éphémères sont oubliées après usage (objets à usage unique).

import Foundation
import CryptoKit

public struct ClientHello: Codable, Equatable {
    public let fingerprint: Data
    public let ephemeralKey: Data
    public let nonce: Data

    func validate() throws {
        try requireLength(fingerprint, RobAirConstants.fingerprintSize, "fingerprint")
        try requireLength(ephemeralKey, RobAirConstants.p256PublicKeySize, "ephemeralKey")
        try requireLength(nonce, RobAirConstants.nonceSize, "nonce")
    }
}

public struct ServerHello: Codable, Equatable {
    public let ephemeralKey: Data
    public let nonce: Data
    public let signature: Data

    func validate() throws {
        try requireLength(ephemeralKey, RobAirConstants.p256PublicKeySize, "ephemeralKey")
        try requireLength(nonce, RobAirConstants.nonceSize, "nonce")
        try requireLength(signature, RobAirConstants.p256SignatureSize, "signature")
    }
}

public struct ClientFinish: Codable, Equatable {
    public let signature: Data
}

/// Clés d'une session, du point de vue de celui qui les détient.
public struct SessionKeys {
    public let sending: SymmetricKey
    public let receiving: SymmetricKey
    public let transcriptHash: Data
}

enum HandshakeMath {
    static func transcriptHash(clientHello: ClientHello,
                               serverFingerprint: Data,
                               serverEphemeral: Data,
                               serverNonce: Data) -> Data {
        // Tous les champs sont de taille fixe : la concaténation est sans ambiguïté.
        var hasher = SHA256()
        hasher.update(data: Data(label: Label.transcript))
        hasher.update(data: clientHello.fingerprint)
        hasher.update(data: serverFingerprint)
        hasher.update(data: clientHello.ephemeralKey)
        hasher.update(data: clientHello.nonce)
        hasher.update(data: serverEphemeral)
        hasher.update(data: serverNonce)
        return Data(hasher.finalize())
    }

    static func deriveKeys(shared: SharedSecret,
                           clientNonce: Data,
                           serverNonce: Data,
                           transcript: Data) -> (clientToServer: SymmetricKey, serverToClient: SymmetricKey) {
        let salt = concat(clientNonce, serverNonce)
        // SÉCURITÉ : une clé par sens → le même couple (clé, nonce) n'est jamais utilisé des deux côtés.
        let c2s = shared.hkdfDerivedSymmetricKey(using: SHA256.self, salt: salt,
                                                 sharedInfo: concat(Data(label: Label.keyClientToServer), transcript),
                                                 outputByteCount: 32)
        let s2c = shared.hkdfDerivedSymmetricKey(using: SHA256.self, salt: salt,
                                                 sharedInfo: concat(Data(label: Label.keyServerToClient), transcript),
                                                 outputByteCount: 32)
        return (c2s, s2c)
    }
}

/// Côté iPhone. Un objet = une tentative de handshake.
public final class HandshakeClient {
    private let identity: SigningIdentity
    private let serverKey: P256.Signing.PublicKey   // clé du Mac épinglée à l'appairage (QR code)
    private var ephemeral: P256.KeyAgreement.PrivateKey?
    private var sentHello: ClientHello?

    public init(identity: SigningIdentity, serverKey: P256.Signing.PublicKey) {
        self.identity = identity
        self.serverKey = serverKey
    }

    public func makeHello() -> ClientHello {
        let eph = P256.KeyAgreement.PrivateKey()
        ephemeral = eph
        let hello = ClientHello(fingerprint: Fingerprint.of(identity.publicKey),
                                ephemeralKey: eph.publicKey.x963Representation,
                                nonce: SecureRandom.bytes(RobAirConstants.nonceSize))
        sentHello = hello
        return hello
    }

    public func handle(_ reply: ServerHello) throws -> (finish: ClientFinish, keys: SessionKeys) {
        guard let eph = ephemeral, let hello = sentHello else { throw RobAirError.unexpectedMessage }
        // SÉCURITÉ : usage unique, la clé éphémère est oubliée quoi qu'il arrive.
        defer { ephemeral = nil; sentHello = nil }

        try reply.validate()
        let serverEphemeral = try P256.KeyAgreement.PublicKey(x963Representation: reply.ephemeralKey)
        let transcript = HandshakeMath.transcriptHash(clientHello: hello,
                                                      serverFingerprint: Fingerprint.of(serverKey),
                                                      serverEphemeral: reply.ephemeralKey,
                                                      serverNonce: reply.nonce)
        // SÉCURITÉ : c'est CETTE vérification qui bloque le faux Mac (S1).
        guard serverKey.isValidSignature(raw: reply.signature,
                                         for: concat(Data(label: Label.serverSignature), transcript)) else {
            throw RobAirError.invalidSignature
        }
        let shared = try eph.sharedSecretFromKeyAgreement(with: serverEphemeral)
        let keys = HandshakeMath.deriveKeys(shared: shared, clientNonce: hello.nonce,
                                            serverNonce: reply.nonce, transcript: transcript)
        let signature = try identity.signature(for: concat(Data(label: Label.clientSignature), transcript))
        return (ClientFinish(signature: signature.rawRepresentation),
                SessionKeys(sending: keys.clientToServer, receiving: keys.serverToClient, transcriptHash: transcript))
    }
}

/// Côté Mac. Un objet = une connexion entrante.
public final class HandshakeServer {
    private enum Phase {
        case awaitingHello
        case awaitingFinish(transcript: Data, clientToServer: SymmetricKey, serverToClient: SymmetricKey)
        case finished
    }

    private let identity: SigningIdentity
    private let clientKey: P256.Signing.PublicKey   // clé de l'iPhone épinglée à l'appairage
    private var phase = Phase.awaitingHello

    public init(identity: SigningIdentity, clientKey: P256.Signing.PublicKey) {
        self.identity = identity
        self.clientKey = clientKey
    }

    public func handle(_ hello: ClientHello) throws -> ServerHello {
        guard case .awaitingHello = phase else { throw RobAirError.unexpectedMessage }
        phase = .finished   // en cas d'erreur ci-dessous, l'objet devient inutilisable (fail-safe)

        try hello.validate()
        guard hello.fingerprint == Fingerprint.of(clientKey) else { throw RobAirError.unknownDevice }
        // L'initialisation vérifie que le point est bien sur la courbe P-256.
        let clientEphemeral = try P256.KeyAgreement.PublicKey(x963Representation: hello.ephemeralKey)

        let eph = P256.KeyAgreement.PrivateKey()
        let nonce = SecureRandom.bytes(RobAirConstants.nonceSize)
        let transcript = HandshakeMath.transcriptHash(clientHello: hello,
                                                      serverFingerprint: Fingerprint.of(identity.publicKey),
                                                      serverEphemeral: eph.publicKey.x963Representation,
                                                      serverNonce: nonce)
        let signature = try identity.signature(for: concat(Data(label: Label.serverSignature), transcript))
        let shared = try eph.sharedSecretFromKeyAgreement(with: clientEphemeral)
        let keys = HandshakeMath.deriveKeys(shared: shared, clientNonce: hello.nonce,
                                            serverNonce: nonce, transcript: transcript)
        phase = .awaitingFinish(transcript: transcript,
                                clientToServer: keys.clientToServer,
                                serverToClient: keys.serverToClient)
        return ServerHello(ephemeralKey: eph.publicKey.x963Representation,
                           nonce: nonce,
                           signature: signature.rawRepresentation)
    }

    public func handle(_ finish: ClientFinish) throws -> SessionKeys {
        guard case let .awaitingFinish(transcript, c2s, s2c) = phase else { throw RobAirError.unexpectedMessage }
        phase = .finished
        // SÉCURITÉ : c'est CETTE vérification qui bloque le faux iPhone (S3).
        guard clientKey.isValidSignature(raw: finish.signature,
                                         for: concat(Data(label: Label.clientSignature), transcript)) else {
            throw RobAirError.invalidSignature
        }
        return SessionKeys(sending: s2c, receiving: c2s, transcriptHash: transcript)
    }
}
