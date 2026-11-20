// Record.swift
// Rôle : chiffrement des messages d'une session (AES-256-GCM) + anti-rejeu par compteur.
// Voir docs/J2-architecture.md §5.
//
// Corps : [version u8][type u8][compteur u64 BE] [chiffré] [tag 16 octets]
//         └────────── en-tête = AAD ─────────┘
// Nonce GCM (12 octets) = 00 00 00 00 ‖ compteur (8 octets)
//
// Menaces : T1 (altération), I1 (écoute), rejeu.
// Points de relecture :
//   1. Le nonce n'est JAMAIS réutilisé avec la même clé (compteur strictement croissant + une clé par sens).
//   2. L'en-tête est authentifié (AAD) : modifier le type ou le compteur fait échouer le tag.
//   3. Le dernier compteur n'est mis à jour qu'APRÈS un déchiffrement réussi
//      (sinon une trame forgée avec un compteur énorme bloquerait la session).

import Foundation
import CryptoKit

enum RecordFormat {
    static let headerSize = 10
    static let tagSize = 16
    /// Bien en dessous de 2^64 : au-delà, on exige une nouvelle session.
    static let maxCounter: UInt64 = 1 << 48

    static func header(type: MessageType, counter: UInt64) -> Data {
        var header = Data([RobAirConstants.protocolVersion, type.rawValue])
        header.appendUInt64BE(counter)
        return header
    }

    static func nonce(counter: UInt64) throws -> AES.GCM.Nonce {
        var bytes = Data(repeating: 0, count: 4)
        bytes.appendUInt64BE(counter)
        return try AES.GCM.Nonce(data: bytes)
    }
}

public struct RecordSealer {
    private let key: SymmetricKey
    private var counter: UInt64 = 0

    public init(key: SymmetricKey) { self.key = key }

    /// Retourne le corps de trame chiffré (à passer ensuite à Wire.frame).
    public mutating func seal(_ type: MessageType, _ payload: Data) throws -> Data {
        guard type.isEncrypted else { throw RobAirError.unexpectedMessage }
        guard counter < RecordFormat.maxCounter else { throw RobAirError.counterExhausted }
        counter += 1   // SÉCURITÉ : incrémenté avant usage, jamais réutilisé même en cas d'erreur
        let header = RecordFormat.header(type: type, counter: counter)
        let box = try AES.GCM.seal(payload, using: key,
                                   nonce: RecordFormat.nonce(counter: counter),
                                   authenticating: header)
        let body = header + box.ciphertext + box.tag
        guard body.count <= RobAirConstants.maxFrameSize else { throw RobAirError.frameTooLarge }
        return body
    }

    public mutating func sealJSON<T: Encodable>(_ type: MessageType, _ value: T) throws -> Data {
        try seal(type, RobAirJSON.encode(value))
    }
}

public struct RecordOpener {
    private let key: SymmetricKey
    public private(set) var lastCounter: UInt64 = 0

    public init(key: SymmetricKey) { self.key = key }

    public mutating func open(_ body: Data) throws -> (type: MessageType, payload: Data) {
        guard body.count <= RobAirConstants.maxFrameSize else { throw RobAirError.frameTooLarge }
        guard body.count >= RecordFormat.headerSize + RecordFormat.tagSize else {
            throw RobAirError.malformed("record")
        }
        let type = try Wire.messageType(of: body)
        guard type.isEncrypted else { throw RobAirError.unexpectedMessage }

        let counter = body.readUInt64BE(at: 2)
        // SÉCURITÉ : anti-rejeu. Un compteur déjà vu (ou plus petit) est refusé.
        guard counter > lastCounter else { throw RobAirError.replayDetected }

        let header = body.bytes(0..<RecordFormat.headerSize)
        let ciphertext = body.bytes(RecordFormat.headerSize..<(body.count - RecordFormat.tagSize))
        let tag = body.bytes((body.count - RecordFormat.tagSize)..<body.count)

        let payload: Data
        do {
            let box = try AES.GCM.SealedBox(nonce: RecordFormat.nonce(counter: counter),
                                            ciphertext: ciphertext, tag: tag)
            payload = try AES.GCM.open(box, using: key, authenticating: header)
        } catch {
            throw RobAirError.authenticationFailed
        }
        lastCounter = counter   // SÉCURITÉ : seulement après authentification réussie
        return (type, payload)
    }
}
