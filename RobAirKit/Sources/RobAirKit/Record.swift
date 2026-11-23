// Record.swift
// Rôle : enveloppe des messages de session (§3.4), chiffrée en AES-256-GCM, avec anti-rejeu.
//
// Enveloppe = { version, type, sender_id, seq, timestamp, ciphertext, tag }
//   [version u8][type u8][sender_id 16][seq u64 BE][timestamp ms u64 BE] [chiffré] [tag 16]
//   └──────────────────────── en-tête = AAD (authentifié) ───────────┘
// Nonce GCM (12 octets) = préfixe de sens (4 octets) ‖ seq (8 octets)
//
// Règles de réception (§3.4) :
//   - expéditeur attendu, type chiffré, seq > dernier seq accepté, horodatage à ±30 s ;
//   - le dernier seq n'est mis à jour qu'APRÈS un déchiffrement réussi
//     (sinon une trame forgée avec un seq énorme bloquerait la session).
// Menaces : T1 (altération), I1 (écoute), rejeu.

import Foundation
import CryptoKit

public enum Direction {
    case clientToServer, serverToClient

    /// Préfixe de nonce : même avec une erreur de dérivation, les deux sens n'utiliseraient jamais le même nonce.
    var noncePrefix: Data { self == .clientToServer ? Data([0x43, 0x32, 0x53, 0x00]) : Data([0x53, 0x32, 0x43, 0x00]) }
}

enum RecordFormat {
    static let headerSize = 2 + RobAirConstants.deviceIDSize + 8 + 8   // 34 octets
    static let tagSize = 16
    /// Bien en dessous de 2^64 : au-delà, on exige une nouvelle session.
    static let maxSeq: UInt64 = 1 << 48

    static func header(type: MessageType, sender: Data, seq: UInt64, timestampMs: UInt64) -> Data {
        var header = Data([RobAirConstants.protocolVersion, type.rawValue])
        header.append(sender)
        header.appendUInt64BE(seq)
        header.appendUInt64BE(timestampMs)
        return header
    }

    static func nonce(_ direction: Direction, seq: UInt64) throws -> AES.GCM.Nonce {
        var bytes = direction.noncePrefix
        bytes.appendUInt64BE(seq)
        return try AES.GCM.Nonce(data: bytes)
    }
}

public struct RecordSealer {
    private var key: SymmetricKey
    private let sender: Data
    private let direction: Direction
    public private(set) var seq: UInt64 = 0

    public init(key: SymmetricKey, sender: Data, direction: Direction) {
        self.key = key
        self.sender = sender
        self.direction = direction
    }

    /// Nouvelle clé après un renouvellement (§3.3) ; le seq continue (jamais de retour en arrière).
    public mutating func rotate(to newKey: SymmetricKey) { key = newKey }

    /// Retourne le corps de trame chiffré (à passer ensuite à Wire.frame).
    public mutating func seal(_ type: MessageType, _ payload: Data, now: Date = Date()) throws -> Data {
        guard type.isEncrypted else { throw RobAirError.unexpectedMessage }
        guard seq < RecordFormat.maxSeq else { throw RobAirError.counterExhausted }
        seq += 1   // SÉCURITÉ : incrémenté avant usage, jamais réutilisé même en cas d'erreur
        let header = RecordFormat.header(type: type, sender: sender, seq: seq, timestampMs: now.millisecondsSince1970)
        let box = try AES.GCM.seal(payload, using: key, nonce: RecordFormat.nonce(direction, seq: seq), authenticating: header)
        let body = header + box.ciphertext + box.tag
        guard body.count <= RobAirConstants.maxMessageSize else { throw RobAirError.messageTooLarge }
        return body
    }

    public mutating func sealJSON<T: WireMessage>(_ type: MessageType, _ value: T, now: Date = Date()) throws -> Data {
        try seal(type, StrictJSON.encode(value), now: now)
    }
}

public struct RecordOpener {
    private var key: SymmetricKey
    private let expectedSender: Data
    private let direction: Direction
    public private(set) var lastSeq: UInt64 = 0

    public init(key: SymmetricKey, expectedSender: Data, direction: Direction) {
        self.key = key
        self.expectedSender = expectedSender
        self.direction = direction
    }

    public mutating func rotate(to newKey: SymmetricKey) { key = newKey }

    public mutating func open(_ body: Data, now: Date = Date()) throws -> (type: MessageType, payload: Data) {
        guard body.count <= RobAirConstants.maxMessageSize else { throw RobAirError.messageTooLarge }
        guard body.count >= RecordFormat.headerSize + RecordFormat.tagSize else { throw RobAirError.malformed("record") }
        let type = try Wire.messageType(of: body)
        guard type.isEncrypted else { throw RobAirError.unexpectedMessage }

        let sender = body.bytes(2..<(2 + RobAirConstants.deviceIDSize))
        guard sender == expectedSender else { throw RobAirError.unknownDevice }
        let seq = body.readUInt64BE(at: 2 + RobAirConstants.deviceIDSize)
        let timestampMs = body.readUInt64BE(at: 2 + RobAirConstants.deviceIDSize + 8)
        // SÉCURITÉ : anti-rejeu (§3.4). Seq déjà vu ou plus petit : refusé.
        guard seq > lastSeq else { throw RobAirError.replayDetected }
        try Freshness.check(timestampMs: timestampMs, now: now, window: RobAirConstants.timestampWindowLocal)

        let header = body.bytes(0..<RecordFormat.headerSize)
        let ciphertext = body.bytes(RecordFormat.headerSize..<(body.count - RecordFormat.tagSize))
        let tag = body.bytes((body.count - RecordFormat.tagSize)..<body.count)
        let payload: Data
        do {
            let box = try AES.GCM.SealedBox(nonce: RecordFormat.nonce(direction, seq: seq), ciphertext: ciphertext, tag: tag)
            payload = try AES.GCM.open(box, using: key, authenticating: header)
        } catch {
            throw RobAirError.authenticationFailed
        }
        lastSeq = seq   // SÉCURITÉ : seulement après authentification réussie
        return (type, payload)
    }
}
