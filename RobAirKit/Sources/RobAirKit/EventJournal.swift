// EventJournal.swift
// Rôle : journal d'événements du Mac, CHAÎNÉ et SCELLÉ, stocké CHIFFRÉ. Voir J2 §8.
//   entrée_n.previousHash = SHA-256(entrée_{n-1})    → supprimer/modifier une entrée casse la chaîne
//   entrée_n.seal         = HMAC(clé_sceau, entrée_n) → impossible de recalculer la chaîne sans la clé
//   fichier               = AES-GCM(clé_chiffrement, JSON)
// Les deux clés sont dérivées d'une clé maîtresse (Keychain du Mac) par HKDF : une clé = un usage.
// Menaces : T2, R2. RGPD : on n'y écrit ni secret, ni RSSI, ni position ; l'appareil est un pseudonyme.

import Foundation
import CryptoKit

public struct JournalEntry: Codable, Equatable, Identifiable {
    public enum Kind: String, Codable {
        case paired, sessionOpened, sessionClosed, status, alert, sensitiveEvent, anomaly, reset
    }

    public let index: UInt64
    public let timestampMs: UInt64
    public let kind: Kind
    public let device: String
    public let detail: String
    public let eventSignature: Data?
    public let previousHash: Data
    public let seal: Data

    public var id: UInt64 { index }
    public var date: Date { Date(millisecondsSince1970: timestampMs) }

    /// Encodage binaire déterministe (champs variables préfixés par leur longueur).
    static func canonicalBytes(index: UInt64, timestampMs: UInt64, kind: Kind, device: String,
                               detail: String, eventSignature: Data?, previousHash: Data) -> Data {
        var bytes = Data()
        bytes.appendUInt64BE(index)
        bytes.appendUInt64BE(timestampMs)
        bytes.appendLengthPrefixed(Data(kind.rawValue.utf8))
        bytes.appendLengthPrefixed(Data(device.utf8))
        bytes.appendLengthPrefixed(Data(detail.utf8))
        bytes.appendLengthPrefixed(eventSignature ?? Data())
        bytes.appendLengthPrefixed(previousHash)
        return bytes
    }

    var canonicalBytes: Data {
        Self.canonicalBytes(index: index, timestampMs: timestampMs, kind: kind, device: device,
                            detail: detail, eventSignature: eventSignature, previousHash: previousHash)
    }

    var hash: Data { Data(SHA256.hash(data: canonicalBytes + seal)) }
}

public struct EventJournal {
    public enum Integrity: Equatable {
        case intact
        case broken(atIndex: UInt64)
    }

    /// Ancre de la chaîne : « hachage » de l'entrée -1.
    static let genesisHash = Data(repeating: 0, count: 32)

    public private(set) var entries: [JournalEntry]
    private let encryptionKey: SymmetricKey
    private let sealKey: SymmetricKey

    public init(masterKey: SymmetricKey, entries: [JournalEntry] = []) {
        encryptionKey = HKDF<SHA256>.deriveKey(inputKeyMaterial: masterKey,
                                               info: Data(label: Label.journalEncryption), outputByteCount: 32)
        sealKey = HKDF<SHA256>.deriveKey(inputKeyMaterial: masterKey,
                                         info: Data(label: Label.journalSeal), outputByteCount: 32)
        self.entries = entries
    }

    @discardableResult
    public mutating func append(_ kind: JournalEntry.Kind, device: String, detail: String,
                                eventSignature: Data? = nil, now: Date = Date()) -> JournalEntry {
        let index = UInt64(entries.count)
        let previous = entries.last?.hash ?? Self.genesisHash
        let ts = now.millisecondsSince1970
        let bytes = JournalEntry.canonicalBytes(index: index, timestampMs: ts, kind: kind, device: device,
                                                detail: detail, eventSignature: eventSignature, previousHash: previous)
        let seal = Data(HMAC<SHA256>.authenticationCode(for: bytes, using: sealKey))
        let entry = JournalEntry(index: index, timestampMs: ts, kind: kind, device: device, detail: detail,
                                 eventSignature: eventSignature, previousHash: previous, seal: seal)
        entries.append(entry)
        return entry
    }

    /// Recalcule toute la chaîne et indique la première entrée incohérente.
    public func verify() -> Integrity {
        var expectedPrevious = Self.genesisHash
        for (position, entry) in entries.enumerated() {
            let sealOK = HMAC<SHA256>.isValidAuthenticationCode(entry.seal, authenticating: entry.canonicalBytes, using: sealKey)
            guard entry.index == UInt64(position), entry.previousHash == expectedPrevious, sealOK else {
                return .broken(atIndex: UInt64(position))
            }
            expectedPrevious = entry.hash
        }
        return .intact
    }

    // MARK: Persistance chiffrée

    public func exportEncrypted() throws -> Data {
        let json = try RobAirJSON.encode(entries)
        guard let combined = try AES.GCM.seal(json, using: encryptionKey).combined else {
            throw RobAirError.malformed("journal")
        }
        return combined
    }

    public static func importEncrypted(_ data: Data, masterKey: SymmetricKey) throws -> EventJournal {
        var journal = EventJournal(masterKey: masterKey)
        let json: Data
        do {
            json = try AES.GCM.open(AES.GCM.SealedBox(combined: data), using: journal.encryptionKey)
        } catch {
            throw RobAirError.authenticationFailed
        }
        do {
            journal.entries = try JSONDecoder().decode([JournalEntry].self, from: json)
        } catch {
            throw RobAirError.malformed("journal")
        }
        return journal
    }
}
