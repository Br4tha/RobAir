// EventJournal.swift
// Rôle : journal d'audit du Mac, en AJOUT SEUL, CHAÎNÉ par hash et SIGNÉ, stocké CHIFFRÉ (J1 §2.2, §4 ; J2 §10).
//   entrée_n.previousHash = SHA-256(entrée_{n-1})     → supprimer/modifier une entrée casse la chaîne
//   entrée_n.signature    = ECDSA(K_journal, entrée_n) → impossible de recalculer la chaîne sans la clé ;
//                                                         vérifiable par un tiers avec la clé publique
//   fichier               = AES-GCM(clé de chiffrement, JSON)
// Ancre (nombre d'entrées + dernier hash), gardée À PART dans le Keychain : détecte aussi la suppression
// des DERNIÈRES entrées ou du fichier entier, que la chaîne seule ne voit pas.
// Menaces : T (journal modifié), R (« ce n'est jamais arrivé »).
// RGPD : ni secret ni RSSI ; l'appareil est un pseudonyme ; les positions n'y sont écrites qu'en alerte.

import Foundation
import CryptoKit

public struct JournalEntry: Codable, Equatable, Identifiable {
    public enum Kind: String, Codable {
        case paired, unpaired, sessionOpened, sessionClosed, status, alert, telemetry,
             challenge, emergencyUnlock, keyRotation, relay, anomaly, reset
    }

    public let index: UInt64
    public let timestampMs: UInt64
    public let kind: Kind
    public let device: String
    public let detail: String
    /// Signature d'un appareil jointe comme preuve (ex. réponse à un défi signée après Face ID).
    public let evidence: Data?
    public let previousHash: Data
    public let signature: Data

    public var id: UInt64 { index }
    public var date: Date { Date(millisecondsSince1970: timestampMs) }

    /// Encodage binaire déterministe (champs variables préfixés par leur longueur).
    static func canonicalBytes(index: UInt64, timestampMs: UInt64, kind: Kind, device: String,
                               detail: String, evidence: Data?, previousHash: Data) -> Data {
        var bytes = Data(label: Label.journalEntry)
        bytes.appendUInt64BE(index)
        bytes.appendUInt64BE(timestampMs)
        bytes.appendLengthPrefixed(Data(kind.rawValue.utf8))
        bytes.appendLengthPrefixed(Data(device.utf8))
        bytes.appendLengthPrefixed(Data(detail.utf8))
        bytes.appendLengthPrefixed(evidence ?? Data())
        bytes.appendLengthPrefixed(previousHash)
        return bytes
    }

    var canonicalBytes: Data {
        Self.canonicalBytes(index: index, timestampMs: timestampMs, kind: kind, device: device,
                            detail: detail, evidence: evidence, previousHash: previousHash)
    }

    var hash: Data { Data(SHA256.hash(data: canonicalBytes + signature)) }
}

/// Résumé de l'état du journal, conservé hors du fichier (Keychain).
public struct JournalAnchor: Codable, Equatable {
    public let count: UInt64
    public let lastHash: Data
}

public struct EventJournal {
    public enum Integrity: Equatable {
        case intact
        case broken(atIndex: UInt64)
        case truncated(expectedCount: UInt64)
    }

    /// Ancre de la chaîne : « hachage » de l'entrée −1.
    static let genesisHash = Data(repeating: 0, count: 32)

    public private(set) var entries: [JournalEntry]
    private let encryptionKey: SymmetricKey
    private let signer: SigningIdentity

    public init(encryptionKey: SymmetricKey, signer: SigningIdentity, entries: [JournalEntry] = []) {
        self.encryptionKey = encryptionKey
        self.signer = signer
        self.entries = entries
    }

    public var anchor: JournalAnchor {
        JournalAnchor(count: UInt64(entries.count), lastHash: entries.last?.hash ?? Self.genesisHash)
    }

    @discardableResult
    public mutating func append(_ kind: JournalEntry.Kind, device: String, detail: String,
                                evidence: Data? = nil, now: Date = Date()) throws -> JournalEntry {
        let index = UInt64(entries.count)
        let previous = entries.last?.hash ?? Self.genesisHash
        let ts = now.millisecondsSince1970
        let bytes = JournalEntry.canonicalBytes(index: index, timestampMs: ts, kind: kind, device: device,
                                                detail: detail, evidence: evidence, previousHash: previous)
        let signature = try signer.signature(for: bytes).rawRepresentation
        let entry = JournalEntry(index: index, timestampMs: ts, kind: kind, device: device, detail: detail,
                                 evidence: evidence, previousHash: previous, signature: signature)
        entries.append(entry)
        return entry
    }

    /// Recalcule toute la chaîne, vérifie chaque signature, puis compare à l'ancre attendue.
    public func verify(publicKey: P256.Signing.PublicKey? = nil, expected anchor: JournalAnchor? = nil) -> Integrity {
        let key = publicKey ?? signer.publicKey
        var expectedPrevious = Self.genesisHash
        for (position, entry) in entries.enumerated() {
            guard entry.index == UInt64(position), entry.previousHash == expectedPrevious,
                  key.isValidSignature(raw: entry.signature, for: entry.canonicalBytes) else {
                return .broken(atIndex: UInt64(position))
            }
            expectedPrevious = entry.hash
        }
        if let anchor {
            let count = UInt64(entries.count)
            if count < anchor.count { return .truncated(expectedCount: anchor.count) }
            if anchor.count > 0, entries[Int(anchor.count) - 1].hash != anchor.lastHash {
                return .broken(atIndex: anchor.count - 1)
            }
        }
        return .intact
    }

    // MARK: Persistance chiffrée

    static let fileAAD = Data(label: "robair-journal-file-v1")

    public func exportEncrypted() throws -> Data {
        let json = try JSONEncoder().encode(entries)
        guard let combined = try AES.GCM.seal(json, using: encryptionKey, authenticating: Self.fileAAD).combined else {
            throw RobAirError.malformed("journal")
        }
        return combined
    }

    public static func importEncrypted(_ data: Data, encryptionKey: SymmetricKey, signer: SigningIdentity) throws -> EventJournal {
        let json: Data
        do {
            json = try AES.GCM.open(AES.GCM.SealedBox(combined: data), using: encryptionKey, authenticating: fileAAD)
        } catch {
            throw RobAirError.authenticationFailed
        }
        do {
            return EventJournal(encryptionKey: encryptionKey, signer: signer,
                                entries: try JSONDecoder().decode([JournalEntry].self, from: json))
        } catch {
            throw RobAirError.malformed("journal")
        }
    }
}
