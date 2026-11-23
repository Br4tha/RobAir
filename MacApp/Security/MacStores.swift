// MacStores.swift (Mac)
// Rôle : clés et données de la centrale (J1 §2.2, §3.1).
//
//   K_id_Mac  : clé maîtresse, Secure Enclave (puce Apple M), Touch ID ou mot de passe de session.
//               Repli si la Secure Enclave est inutilisable (compte gratuit, Mac Intel) : clé logicielle
//               dans le Keychain, elle aussi protégée par Touch ID / mot de passe. L'interface affiche lequel.
//   K_enc_Mac : X25519 (HPKE), Keychain, rotation hebdomadaire ; anciennes clés gardées 14 jours.
//   K_journal : signature du journal (P-256) + clé de chiffrement du fichier, Keychain.
// « Session opérateur » : Touch ID une fois → LAContext gardé 30 min pour signer les handshakes.
// Les signatures RARES et sensibles (confirmation d'appairage, déverrouillage de secours, rotation)
// redemandent TOUJOURS Touch ID.
// Un Mac différent à chaque séance → nouvelles clés → réappairage (voulu : clés non exportables).

import os
import Foundation
import CryptoKit
import LocalAuthentication
import RobAirKit

// MARK: - Clé maîtresse K_id_Mac

final class MacIdentity {
    let publicKey: P256.Signing.PublicKey
    let storageDescription: String
    private let usesSecureEnclave: Bool

    private static let keychain = KeychainStore(service: "robair.mac.identity")
    private enum Account {
        static let secureEnclave = "k_id_se"
        static let software = "k_id_sw"
        static let publicKey = "k_id_pub"
    }

    var macID: Data { DeviceID.of(publicKey) }

    private init(publicKey: P256.Signing.PublicKey, secureEnclave: Bool) {
        self.publicKey = publicKey
        usesSecureEnclave = secureEnclave
        storageDescription = secureEnclave ? "Secure Enclave · Touch ID" : "Keychain (repli logiciel) · Touch ID"
    }

    /// Charge la clé publique sans authentification (la clé privée, elle, exigera Touch ID à l'usage).
    static func loadOrCreate() throws -> MacIdentity {
        if let pub = try keychain.load(account: Account.publicKey) {
            let key = try P256.Signing.PublicKey(x963Representation: pub)
            return MacIdentity(publicKey: key, secureEnclave: try keychain.load(account: Account.secureEnclave) != nil)
        }
        if let key = try? SecureEnclaveSigningIdentity.create(.userPresence) {
            try keychain.save(key.privateKey.dataRepresentation, account: Account.secureEnclave)
            try keychain.save(key.publicKey.x963Representation, account: Account.publicKey)
            Log.app.info("Clé maîtresse créée dans la Secure Enclave")
            return MacIdentity(publicKey: key.publicKey, secureEnclave: true)
        }
        Log.app.notice("Secure Enclave indisponible : repli sur une clé logicielle protégée par Touch ID")
        let key = SoftwareSigningIdentity()
        try keychain.save(key.privateKey.rawRepresentation, account: Account.software, protection: .userPresence)
        try keychain.save(key.publicKey.x963Representation, account: Account.publicKey)
        return MacIdentity(publicKey: key.publicKey, secureEnclave: false)
    }

    /// Clé privée utilisable, avec un LAContext déjà validé par Touch ID / mot de passe.
    func signer(context: LAContext) throws -> SigningIdentity {
        if usesSecureEnclave {
            guard let blob = try Self.keychain.load(account: Account.secureEnclave) else { throw RobAirError.unknownDevice }
            return try SecureEnclaveSigningIdentity.load(blob, context: context)
        }
        guard let raw = try Self.keychain.load(account: Account.software, context: context) else { throw RobAirError.unknownDevice }
        return SoftwareSigningIdentity(privateKey: try P256.Signing.PrivateKey(rawRepresentation: raw))
    }

    static func wipe() { keychain.deleteAll() }
}

/// Authentification de l'opérateur du Mac (Touch ID, ou mot de passe de session).
enum OperatorAuth {
    static func authenticate(_ reason: String) async -> LAContext? {
        let context = LAContext()
        do {
            guard try await context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason) else { return nil }
            return context
        } catch {
            return nil
        }
    }
}

// MARK: - Clés de chiffrement HPKE K_enc_Mac (rotation hebdomadaire)

final class EncryptionKeyring {
    struct Entry: Codable {
        let epoch: UInt32
        let privateKey: Data       // X25519 brut (SECRET : uniquement dans le Keychain)
        let signed: SignedEncryptionKey
    }

    private let keychain = KeychainStore(service: "robair.mac.enc")
    private(set) var entries: [Entry]

    init() {
        entries = keychain.loadJSON([Entry].self, account: "keys") ?? []
    }

    var current: Entry? { entries.max { $0.epoch < $1.epoch } }

    var rotationDue: Bool {
        guard let current else { return true }
        return Date().timeIntervalSince(Date(millisecondsSince1970: current.signed.notBeforeMs)) > RobAirConstants.encryptionKeyRotation
    }

    /// Nouvelle clé, signée par K_id_Mac (Touch ID demandé par l'appelant).
    func rotate(signer: SigningIdentity) throws -> SignedEncryptionKey {
        let key = Curve25519.KeyAgreement.PrivateKey()
        let epoch = (current?.epoch ?? 0) + 1
        let signed = try SignedEncryptionKey.make(epoch: epoch, key: key.publicKey, signer: signer)
        let cutoff = Date().addingTimeInterval(-RobAirConstants.encryptionKeyGrace).millisecondsSince1970
        entries = entries.filter { $0.signed.notBeforeMs >= cutoff } + [Entry(epoch: epoch, privateKey: key.rawRepresentation, signed: signed)]
        try keychain.saveJSON(entries, account: "keys")
        return signed
    }

    func privateKey(epoch: UInt32) throws -> Curve25519.KeyAgreement.PrivateKey {
        guard let entry = entries.first(where: { $0.epoch == epoch }) else { throw RobAirError.unknownKeyEpoch }
        return try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: entry.privateKey)
    }

    func wipe() {
        keychain.deleteAll()
        entries = []
    }
}

// MARK: - iPhone appairé (un seul pour le MVP)

struct PairedDevice: Codable, Equatable {
    let identityKey: Data       // K_id_iPhone : handshakes, défis (Face ID)
    let telemetryKey: Data      // K_tel_iPhone : TÉLÉMÉTRIE SEULEMENT
    let pairedAtMs: UInt64
    var telemetry = TelemetryReceiver()
    var mailbox: RelayAPI.CreatedMailbox?

    func identity() throws -> P256.Signing.PublicKey { try P256.Signing.PublicKey(x963Representation: identityKey) }
    func telemetryPublicKey() throws -> P256.Signing.PublicKey { try P256.Signing.PublicKey(x963Representation: telemetryKey) }

    var iphoneID: Data { (try? identity()).map(DeviceID.of) ?? Data() }
    /// Pseudonyme affiché et journalisé (RGPD : pas de nom d'appareil).
    var shortName: String { DeviceID.short(iphoneID) }
}

final class PairedDeviceStore {
    private let keychain = KeychainStore(service: "robair.mac.paired")
    func load() -> PairedDevice? { keychain.loadJSON(PairedDevice.self, account: "iphone") }
    func save(_ device: PairedDevice) throws { try keychain.saveJSON(device, account: "iphone") }
    func wipe() { keychain.deleteAll() }
}

// MARK: - Réglages du relais (extension P2)

struct RelaySettings: Codable, Equatable {
    var url: String
    var pin: String
    var enrollmentKey: String

    var info: RelayInfo { RelayInfo(url: url, pin: pin) }
}

final class RelaySettingsStore {
    private let keychain = KeychainStore(service: "robair.mac.relay")
    func load() -> RelaySettings? { keychain.loadJSON(RelaySettings.self, account: "settings") }
    func save(_ settings: RelaySettings) throws { try keychain.saveJSON(settings, account: "settings") }
    func wipe() { keychain.deleteAll() }
}

// MARK: - Journal d'audit chiffré, chaîné et signé (logique dans RobAirKit/EventJournal.swift)

final class JournalStore {
    private(set) var journal: EventJournal
    let publicKey: P256.Signing.PublicKey
    private static let keychain = KeychainStore(service: "robair.mac.journal")

    private static var directory: URL {
        FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("RobAir", isDirectory: true)
    }
    private static var fileURL: URL { directory.appendingPathComponent("journal.bin") }

    /// `startupIntegrity` : résultat de la vérification au chargement (chaîne + ancre).
    private(set) var startupIntegrity: EventJournal.Integrity = .intact

    init() throws {
        let encryptionKey: SymmetricKey
        if let raw = try Self.keychain.load(account: "k_journal_enc") {
            encryptionKey = SymmetricKey(data: raw)
        } else {
            encryptionKey = SymmetricKey(size: .bits256)
            try Self.keychain.save(encryptionKey.withUnsafeBytes { Data($0) }, account: "k_journal_enc")
        }
        let signer: SoftwareSigningIdentity
        if let raw = try Self.keychain.load(account: "k_journal_sign") {
            signer = SoftwareSigningIdentity(privateKey: try P256.Signing.PrivateKey(rawRepresentation: raw))
        } else {
            signer = SoftwareSigningIdentity()
            try Self.keychain.save(signer.privateKey.rawRepresentation, account: "k_journal_sign")
        }
        publicKey = signer.publicKey
        try FileManager.default.createDirectory(at: Self.directory, withIntermediateDirectories: true)

        let anchor = Self.keychain.loadJSON(JournalAnchor.self, account: "anchor")
        if let data = try? Data(contentsOf: Self.fileURL),
           let loaded = try? EventJournal.importEncrypted(data, encryptionKey: encryptionKey, signer: signer) {
            journal = loaded
            startupIntegrity = loaded.verify(expected: anchor)
        } else {
            journal = EventJournal(encryptionKey: encryptionKey, signer: signer)
            if let anchor, anchor.count > 0 {
                // Fichier supprimé ou illisible alors que l'ancre dit qu'il existait : on le signale.
                startupIntegrity = .truncated(expectedCount: anchor.count)
                if FileManager.default.fileExists(atPath: Self.fileURL.path) {
                    let aside = Self.directory.appendingPathComponent("journal-illisible-\(Date().millisecondsSince1970).bin")
                    try? FileManager.default.moveItem(at: Self.fileURL, to: aside)
                }
            }
        }
        if startupIntegrity != .intact {
            append(.anomaly, device: "-", detail: "Journal précédent altéré ou supprimé (\(startupIntegrity))")
        }
    }

    func append(_ kind: JournalEntry.Kind, device: String, detail: String, evidence: Data? = nil) {
        do {
            try journal.append(kind, device: device, detail: detail, evidence: evidence)
            try journal.exportEncrypted().write(to: Self.fileURL, options: .atomic)
            try Self.keychain.saveJSON(journal.anchor, account: "anchor")
        } catch {
            Log.app.error("Écriture du journal impossible")
        }
    }

    func verify() -> EventJournal.Integrity {
        journal.verify(publicKey: publicKey, expected: Self.keychain.loadJSON(JournalAnchor.self, account: "anchor"))
    }

    static func wipe() {
        keychain.deleteAll()
        try? FileManager.default.removeItem(at: fileURL)
    }
}
