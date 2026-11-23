// Stores.swift (iPhone)
// Rôle : ce que le capteur mémorise, toujours dans le Keychain (ThisDeviceOnly, jamais dans UserDefaults).
//   - la centrale appairée : clé du Mac ÉPINGLÉE, clé HPKE signée, relais (URL + pin), accès à la boîte
//   - la balise appairée : UUID de service + K_balise (secret partagé, §3.9)
//   - l'état de protection (armé / alerte) : il doit survivre à un redémarrage de l'app (fail-safe)
//   - le compteur seq de la télémétrie : il ne doit JAMAIS revenir en arrière (anti-rejeu côté Mac)
// Rien de tout cela n'est lisible par une autre app ni copié dans les sauvegardes.

import os
import Foundation
import CryptoKit
import RobAirKit

struct CentraleConfig: Codable, Equatable {
    let macIdentityKey: Data
    let macID: Data
    let serviceName: String
    var encryptionKey: SignedEncryptionKey
    let relay: RelayInfo?
    var mailbox: MailboxConfig?

    func macKey() throws -> P256.Signing.PublicKey {
        try P256.Signing.PublicKey(x963Representation: macIdentityKey)
    }

    /// Clé HPKE du Mac, re-vérifiée à chaque usage (signature par la clé épinglée).
    func encryptionPublicKey() throws -> Curve25519.KeyAgreement.PublicKey {
        try encryptionKey.verified(by: macKey())
    }
}

final class CentraleStore {
    private let keychain = KeychainStore(service: "robair.ios.centrale")
    func load() -> CentraleConfig? { keychain.loadJSON(CentraleConfig.self, account: "centrale") }
    func save(_ config: CentraleConfig) throws { try keychain.saveJSON(config, account: "centrale") }
    func wipe() { keychain.deleteAll() }
}

final class BeaconKeyStore {
    private let keychain: KeychainStore
    init(service: String) { keychain = KeychainStore(service: service) }
    func load() -> BeaconPairingCode? { keychain.loadJSON(BeaconPairingCode.self, account: "beacon") }
    func save(_ code: BeaconPairingCode) throws { try keychain.saveJSON(code, account: "beacon") }
    func wipe() { keychain.deleteAll() }
}

final class StateStore {
    private let keychain = KeychainStore(service: "robair.ios.state")

    /// "disarmed" | "armed" | "alert:<raison>"
    func loadProtection() -> ProtectionState {
        guard let raw = (try? keychain.load(account: "protection")).flatMap({ String(data: $0, encoding: .utf8) }) else {
            return .disarmed
        }
        if raw == "armed" { return .armed }
        if raw.hasPrefix("alert:") { return .alert(TelemetryTrigger(rawValue: String(raw.dropFirst(6))) ?? .failSafe) }
        return .disarmed
    }

    func saveProtection(_ state: ProtectionState) {
        let raw: String
        switch state {
        case .disarmed: raw = "disarmed"
        case .armed: raw = "armed"
        case .alert(let reason): raw = "alert:\(reason.rawValue)"
        }
        try? keychain.save(Data(raw.utf8), account: "protection")
    }

    /// Prochain seq de télémétrie, persisté AVANT usage : un plantage ne peut pas faire réutiliser un seq.
    func nextTelemetrySeq() throws -> UInt64 {
        let current = (try keychain.load(account: "seq")).map { $0.readUInt64() } ?? 0
        let next = current + 1
        var bytes = Data()
        withUnsafeBytes(of: next.bigEndian) { bytes.append(contentsOf: $0) }
        try keychain.save(bytes, account: "seq")
        return next
    }

    func wipe() { keychain.deleteAll() }
}

private extension Data {
    func readUInt64() -> UInt64 {
        guard count == 8 else { return 0 }
        return reduce(0) { ($0 << 8) | UInt64($1) }
    }
}
