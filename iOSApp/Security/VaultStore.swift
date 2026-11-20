// VaultStore.swift (iPhone)
// Rôle : le coffre de l'app (une note chiffrée) : ce que RobAir protège (J1 §1.2).
//   - K_vault (AES-256) dans le Keychain : WhenUnlockedThisDeviceOnly + biometryCurrentSet (J1 §3.1),
//     donc lisible UNIQUEMENT après Face ID, et invalidée si un visage est ajouté
//   - fichier chiffré AES-GCM + protection iOS « Complete » (illisible téléphone verrouillé)
// À la fermeture (verrouillage, alerte) : la clé et le texte sont effacés de la mémoire au mieux (§3.5).
// Menaces : I (lecture sur un téléphone volé), E (contourner l'écran d'alerte : fermer l'écran n'ouvre rien).

import Foundation
import CryptoKit
import LocalAuthentication
import RobAirKit

final class VaultStore {
    private let keychain = KeychainStore(service: "robair.ios.vault")
    private let account = "k_vault"

    private var fileURL: URL {
        FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("vault.bin")
    }

    /// Ouvre le coffre. `context` doit avoir été validé par Face ID JUSTE AVANT.
    func open(context: LAContext) throws -> (key: SymmetricKey, text: String) {
        var raw: Data
        if let stored = try keychain.load(account: account, context: context) {
            raw = stored
        } else {
            raw = SecureRandom.bytes(32)
            try keychain.save(raw, account: account, protection: .biometry)
        }
        let key = SymmetricKey(data: raw)
        SecureWipe.wipe(&raw)   // la copie brute ne reste pas en mémoire
        guard FileManager.default.fileExists(atPath: fileURL.path) else { return (key, "") }
        do {
            var plain = try AES.GCM.open(AES.GCM.SealedBox(combined: Data(contentsOf: fileURL)), using: key)
            let text = String(decoding: plain, as: UTF8.self)
            SecureWipe.wipe(&plain)
            return (key, text)
        } catch {
            // Fichier modifié ou clé différente : on refuse (fail-safe), on ne renvoie rien.
            throw RobAirError.authenticationFailed
        }
    }

    func save(_ text: String, key: SymmetricKey) throws {
        var plain = Data(text.utf8)
        defer { SecureWipe.wipe(&plain) }
        guard let combined = try AES.GCM.seal(plain, using: key).combined else { throw RobAirError.malformed("vault") }
        try FileManager.default.createDirectory(at: fileURL.deletingLastPathComponent(), withIntermediateDirectories: true)
        // SÉCURITÉ : completeFileProtection = chiffré par iOS dès que l'appareil est verrouillé.
        try combined.write(to: fileURL, options: [.atomic, .completeFileProtection])
    }

    func wipe() {
        keychain.deleteAll()
        try? FileManager.default.removeItem(at: fileURL)
    }
}
