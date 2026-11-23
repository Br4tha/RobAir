// DeviceIdentity.swift (iPhone)
// Rôle : les deux clés de signature de l'iPhone, dans la Secure Enclave (J1 §3.1).
//   K_id_iPhone  : Face ID à chaque usage (biometryCurrentSet). Signe les handshakes (§3.3) et les
//                  réponses aux défis du Mac (§3.7).
//   K_tel_iPhone : SANS biométrie (AfterFirstUnlock), car la télémétrie part téléphone verrouillé,
//                  dans la main du voleur. Elle ne signe QUE des messages TELEMETRY : le Mac la refuse
//                  pour toute autre action.
// Le Keychain ne stocke que les « blobs » opaques de la Secure Enclave, inutilisables ailleurs.
// Menaces : I (vol de l'appareil), E (Face ID contourné, visage ajouté), R (non-répudiation).

import os
import Foundation
import CryptoKit
import LocalAuthentication
import RobAirKit

final class DeviceIdentity {
    private let keychain = KeychainStore(service: "robair.ios.identity")

    private enum Account {
        static let identity = "k_id"
        static let telemetry = "k_tel"
    }

    /// Nouvelles clés à chaque appairage : une clé compromise ne survit pas à un réappairage.
    func regenerate() throws -> (identity: P256.Signing.PublicKey, telemetry: P256.Signing.PublicKey) {
        wipe()
        #if targetEnvironment(simulator)
        // Simulateur uniquement (pas de Secure Enclave) : clés logicielles pour tester l'interface.
        let id = SoftwareSigningIdentity(), tel = SoftwareSigningIdentity()
        try keychain.save(id.privateKey.rawRepresentation, account: Account.identity)
        try keychain.save(tel.privateKey.rawRepresentation, account: Account.telemetry)
        #else
        let id = try SecureEnclaveSigningIdentity.create(.biometric)
        let tel = try SecureEnclaveSigningIdentity.create(.background)
        try keychain.save(id.privateKey.dataRepresentation, account: Account.identity)
        try keychain.save(tel.privateKey.dataRepresentation, account: Account.telemetry)
        #endif
        return (id.publicKey, tel.publicKey)
    }

    /// K_id_iPhone. Sans `context`, la clé publique est lisible mais toute signature demandera Face ID.
    /// Avec un LAContext déjà validé, la Secure Enclave signe sans redemander.
    func loadIdentity(context: LAContext? = nil) throws -> SigningIdentity {
        guard let blob = try keychain.load(account: Account.identity) else { throw RobAirError.unknownDevice }
        #if targetEnvironment(simulator)
        return SoftwareSigningIdentity(privateKey: try P256.Signing.PrivateKey(rawRepresentation: blob))
        #else
        return try SecureEnclaveSigningIdentity.load(blob, context: context)
        #endif
    }

    /// K_tel_iPhone : utilisable en arrière-plan, téléphone verrouillé.
    func loadTelemetry() throws -> SigningIdentity {
        guard let blob = try keychain.load(account: Account.telemetry) else { throw RobAirError.unknownDevice }
        #if targetEnvironment(simulator)
        return SoftwareSigningIdentity(privateKey: try P256.Signing.PrivateKey(rawRepresentation: blob))
        #else
        return try SecureEnclaveSigningIdentity.load(blob)
        #endif
    }

    /// Identifiant public (pseudonyme) de cet iPhone.
    var iphoneID: Data? { (try? loadIdentity()).map { DeviceID.of($0.publicKey) } }

    func wipe() { keychain.deleteAll() }
}
