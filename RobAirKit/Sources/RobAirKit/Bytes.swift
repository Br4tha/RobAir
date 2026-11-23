// Bytes.swift
// Rôle : utilitaires d'octets (big-endian, aléa cryptographique, identifiants, effacement mémoire).
// Relecture : SecureRandom doit rester la SEULE source d'aléa du projet (pas de random(), arc4random, Date…).

import Foundation
import CryptoKit
#if canImport(Darwin)
import Darwin
#else
import Glibc
#endif

extension Data {
    init(label: String) { self = Data(label.utf8) }

    /// Octet à une position relative au début (fonctionne aussi sur une sous-partie de Data).
    func byte(at offset: Int) -> UInt8 { self[startIndex + offset] }

    /// Extrait une sous-partie avec des indices relatifs, ré-indexée à partir de 0.
    func bytes(_ range: Range<Int>) -> Data {
        subdata(in: (startIndex + range.lowerBound)..<(startIndex + range.upperBound))
    }

    mutating func appendUInt64BE(_ value: UInt64) {
        for shift in stride(from: 56, through: 0, by: -8) {
            append(UInt8(truncatingIfNeeded: value >> UInt64(shift)))
        }
    }

    mutating func appendUInt32BE(_ value: UInt32) {
        for shift in stride(from: 24, through: 0, by: -8) {
            append(UInt8(truncatingIfNeeded: value >> UInt32(shift)))
        }
    }

    /// Champ précédé de sa longueur : évite toute ambiguïté quand on concatène des champs de taille variable.
    mutating func appendLengthPrefixed(_ field: Data) {
        appendUInt32BE(UInt32(field.count))
        append(field)
    }

    func readUInt64BE(at offset: Int) -> UInt64 {
        var value: UInt64 = 0
        for i in 0..<8 { value = (value << 8) | UInt64(byte(at: offset + i)) }
        return value
    }

    func readUInt32BE(at offset: Int) -> UInt32 {
        var value: UInt32 = 0
        for i in 0..<4 { value = (value << 8) | UInt32(byte(at: offset + i)) }
        return value
    }

    public var hexString: String { map { String(format: "%02x", $0) }.joined() }
}

/// Concatène des champs de TAILLE FIXE (sinon utiliser appendLengthPrefixed).
func concat(_ parts: Data...) -> Data {
    parts.reduce(into: Data()) { $0.append($1) }
}

/// Vérifie la taille exacte d'un champ reçu (validation stricte des entrées).
func requireLength(_ data: Data, _ expected: Int, _ field: String) throws {
    guard data.count == expected else { throw RobAirError.malformed(field) }
}

public enum SecureRandom {
    /// Octets aléatoires issus du générateur cryptographique du système (via CryptoKit).
    public static func bytes(_ count: Int) -> Data {
        SymmetricKey(size: SymmetricKeySize(bitCount: count * 8)).withUnsafeBytes { Data($0) }
    }
}

/// Identifiant public d'un appareil (16 octets) = SHA-256(étiquette ‖ clé publique d'identité), tronqué.
/// C'est un pseudonyme : il ne contient ni nom ni numéro de série (RGPD).
public enum DeviceID {
    public static func of(_ key: P256.Signing.PublicKey) -> Data {
        Data(SHA256.hash(data: concat(Data(label: Label.deviceID), key.x963Representation)).prefix(RobAirConstants.deviceIDSize))
    }

    /// Forme courte lisible pour l'interface et le journal, ex. « 3FA2-91C0 ».
    public static func short(_ id: Data) -> String {
        let hex = id.prefix(4).map { String(format: "%02X", $0) }.joined()
        return String(hex.prefix(4)) + "-" + String(hex.suffix(4))
    }
}

/// Effacement « au mieux » des secrets que NOUS gérons (§3.5, étape 1).
/// memset_s / explicit_bzero ne peuvent pas être supprimés par l'optimiseur, contrairement à une boucle.
/// LIMITE ASSUMÉE : Swift peut avoir fait des copies ailleurs en mémoire ; la vraie protection reste
/// la Secure Enclave (clés non exportables) et Face ID pour K_vault.
public enum SecureWipe {
    public static func wipe(_ data: inout Data) {
        data.withUnsafeMutableBytes { buffer in
            guard let base = buffer.baseAddress, buffer.count > 0 else { return }
            #if canImport(Darwin)
            _ = memset_s(base, buffer.count, 0, buffer.count)
            #else
            explicit_bzero(base, buffer.count)
            #endif
        }
        data.removeAll()
    }
}

public extension Date {
    var millisecondsSince1970: UInt64 {
        UInt64(max(0, (timeIntervalSince1970 * 1000).rounded()))
    }

    init(millisecondsSince1970 ms: UInt64) {
        self.init(timeIntervalSince1970: TimeInterval(ms) / 1000)
    }
}

public enum Freshness {
    /// Rejette un message dont l'horodatage est trop loin de l'horloge locale (rejeu différé).
    public static func check(timestampMs: UInt64, now: Date = Date(), window: TimeInterval) throws {
        let sent = Date(millisecondsSince1970: timestampMs)
        guard abs(sent.timeIntervalSince(now)) <= window else { throw RobAirError.staleTimestamp }
    }
}

public extension P256.Signing.PublicKey {
    /// Vérifie une signature au format brut (64 octets). Toute erreur de format = signature invalide.
    func isValidSignature(raw signature: Data, for message: Data) -> Bool {
        guard signature.count == RobAirConstants.p256SignatureSize,
              let parsed = try? P256.Signing.ECDSASignature(rawRepresentation: signature) else {
            return false
        }
        return isValidSignature(parsed, for: message)
    }

    /// Décode une clé publique reçue en vérifiant sa taille (le décodage vérifie qu'elle est sur la courbe).
    static func decode(_ data: Data, field: String) throws -> P256.Signing.PublicKey {
        try requireLength(data, RobAirConstants.p256PublicKeySize, field)
        do { return try P256.Signing.PublicKey(x963Representation: data) } catch { throw RobAirError.malformed(field) }
    }
}
