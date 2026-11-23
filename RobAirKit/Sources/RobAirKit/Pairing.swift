// Pairing.swift
// Rôle : appairage iPhone ↔ Mac par QR code + empreinte courte (J1 §3.2, J2 §4).
//
// 1. Le Mac affiche un QR : {v, mac_id, nom Bonjour, pk_id_Mac, K_enc_Mac signée, relais (URL + pin TLS),
//    jeton d'appairage à usage unique valable 5 min}
// 2. L'iPhone épingle pk_id_Mac (canal visuel = de confiance), crée K_id_iPhone et K_tel_iPhone dans la
//    Secure Enclave, envoie leurs clés publiques + HMAC_jeton(...) : preuve qu'il a vu le QR
// 3. Les deux écrans affichent une empreinte courte de 6 chiffres calculée sur TOUTES les clés publiques ;
//    l'utilisateur compare et confirme sur le Mac (c'est ce qui bloque l'homme du milieu)
// 4. Le Mac renvoie une confirmation signée, puis (dans la session chiffrée) les accès à la boîte du relais
//
// Menaces : S (homme du milieu à l'appairage), S3 (faux iPhone).
// Points de relecture : jeton à usage unique, expiration, comparaison HMAC en temps constant.

import Foundation
import CryptoKit

/// Ce que le Mac communique au sujet de son relais (extension P2). Absent si aucun relais n'est configuré.
public struct RelayInfo: WireMessage, Equatable {
    public let url: String
    /// SHA-256 (base64) de la clé publique TLS du relais, épinglée par les apps (§3.6).
    public let pin: String

    public init(url: String, pin: String) {
        self.url = url
        self.pin = pin
    }

    public func validate() throws {
        guard url.utf8.count <= 200, let parsed = URL(string: url), parsed.scheme == "https", parsed.host != nil else {
            throw RobAirError.malformed("relay.url")
        }
        guard let pinData = Data(base64Encoded: pin), pinData.count == 32 else { throw RobAirError.malformed("relay.pin") }
    }
}

public struct PairingInvitation: WireMessage, Equatable {
    public let v: UInt8
    public let macID: Data
    public let serviceName: String
    public let macIdentityKey: Data
    public let encryptionKey: SignedEncryptionKey
    public let relay: RelayInfo?
    public let token: Data
    public let expiresAtMs: UInt64

    public func encodedForQRCode() throws -> String {
        String(decoding: try StrictJSON.encode(self), as: UTF8.self)
    }

    public func validate() throws {
        guard v == RobAirConstants.protocolVersion else { throw RobAirError.unsupportedVersion }
        guard !serviceName.isEmpty, serviceName.utf8.count <= 63 else { throw RobAirError.malformed("serviceName") }
        try requireLength(token, RobAirConstants.pairingTokenSize, "token")
        let key = try macPublicKey()
        guard macID == DeviceID.of(key) else { throw RobAirError.malformed("macID") }
        // La clé de chiffrement doit être signée par la clé d'identité présente dans le même QR.
        _ = try encryptionKey.verified(by: key)
        try relay?.validate()
    }

    /// Décode ET valide le contenu d'un QR code (il vient de l'extérieur : on ne lui fait pas confiance).
    public static func decode(qrCode: String, now: Date = Date()) throws -> PairingInvitation {
        guard qrCode.utf8.count <= 1500 else { throw RobAirError.messageTooLarge }
        let invitation = try StrictJSON.decode(PairingInvitation.self, from: Data(qrCode.utf8))
        guard now.millisecondsSince1970 <= invitation.expiresAtMs else { throw RobAirError.expired }
        return invitation
    }

    public func macPublicKey() throws -> P256.Signing.PublicKey {
        try P256.Signing.PublicKey.decode(macIdentityKey, field: "macIdentityKey")
    }
}

public struct PairingRequest: WireMessage, Equatable {
    public let identityKey: Data     // K_id_iPhone (publique), protégée par Face ID
    public let telemetryKey: Data    // K_tel_iPhone (publique), sans biométrie, télémétrie seulement
    public let proof: Data           // HMAC-SHA256(jeton, ...)

    public func validate() throws {
        _ = try P256.Signing.PublicKey.decode(identityKey, field: "identityKey")
        _ = try P256.Signing.PublicKey.decode(telemetryKey, field: "telemetryKey")
        try requireLength(proof, 32, "proof")
        guard identityKey != telemetryKey else { throw RobAirError.malformed("keys") }   // une clé par usage
    }
}

public struct PairingResult: WireMessage, Equatable {
    public let accepted: Bool
    public let signature: Data       // signature du Mac sur la confirmation (vide si refus)

    public init(accepted: Bool, signature: Data) {
        self.accepted = accepted
        self.signature = signature
    }

    public func validate() throws {
        if accepted { try requireLength(signature, RobAirConstants.p256SignatureSize, "signature") }
    }
}

public enum PairingCrypto {
    static func proofMessage(_ request: (identity: Data, telemetry: Data), invitation: PairingInvitation) -> Data {
        concat(Data(label: Label.pairingProof), request.identity, request.telemetry,
               invitation.macIdentityKey, invitation.encryptionKey.publicKey)
    }

    public static func makeRequest(invitation: PairingInvitation, identityKey: P256.Signing.PublicKey,
                                   telemetryKey: P256.Signing.PublicKey) -> PairingRequest {
        let id = identityKey.x963Representation
        let tel = telemetryKey.x963Representation
        let mac = HMAC<SHA256>.authenticationCode(for: proofMessage((id, tel), invitation: invitation),
                                                  using: SymmetricKey(data: invitation.token))
        return PairingRequest(identityKey: id, telemetryKey: tel, proof: Data(mac))
    }

    /// Empreinte courte à 6 chiffres affichée des deux côtés, calculée sur toutes les clés publiques échangées.
    public static func shortFingerprint(invitation: PairingInvitation, request: PairingRequest) -> String {
        let digest = Array(SHA256.hash(data: concat(Data(label: Label.sas), invitation.macIdentityKey,
                                                    invitation.encryptionKey.publicKey,
                                                    request.identityKey, request.telemetryKey)))
        let value = (UInt32(digest[0]) << 24 | UInt32(digest[1]) << 16 | UInt32(digest[2]) << 8 | UInt32(digest[3])) % 1_000_000
        let digits = String(format: "%06u", value)
        return String(digits.prefix(3)) + " " + String(digits.suffix(3))
    }

    static func confirmationMessage(_ request: PairingRequest, invitation: PairingInvitation) -> Data {
        concat(Data(label: Label.pairingConfirm), request.identityKey, request.telemetryKey, invitation.token)
    }

    /// Côté Mac : signature envoyée à l'iPhone une fois l'empreinte confirmée par l'utilisateur.
    public static func makeResult(accepted: Bool, request: PairingRequest, invitation: PairingInvitation,
                                  macIdentity: SigningIdentity) throws -> PairingResult {
        guard accepted else { return PairingResult(accepted: false, signature: Data()) }
        let sig = try macIdentity.signature(for: confirmationMessage(request, invitation: invitation))
        return PairingResult(accepted: true, signature: sig.rawRepresentation)
    }

    /// Côté iPhone : vérifie que la confirmation vient bien du Mac dont on a scanné le QR.
    public static func verify(result: PairingResult, request: PairingRequest, invitation: PairingInvitation) -> Bool {
        guard result.accepted, let macKey = try? invitation.macPublicKey() else { return false }
        return macKey.isValidSignature(raw: result.signature, for: confirmationMessage(request, invitation: invitation))
    }
}

/// Côté Mac : une invitation en cours. Usage unique, 5 min, 3 essais maximum.
public final class PairingSession {
    public let invitation: PairingInvitation
    public private(set) var isConsumed = false
    private var attempts = 0

    public init(serviceName: String, macIdentityKey: P256.Signing.PublicKey, encryptionKey: SignedEncryptionKey,
                relay: RelayInfo?, now: Date = Date()) {
        invitation = PairingInvitation(
            v: RobAirConstants.protocolVersion,
            macID: DeviceID.of(macIdentityKey),
            serviceName: serviceName,
            macIdentityKey: macIdentityKey.x963Representation,
            encryptionKey: encryptionKey,
            relay: relay,
            token: SecureRandom.bytes(RobAirConstants.pairingTokenSize),
            expiresAtMs: now.addingTimeInterval(RobAirConstants.pairingTokenLifetime).millisecondsSince1970)
    }

    public func isExpired(now: Date = Date()) -> Bool {
        now.millisecondsSince1970 > invitation.expiresAtMs
    }

    /// Valide une demande d'appairage. En cas de succès, l'invitation est consommée.
    public func validate(_ request: PairingRequest, now: Date = Date())
        throws -> (identityKey: P256.Signing.PublicKey, telemetryKey: P256.Signing.PublicKey) {
        guard !isConsumed else { throw RobAirError.tokenAlreadyUsed }
        guard !isExpired(now: now) else { throw RobAirError.expired }
        attempts += 1
        if attempts >= RobAirConstants.pairingMaxAttempts { isConsumed = true }

        try request.validate()
        // SÉCURITÉ : comparaison en temps constant (pas de ==).
        let valid = HMAC<SHA256>.isValidAuthenticationCode(
            request.proof,
            authenticating: PairingCrypto.proofMessage((request.identityKey, request.telemetryKey), invitation: invitation),
            using: SymmetricKey(data: invitation.token))
        guard valid else { throw RobAirError.authenticationFailed }
        isConsumed = true
        return (try P256.Signing.PublicKey.decode(request.identityKey, field: "identityKey"),
                try P256.Signing.PublicKey.decode(request.telemetryKey, field: "telemetryKey"))
    }
}
