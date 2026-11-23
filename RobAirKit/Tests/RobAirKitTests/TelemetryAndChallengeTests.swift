// Tests de la télémétrie HPKE signée (§3.5) et des deux défis-réponses (§3.7, §3.8).

import XCTest
import CryptoKit
@testable import RobAirKit

final class TelemetryTests: XCTestCase {
    let telKey = SoftwareSigningIdentity()
    let iphoneID = SecureRandom.bytes(16)
    let mac = SoftwareSigningIdentity()
    let encKey = Curve25519.KeyAgreement.PrivateKey()
    var macID: Data { DeviceID.of(mac.publicKey) }

    func payload(seq: UInt64 = 1, lat: Double? = 48.8566, lon: Double? = 2.3522, now: Date = Date()) -> TelemetryPayload {
        TelemetryPayload(iphoneID: iphoneID, seq: seq, lat: lat, lon: lon, accuracy: 12, battery: 0.8, trigger: .bleDisconnected, now: now)
    }

    func seal(_ p: TelemetryPayload, signer: SigningIdentity? = nil) throws -> TelemetryEnvelope {
        try TelemetryCrypto.seal(p, signer: signer ?? telKey, macKey: encKey.publicKey, epoch: 1, macID: macID)
    }

    func open(_ e: TelemetryEnvelope, key: Curve25519.KeyAgreement.PrivateKey? = nil) throws -> TelemetryPayload {
        try TelemetryCrypto.open(e, privateKey: key ?? encKey, macID: macID, telemetryKey: telKey.publicKey)
    }

    func testRoundTrip() throws {
        let p = payload()
        XCTAssertEqual(try open(try seal(p)), p)
    }

    /// I : l'enveloppe ne contient la position ni en clair, ni sous une forme reconnaissable.
    func testEnvelopeHidesPosition() throws {
        let serialized = String(decoding: try seal(payload()).serialized(), as: UTF8.self)
        XCTAssertFalse(serialized.contains("48.85"))
        XCTAssertFalse(serialized.contains("bleDisconnected"))
    }

    /// Première alerte avant le premier point GPS : position absente, mais autorisée.
    func testAlertWithoutPositionIsAllowed() throws {
        XCTAssertNoThrow(try open(try seal(payload(lat: nil, lon: nil))))
    }

    /// Le relais (ou un attaquant) ne peut pas déchiffrer sans K_enc_Mac.
    func testWrongMacKeyCannotOpen() throws {
        XCTAssertThrowsError(try open(try seal(payload()), key: Curve25519.KeyAgreement.PrivateKey())) {
            XCTAssertEqual($0 as? RobAirError, .authenticationFailed)
        }
    }

    /// T : modifier un octet du chiffré ou de l'en-tête (AAD) est détecté.
    func testTamperingIsDetected() throws {
        let e = try seal(payload())
        var ct = e.ciphertext; ct[ct.startIndex + 5] ^= 1
        XCTAssertThrowsError(try open(TelemetryEnvelope(v: e.v, iphoneID: e.iphoneID, epoch: e.epoch, encapsulatedKey: e.encapsulatedKey, ciphertext: ct)))
        XCTAssertThrowsError(try open(TelemetryEnvelope(v: e.v, iphoneID: e.iphoneID, epoch: 2, encapsulatedKey: e.encapsulatedKey, ciphertext: e.ciphertext)))
    }

    /// S : quelqu'un qui connaît la clé publique HPKE du Mac (le relais, un auditeur…) peut chiffrer,
    /// mais sans K_tel_iPhone sa télémétrie est refusée.
    func testForgedTelemetryIsRejected() throws {
        XCTAssertThrowsError(try open(try seal(payload(), signer: SoftwareSigningIdentity()))) {
            XCTAssertEqual($0 as? RobAirError, .invalidSignature)
        }
    }

    /// L'identifiant en clair de l'enveloppe doit être celui du contenu signé.
    func testEnvelopeIDMustMatchSignedPayload() throws {
        let other = SecureRandom.bytes(16)
        let p = TelemetryPayload(iphoneID: other, seq: 1, lat: nil, lon: nil, accuracy: nil, battery: nil, trigger: .test)
        let e = try TelemetryCrypto.seal(p, signer: telKey, macKey: encKey.publicKey, epoch: 1, macID: macID)
        // Un attaquant réécrit l'iphone_id en clair : l'info HPKE et l'AAD ne correspondent plus.
        XCTAssertThrowsError(try open(TelemetryEnvelope(v: e.v, iphoneID: iphoneID, epoch: 1, encapsulatedKey: e.encapsulatedKey, ciphertext: e.ciphertext)))
    }

    /// Validation des bornes (§3.4) : latitude hors [−90, 90] refusée dès l'émission.
    func testOutOfBoundsValuesAreRejected() {
        XCTAssertThrowsError(try seal(payload(lat: 91, lon: 2)))
        XCTAssertThrowsError(try seal(payload(lat: 48, lon: 181)))
        XCTAssertThrowsError(try seal(payload(lat: .nan, lon: 2)))
        XCTAssertThrowsError(try seal(payload(lat: 48, lon: nil)))
    }

    /// Anti-rejeu : seq strictement croissant, horodatage à ±300 s ; doublon = ignoré sans erreur.
    func testReceiverRejectsReplayAndStaleMessages() throws {
        var receiver = TelemetryReceiver()
        let first = payload(seq: 1), second = payload(seq: 2)
        XCTAssertEqual(try receiver.accept(first), .accepted)
        XCTAssertEqual(try receiver.accept(first), .duplicate)
        XCTAssertEqual(try receiver.accept(second), .accepted)
        XCTAssertEqual(try receiver.accept(first), .duplicate)
        XCTAssertThrowsError(try receiver.accept(payload(seq: 3, now: Date().addingTimeInterval(-301))))
        XCTAssertEqual(receiver.lastSeq, 2)
    }

    func testAckSecretIsRandomPerMessage() {
        XCTAssertNotEqual(payload().ackSecret, payload().ackSecret)
    }

    func testEnvelopeFitsInRelayLimit() throws {
        XCTAssertLessThan(try seal(payload()).serialized().count, RobAirConstants.maxMessageSize)
    }
}

final class MacChallengeTests: XCTestCase {
    let iphoneKey = SoftwareSigningIdentity()   // K_id_iPhone (Face ID en vrai)
    let macID = SecureRandom.bytes(16)
    let now = Date()

    func testValidResponseIsAcceptedOnce() throws {
        let issuer = ChallengeIssuer()
        let challenge = issuer.issue(.endAlert, now: now)
        let response = try ChallengeCrypto.respond(to: challenge, signer: iphoneKey, macID: macID, now: now)
        XCTAssertEqual(try issuer.verify(response, iphoneKey: iphoneKey.publicKey, macID: macID, now: now), .endAlert)
        XCTAssertThrowsError(try issuer.verify(response, iphoneKey: iphoneKey.publicKey, macID: macID, now: now)) {
            XCTAssertEqual($0 as? RobAirError, .tokenAlreadyUsed)
        }
    }

    func testExpiredChallengeIsRejected() throws {
        let issuer = ChallengeIssuer()
        let challenge = issuer.issue(.disarm, now: now)
        let response = try ChallengeCrypto.respond(to: challenge, signer: iphoneKey, macID: macID, now: now)
        XCTAssertThrowsError(try issuer.verify(response, iphoneKey: iphoneKey.publicKey, macID: macID, now: now.addingTimeInterval(31)))
    }

    /// La signature est liée à l'action : un « fin d'alerte » ne peut pas devenir « désarmer ».
    func testActionCannotBeSwapped() throws {
        let issuer = ChallengeIssuer()
        let challenge = issuer.issue(.endAlert, now: now)
        let response = try ChallengeCrypto.respond(to: challenge, signer: iphoneKey, macID: macID, now: now)
        let swapped = ChallengeResponse(challenge: response.challenge, action: .disarm, signature: response.signature)
        XCTAssertThrowsError(try issuer.verify(swapped, iphoneKey: iphoneKey.publicKey, macID: macID, now: now))
    }

    /// … et au Mac : une réponse obtenue pour un autre Mac ne sert à rien.
    func testResponseIsBoundToMac() throws {
        let issuer = ChallengeIssuer()
        let challenge = issuer.issue(.endAlert, now: now)
        let response = try ChallengeCrypto.respond(to: challenge, signer: iphoneKey, macID: SecureRandom.bytes(16), now: now)
        XCTAssertThrowsError(try issuer.verify(response, iphoneKey: iphoneKey.publicKey, macID: macID, now: now))
    }

    func testWrongKeyIsRejectedAndChallengeConsumed() throws {
        let issuer = ChallengeIssuer()
        let challenge = issuer.issue(.endAlert, now: now)
        let bad = try ChallengeCrypto.respond(to: challenge, signer: SoftwareSigningIdentity(), macID: macID, now: now)
        XCTAssertThrowsError(try issuer.verify(bad, iphoneKey: iphoneKey.publicKey, macID: macID, now: now))
        let good = try ChallengeCrypto.respond(to: challenge, signer: iphoneKey, macID: macID, now: now)
        XCTAssertThrowsError(try issuer.verify(good, iphoneKey: iphoneKey.publicKey, macID: macID, now: now))   // déjà consommé
    }

    func testIPhoneRefusesToSignExpiredChallenge() {
        let challenge = ChallengeIssuer().issue(.endAlert, now: now)
        XCTAssertThrowsError(try ChallengeCrypto.respond(to: challenge, signer: iphoneKey, macID: macID, now: now.addingTimeInterval(31)))
    }
}

final class EmergencyUnlockTests: XCTestCase {
    let mac = SoftwareSigningIdentity()   // K_id_Mac (Touch ID en vrai)
    let iphoneID = SecureRandom.bytes(16)
    let now = Date()

    func testGrantUnlocksOnce() throws {
        let session = EmergencyUnlockSession(iphoneID: iphoneID, now: now)
        let grant = try EmergencyCrypto.grant(session.request, pairedIPhoneID: iphoneID, signer: mac, now: now)
        XCTAssertNoThrow(try session.verify(grant, macKey: mac.publicKey, now: now))
        XCTAssertThrowsError(try session.verify(grant, macKey: mac.publicKey, now: now)) { XCTAssertEqual($0 as? RobAirError, .tokenAlreadyUsed) }
    }

    /// S : un faux Mac sur le Wi-Fi ne peut pas produire un ordre valide.
    func testFakeMacGrantIsRejected() throws {
        let session = EmergencyUnlockSession(iphoneID: iphoneID, now: now)
        let grant = try EmergencyCrypto.grant(session.request, pairedIPhoneID: iphoneID, signer: SoftwareSigningIdentity(), now: now)
        XCTAssertThrowsError(try session.verify(grant, macKey: mac.publicKey, now: now)) { XCTAssertEqual($0 as? RobAirError, .invalidSignature) }
        XCTAssertFalse(session.isConsumed)
    }

    /// Rejeu : un ordre capturé lors d'une alerte précédente ne vaut pas pour le nouveau défi.
    func testCapturedGrantForOldChallengeIsUseless() throws {
        let old = EmergencyUnlockSession(iphoneID: iphoneID, now: now)
        let captured = try EmergencyCrypto.grant(old.request, pairedIPhoneID: iphoneID, signer: mac, now: now)
        let current = EmergencyUnlockSession(iphoneID: iphoneID, now: now)
        XCTAssertThrowsError(try current.verify(captured, macKey: mac.publicKey, now: now))
    }

    func testExpiredChallengeIsRejected() throws {
        let session = EmergencyUnlockSession(iphoneID: iphoneID, now: now)
        let grant = try EmergencyCrypto.grant(session.request, pairedIPhoneID: iphoneID, signer: mac, now: now)
        XCTAssertThrowsError(try session.verify(grant, macKey: mac.publicKey, now: now.addingTimeInterval(121)))
        XCTAssertThrowsError(try EmergencyCrypto.grant(session.request, pairedIPhoneID: iphoneID, signer: mac, now: now.addingTimeInterval(121)))
    }

    func testMacOnlyGrantsForPairedIPhone() {
        let session = EmergencyUnlockSession(iphoneID: SecureRandom.bytes(16), now: now)
        XCTAssertThrowsError(try EmergencyCrypto.grant(session.request, pairedIPhoneID: iphoneID, signer: mac, now: now))
    }

    func testQRTransportRoundTripAndShortCode() throws {
        let session = EmergencyUnlockSession(iphoneID: iphoneID, now: now)
        let text = try QRPayload.encode(session.request, prefix: QRPayload.emergencyRequestPrefix)
        let decoded = try QRPayload.decode(text, prefix: QRPayload.emergencyRequestPrefix, as: EmergencyRequest.self)
        XCTAssertEqual(decoded, session.request)
        XCTAssertEqual(decoded.shortCode, session.request.shortCode)
        XCTAssertThrowsError(try QRPayload.decode(text, prefix: QRPayload.emergencyGrantPrefix, as: EmergencyGrant.self))
    }
}
