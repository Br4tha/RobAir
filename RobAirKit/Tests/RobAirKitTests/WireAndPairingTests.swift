// Tests du découpage en trames, du décodage strict (§3.4) et de l'appairage par QR code (§3.2).

import XCTest
import CryptoKit
@testable import RobAirKit

final class WireTests: XCTestCase {
    func testFramesSplitAcrossChunksAreReassembled() throws {
        let a = try Wire.frame(Data("bonjour".utf8)), b = try Wire.frame(Data("robair".utf8))
        let all = a + b
        var decoder = FrameDecoder()
        var frames: [Data] = []
        for byte in all { frames += try decoder.append(Data([byte])) }
        XCTAssertEqual(frames, [Data("bonjour".utf8), Data("robair".utf8)])
    }

    /// D : une longueur annoncée géante est refusée AVANT d'attendre les données.
    func testOversizedLengthIsRejectedImmediately() {
        var decoder = FrameDecoder()
        var header = Data(); header.appendUInt32BE(1_000_000)
        XCTAssertThrowsError(try decoder.append(header)) { XCTAssertEqual($0 as? RobAirError, .messageTooLarge) }
    }

    func testZeroLengthIsRejected() {
        var decoder = FrameDecoder()
        XCTAssertThrowsError(try decoder.append(Data([0, 0, 0, 0])))
    }

    func testPlaintextDecodingChecksExpectedType() throws {
        let finish = ClientFinish(signature: Data(repeating: 1, count: 64))
        let body = try Wire.plaintextFrame(.clientFinish, finish).dropFirst(4)
        XCTAssertEqual(try Wire.decodePlaintext(Data(body), expected: .clientFinish, as: ClientFinish.self), finish)
        XCTAssertThrowsError(try Wire.decodePlaintext(Data(body), expected: .clientHello, as: ClientFinish.self))
    }

    func testWrongVersionIsRejected() {
        XCTAssertThrowsError(try Wire.messageType(of: Data([9, MessageType.status.rawValue]))) { XCTAssertEqual($0 as? RobAirError, .unsupportedVersion) }
    }

    func testEncryptedTypesCannotTravelInClear() {
        XCTAssertThrowsError(try Wire.plaintextFrame(.status, StatusPayload(state: .armed, vaultOpen: false, beacon: .present)))
    }

    // MARK: Décodage strict

    /// §3.4 : tout champ inconnu fait rejeter le message.
    func testUnknownFieldIsRejected() {
        let json = #"{"signature":"\#(Data(repeating: 1, count: 64).base64EncodedString())","admin":true}"#
        XCTAssertThrowsError(try StrictJSON.decode(ClientFinish.self, from: Data(json.utf8))) {
            XCTAssertEqual($0 as? RobAirError, .unknownField("ClientFinish.admin"))
        }
    }

    func testUnknownNestedFieldIsRejected() throws {
        let mac = SoftwareSigningIdentity()
        let enc = try SignedEncryptionKey.make(epoch: 1, key: Curve25519.KeyAgreement.PrivateKey().publicKey, signer: mac)
        let invitation = PairingSession(serviceName: "RobAir-TEST", macIdentityKey: mac.publicKey, encryptionKey: enc, relay: nil).invitation
        var tree = try JSONSerialization.jsonObject(with: try StrictJSON.encode(invitation)) as! [String: Any]
        var nested = tree["encryptionKey"] as! [String: Any]
        nested["extra"] = 1
        tree["encryptionKey"] = nested
        let data = try JSONSerialization.data(withJSONObject: tree)
        XCTAssertThrowsError(try StrictJSON.decode(PairingInvitation.self, from: data)) {
            XCTAssertEqual($0 as? RobAirError, .unknownField("PairingInvitation.encryptionKey.extra"))
        }
    }

    func testWrongTypesAreRejected() {
        XCTAssertThrowsError(try StrictJSON.decode(ClientFinish.self, from: Data(#"{"signature":42}"#.utf8)))
        XCTAssertThrowsError(try StrictJSON.decode(ClientFinish.self, from: Data("pas du json".utf8)))
    }

    func testValidationRunsAfterDecoding() {
        let short = #"{"signature":"\#(Data(repeating: 1, count: 10).base64EncodedString())"}"#
        XCTAssertThrowsError(try StrictJSON.decode(ClientFinish.self, from: Data(short.utf8)))
    }
}

final class PairingTests: XCTestCase {
    let mac = SoftwareSigningIdentity()
    let idKey = SoftwareSigningIdentity()
    let telKey = SoftwareSigningIdentity()
    let now = Date()

    func session(relay: RelayInfo? = nil) throws -> PairingSession {
        let enc = try SignedEncryptionKey.make(epoch: 1, key: Curve25519.KeyAgreement.PrivateKey().publicKey, signer: mac)
        return PairingSession(serviceName: "RobAir-TEST", macIdentityKey: mac.publicKey, encryptionKey: enc, relay: relay, now: now)
    }

    func request(_ s: PairingSession) -> PairingRequest {
        PairingCrypto.makeRequest(invitation: s.invitation, identityKey: idKey.publicKey, telemetryKey: telKey.publicKey)
    }

    func testQRCodeRoundTrip() throws {
        let relay = RelayInfo(url: "https://relais.example.org", pin: Data(repeating: 7, count: 32).base64EncodedString())
        let s = try session(relay: relay)
        let decoded = try PairingInvitation.decode(qrCode: try s.invitation.encodedForQRCode(), now: now)
        XCTAssertEqual(decoded, s.invitation)
        XCTAssertLessThan(try s.invitation.encodedForQRCode().utf8.count, 900)   // reste lisible en QR
    }

    func testValidRequestIsAccepted() throws {
        let s = try session()
        let keys = try s.validate(request(s), now: now)
        XCTAssertEqual(keys.identityKey.x963Representation, idKey.publicKey.x963Representation)
        XCTAssertTrue(s.isConsumed)
    }

    /// S3 : sans le jeton du QR, impossible de calculer la preuve.
    func testWrongTokenIsRejected() throws {
        let s = try session(), other = try session()
        XCTAssertThrowsError(try s.validate(request(other), now: now)) { XCTAssertEqual($0 as? RobAirError, .authenticationFailed) }
    }

    func testTokenIsSingleUse() throws {
        let s = try session()
        _ = try s.validate(request(s), now: now)
        XCTAssertThrowsError(try s.validate(request(s), now: now)) { XCTAssertEqual($0 as? RobAirError, .tokenAlreadyUsed) }
    }

    /// Jeton valable 5 min (§3.2) : une photo du QR prise plus tard ne sert à rien.
    func testExpiredInvitationIsRejected() throws {
        let s = try session()
        XCTAssertThrowsError(try s.validate(request(s), now: now.addingTimeInterval(301))) { XCTAssertEqual($0 as? RobAirError, .expired) }
        XCTAssertThrowsError(try PairingInvitation.decode(qrCode: try s.invitation.encodedForQRCode(), now: now.addingTimeInterval(301)))
    }

    func testTooManyAttemptsConsumesInvitation() throws {
        let s = try session(), other = try session()
        for _ in 0..<3 { XCTAssertThrowsError(try s.validate(request(other), now: now)) }
        XCTAssertTrue(s.isConsumed)
        XCTAssertThrowsError(try s.validate(request(s), now: now)) { XCTAssertEqual($0 as? RobAirError, .tokenAlreadyUsed) }
    }

    /// Une clé par usage : K_id et K_tel identiques sont refusées.
    func testSameKeyForBothUsesIsRejected() throws {
        let s = try session()
        let r = PairingCrypto.makeRequest(invitation: s.invitation, identityKey: idKey.publicKey, telemetryKey: idKey.publicKey)
        XCTAssertThrowsError(try s.validate(r, now: now))
    }

    /// Empreinte courte : identique des deux côtés, 6 chiffres, et différente si une clé change (homme du milieu).
    func testShortFingerprintCoversAllKeys() throws {
        let s = try session()
        let fp = PairingCrypto.shortFingerprint(invitation: s.invitation, request: request(s))
        XCTAssertEqual(fp.filter(\.isNumber).count, 6)
        let mitm = PairingCrypto.makeRequest(invitation: s.invitation, identityKey: idKey.publicKey, telemetryKey: SoftwareSigningIdentity().publicKey)
        XCTAssertNotEqual(fp, PairingCrypto.shortFingerprint(invitation: s.invitation, request: mitm))
    }

    func testConfirmationIsVerifiedWithPinnedMacKey() throws {
        let s = try session()
        let r = request(s)
        XCTAssertTrue(PairingCrypto.verify(result: try PairingCrypto.makeResult(accepted: true, request: r, invitation: s.invitation, macIdentity: mac), request: r, invitation: s.invitation))
        let fake = try PairingCrypto.makeResult(accepted: true, request: r, invitation: s.invitation, macIdentity: SoftwareSigningIdentity())
        XCTAssertFalse(PairingCrypto.verify(result: fake, request: r, invitation: s.invitation))
        XCTAssertFalse(PairingCrypto.verify(result: PairingResult(accepted: false, signature: Data()), request: r, invitation: s.invitation))
    }

    /// Un QR dont la clé de chiffrement n'est pas signée par la clé d'identité du même QR est refusé.
    func testInvitationWithForeignEncryptionKeyIsRejected() throws {
        let foreign = try SignedEncryptionKey.make(epoch: 1, key: Curve25519.KeyAgreement.PrivateKey().publicKey, signer: SoftwareSigningIdentity())
        let s = PairingSession(serviceName: "RobAir-TEST", macIdentityKey: mac.publicKey, encryptionKey: foreign, relay: nil, now: now)
        XCTAssertThrowsError(try PairingInvitation.decode(qrCode: try s.invitation.encodedForQRCode(), now: now))
    }

    func testRelayMustBeHTTPSWithValidPin() {
        XCTAssertThrowsError(try RelayInfo(url: "http://relais.example.org", pin: Data(count: 32).base64EncodedString()).validate())
        XCTAssertThrowsError(try RelayInfo(url: "https://relais.example.org", pin: "abc").validate())
    }

    func testMalformedQRCodesAreRejected() {
        for text in ["", "{}", "bonjour", String(repeating: "A", count: 5000)] {
            XCTAssertThrowsError(try PairingInvitation.decode(qrCode: text, now: now))
        }
    }

    /// Rotation de K_enc_Mac : signée par K_id_Mac, plus récente seulement.
    func testEncryptionKeyRotation() throws {
        let k1 = try SignedEncryptionKey.make(epoch: 1, key: Curve25519.KeyAgreement.PrivateKey().publicKey, signer: mac)
        let k2 = try SignedEncryptionKey.make(epoch: 2, key: Curve25519.KeyAgreement.PrivateKey().publicKey, signer: mac)
        XCTAssertNoThrow(try k2.verified(by: mac.publicKey))
        XCTAssertTrue(k2.isNewer(than: k1))
        XCTAssertFalse(k1.isNewer(than: k2))
        let forged = SignedEncryptionKey(epoch: 3, publicKey: Curve25519.KeyAgreement.PrivateKey().publicKey.rawRepresentation,
                                         notBeforeMs: k2.notBeforeMs, signature: k2.signature)
        XCTAssertThrowsError(try forged.verified(by: mac.publicKey)) { XCTAssertEqual($0 as? RobAirError, .invalidSignature) }
    }
}
