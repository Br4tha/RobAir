// Tests de l'appairage : preuve du jeton, expiration, usage unique, SAS, confirmation signée.

import XCTest
import CryptoKit
@testable import RobAirKit

final class PairingTests: XCTestCase {
    let mac = SoftwareSigningIdentity()
    let idKey = SoftwareSigningIdentity()
    let bioKey = SoftwareSigningIdentity()

    func makeSession(now: Date = Date()) -> PairingSession {
        PairingSession(serviceName: "RobAir-TEST", macIdentityKey: mac.publicKey, now: now)
    }

    func testQRCodeRoundTrip() throws {
        let session = makeSession()
        let decoded = try PairingInvitation.decode(qrCode: try session.invitation.encodedForQRCode())
        XCTAssertEqual(decoded, session.invitation)
        XCTAssertEqual(try decoded.macPublicKey().x963Representation, mac.publicKey.x963Representation)
    }

    func testValidRequestIsAccepted() throws {
        let session = makeSession()
        let request = PairingCrypto.makeRequest(invitation: session.invitation, identityKey: idKey.publicKey, biometricKey: bioKey.publicKey)
        let keys = try session.validate(request)
        XCTAssertEqual(keys.identityKey.x963Representation, idKey.publicKey.x963Representation)
        XCTAssertTrue(session.isConsumed)
    }

    /// Attaquant réseau qui n'a pas vu le QR code : il ne connaît pas le jeton.
    func testWrongTokenIsRejected() throws {
        let session = makeSession()
        let forgedInvitation = PairingInvitation(version: 1, serviceName: "x", macIdentityKey: session.invitation.macIdentityKey,
                                                 token: SecureRandom.bytes(32), expiresAtMs: session.invitation.expiresAtMs)
        let request = PairingCrypto.makeRequest(invitation: forgedInvitation, identityKey: idKey.publicKey, biometricKey: bioKey.publicKey)
        XCTAssertThrowsError(try session.validate(request)) { XCTAssertEqual($0 as? RobAirError, .authenticationFailed) }
    }

    /// Test d'attaque n°6 : réutiliser un QR code après appairage.
    func testTokenIsSingleUse() throws {
        let session = makeSession()
        let request = PairingCrypto.makeRequest(invitation: session.invitation, identityKey: idKey.publicKey, biometricKey: bioKey.publicKey)
        _ = try session.validate(request)
        XCTAssertThrowsError(try session.validate(request)) { XCTAssertEqual($0 as? RobAirError, .tokenAlreadyUsed) }
    }

    /// Test d'attaque n°6 : QR code expiré (plus de 2 minutes).
    func testExpiredInvitationIsRejected() throws {
        let start = Date()
        let session = makeSession(now: start)
        let later = start.addingTimeInterval(RobAirConstants.pairingTokenLifetime + 1)
        let request = PairingCrypto.makeRequest(invitation: session.invitation, identityKey: idKey.publicKey, biometricKey: bioKey.publicKey)
        XCTAssertThrowsError(try session.validate(request, now: later)) { XCTAssertEqual($0 as? RobAirError, .expired) }
        XCTAssertThrowsError(try PairingInvitation.decode(qrCode: try session.invitation.encodedForQRCode(), now: later))
    }

    func testTooManyAttemptsConsumesInvitation() throws {
        let session = makeSession()
        let bad = PairingRequest(identityKey: idKey.publicKey.x963Representation,
                                 biometricKey: bioKey.publicKey.x963Representation, proof: Data(count: 32))
        for _ in 0..<RobAirConstants.pairingMaxAttempts { XCTAssertThrowsError(try session.validate(bad)) }
        let good = PairingCrypto.makeRequest(invitation: session.invitation, identityKey: idKey.publicKey, biometricKey: bioKey.publicKey)
        XCTAssertThrowsError(try session.validate(good)) { XCTAssertEqual($0 as? RobAirError, .tokenAlreadyUsed) }
    }

    func testSASIsIdenticalOnBothSidesAndSixDigits() {
        let a = PairingCrypto.sas(macKey: mac.publicKey.x963Representation, identityKey: idKey.publicKey.x963Representation,
                                  biometricKey: bioKey.publicKey.x963Representation)
        let b = PairingCrypto.sas(macKey: mac.publicKey.x963Representation, identityKey: idKey.publicKey.x963Representation,
                                  biometricKey: bioKey.publicKey.x963Representation)
        XCTAssertEqual(a, b)
        XCTAssertEqual(a.filter(\.isNumber).count, 6)
        let other = PairingCrypto.sas(macKey: SoftwareSigningIdentity().publicKey.x963Representation,
                                      identityKey: idKey.publicKey.x963Representation,
                                      biometricKey: bioKey.publicKey.x963Representation)
        XCTAssertNotEqual(a, other)
    }

    func testConfirmationIsVerifiedWithPinnedMacKey() throws {
        let session = makeSession()
        let request = PairingCrypto.makeRequest(invitation: session.invitation, identityKey: idKey.publicKey, biometricKey: bioKey.publicKey)
        let result = try PairingCrypto.makeResult(accepted: true, request: request, macIdentity: mac)
        XCTAssertTrue(PairingCrypto.verify(result: result, request: request, macKey: mac.publicKey))
        let fake = try PairingCrypto.makeResult(accepted: true, request: request, macIdentity: SoftwareSigningIdentity())
        XCTAssertFalse(PairingCrypto.verify(result: fake, request: request, macKey: mac.publicKey))
        let refused = try PairingCrypto.makeResult(accepted: false, request: request, macIdentity: mac)
        XCTAssertFalse(PairingCrypto.verify(result: refused, request: request, macKey: mac.publicKey))
    }

    func testMalformedQRCodesAreRejected() {
        XCTAssertThrowsError(try PairingInvitation.decode(qrCode: "pas du json"))
        XCTAssertThrowsError(try PairingInvitation.decode(qrCode: String(repeating: "a", count: 5000)))
        XCTAssertThrowsError(try PairingInvitation.decode(qrCode: #"{"version":1}"#))
    }
}
