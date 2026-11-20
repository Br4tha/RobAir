// Tests du handshake : cas nominal + attaques S1 (faux Mac), S3 (faux iPhone), altération, miroir.

import XCTest
import CryptoKit
@testable import RobAirKit

final class HandshakeTests: XCTestCase {
    let iphone = SoftwareSigningIdentity()
    let mac = SoftwareSigningIdentity()

    /// Exécute un handshake complet et renvoie les clés des deux côtés.
    func runHandshake() throws -> (client: SessionKeys, server: SessionKeys) {
        let client = HandshakeClient(identity: iphone, serverKey: mac.publicKey)
        let server = HandshakeServer(identity: mac, clientKey: iphone.publicKey)
        let hello = client.makeHello()
        let reply = try server.handle(hello)
        let (finish, clientKeys) = try client.handle(reply)
        let serverKeys = try server.handle(finish)
        return (clientKeys, serverKeys)
    }

    func testBothSidesDeriveMatchingKeys() throws {
        let (c, s) = try runHandshake()
        XCTAssertEqual(c.sending, s.receiving)
        XCTAssertEqual(c.receiving, s.sending)
        XCTAssertEqual(c.transcriptHash, s.transcriptHash)
    }

    func testDirectionKeysAreDifferent() throws {
        let (c, _) = try runHandshake()
        XCTAssertNotEqual(c.sending, c.receiving)
    }

    func testEachSessionHasFreshKeys() throws {
        let first = try runHandshake()
        let second = try runHandshake()
        XCTAssertNotEqual(first.client.sending, second.client.sending)
    }

    /// S1 : un faux Mac (autre clé) ne peut pas produire une signature acceptée par l'iPhone.
    func testFakeMacIsRejected() throws {
        let fakeMac = SoftwareSigningIdentity()
        let client = HandshakeClient(identity: iphone, serverKey: mac.publicKey)
        let fakeServer = HandshakeServer(identity: fakeMac, clientKey: iphone.publicKey)
        let reply = try fakeServer.handle(client.makeHello())
        XCTAssertThrowsError(try client.handle(reply)) { XCTAssertEqual($0 as? RobAirError, .invalidSignature) }
    }

    /// S3 : un iPhone non appairé est refusé dès le ClientHello.
    func testUnknownIPhoneIsRejected() throws {
        let stranger = SoftwareSigningIdentity()
        let client = HandshakeClient(identity: stranger, serverKey: mac.publicKey)
        let server = HandshakeServer(identity: mac, clientKey: iphone.publicKey)
        XCTAssertThrowsError(try server.handle(client.makeHello())) { XCTAssertEqual($0 as? RobAirError, .unknownDevice) }
    }

    /// S3 : un attaquant qui copie l'empreinte de l'iPhone mais n'a pas sa clé privée échoue au ClientFinish.
    func testImpostorWithCopiedFingerprintFailsAtFinish() throws {
        let impostor = SoftwareSigningIdentity()
        let server = HandshakeServer(identity: mac, clientKey: iphone.publicKey)
        let realClient = HandshakeClient(identity: iphone, serverKey: mac.publicKey)
        let hello = realClient.makeHello()   // empreinte de l'iPhone légitime
        let reply = try server.handle(hello)
        // L'imposteur signe le transcript avec SA clé
        let transcript = HandshakeMath.transcriptHash(clientHello: hello, serverFingerprint: Fingerprint.of(mac.publicKey),
                                                      serverEphemeral: reply.ephemeralKey, serverNonce: reply.nonce)
        let forged = try impostor.signature(for: concat(Data(label: Label.clientSignature), transcript))
        XCTAssertThrowsError(try server.handle(ClientFinish(signature: forged.rawRepresentation))) {
            XCTAssertEqual($0 as? RobAirError, .invalidSignature)
        }
    }

    /// Homme du milieu : remplacer la clé éphémère du Mac casse la signature.
    func testTamperedServerEphemeralIsRejected() throws {
        let client = HandshakeClient(identity: iphone, serverKey: mac.publicKey)
        let server = HandshakeServer(identity: mac, clientKey: iphone.publicKey)
        let reply = try server.handle(client.makeHello())
        let attackerEph = P256.KeyAgreement.PrivateKey().publicKey.x963Representation
        let tampered = ServerHello(ephemeralKey: attackerEph, nonce: reply.nonce, signature: reply.signature)
        XCTAssertThrowsError(try client.handle(tampered)) { XCTAssertEqual($0 as? RobAirError, .invalidSignature) }
    }

    /// Miroir : renvoyer la signature du serveur comme ClientFinish ne marche pas (étiquettes différentes).
    func testReflectedSignatureIsRejected() throws {
        // Cas d'école : même clé des deux côtés pour isoler l'effet des étiquettes.
        let same = SoftwareSigningIdentity()
        let client = HandshakeClient(identity: same, serverKey: same.publicKey)
        let server = HandshakeServer(identity: same, clientKey: same.publicKey)
        let reply = try server.handle(client.makeHello())
        XCTAssertThrowsError(try server.handle(ClientFinish(signature: reply.signature)))
    }

    /// Un objet de handshake est à usage unique.
    func testHandshakeObjectsAreSingleUse() throws {
        let client = HandshakeClient(identity: iphone, serverKey: mac.publicKey)
        let server = HandshakeServer(identity: mac, clientKey: iphone.publicKey)
        let hello = client.makeHello()
        let reply = try server.handle(hello)
        XCTAssertThrowsError(try server.handle(hello))
        _ = try client.handle(reply)
        XCTAssertThrowsError(try client.handle(reply))
    }

    func testMalformedHelloIsRejected() throws {
        let server = HandshakeServer(identity: mac, clientKey: iphone.publicKey)
        let bad = ClientHello(fingerprint: Fingerprint.of(iphone.publicKey), ephemeralKey: Data(repeating: 4, count: 65), nonce: Data(count: 32))
        XCTAssertThrowsError(try server.handle(bad))   // point hors de la courbe
        let server2 = HandshakeServer(identity: mac, clientKey: iphone.publicKey)
        let short = ClientHello(fingerprint: Data(count: 3), ephemeralKey: Data(), nonce: Data())
        XCTAssertThrowsError(try server2.handle(short))
    }

    func testFinishBeforeHelloIsRejected() {
        let server = HandshakeServer(identity: mac, clientKey: iphone.publicKey)
        XCTAssertThrowsError(try server.handle(ClientFinish(signature: Data(count: 64)))) {
            XCTAssertEqual($0 as? RobAirError, .unexpectedMessage)
        }
    }
}
