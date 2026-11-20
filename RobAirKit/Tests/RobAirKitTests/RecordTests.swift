// Tests du chiffrement des messages : aller-retour, rejeu, altération, troncature, nonces.

import XCTest
import CryptoKit
@testable import RobAirKit

final class RecordTests: XCTestCase {
    let key = SymmetricKey(size: .bits256)

    func testRoundTrip() throws {
        var sealer = RecordSealer(key: key)
        var opener = RecordOpener(key: key)
        let body = try sealer.seal(.status, Data("bonjour".utf8))
        let (type, payload) = try opener.open(body)
        XCTAssertEqual(type, .status)
        XCTAssertEqual(payload, Data("bonjour".utf8))
    }

    /// Test d'attaque n°1 du J2 : rejouer une trame capturée.
    func testReplayIsRejected() throws {
        var sealer = RecordSealer(key: key)
        var opener = RecordOpener(key: key)
        let body = try sealer.seal(.alert, Data("x".utf8))
        _ = try opener.open(body)
        XCTAssertThrowsError(try opener.open(body)) { XCTAssertEqual($0 as? RobAirError, .replayDetected) }
    }

    func testOlderMessageIsRejectedAfterNewer() throws {
        var sealer = RecordSealer(key: key)
        var opener = RecordOpener(key: key)
        let first = try sealer.seal(.status, Data("1".utf8))
        let second = try sealer.seal(.status, Data("2".utf8))
        _ = try opener.open(second)
        XCTAssertThrowsError(try opener.open(first)) { XCTAssertEqual($0 as? RobAirError, .replayDetected) }
    }

    /// Test d'attaque n°2 : modifier un bit du chiffré, de l'en-tête ou du tag.
    func testAnyBitFlipIsDetected() throws {
        var sealer = RecordSealer(key: key)
        let body = try sealer.seal(.status, Data("message de test".utf8))
        for position in [1, 9, RecordFormat.headerSize + 2, body.count - 1] {
            var tampered = body
            tampered[position] ^= 0x01
            var opener = RecordOpener(key: key)
            XCTAssertThrowsError(try opener.open(tampered), "bit modifié en position \(position) non détecté")
        }
    }

    /// Changer le type dans l'en-tête (AAD) doit échouer à l'authentification.
    func testHeaderTypeChangeIsDetected() throws {
        var sealer = RecordSealer(key: key)
        var body = try sealer.seal(.status, Data("a".utf8))
        body[1] = MessageType.alert.rawValue
        var opener = RecordOpener(key: key)
        XCTAssertThrowsError(try opener.open(body)) { XCTAssertEqual($0 as? RobAirError, .authenticationFailed) }
    }

    /// Une trame forgée avec un compteur énorme ne doit PAS faire avancer le compteur.
    func testForgedFrameDoesNotAdvanceCounter() throws {
        var sealer = RecordSealer(key: key)
        var opener = RecordOpener(key: key)
        var forged = RecordFormat.header(type: .status, counter: 1_000_000)
        forged.append(Data(repeating: 0xAA, count: 32))
        XCTAssertThrowsError(try opener.open(forged))
        XCTAssertEqual(opener.lastCounter, 0)
        XCTAssertNoThrow(try opener.open(try sealer.seal(.status, Data("ok".utf8))))
    }

    /// Test d'attaque n°3 : trame tronquée.
    func testTruncatedFrameIsRejected() throws {
        var sealer = RecordSealer(key: key)
        let body = try sealer.seal(.status, Data("abc".utf8))
        var opener = RecordOpener(key: key)
        XCTAssertThrowsError(try opener.open(body.prefix(12)))
        XCTAssertThrowsError(try opener.open(body.dropLast()))
    }

    func testWrongKeyIsRejected() throws {
        var sealer = RecordSealer(key: key)
        var opener = RecordOpener(key: SymmetricKey(size: .bits256))
        XCTAssertThrowsError(try opener.open(try sealer.seal(.status, Data("x".utf8))))
    }

    func testPlaintextTypeCannotBeSealedOrOpened() throws {
        var sealer = RecordSealer(key: key)
        XCTAssertThrowsError(try sealer.seal(.clientHello, Data()))
        var body = try sealer.seal(.status, Data("x".utf8))
        body[1] = MessageType.clientHello.rawValue
        var opener = RecordOpener(key: key)
        XCTAssertThrowsError(try opener.open(body)) { XCTAssertEqual($0 as? RobAirError, .unexpectedMessage) }
    }

    /// Le nonce GCM dépend du compteur : deux messages ne partagent jamais le même nonce.
    func testNoncesAreUniquePerCounter() throws {
        let a = try RecordFormat.nonce(counter: 1).withUnsafeBytes { Data($0) }
        let b = try RecordFormat.nonce(counter: 2).withUnsafeBytes { Data($0) }
        XCTAssertNotEqual(a, b)
        XCTAssertEqual(a.count, 12)
    }

    /// Même contenu chiffré deux fois → chiffrés différents (pas de motif visible, contrairement à ECB).
    func testSamePlaintextGivesDifferentCiphertexts() throws {
        var sealer = RecordSealer(key: key)
        let a = try sealer.seal(.status, Data("identique".utf8))
        let b = try sealer.seal(.status, Data("identique".utf8))
        XCTAssertNotEqual(a.dropFirst(RecordFormat.headerSize), b.dropFirst(RecordFormat.headerSize))
    }

    func testOversizedPayloadIsRefused() {
        var sealer = RecordSealer(key: key)
        XCTAssertThrowsError(try sealer.seal(.status, Data(count: RobAirConstants.maxFrameSize))) {
            XCTAssertEqual($0 as? RobAirError, .frameTooLarge)
        }
    }

    /// Bout en bout : handshake puis échange chiffré dans les deux sens.
    func testEndToEndAfterHandshake() throws {
        let iphone = SoftwareSigningIdentity(), mac = SoftwareSigningIdentity()
        let client = HandshakeClient(identity: iphone, serverKey: mac.publicKey)
        let server = HandshakeServer(identity: mac, clientKey: iphone.publicKey)
        let reply = try server.handle(client.makeHello())
        let (finish, ck) = try client.handle(reply)
        let sk = try server.handle(finish)

        var iphoneOut = RecordSealer(key: ck.sending), macIn = RecordOpener(key: sk.receiving)
        var macOut = RecordSealer(key: sk.sending), iphoneIn = RecordOpener(key: ck.receiving)
        let status = StatusPayload(proximity: .near, lock: .locked)
        let received = try macIn.open(try iphoneOut.sealJSON(.status, status))
        XCTAssertEqual(try RobAirJSON.decode(StatusPayload.self, from: received.payload), status)
        XCTAssertEqual(try iphoneIn.open(try macOut.sealJSON(.ack, AckPayload(acknowledging: .status))).type, .ack)
        // Une trame iPhone→Mac ne peut pas être renvoyée à l'iPhone (clé du sens opposé).
        XCTAssertThrowsError(try iphoneIn.open(try iphoneOut.seal(.status, Data("x".utf8))))
    }
}
