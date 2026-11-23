// Tests de la session locale (§3.3, §3.4) : handshake, enveloppes, anti-rejeu, renouvellement.
// Attaques : faux Mac, faux iPhone, signature en miroir, altération, rejeu, message retardé.

import XCTest
import CryptoKit
@testable import RobAirKit

final class HandshakeTests: XCTestCase {
    let iphone = SoftwareSigningIdentity()
    let mac = SoftwareSigningIdentity()

    func runHandshake() throws -> (client: SessionKeys, server: SessionKeys) {
        let client = HandshakeClient(identity: iphone, macKey: mac.publicKey)
        let server = HandshakeServer(identity: mac, iphoneKey: iphone.publicKey)
        let reply = try server.handle(client.makeHello())
        let (finish, clientKeys) = try client.handle(reply)
        return (clientKeys, try server.handle(finish))
    }

    func testBothSidesDeriveMatchingKeys() throws {
        let (c, s) = try runHandshake()
        XCTAssertEqual(c.sending, s.receiving)
        XCTAssertEqual(c.receiving, s.sending)
        XCTAssertEqual(c.transcriptHash, s.transcriptHash)
    }

    func testOneKeyPerDirection() throws {
        let (c, _) = try runHandshake()
        XCTAssertNotEqual(c.sending, c.receiving)
    }

    /// Forward secrecy : chaque session a des clés neuves (éphémères neuves).
    func testEachSessionHasFreshKeys() throws {
        XCTAssertNotEqual(try runHandshake().client.sending, try runHandshake().client.sending)
    }

    /// S : un faux Mac (autre clé d'identité) ne peut pas produire une signature acceptée.
    func testFakeMacIsRejected() throws {
        let impostor = SoftwareSigningIdentity()
        let client = HandshakeClient(identity: iphone, macKey: mac.publicKey)
        let hello = client.makeHello()
        // L'imposteur annonce le bon mac_id mais signe avec SA clé.
        let fake = try HandshakeServer(identity: impostor, iphoneKey: iphone.publicKey).handle(hello)
        let forged = ServerHello(macID: DeviceID.of(mac.publicKey), ephemeralKey: fake.ephemeralKey,
                                 nonce: fake.nonce, signature: fake.signature)
        XCTAssertThrowsError(try client.handle(forged)) { XCTAssertEqual($0 as? RobAirError, .invalidSignature) }
    }

    /// S3 : un iPhone non appairé est refusé dès le ClientHello.
    func testUnknownIPhoneIsRejected() throws {
        let stranger = HandshakeClient(identity: SoftwareSigningIdentity(), macKey: mac.publicKey)
        let server = HandshakeServer(identity: mac, iphoneKey: iphone.publicKey)
        XCTAssertThrowsError(try server.handle(stranger.makeHello())) { XCTAssertEqual($0 as? RobAirError, .unknownDevice) }
    }

    /// S3 : copier l'iphone_id ne suffit pas, la signature du ClientFinish échoue.
    func testImpostorWithCopiedIDFailsAtFinish() throws {
        let server = HandshakeServer(identity: mac, iphoneKey: iphone.publicKey)
        let eph = Curve25519.KeyAgreement.PrivateKey()
        let hello = ClientHello(iphoneID: DeviceID.of(iphone.publicKey), ephemeralKey: eph.publicKey.rawRepresentation,
                                nonce: SecureRandom.bytes(32))
        _ = try server.handle(hello)
        let bad = try SoftwareSigningIdentity().signature(for: Data("x".utf8)).rawRepresentation
        XCTAssertThrowsError(try server.handle(ClientFinish(signature: bad))) { XCTAssertEqual($0 as? RobAirError, .invalidSignature) }
    }

    /// Homme du milieu : remplacer la clé éphémère du Mac casse la signature de la transcription.
    func testTamperedServerEphemeralIsRejected() throws {
        let client = HandshakeClient(identity: iphone, macKey: mac.publicKey)
        let reply = try HandshakeServer(identity: mac, iphoneKey: iphone.publicKey).handle(client.makeHello())
        let tampered = ServerHello(macID: reply.macID, ephemeralKey: Curve25519.KeyAgreement.PrivateKey().publicKey.rawRepresentation,
                                   nonce: reply.nonce, signature: reply.signature)
        XCTAssertThrowsError(try client.handle(tampered))
    }

    /// Miroir : renvoyer au Mac sa propre signature comme ClientFinish ne marche pas (étiquettes différentes).
    func testReflectedSignatureIsRejected() throws {
        let client = HandshakeClient(identity: iphone, macKey: mac.publicKey)
        let server = HandshakeServer(identity: mac, iphoneKey: iphone.publicKey)
        let reply = try server.handle(client.makeHello())
        XCTAssertThrowsError(try server.handle(ClientFinish(signature: reply.signature)))
    }

    func testHandshakeObjectsAreSingleUse() throws {
        let client = HandshakeClient(identity: iphone, macKey: mac.publicKey)
        let server = HandshakeServer(identity: mac, iphoneKey: iphone.publicKey)
        let hello = client.makeHello()
        let reply = try server.handle(hello)
        XCTAssertThrowsError(try server.handle(hello))
        _ = try client.handle(reply)
        XCTAssertThrowsError(try client.handle(reply))
    }

    func testMalformedHelloIsRejected() {
        let server = HandshakeServer(identity: mac, iphoneKey: iphone.publicKey)
        let hello = ClientHello(iphoneID: DeviceID.of(iphone.publicKey), ephemeralKey: Data(repeating: 1, count: 31), nonce: SecureRandom.bytes(32))
        XCTAssertThrowsError(try server.handle(hello))
    }

    /// Clé X25519 de faible ordre (tout à zéro) : le secret partagé serait nul → refus.
    func testLowOrderEphemeralIsRejected() {
        let server = HandshakeServer(identity: mac, iphoneKey: iphone.publicKey)
        let hello = ClientHello(iphoneID: DeviceID.of(iphone.publicKey), ephemeralKey: Data(repeating: 0, count: 32), nonce: SecureRandom.bytes(32))
        XCTAssertThrowsError(try server.handle(hello))
    }

    func testFinishBeforeHelloIsRejected() {
        let server = HandshakeServer(identity: mac, iphoneKey: iphone.publicKey)
        XCTAssertThrowsError(try server.handle(ClientFinish(signature: Data(repeating: 0, count: 64))))
    }

    // MARK: Renouvellement (15 min)

    func testRekeyGivesMatchingFreshKeys() throws {
        let (c, s) = try runHandshake()
        let initiator = RekeyInitiator()
        let (ack, responderKeys) = try RekeyResponder.respond(to: initiator.message, previousTranscript: s.transcriptHash)
        let initiatorKeys = try initiator.finish(ack: ack, previousTranscript: c.transcriptHash)
        XCTAssertEqual(initiatorKeys.clientToServer, responderKeys.clientToServer)
        XCTAssertEqual(initiatorKeys.serverToClient, responderKeys.serverToClient)
        XCTAssertNotEqual(initiatorKeys.clientToServer, c.sending)
        XCTAssertNotEqual(initiatorKeys.transcriptHash, c.transcriptHash)
    }

    func testRekeyIsBoundToPreviousSession() throws {
        let (c, _) = try runHandshake()
        let other = try runHandshake().server
        let initiator = RekeyInitiator()
        let (ack, responderKeys) = try RekeyResponder.respond(to: initiator.message, previousTranscript: other.transcriptHash)
        XCTAssertNotEqual(try initiator.finish(ack: ack, previousTranscript: c.transcriptHash).clientToServer, responderKeys.clientToServer)
    }
}

final class RecordTests: XCTestCase {
    let iphoneID = SecureRandom.bytes(16)
    let key = SymmetricKey(size: .bits256)

    func pair() -> (RecordSealer, RecordOpener) {
        (RecordSealer(key: key, sender: iphoneID, direction: .clientToServer),
         RecordOpener(key: key, expectedSender: iphoneID, direction: .clientToServer))
    }

    func status() -> StatusPayload { StatusPayload(state: .armed, vaultOpen: false, beacon: .present) }

    func testRoundTrip() throws {
        var (sealer, opener) = pair()
        let (type, payload) = try opener.open(try sealer.sealJSON(.status, status()))
        XCTAssertEqual(type, .status)
        XCTAssertEqual(try StrictJSON.decode(StatusPayload.self, from: payload), status())
    }

    func testReplayIsRejected() throws {
        var (sealer, opener) = pair()
        let body = try sealer.sealJSON(.status, status())
        _ = try opener.open(body)
        XCTAssertThrowsError(try opener.open(body)) { XCTAssertEqual($0 as? RobAirError, .replayDetected) }
    }

    func testOlderMessageIsRejectedAfterNewer() throws {
        var (sealer, opener) = pair()
        let first = try sealer.sealJSON(.status, status())
        let second = try sealer.sealJSON(.status, status())
        _ = try opener.open(second)
        XCTAssertThrowsError(try opener.open(first))
    }

    /// §3.4 : horodatage à plus de 30 s → refusé (message retenu puis relâché par l'attaquant).
    func testDelayedMessageIsRejected() throws {
        var (sealer, opener) = pair()
        let body = try sealer.sealJSON(.status, status(), now: Date().addingTimeInterval(-31))
        XCTAssertThrowsError(try opener.open(body)) { XCTAssertEqual($0 as? RobAirError, .staleTimestamp) }
    }

    /// T : un seul bit modifié, n'importe où (en-tête compris), fait échouer l'ouverture.
    func testAnyBitFlipIsDetected() throws {
        var (sealer, _) = pair()
        let body = try sealer.sealJSON(.status, status())
        for index in 0..<body.count {
            var tampered = body
            tampered[index] ^= 0x01
            var opener = RecordOpener(key: key, expectedSender: iphoneID, direction: .clientToServer)
            XCTAssertThrowsError(try opener.open(tampered), "octet \(index)")
        }
    }

    func testWrongSenderIsRejected() throws {
        var sealer = RecordSealer(key: key, sender: SecureRandom.bytes(16), direction: .clientToServer)
        var opener = RecordOpener(key: key, expectedSender: iphoneID, direction: .clientToServer)
        XCTAssertThrowsError(try opener.open(try sealer.sealJSON(.status, status()))) { XCTAssertEqual($0 as? RobAirError, .unknownDevice) }
    }

    /// Un message chiffré pour un sens ne s'ouvre pas dans l'autre sens (préfixe de nonce).
    func testDirectionsAreSeparated() throws {
        var sealer = RecordSealer(key: key, sender: iphoneID, direction: .clientToServer)
        var opener = RecordOpener(key: key, expectedSender: iphoneID, direction: .serverToClient)
        XCTAssertThrowsError(try opener.open(try sealer.sealJSON(.status, status())))
    }

    /// Une trame forgée avec un seq énorme ne doit pas bloquer la session.
    func testForgedFrameDoesNotAdvanceCounter() throws {
        var (sealer, opener) = pair()
        var forged = RecordFormat.header(type: .status, sender: iphoneID, seq: 1_000_000, timestampMs: Date().millisecondsSince1970)
        forged.append(Data(repeating: 0xAA, count: 40))
        XCTAssertThrowsError(try opener.open(forged))
        XCTAssertEqual(opener.lastSeq, 0)
        XCTAssertNoThrow(try opener.open(try sealer.sealJSON(.status, status())))
    }

    func testPlaintextTypeCannotBeSealedOrOpened() throws {
        var (sealer, opener) = pair()
        XCTAssertThrowsError(try sealer.seal(.clientHello, Data("x".utf8)))
        var body = try sealer.sealJSON(.status, status())
        body[1] = MessageType.clientHello.rawValue
        XCTAssertThrowsError(try opener.open(body)) { XCTAssertEqual($0 as? RobAirError, .unexpectedMessage) }
    }

    func testOversizedPayloadIsRefused() {
        var (sealer, _) = pair()
        XCTAssertThrowsError(try sealer.seal(.status, Data(count: 5000)))
    }

    func testRotationKeepsCounterAndChangesKey() throws {
        var (sealer, opener) = pair()
        _ = try opener.open(try sealer.sealJSON(.status, status()))
        let newKey = SymmetricKey(size: .bits256)
        sealer.rotate(to: newKey)
        let body = try sealer.sealJSON(.status, status())
        var stale = opener
        XCTAssertThrowsError(try stale.open(body))      // ancienne clé : refus
        opener.rotate(to: newKey)
        XCTAssertNoThrow(try opener.open(body))
        XCTAssertEqual(opener.lastSeq, 2)
    }

    func testEndToEndAfterHandshake() throws {
        let iphone = SoftwareSigningIdentity(), mac = SoftwareSigningIdentity()
        let client = HandshakeClient(identity: iphone, macKey: mac.publicKey)
        let server = HandshakeServer(identity: mac, iphoneKey: iphone.publicKey)
        let (finish, ck) = try client.handle(try server.handle(client.makeHello()))
        let sk = try server.handle(finish)
        let id = DeviceID.of(iphone.publicKey), macID = DeviceID.of(mac.publicKey)
        var toMac = RecordSealer(key: ck.sending, sender: id, direction: .clientToServer)
        var macIn = RecordOpener(key: sk.receiving, expectedSender: id, direction: .clientToServer)
        var toPhone = RecordSealer(key: sk.sending, sender: macID, direction: .serverToClient)
        var phoneIn = RecordOpener(key: ck.receiving, expectedSender: macID, direction: .serverToClient)
        XCTAssertEqual(try macIn.open(try toMac.sealJSON(.status, status())).type, .status)
        let challenge = ChallengeIssuer().issue(.endAlert)
        XCTAssertEqual(try StrictJSON.decode(MacChallenge.self, from: try phoneIn.open(try toPhone.sealJSON(.challenge, challenge)).payload), challenge)
    }
}
