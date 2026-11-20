// Tests : découpage des trames, preuve BLE, proximité, verrou, événements signés, horodatage, journal.

import XCTest
import CryptoKit
@testable import RobAirKit

final class FramingTests: XCTestCase {
    func testFramesSplitAcrossChunksAreReassembled() throws {
        let a = try Wire.frame(Data("premier".utf8))
        let b = try Wire.frame(Data("second".utf8))
        let stream = a + b
        var decoder = FrameDecoder()
        var frames: [Data] = []
        for byte in stream { frames += try decoder.append(Data([byte])) }   // un octet à la fois
        XCTAssertEqual(frames, [Data("premier".utf8), Data("second".utf8)])
    }

    /// Test d'attaque n°3 : annonce d'une trame de 1 Mo → rejet immédiat, sans attendre les données.
    func testOversizedLengthIsRejectedImmediately() {
        var decoder = FrameDecoder()
        var header = Data()
        header.appendUInt32BE(1_000_000)
        XCTAssertThrowsError(try decoder.append(header)) { XCTAssertEqual($0 as? RobAirError, .frameTooLarge) }
    }

    func testZeroLengthIsRejected() {
        var decoder = FrameDecoder()
        XCTAssertThrowsError(try decoder.append(Data([0, 0, 0, 0])))
    }

    func testPlaintextDecodingChecksExpectedType() throws {
        let hello = ClientHello(fingerprint: Data(count: 32), ephemeralKey: Data(count: 65), nonce: Data(count: 32))
        let frame = try Wire.plaintextFrame(.clientHello, hello)
        var decoder = FrameDecoder()
        let body = try decoder.append(frame)[0]
        XCTAssertEqual(try Wire.decodePlaintext(body, expected: .clientHello, as: ClientHello.self), hello)
        XCTAssertThrowsError(try Wire.decodePlaintext(body, expected: .pairRequest, as: ClientHello.self))
    }

    func testWrongVersionIsRejected() {
        XCTAssertThrowsError(try Wire.messageType(of: Data([99, 0x10]))) { XCTAssertEqual($0 as? RobAirError, .unsupportedVersion) }
    }
}

final class BLEProofTests: XCTestCase {
    let mac = SoftwareSigningIdentity()
    let iphoneFP = Fingerprint.of(SoftwareSigningIdentity().publicKey)

    func testValidProof() throws {
        let challenge = BLEProof.makeChallenge()
        let response = try BLEProof.respond(to: BLEProof.request(challenge: challenge, fingerprint: iphoneFP),
                                            identity: mac, allowedFingerprint: iphoneFP)
        XCTAssertTrue(BLEProof.verify(response: response, challenge: challenge, fingerprint: iphoneFP, macKey: mac.publicKey))
    }

    /// Test d'attaque n°5 : balise clonée (autre clé) → preuve refusée.
    func testClonedBeaconFails() throws {
        let clone = SoftwareSigningIdentity()
        let challenge = BLEProof.makeChallenge()
        let response = try BLEProof.respond(to: BLEProof.request(challenge: challenge, fingerprint: iphoneFP),
                                            identity: clone, allowedFingerprint: iphoneFP)
        XCTAssertFalse(BLEProof.verify(response: response, challenge: challenge, fingerprint: iphoneFP, macKey: mac.publicKey))
    }

    /// Rejouer une ancienne réponse pour un nouveau défi → refusé.
    func testOldResponseDoesNotMatchNewChallenge() throws {
        let old = BLEProof.makeChallenge()
        let response = try BLEProof.respond(to: BLEProof.request(challenge: old, fingerprint: iphoneFP),
                                            identity: mac, allowedFingerprint: iphoneFP)
        XCTAssertFalse(BLEProof.verify(response: response, challenge: BLEProof.makeChallenge(), fingerprint: iphoneFP, macKey: mac.publicKey))
    }

    func testMacRefusesToSignForUnknownDevice() {
        let other = Fingerprint.of(SoftwareSigningIdentity().publicKey)
        XCTAssertThrowsError(try BLEProof.respond(to: BLEProof.request(challenge: BLEProof.makeChallenge(), fingerprint: other),
                                                  identity: mac, allowedFingerprint: iphoneFP))
    }

    func testServiceUUIDIsStableAndWellFormed() {
        let a = BLEProof.serviceUUID(for: mac.publicKey)
        XCTAssertEqual(a, BLEProof.serviceUUID(for: mac.publicKey))
        XCTAssertNotEqual(a, BLEProof.serviceUUID(for: SoftwareSigningIdentity().publicKey))
        XCTAssertNotNil(UUID(uuidString: a))
    }
}

final class ProximityTests: XCTestCase {
    let t0 = Date()

    func nearEvaluator() -> ProximityEvaluator {
        var e = ProximityEvaluator()
        e.connectionChanged(true, now: t0)
        e.recordRSSI(-60, now: t0)
        e.recordProof(valid: true, latency: 0.2, now: t0)
        return e
    }

    func testConnectedWithoutProofIsNotNear() {
        var e = ProximityEvaluator()
        e.connectionChanged(true, now: t0)
        e.recordRSSI(-50, now: t0)
        XCTAssertNotEqual(e.state, .near)
    }

    func testValidProofAndStrongSignalIsNear() {
        XCTAssertEqual(nearEvaluator().state, .near)
    }

    func testDisconnectionIsAway() {
        var e = nearEvaluator()
        XCTAssertEqual(e.connectionChanged(false, now: t0), .away)
        XCTAssertEqual(e.lastAwayReason, .bleDisconnected)
    }

    func testInvalidOrSlowProofIsAway() {
        var e = nearEvaluator()
        XCTAssertEqual(e.recordProof(valid: false, latency: 0.1, now: t0), .away)
        var slow = nearEvaluator()
        XCTAssertEqual(slow.recordProof(valid: true, latency: 3, now: t0), .away)
    }

    func testStaleProofExpires() {
        var e = nearEvaluator()
        XCTAssertEqual(e.tick(now: t0.addingTimeInterval(RobAirConstants.proofMaxAge + 1)), .away)
    }

    func testHysteresis() {
        var e = nearEvaluator()
        for _ in 0..<5 { e.recordRSSI(-75, now: t0) }      // entre les deux seuils : reste proche
        XCTAssertEqual(e.state, .near)
        for _ in 0..<5 { e.recordRSSI(-90, now: t0) }      // sous -80 : éloigné
        XCTAssertEqual(e.state, .away)
        for _ in 0..<5 { e.recordRSSI(-75, now: t0) }      // -75 ne suffit pas pour redevenir proche
        XCTAssertEqual(e.state, .away)
        for _ in 0..<5 { e.recordRSSI(-65, now: t0) }      // au-dessus de -70 : proche
        XCTAssertEqual(e.state, .near)
    }

    func testInvalidRSSIIsIgnored() {
        var e = nearEvaluator()
        XCTAssertEqual(e.recordRSSI(127, now: t0), .near)
    }
}

final class LockTests: XCTestCase {
    func testStartsLocked() {
        XCTAssertEqual(LockStateMachine().status, .locked)
    }

    func testUnlockRequiresProximity() {
        var m = LockStateMachine()
        XCTAssertEqual(m.handle(.unlockAuthorized(proximity: .away)), .locked)
        XCTAssertEqual(m.handle(.unlockAuthorized(proximity: .unknown)), .locked)
        XCTAssertEqual(m.handle(.unlockAuthorized(proximity: .near)), .unlocked)
    }

    func testAnyAnomalyLocks() {
        for event: LockStateMachine.Event in [.proximityChanged(.away), .proximityChanged(.unknown), .failure, .manualLock,
                                              .backgroundElapsed(RobAirConstants.backgroundLockDelay)] {
            var m = LockStateMachine()
            m.handle(.unlockAuthorized(proximity: .near))
            XCTAssertEqual(m.handle(event), .locked, "\(event)")
        }
    }

    func testShortBackgroundKeepsUnlocked() {
        var m = LockStateMachine()
        m.handle(.unlockAuthorized(proximity: .near))
        XCTAssertEqual(m.handle(.backgroundElapsed(5)), .unlocked)
    }
}

final class MessageTests: XCTestCase {
    func testSensitiveEventSignatureVerifies() throws {
        let bio = SoftwareSigningIdentity()
        let event = try SensitiveEventPayload.make(action: .unlock, signer: bio)
        XCTAssertTrue(event.isValid(for: bio.publicKey))
        XCTAssertFalse(event.isValid(for: SoftwareSigningIdentity().publicKey))
    }

    /// Non-répudiation : modifier l'horodatage invalide la signature.
    func testTamperedEventIsInvalid() throws {
        let bio = SoftwareSigningIdentity()
        let event = try SensitiveEventPayload.make(action: .unlock, signer: bio)
        let tampered = SensitiveEventPayload(timestampMs: event.timestampMs + 1, action: event.action,
                                             eventID: event.eventID, signature: event.signature)
        XCTAssertFalse(tampered.isValid(for: bio.publicKey))
    }

    func testFreshnessWindow() {
        let now = Date()
        XCTAssertNoThrow(try Freshness.check(timestampMs: now.millisecondsSince1970, now: now))
        XCTAssertThrowsError(try Freshness.check(timestampMs: now.addingTimeInterval(-120).millisecondsSince1970, now: now))
        XCTAssertThrowsError(try Freshness.check(timestampMs: now.addingTimeInterval(120).millisecondsSince1970, now: now))
    }
}

final class JournalTests: XCTestCase {
    let master = SymmetricKey(size: .bits256)

    func filledJournal() -> EventJournal {
        var j = EventJournal(masterKey: master)
        j.append(.paired, device: "AAAA-BBBB", detail: "appairage")
        j.append(.alert, device: "AAAA-BBBB", detail: "éloignement")
        j.append(.sensitiveEvent, device: "AAAA-BBBB", detail: "déverrouillage", eventSignature: Data(count: 64))
        return j
    }

    func testIntactChainVerifies() {
        XCTAssertEqual(filledJournal().verify(), .intact)
    }

    /// Test d'attaque n°9 : modifier une ligne du journal.
    func testModifiedEntryIsDetected() throws {
        let j = filledJournal()
        var entries = j.entries
        let e = entries[1]
        entries[1] = JournalEntry(index: e.index, timestampMs: e.timestampMs, kind: e.kind, device: e.device,
                                  detail: "rien à signaler", eventSignature: e.eventSignature,
                                  previousHash: e.previousHash, seal: e.seal)
        XCTAssertEqual(EventJournal(masterKey: master, entries: entries).verify(), .broken(atIndex: 1))
    }

    func testDeletedEntryIsDetected() {
        var entries = filledJournal().entries
        entries.remove(at: 1)
        XCTAssertEqual(EventJournal(masterKey: master, entries: entries).verify(), .broken(atIndex: 1))
    }

    func testWrongKeyCannotVerify() {
        let entries = filledJournal().entries
        XCTAssertEqual(EventJournal(masterKey: SymmetricKey(size: .bits256), entries: entries).verify(), .broken(atIndex: 0))
    }

    func testEncryptedExportRoundTrip() throws {
        let j = filledJournal()
        let blob = try j.exportEncrypted()
        XCTAssertNil(String(data: blob, encoding: .utf8)?.range(of: "appairage"))   // rien en clair
        let restored = try EventJournal.importEncrypted(blob, masterKey: master)
        XCTAssertEqual(restored.entries, j.entries)
        XCTAssertEqual(restored.verify(), .intact)
        XCTAssertThrowsError(try EventJournal.importEncrypted(blob, masterKey: SymmetricKey(size: .bits256)))
    }
}
