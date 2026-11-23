// Tests de la balise (§3.9), de la machine à états d'alerte, du journal chaîné et des utilitaires.

import XCTest
import CryptoKit
@testable import RobAirKit

final class BeaconTests: XCTestCase {
    func testPairingCodeRoundTrip() throws {
        let code = BeaconPairingCode.generate()
        XCTAssertEqual(try BeaconPairingCode.parse(qrText: try code.qrText()), code)
        XCTAssertNotNil(UUID(uuidString: code.serviceUUID))
        XCTAssertNotEqual(code.key, BeaconPairingCode.generate().key)
    }

    func testValidProof() throws {
        let key = SymmetricKey(size: .bits256)
        let challenge = BeaconProof.makeChallenge()
        XCTAssertTrue(BeaconProof.verify(response: try BeaconProof.respond(to: challenge, key: key), challenge: challenge, key: key))
    }

    /// S : une balise clonée (même UUID, pas la clé) ne sait pas répondre.
    func testClonedBeaconFails() throws {
        let challenge = BeaconProof.makeChallenge()
        let clone = try BeaconProof.respond(to: challenge, key: SymmetricKey(size: .bits256))
        XCTAssertFalse(BeaconProof.verify(response: clone, challenge: challenge, key: SymmetricKey(size: .bits256)))
    }

    /// Rejouer une ancienne réponse ne correspond pas au nouveau défi.
    func testOldResponseDoesNotMatchNewChallenge() throws {
        let key = SymmetricKey(size: .bits256)
        let old = try BeaconProof.respond(to: BeaconProof.makeChallenge(), key: key)
        XCTAssertFalse(BeaconProof.verify(response: old, challenge: BeaconProof.makeChallenge(), key: key))
    }

    func testMalformedChallengeIsRefusedByBeacon() {
        XCTAssertThrowsError(try BeaconProof.respond(to: Data(count: 3), key: SymmetricKey(size: .bits256)))
    }
}

final class RuptureDetectorTests: XCTestCase {
    let t0 = Date()
    func at(_ s: TimeInterval) -> Date { t0.addingTimeInterval(s) }

    func present() -> RuptureDetector {
        var d = RuptureDetector()
        d.connectionChanged(true, now: t0)
        d.recordProof(valid: true, latency: 0.2, now: t0)
        d.recordRSSI(-50, now: t0)
        return d
    }

    func testStartsUnknownAndConnectionAloneIsNotEnough() {
        var d = RuptureDetector()
        XCTAssertEqual(d.state, .unknown)
        XCTAssertEqual(d.connectionChanged(true, now: t0), .unknown)   // il faut une preuve HMAC
    }

    func testValidProofMakesBeaconPresent() { XCTAssertEqual(present().state, .present) }

    func testDisconnectionIsRupture() {
        var d = present()
        XCTAssertEqual(d.connectionChanged(false, now: at(1)), .ruptured(.bleDisconnected))
    }

    func testInvalidOrSlowProofIsRupture() {
        var d = present()
        XCTAssertEqual(d.recordProof(valid: false, latency: 0.1, now: at(1)), .ruptured(.beaconProofFailed))
        var slow = present()
        XCTAssertEqual(slow.recordProof(valid: true, latency: 2.5, now: at(1)), .ruptured(.beaconProofFailed))
    }

    func testMissingProofExpires() {
        var d = present()
        XCTAssertEqual(d.tick(now: at(14)), .present)
        XCTAssertEqual(d.tick(now: at(16)), .ruptured(.beaconProofFailed))
    }

    /// §3.9 : RSSI moyen sous −85 dBm pendant PLUS de 3 s → rupture ; un creux bref ne suffit pas.
    func testWeakSignalMustLastThreeSeconds() {
        var d = present()
        for s in 1...4 { d.recordRSSI(-95, now: at(Double(s))) }
        XCTAssertEqual(d.state, .present, "moyenne encore au-dessus du seuil ou durée trop courte")
        for s in 5...9 { d.recordProof(valid: true, latency: 0.1, now: at(Double(s))); d.recordRSSI(-95, now: at(Double(s))) }
        XCTAssertEqual(d.state, .ruptured(.signalLow))
    }

    /// Hystérésis : il faut remonter au-dessus de −75 pour sortir, −80 ne suffit pas.
    func testHysteresis() {
        var d = present()
        for s in 1...9 { d.recordProof(valid: true, latency: 0.1, now: at(Double(s))); d.recordRSSI(-95, now: at(Double(s))) }
        XCTAssertEqual(d.state, .ruptured(.signalLow))
        for s in 10...16 { d.recordProof(valid: true, latency: 0.1, now: at(Double(s))); d.recordRSSI(-80, now: at(Double(s))) }
        XCTAssertEqual(d.state, .ruptured(.signalLow))
        for s in 17...23 { d.recordProof(valid: true, latency: 0.1, now: at(Double(s))); d.recordRSSI(-60, now: at(Double(s))) }
        XCTAssertEqual(d.state, .present)
    }

    func testInvalidRSSIIsIgnored() {
        var d = present()
        XCTAssertEqual(d.recordRSSI(127, now: at(1)), .present)
    }
}

final class AlertStateTests: XCTestCase {
    func testStartsDisarmedAndArmingRequiresPresentBeacon() {
        var m = AlertStateMachine()
        XCTAssertEqual(m.state, .disarmed)
        XCTAssertEqual(m.handle(.arm(beacon: .unknown)), .disarmed)
        XCTAssertEqual(m.handle(.arm(beacon: .ruptured(.signalLow))), .disarmed)
        XCTAssertEqual(m.handle(.arm(beacon: .present)), .armed)
    }

    func testRuptureWhileArmedRaisesAlertAndClosesVault() {
        var m = AlertStateMachine()
        m.handle(.arm(beacon: .present))
        XCTAssertEqual(m.handle(.beaconChanged(.ruptured(.bleDisconnected))), .alert(.bleDisconnected))
        XCTAssertFalse(m.canOpenVault)
    }

    /// Fail-safe : une anomalie pendant la surveillance déclenche l'alerte.
    func testFailureWhileArmedRaisesAlert() {
        var m = AlertStateMachine()
        m.handle(.arm(beacon: .present))
        XCTAssertEqual(m.handle(.failure), .alert(.failSafe))
    }

    /// Le retour de la balise ne lève PAS l'alerte : il faut Face ID, le secours ou le Mac.
    func testBeaconReturnDoesNotClearAlert() {
        var m = AlertStateMachine()
        m.handle(.arm(beacon: .present))
        m.handle(.beaconChanged(.ruptured(.signalLow)))
        XCTAssertTrue(m.handle(.beaconChanged(.present)).isAlert)
        XCTAssertTrue(m.handle(.arm(beacon: .present)).isAlert)
        XCTAssertTrue(m.handle(.macAuthorized(.configChange)).isAlert)
    }

    func testAlertCanBeLifted() {
        for event: AlertStateMachine.Event in [.ownerAuthenticated, .emergencyUnlocked, .macAuthorized(.endAlert), .macAuthorized(.disarm)] {
            var m = AlertStateMachine()
            m.handle(.arm(beacon: .present))
            m.handle(.beaconChanged(.ruptured(.bleDisconnected)))
            XCTAssertEqual(m.handle(event), .disarmed, "\(event)")
        }
    }

    func testRuptureWhileDisarmedDoesNothing() {
        var m = AlertStateMachine()
        XCTAssertEqual(m.handle(.beaconChanged(.ruptured(.bleDisconnected))), .disarmed)
        XCTAssertEqual(m.handle(.failure), .disarmed)
    }

    func testStatusPayloadRoundTrip() throws {
        let s = StatusPayload(state: .alert(.signalLow), vaultOpen: false, beacon: .absent)
        XCTAssertEqual(try StrictJSON.decode(StatusPayload.self, from: try StrictJSON.encode(s)).protectionState, .alert(.signalLow))
        XCTAssertThrowsError(try StrictJSON.decode(StatusPayload.self, from: Data(#"{"state":"alert","vaultOpen":false,"beacon":"absent"}"#.utf8)))
    }
}

final class JournalTests: XCTestCase {
    let encKey = SymmetricKey(size: .bits256)
    let signer = SoftwareSigningIdentity()

    func sample() throws -> EventJournal {
        var j = EventJournal(encryptionKey: encKey, signer: signer)
        try j.append(.paired, device: "3FA2-91C0", detail: "Appairage")
        try j.append(.alert, device: "3FA2-91C0", detail: "Rupture BLE")
        try j.append(.challenge, device: "3FA2-91C0", detail: "Fin d'alerte", evidence: Data(repeating: 1, count: 64))
        return j
    }

    func testIntactChainVerifies() throws {
        let j = try sample()
        XCTAssertEqual(j.verify(expected: j.anchor), .intact)
    }

    /// T : modifier une entrée (même en recalculant son hash) est détecté, faute de pouvoir la re-signer.
    func testModifiedEntryIsDetected() throws {
        var entries = try sample().entries
        let e = entries[1]
        entries[1] = JournalEntry(index: e.index, timestampMs: e.timestampMs, kind: e.kind, device: e.device,
                                  detail: "Rien à signaler", evidence: e.evidence, previousHash: e.previousHash, signature: e.signature)
        XCTAssertEqual(EventJournal(encryptionKey: encKey, signer: signer, entries: entries).verify(), .broken(atIndex: 1))
    }

    func testDeletedMiddleEntryIsDetected() throws {
        var entries = try sample().entries
        entries.remove(at: 1)
        XCTAssertEqual(EventJournal(encryptionKey: encKey, signer: signer, entries: entries).verify(), .broken(atIndex: 1))
    }

    /// Suppression des dernières entrées : la chaîne reste cohérente, mais l'ancre la détecte.
    func testTruncationIsDetectedByAnchor() throws {
        let j = try sample()
        let truncated = EventJournal(encryptionKey: encKey, signer: signer, entries: Array(j.entries.prefix(1)))
        XCTAssertEqual(truncated.verify(), .intact)
        XCTAssertEqual(truncated.verify(expected: j.anchor), .truncated(expectedCount: 3))
    }

    /// Un journal entièrement reforgé avec une autre clé ne passe pas la vérification avec la bonne clé publique.
    func testForgedJournalWithOtherKeyIsRejected() throws {
        var forged = EventJournal(encryptionKey: encKey, signer: SoftwareSigningIdentity())
        try forged.append(.paired, device: "X", detail: "faux")
        XCTAssertEqual(forged.verify(publicKey: signer.publicKey), .broken(atIndex: 0))
    }

    func testEncryptedExportRoundTrip() throws {
        let j = try sample()
        let data = try j.exportEncrypted()
        XCTAssertFalse(String(decoding: data, as: UTF8.self).contains("Rupture"))
        XCTAssertEqual(try EventJournal.importEncrypted(data, encryptionKey: encKey, signer: signer).entries, j.entries)
        XCTAssertThrowsError(try EventJournal.importEncrypted(data, encryptionKey: SymmetricKey(size: .bits256), signer: signer))
    }
}

final class UtilityTests: XCTestCase {
    func testSecureWipeClearsBuffer() {
        var secret = Data(repeating: 0xAB, count: 32)
        SecureWipe.wipe(&secret)
        XCTAssertTrue(secret.isEmpty)
    }

    func testDeviceIDIsStablePseudonym() {
        let key = SoftwareSigningIdentity().publicKey
        XCTAssertEqual(DeviceID.of(key), DeviceID.of(key))
        XCTAssertEqual(DeviceID.of(key).count, 16)
        XCTAssertEqual(DeviceID.short(DeviceID.of(key)).count, 9)
    }

    func testRelayIdentifiersAreValidated() {
        XCTAssertNoThrow(try RelayAPI.validateIdentifier("AbCdEfGhIjKlMnOpQrStUv", field: "id"))
        for bad in ["court", "../../etc/passwd/aaaaaaaaaaaa", "espace interdit aaaaaaaaaa", String(repeating: "a", count: 65)] {
            XCTAssertThrowsError(try RelayAPI.validateIdentifier(bad, field: "id"), bad)
        }
    }

    func testRelayPinMatchesOnlySameKey() {
        let key = Data(repeating: 4, count: 65)
        let pin = RelayPin.pin(ofPublicKey: key)
        XCTAssertTrue(RelayPin.matches(publicKey: key, pin: pin))
        XCTAssertFalse(RelayPin.matches(publicKey: Data(repeating: 5, count: 65), pin: pin))
        XCTAssertFalse(RelayPin.matches(publicKey: key, pin: "pas du base64"))
    }

    func testMailboxConfigValidation() {
        XCTAssertNoThrow(try MailboxConfig(mailboxID: "AbCdEfGhIjKlMnOpQrStUv", writeToken: "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789-_abcde").validate())
        XCTAssertThrowsError(try MailboxConfig(mailboxID: "x", writeToken: "y").validate())
    }
}
