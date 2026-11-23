// BeaconLink.swift (iPhone, mode Capteur)
// Rôle : connexion à la balise de confiance (2e iPhone en mode Balise), J1 §2.1 et §3.9.
// La DÉCISION « présente / rupture » est prise par RuptureDetector (RobAirKit, testé) ;
// ce fichier ne fait que brancher CoreBluetooth.
//
//   1. cherche le service BLE de NOTRE balise (UUID tiré au hasard à l'appairage de la balise)
//   2. se connecte, s'abonne à la caractéristique de preuve
//   3. toutes les 10 s : écrit un défi aléatoire, attend HMAC(K_balise, défi) en moins de 2 s
//   4. toutes les secondes (premier plan) : lit le RSSI → moyenne glissante sur 5 s
//   5. déconnexion → rupture immédiate, puis demande de reconnexion en attente
//
// Arrière-plan (mode bluetooth-central) : iOS réveille l'app sur DÉCONNEXION, mais suspend les minuteries.
// En arrière-plan, la détection repose donc sur la déconnexion (limite documentée, J1 §10).
// Menaces : S (balise clonée → HMAC invalide → rupture), D (brouillage = déconnexion = alerte).

import os
import Foundation
import CoreBluetooth
import CryptoKit
import RobAirKit

final class BeaconLink: NSObject {
    var onChange: ((RuptureDetector.State) -> Void)?

    private let serviceUUID: CBUUID
    private let characteristicUUID = CBUUID(string: BeaconProof.characteristicUUID)
    private let key: SymmetricKey

    private var central: CBCentralManager?
    private var peripheral: CBPeripheral?
    private var characteristic: CBCharacteristic?
    private var detector = RuptureDetector()
    private var lastPublished: RuptureDetector.State?
    private var pending: (challenge: Data, sentAt: Date)?
    private var timers: [Timer] = []
    private var tickTimer: Timer?

    init(code: BeaconPairingCode) {
        serviceUUID = CBUUID(string: code.serviceUUID)
        key = SymmetricKey(data: code.key)
        super.init()
    }

    var state: RuptureDetector.State { detector.state }

    func start() {
        guard central == nil else { return }
        central = CBCentralManager(delegate: self, queue: .main,
                                   options: [CBCentralManagerOptionRestoreIdentifierKey: "robair.central"])
        tickTimer = Timer.scheduledTimer(withTimeInterval: 1, repeats: true) { [weak self] _ in
            guard let self else { return }
            self.publish(self.detector.tick(now: Date()))
        }
    }

    func stop() {
        stopProofTimers()
        tickTimer?.invalidate()
        tickTimer = nil
        if let peripheral { central?.cancelPeripheralConnection(peripheral) }
        central?.stopScan()
        central = nil
        peripheral = nil
        characteristic = nil
    }

    // MARK: Défi HMAC

    private func sendChallenge() {
        guard let peripheral, let characteristic else { return }
        let challenge = BeaconProof.makeChallenge()
        pending = (challenge, Date())
        peripheral.writeValue(challenge, for: characteristic, type: .withResponse)
        DispatchQueue.main.asyncAfter(deadline: .now() + RobAirConstants.beaconChallengeTimeout) { [weak self] in
            guard let self, let pending = self.pending, pending.challenge == challenge else { return }
            self.pending = nil
            Log.ble.notice("Défi balise sans réponse dans les temps")
            self.publish(self.detector.recordProof(valid: false, latency: .infinity, now: Date()))
        }
    }

    private func handleResponse(_ value: Data) {
        guard let pending else { return }
        self.pending = nil
        let valid = BeaconProof.verify(response: value, challenge: pending.challenge, key: key)
        if !valid { Log.ble.error("Réponse de balise invalide (clone ?)") }
        publish(detector.recordProof(valid: valid, latency: Date().timeIntervalSince(pending.sentAt), now: Date()))
    }

    // MARK: Minuteries (premier plan)

    private func startProofTimers() {
        stopProofTimers()
        timers = [
            Timer.scheduledTimer(withTimeInterval: RobAirConstants.beaconChallengeInterval, repeats: true) { [weak self] _ in
                self?.sendChallenge()
            },
            Timer.scheduledTimer(withTimeInterval: RobAirConstants.rssiSampleInterval, repeats: true) { [weak self] _ in
                self?.peripheral?.readRSSI()
            }
        ]
    }

    private func stopProofTimers() {
        timers.forEach { $0.invalidate() }
        timers = []
        pending = nil
    }

    private func publish(_ state: RuptureDetector.State) {
        guard state != lastPublished else { return }
        lastPublished = state
        onChange?(state)
    }

    private func scan(_ central: CBCentralManager) {
        guard central.state == .poweredOn else { return }
        central.scanForPeripherals(withServices: [serviceUUID], options: nil)
    }
}

extension BeaconLink: CBCentralManagerDelegate {
    func centralManagerDidUpdateState(_ central: CBCentralManager) {
        if central.state == .poweredOn {
            if let peripheral { central.connect(peripheral) } else { scan(central) }
        } else {
            // Bluetooth coupé = fail-safe : rupture.
            stopProofTimers()
            publish(detector.connectionChanged(false, now: Date()))
        }
    }

    func centralManager(_ central: CBCentralManager, willRestoreState dict: [String: Any]) {
        if let restored = (dict[CBCentralManagerRestoredStatePeripheralsKey] as? [CBPeripheral])?.first {
            peripheral = restored
            restored.delegate = self
        }
    }

    func centralManager(_ central: CBCentralManager, didDiscover peripheral: CBPeripheral,
                        advertisementData: [String: Any], rssi RSSI: NSNumber) {
        guard self.peripheral == nil else { return }
        self.peripheral = peripheral
        peripheral.delegate = self
        central.stopScan()
        central.connect(peripheral)
    }

    func centralManager(_ central: CBCentralManager, didConnect peripheral: CBPeripheral) {
        Log.ble.info("Connecté à la balise, vérification en cours")
        publish(detector.connectionChanged(true, now: Date()))
        peripheral.discoverServices([serviceUUID])
    }

    func centralManager(_ central: CBCentralManager, didFailToConnect peripheral: CBPeripheral, error: Error?) {
        self.peripheral = nil
        scan(central)
    }

    func centralManager(_ central: CBCentralManager, didDisconnectPeripheral peripheral: CBPeripheral, error: Error?) {
        Log.ble.notice("Liaison avec la balise perdue")
        stopProofTimers()
        characteristic = nil
        publish(detector.connectionChanged(false, now: Date()))
        central.connect(peripheral)   // demande en attente : reconnexion dès le retour à portée
    }
}

extension BeaconLink: CBPeripheralDelegate {
    func peripheral(_ peripheral: CBPeripheral, didDiscoverServices error: Error?) {
        guard let service = peripheral.services?.first(where: { $0.uuid == serviceUUID }) else {
            central?.cancelPeripheralConnection(peripheral)
            return
        }
        peripheral.discoverCharacteristics([characteristicUUID], for: service)
    }

    func peripheral(_ peripheral: CBPeripheral, didDiscoverCharacteristicsFor service: CBService, error: Error?) {
        guard let found = service.characteristics?.first(where: { $0.uuid == characteristicUUID }) else {
            central?.cancelPeripheralConnection(peripheral)
            return
        }
        characteristic = found
        peripheral.setNotifyValue(true, for: found)
    }

    func peripheral(_ peripheral: CBPeripheral, didUpdateNotificationStateFor characteristic: CBCharacteristic, error: Error?) {
        guard error == nil, characteristic.isNotifying else {
            central?.cancelPeripheralConnection(peripheral)
            return
        }
        startProofTimers()
        sendChallenge()
        peripheral.readRSSI()
    }

    func peripheral(_ peripheral: CBPeripheral, didUpdateValueFor characteristic: CBCharacteristic, error: Error?) {
        guard error == nil, let value = characteristic.value, value.count <= 64 else { return }
        handleResponse(value)
    }

    func peripheral(_ peripheral: CBPeripheral, didReadRSSI RSSI: NSNumber, error: Error?) {
        guard error == nil else { return }
        publish(detector.recordRSSI(RSSI.intValue, now: Date()))
    }
}
