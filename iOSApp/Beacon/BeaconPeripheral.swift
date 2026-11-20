// BeaconPeripheral.swift (iPhone, mode Balise)
// Rôle : le 2e iPhone, porté par l'utilisateur, joue la BALISE BLE de confiance (J1 §1.3, §3.9).
// Pourquoi un iPhone ? AirPods et Apple Watch ne sont pas exposés aux apps tierces comme périphériques
// BLE surveillables. Un 2e iPhone en mode Balise : 0 €, sans matériel, même code Swift
// (une carte ESP32 à ≈ 5 € pourra le remplacer plus tard).
//   - annonce l'UUID de service tiré au hasard à l'appairage, sans nom (RGPD : pas de traçage par nom)
//   - reçoit un défi de 16 octets, répond HMAC-SHA256(K_balise, étiquette ‖ défi) par notification
//   - au plus une réponse par seconde et par appareil connecté (pas d'oracle illimité)
// Arrière-plan : mode bluetooth-peripheral. iOS réduit l'annonce en arrière-plan, mais une connexion
// déjà établie continue de répondre. En démo, l'app Balise reste au premier plan (J1 §10).

import Foundation
import CoreBluetooth
import CryptoKit
import RobAirKit

final class BeaconPeripheral: NSObject, CBPeripheralManagerDelegate {
    var onActivity: ((_ connected: Int, _ lastAnswer: Date?) -> Void)?

    private let serviceUUID: CBUUID
    private let key: SymmetricKey
    private var manager: CBPeripheralManager?
    private var characteristic: CBMutableCharacteristic?
    private var subscribers: [UUID: CBCentral] = [:]
    private var lastAnswer: [UUID: Date] = [:]
    private var lastAnswerAny: Date?
    private var pendingNotification: (value: Data, central: CBCentral)?

    init(code: BeaconPairingCode) {
        serviceUUID = CBUUID(string: code.serviceUUID)
        key = SymmetricKey(data: code.key)
        super.init()
    }

    func start() {
        guard manager == nil else { return }
        manager = CBPeripheralManager(delegate: self, queue: .main,
                                      options: [CBPeripheralManagerOptionRestoreIdentifierKey: "robair.beacon"])
    }

    func stop() {
        manager?.stopAdvertising()
        manager?.removeAllServices()
        manager = nil
        characteristic = nil
        subscribers.removeAll()
        report()
    }

    private func report() { onActivity?(subscribers.count, lastAnswerAny) }

    func peripheralManagerDidUpdateState(_ peripheral: CBPeripheralManager) {
        guard peripheral.state == .poweredOn else {
            subscribers.removeAll()
            report()
            return
        }
        let proof = CBMutableCharacteristic(type: CBUUID(string: BeaconProof.characteristicUUID),
                                            properties: [.write, .notify], value: nil, permissions: [.writeable])
        let service = CBMutableService(type: serviceUUID, primary: true)
        service.characteristics = [proof]
        characteristic = proof
        peripheral.removeAllServices()
        peripheral.add(service)
    }

    func peripheralManager(_ peripheral: CBPeripheralManager, willRestoreState dict: [String: Any]) {}

    func peripheralManager(_ peripheral: CBPeripheralManager, didAdd service: CBService, error: Error?) {
        guard error == nil else {
            Log.ble.error("Ajout du service BLE impossible")
            return
        }
        // RGPD : uniquement l'UUID de service, aucun nom d'appareil.
        peripheral.startAdvertising([CBAdvertisementDataServiceUUIDsKey: [serviceUUID]])
        Log.ble.info("Balise active")
    }

    func peripheralManager(_ peripheral: CBPeripheralManager, central: CBCentral, didSubscribeTo characteristic: CBCharacteristic) {
        subscribers[central.identifier] = central
        report()
    }

    func peripheralManager(_ peripheral: CBPeripheralManager, central: CBCentral, didUnsubscribeFrom characteristic: CBCharacteristic) {
        subscribers[central.identifier] = nil
        report()
    }

    func peripheralManager(_ peripheral: CBPeripheralManager, didReceiveWrite requests: [CBATTRequest]) {
        guard let request = requests.first else { return }
        guard requests.count == 1, request.offset == 0, let value = request.value, let characteristic else {
            peripheral.respond(to: request, withResult: .invalidOffset)
            return
        }
        let now = Date()
        if let last = lastAnswer[request.central.identifier], now.timeIntervalSince(last) < 1 {
            peripheral.respond(to: request, withResult: .unlikelyError)   // limite de débit
            return
        }
        guard let mac = try? BeaconProof.respond(to: value, key: key) else {
            peripheral.respond(to: request, withResult: .invalidAttributeValueLength)
            return
        }
        lastAnswer[request.central.identifier] = now
        lastAnswerAny = now
        peripheral.respond(to: request, withResult: .success)
        if !peripheral.updateValue(mac, for: characteristic, onSubscribedCentrals: [request.central]) {
            pendingNotification = (mac, request.central)
        }
        report()
    }

    func peripheralManagerIsReady(toUpdateSubscribers peripheral: CBPeripheralManager) {
        guard let pending = pendingNotification, let characteristic else { return }
        if peripheral.updateValue(pending.value, for: characteristic, onSubscribedCentrals: [pending.central]) {
            pendingNotification = nil
        }
    }
}
