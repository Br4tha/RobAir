// BeaconModel.swift (iPhone, mode Balise)
// Rôle : état du 2e iPhone qui sert de balise de confiance.
// La clé K_balise est créée ici (aléa cryptographique), gardée dans le Keychain (ThisDeviceOnly,
// AfterFirstUnlock : la balise doit répondre téléphone verrouillé) et montrée UNE fois en QR code
// au capteur. Régénérer la clé = réappairer le capteur.

import Combine
import os
import SwiftUI
import RobAirKit

@MainActor
final class BeaconModel: ObservableObject {
    @Published private(set) var code: BeaconPairingCode
    @Published private(set) var connectedCount = 0
    @Published private(set) var lastAnswer: Date?

    private let store = BeaconKeyStore(service: "robair.ios.own-beacon")
    private var peripheral: BeaconPeripheral?

    init() {
        if let saved = store.load() {
            code = saved
        } else {
            let fresh = BeaconPairingCode.generate()
            try? store.save(fresh)
            code = fresh
        }
    }

    func start() {
        guard peripheral == nil else { return }
        let peripheral = BeaconPeripheral(code: code)
        peripheral.onActivity = { [weak self] count, last in
            Task { @MainActor in
                self?.connectedCount = count
                self?.lastAnswer = last
            }
        }
        peripheral.start()
        self.peripheral = peripheral
    }

    func stop() {
        peripheral?.stop()
        peripheral = nil
    }

    /// Nouvelle clé et nouvel UUID : l'ancien appairage (et toute copie de l'ancien QR) ne vaut plus rien.
    func regenerate() {
        stop()
        let fresh = BeaconPairingCode.generate()
        try? store.save(fresh)
        code = fresh
        start()
    }

    var qrText: String { (try? code.qrText()) ?? "" }
}
