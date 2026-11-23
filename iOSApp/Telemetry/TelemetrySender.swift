// TelemetrySender.swift (iPhone, mode Capteur)
// Rôle : acheminement de la télémétrie (J1 §3.5, étapes 5 et 6).
//   1. chaque message est signé (K_tel) et chiffré (HPKE pour K_enc_Mac) PUIS mis en file ;
//   2. envoi : canal local si le Mac est joignable, sinon POST HTTPS vers la boîte du relais ;
//   3. retiré de la file seulement une fois acquitté : accusé du Mac (ackSecret prouvé) ou 201 du relais ;
//   4. file de 100 entrées au plus ; au-delà, la plus ancienne position « periodic » est abandonnée,
//      jamais l'alerte initiale.
// Fichier de la file : protection « CompleteUnlessOpen », LA SEULE exception à « Complete » (J1 §3.1) :
// il doit pouvoir être écrit téléphone verrouillé. Il ne contient que des enveloppes déjà chiffrées pour
// le Mac, que l'iPhone ne peut lui-même pas relire. Une copie en mémoire sert aux envois (un fichier
// CompleteUnlessOpen fermé n'est pas relisible téléphone verrouillé).

import os
import Foundation
import RobAirKit

@MainActor
final class TelemetrySender {
    struct Item: Codable, Equatable {
        let seq: UInt64
        let trigger: TelemetryTrigger
        let envelope: Data      // enveloppe HPKE sérialisée (opaque)
        let ackSecret: Data     // pour reconnaître l'accusé du Mac
    }

    var onQueueChange: ((Int) -> Void)?
    var onDelivered: ((String) -> Void)?

    private let identity: DeviceIdentity
    private let state: StateStore
    private var items: [Item] = []
    private var flushing = false

    private var fileURL: URL {
        FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("telemetry-queue.json")
    }

    init(identity: DeviceIdentity, state: StateStore) {
        self.identity = identity
        self.state = state
        if let data = try? Data(contentsOf: fileURL), let saved = try? JSONDecoder().decode([Item].self, from: data) {
            items = saved
        }
    }

    var queuedCount: Int { items.count }

    /// Construit, signe, chiffre et met en file un message, puis tente l'envoi.
    func enqueue(trigger: TelemetryTrigger, lat: Double?, lon: Double?, accuracy: Double?, battery: Double?,
                 centrale: CentraleConfig) {
        do {
            guard let iphoneID = identity.iphoneID else { throw RobAirError.unknownDevice }
            let payload = TelemetryPayload(iphoneID: iphoneID, seq: try state.nextTelemetrySeq(), lat: lat, lon: lon,
                                           accuracy: accuracy, battery: battery, trigger: trigger)
            let envelope = try TelemetryCrypto.seal(payload, signer: identity.loadTelemetry(),
                                                    macKey: centrale.encryptionPublicKey(),
                                                    epoch: centrale.encryptionKey.epoch, macID: centrale.macID)
            items.append(Item(seq: payload.seq, trigger: trigger, envelope: try envelope.serialized(), ackSecret: payload.ackSecret))
            trim()
            persist()
            flush(centrale: centrale)
        } catch {
            Log.app.error("Télémétrie : construction impossible")
        }
    }

    /// Envoie la file dans l'ordre (seq croissant : le Mac refuse un seq plus petit que le dernier accepté).
    func flush(centrale: CentraleConfig) {
        guard !flushing, !items.isEmpty else { return }
        flushing = true
        Task { @MainActor in
            defer { flushing = false }
            while let item = items.first {
                guard let route = await deliver(item, centrale: centrale) else { break }   // réessai plus tard
                items.removeFirst()
                persist()
                onDelivered?(route)
            }
        }
    }

    func clear() {
        items.removeAll()
        try? FileManager.default.removeItem(at: fileURL)
        onQueueChange?(0)
    }

    // MARK: Acheminement

    private func deliver(_ item: Item, centrale: CentraleConfig) async -> String? {
        // 1. Canal local : le Mac doit renvoyer le bon ackSecret (lui seul a pu le déchiffrer).
        if let frame = try? Wire.plaintextFrame(.telemetry, TelemetryEnvelope.parse(item.envelope)),
           let reply = try? await PlainExchange.exchange(serviceName: centrale.serviceName, frame: frame,
                                                         expecting: .telemetryAck, timeout: 4),
           let ack = try? Wire.decodePlaintext(reply, expected: .telemetryAck, as: TelemetryAck.self),
           ack.ackSecret == item.ackSecret {
            return "Wi-Fi local"
        }
        // 2. Relais aveugle (extension P2), si configuré.
        if let relay = centrale.relay, let mailbox = centrale.mailbox, let client = try? RelayClient(info: relay),
           (try? await client.post(envelope: item.envelope, mailboxID: mailbox.mailboxID, writeToken: mailbox.writeToken)) != nil {
            return "relais"
        }
        return nil
    }

    private func trim() {
        while items.count > RobAirConstants.telemetryQueueMax {
            if let index = items.firstIndex(where: { $0.trigger == .periodic }) { items.remove(at: index) } else { items.removeFirst() }
        }
    }

    private func persist() {
        onQueueChange?(items.count)
        do {
            try FileManager.default.createDirectory(at: fileURL.deletingLastPathComponent(), withIntermediateDirectories: true)
            try JSONEncoder().encode(items).write(to: fileURL, options: [.atomic, .completeFileProtectionUnlessOpen])
        } catch {
            Log.app.error("File de télémétrie : écriture impossible")
        }
    }
}
