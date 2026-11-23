// ChannelServer.swift (Mac)
// Rôle : écoute TCP annoncée en Bonjour + une machine à états par connexion (J1 §3.2-3.8, J2 §5).
//
//   1er message ─┬─ PAIR_REQ          → invitation ouverte ? → validation → attente empreinte → PAIR_RESULT
//                ├─ ClientHello        → iPhone appairé ET centrale déverrouillée ? → ServerHello → ClientFinish → session
//                ├─ TELEMETRY          → déchiffrement HPKE + signature K_tel → TELEMETRY_ACK (ackSecret) → fermeture
//                └─ EMERGENCY_REQUEST  → présenté à l'opérateur (Touch ID) → EMERGENCY_GRANT signé → fermeture
//   Session établie : uniquement des messages chiffrés et authentifiés (+ renouvellement des clés).
//
// Défenses (déni de service) : 4 connexions non authentifiées max, handshake ≤ 5 s, 20 trames/s max,
// trames ≤ 4 Ko. Règle §3.4 : erreur = rejet SILENCIEUX + entrée au journal (jamais de détail renvoyé).

import Foundation
import Network
import CryptoKit
import RobAirKit

protocol ChannelServerDelegate: AnyObject {
    func serverReceivedPairing(_ request: PairingRequest, from connection: ServerConnection)
    /// Signataire K_id_Mac pour un handshake, si la centrale est déverrouillée (session opérateur).
    func serverHandshakeSigner() -> SigningIdentity?
    func serverSessionEstablished(_ connection: ServerConnection)
    func serverSessionEnded(_ connection: ServerConnection, reason: String)
    func server(_ connection: ServerConnection, received type: MessageType, payload: Data) throws
    /// Renvoie l'ackSecret à retourner si la télémétrie est authentique.
    func serverReceivedTelemetry(_ envelope: TelemetryEnvelope, via: String) throws -> Data
    func serverReceivedEmergency(_ request: EmergencyRequest, from connection: ServerConnection) throws
    func serverRejected(reason: String)
}

final class ChannelServer {
    weak var delegate: ChannelServerDelegate?
    var pairingSession: PairingSession?
    var pairedIPhoneKey: P256.Signing.PublicKey?
    let macID: Data

    private var listener: NWListener?
    private var connections: [ServerConnection] = []
    private(set) var active: ServerConnection?

    init(macID: Data) { self.macID = macID }

    func start(serviceName: String) throws {
        let listener = try NWListener(using: .tcp)
        listener.service = NWListener.Service(name: serviceName, type: RobAirConstants.bonjourServiceType)
        listener.newConnectionHandler = { [weak self] connection in self?.accept(connection) }
        listener.stateUpdateHandler = { state in
            if case .failed(let error) = state {
                Log.net.error("Écoute réseau en échec : \(error.localizedDescription, privacy: .public)")
            }
        }
        listener.start(queue: .main)
        self.listener = listener
    }

    func stop() {
        listener?.cancel()
        listener = nil
        let all = connections
        connections.removeAll()
        active = nil
        all.forEach { $0.close("arrêt de la centrale") }
    }

    private func accept(_ nwConnection: NWConnection) {
        guard connections.filter({ !$0.isEstablished }).count < 4 else {
            nwConnection.cancel()   // on refuse sans rien traiter
            return
        }
        let connection = ServerConnection(nwConnection, server: self)
        connections.append(connection)
        connection.start()
    }

    // Appelés par ServerConnection

    func connectionClosed(_ connection: ServerConnection, reason: String, quiet: Bool) {
        connections.removeAll { $0 === connection }
        if active === connection {
            active = nil
            delegate?.serverSessionEnded(connection, reason: reason)
        } else if !quiet {
            delegate?.serverRejected(reason: reason)
        }
    }

    func connectionEstablished(_ connection: ServerConnection) {
        let previous = active
        active = connection
        previous?.close("remplacée par une nouvelle session")
        delegate?.serverSessionEstablished(connection)
    }
}

final class ServerConnection {
    private enum Phase {
        case awaitingFirst
        case pairingPending
        case emergencyPending
        case handshaking(HandshakeServer)
        case established
        case closed
    }

    private let nw: NWConnection
    private weak var server: ChannelServer?
    private var phase = Phase.awaitingFirst
    private var decoder = FrameDecoder()
    private var sealer: RecordSealer?
    private var opener: RecordOpener?
    private var transcript: Data?
    private var recentFrames: [Date] = []
    private var quietClose = false

    var isEstablished: Bool {
        if case .established = phase { return true }
        return false
    }

    init(_ nw: NWConnection, server: ChannelServer) {
        self.nw = nw
        self.server = server
    }

    func start() {
        nw.stateUpdateHandler = { [weak self] state in
            switch state {
            case .failed, .cancelled: self?.close("connexion perdue")
            default: break
            }
        }
        nw.start(queue: .main)
        receive()
        DispatchQueue.main.asyncAfter(deadline: .now() + RobAirConstants.handshakeTimeout) { [weak self] in
            guard let self else { return }
            switch self.phase {
            case .awaitingFirst, .handshaking: self.close("délai de handshake dépassé")
            default: break
            }
        }
    }

    func close(_ reason: String) {
        if case .closed = phase { return }
        let wasEstablished = isEstablished
        phase = .closed
        sealer = nil   // SÉCURITÉ : clés de session oubliées
        opener = nil
        transcript = nil
        nw.cancel()
        server?.connectionClosed(self, reason: reason, quiet: wasEstablished || quietClose)
    }

    // MARK: Réception

    private func receive() {
        nw.receive(minimumIncompleteLength: 1, maximumLength: 8192) { [weak self] data, _, isComplete, error in
            guard let self else { return }
            if let data, !data.isEmpty {
                do {
                    for body in try self.decoder.append(data) {
                        if case .closed = self.phase { return }
                        try self.checkRate()
                        try self.handle(body)
                    }
                } catch {
                    self.close("message refusé : \(error.localizedDescription)")
                    return
                }
            }
            if isComplete || error != nil {
                self.close("connexion fermée par l'iPhone")
                return
            }
            if case .closed = self.phase { return }
            self.receive()
        }
    }

    private func checkRate() throws {
        let now = Date()
        recentFrames = recentFrames.filter { now.timeIntervalSince($0) < 1 }
        recentFrames.append(now)
        if recentFrames.count > 20 { throw RobAirError.messageTooLarge }
    }

    private func handle(_ body: Data) throws {
        guard let server, let delegate = server.delegate else { throw RobAirError.unexpectedMessage }
        switch phase {
        case .awaitingFirst:
            switch try Wire.messageType(of: body) {
            case .pairRequest:
                guard let session = server.pairingSession else { throw RobAirError.unexpectedMessage }
                let request = try Wire.decodePlaintext(body, expected: .pairRequest, as: PairingRequest.self)
                _ = try session.validate(request)   // jeton, expiration, usage unique (faux iPhone)
                phase = .pairingPending
                delegate.serverReceivedPairing(request, from: self)
                closeIfStill(.pairingPending, after: RobAirConstants.pairingTokenLifetime, reason: "appairage non confirmé à temps")

            case .clientHello:
                guard let iphoneKey = server.pairedIPhoneKey else { throw RobAirError.unknownDevice }
                // Fail-safe : centrale verrouillée (pas de session opérateur) → on refuse, on ne signe rien.
                guard let signer = delegate.serverHandshakeSigner() else { throw RobAirError.authenticationFailed }
                let hello = try Wire.decodePlaintext(body, expected: .clientHello, as: ClientHello.self)
                let handshake = HandshakeServer(identity: signer, iphoneKey: iphoneKey)
                let reply = try handshake.handle(hello)
                phase = .handshaking(handshake)
                try sendRaw(Wire.plaintextFrame(.serverHello, reply))

            case .telemetry:
                let envelope = try Wire.decodePlaintext(body, expected: .telemetry, as: TelemetryEnvelope.self)
                let ackSecret = try delegate.serverReceivedTelemetry(envelope, via: "Wi-Fi local")
                quietClose = true
                sendThenClose(try Wire.plaintextFrame(.telemetryAck, TelemetryAck(ackSecret: ackSecret)), reason: "télémétrie reçue")

            case .emergencyRequest:
                let request = try Wire.decodePlaintext(body, expected: .emergencyRequest, as: EmergencyRequest.self)
                try delegate.serverReceivedEmergency(request, from: self)
                phase = .emergencyPending
                closeIfStill(.emergencyPending, after: RobAirConstants.emergencyChallengeLifetime, reason: "secours non accordé à temps")

            default:
                throw RobAirError.unexpectedMessage
            }

        case .handshaking(let handshake):
            let finish = try Wire.decodePlaintext(body, expected: .clientFinish, as: ClientFinish.self)
            let keys = try handshake.handle(finish)   // vérifie la signature de l'iPhone (faux iPhone)
            guard let iphoneKey = server.pairedIPhoneKey else { throw RobAirError.unknownDevice }
            sealer = RecordSealer(key: keys.sending, sender: server.macID, direction: .serverToClient)
            opener = RecordOpener(key: keys.receiving, expectedSender: DeviceID.of(iphoneKey), direction: .clientToServer)
            transcript = keys.transcriptHash
            phase = .established
            server.connectionEstablished(self)

        case .established:
            guard var opener else { throw RobAirError.unexpectedMessage }
            let (type, payload) = try opener.open(body)   // intégrité + anti-rejeu + horodatage
            self.opener = opener
            if type == .rekey {
                try respondToRekey(payload)
            } else {
                try delegate.server(self, received: type, payload: payload)
            }

        case .pairingPending, .emergencyPending, .closed:
            throw RobAirError.unexpectedMessage
        }
    }

    /// Renouvellement des clés demandé par l'iPhone : accusé sous l'ANCIENNE clé, puis bascule.
    private func respondToRekey(_ payload: Data) throws {
        guard let previous = transcript else { throw RobAirError.unexpectedMessage }
        let (ack, keys) = try RekeyResponder.respond(to: StrictJSON.decode(RekeyMessage.self, from: payload), previousTranscript: previous)
        send(.rekeyAck, ack)
        sealer?.rotate(to: keys.serverToClient)
        opener?.rotate(to: keys.clientToServer)
        transcript = keys.transcriptHash
    }

    private func closeIfStill(_ expected: Phase, after delay: TimeInterval, reason: String) {
        DispatchQueue.main.asyncAfter(deadline: .now() + delay) { [weak self] in
            guard let self else { return }
            switch (self.phase, expected) {
            case (.pairingPending, .pairingPending), (.emergencyPending, .emergencyPending): self.close(reason)
            default: break
            }
        }
    }

    // MARK: Envoi

    /// Termine l'appairage : envoie le résultat (signé si accepté) puis ferme.
    func completePairing(_ result: PairingResult) {
        guard case .pairingPending = phase, let frame = try? Wire.plaintextFrame(.pairResult, result) else { return }
        quietClose = true
        sendThenClose(frame, reason: "appairage terminé")
    }

    /// Termine un déverrouillage de secours accordé par l'opérateur.
    func completeEmergency(_ grant: EmergencyGrant) {
        guard case .emergencyPending = phase, let frame = try? Wire.plaintextFrame(.emergencyGrant, grant) else { return }
        quietClose = true
        sendThenClose(frame, reason: "secours accordé")
    }

    func send<T: WireMessage>(_ type: MessageType, _ value: T) {
        guard isEstablished, var sealer else { return }
        do {
            let body = try sealer.sealJSON(type, value)
            self.sealer = sealer
            try sendRaw(Wire.frame(body))
        } catch {
            close("envoi impossible")
        }
    }

    private func sendThenClose(_ frame: Data, reason: String) {
        nw.send(content: frame, completion: .contentProcessed { [weak self] _ in self?.close(reason) })
    }

    private func sendRaw(_ frame: Data) throws {
        nw.send(content: frame, completion: .contentProcessed { [weak self] error in
            if error != nil { self?.close("envoi échoué") }
        })
    }
}
