// ChannelClient.swift (iPhone)
// Rôle : connexion TCP vers le Mac (Bonjour) et session chiffrée (J1 §3.3-3.4, J2 §5).
// Toute la cryptographie est dans RobAirKit ; ce fichier gère la connexion et l'enchaînement des étapes.
//
//   Appairage : PAIR_REQ → attend PAIR_RESULT (le Mac attend que l'opérateur compare l'empreinte)
//   Session   : ClientHello → ServerHello → ClientFinish → messages chiffrés dans les deux sens
//               + renouvellement des clés toutes les 15 min (rekey / rekeyAck, sans Face ID)
//
// Le handshake signe avec K_id_iPhone : il faut un LAContext DÉJÀ validé par Face ID (fourni par AppModel).
// Fail-safe : la moindre erreur (trame invalide, rejeu, signature) ferme la connexion ; erreur = rejet
// silencieux, on ne renvoie jamais de détail au Mac (§3.4).

import os
import Foundation
import Network
import CryptoKit
import RobAirKit

final class ChannelClient {
    enum State: Equatable {
        case idle, connecting, handshaking, established
        case failed(String)

        var label: String {
            switch self {
            case .idle: return "Non connecté"
            case .connecting: return "Connexion…"
            case .handshaking: return "Authentification…"
            case .established: return "Chiffré et authentifié"
            case .failed(let reason): return "Échec : \(reason)"
            }
        }
    }

    var onStateChange: ((State) -> Void)?
    var onEstablished: (() -> Void)?
    var onChallenge: ((MacChallenge) -> Void)?
    var onMailbox: ((MailboxConfig) -> Void)?
    var onEncryptionKey: ((SignedEncryptionKey) -> Void)?

    private(set) var state: State = .idle {
        didSet { if state != oldValue { onStateChange?(state) } }
    }

    private struct SessionConfig {
        let identity: SigningIdentity
        let centrale: CentraleConfig
    }

    private struct PairingConfig {
        let request: PairingRequest
        let completion: (Result<PairingResult, Error>) -> Void
    }

    private var connection: NWConnection?
    private var decoder = FrameDecoder()
    private var handshake: HandshakeClient?
    private var sealer: RecordSealer?
    private var opener: RecordOpener?
    private var transcript: Data?
    private var rekey: RekeyInitiator?
    private var rekeyTimer: Timer?
    private var session: SessionConfig?
    private var pairing: PairingConfig?
    private var reconnectWork: DispatchWorkItem?
    private var failures = 0
    /// Chaque connexion a un numéro : les rappels d'une ancienne connexion sont ignorés.
    private var generation = 0

    // MARK: API

    func startSession(identity: SigningIdentity, centrale: CentraleConfig) {
        pairing = nil
        failures = 0
        session = SessionConfig(identity: identity, centrale: centrale)
        connect(to: centrale.serviceName)
    }

    func pair(serviceName: String, request: PairingRequest, completion: @escaping (Result<PairingResult, Error>) -> Void) {
        session = nil
        pairing = PairingConfig(request: request, completion: completion)
        connect(to: serviceName)
    }

    /// Ferme la session et OUBLIE les clés (alerte, désappairage, verrouillage).
    func stop() {
        session = nil
        pairing = nil
        reconnectWork?.cancel()
        teardown()
        state = .idle
    }

    /// Envoie un message chiffré. Retourne false si la session n'est pas établie.
    @discardableResult
    func send<T: WireMessage>(_ type: MessageType, _ value: T) -> Bool {
        guard state == .established, var sealer else { return false }
        // Pendant un renouvellement, l'initiateur n'envoie RIEN d'autre (voir Handshake.swift).
        guard rekey == nil || type == .rekey else { return false }
        do {
            let body = try sealer.sealJSON(type, value)
            self.sealer = sealer
            try sendRaw(Wire.frame(body))
            return true
        } catch {
            fail("envoi impossible")
            return false
        }
    }

    // MARK: Connexion

    private func connect(to serviceName: String) {
        teardown()
        generation += 1
        let current = generation
        let endpoint = NWEndpoint.service(name: serviceName, type: RobAirConstants.bonjourServiceType, domain: "local.", interface: nil)
        let connection = NWConnection(to: endpoint, using: .tcp)
        self.connection = connection
        decoder = FrameDecoder()
        state = .connecting

        connection.stateUpdateHandler = { [weak self] newState in
            guard let self, current == self.generation else { return }
            switch newState {
            case .ready: self.connectionReady()
            case .failed(let error), .waiting(let error): self.fail(error.localizedDescription)
            default: break
            }
        }
        connection.start(queue: .main)
        receive(on: connection, generation: current)

        // Fail-safe : une session doit être établie rapidement (l'appairage, lui, attend l'opérateur).
        DispatchQueue.main.asyncAfter(deadline: .now() + RobAirConstants.handshakeTimeout + 5) { [weak self] in
            guard let self, current == self.generation, self.session != nil, self.state != .established else { return }
            self.fail("délai dépassé")
        }
    }

    private func connectionReady() {
        do {
            if let pairing {
                state = .handshaking
                try sendRaw(Wire.plaintextFrame(.pairRequest, pairing.request))
            } else if let session {
                let client = HandshakeClient(identity: session.identity, macKey: try session.centrale.macKey())
                handshake = client
                state = .handshaking
                try sendRaw(Wire.plaintextFrame(.clientHello, client.makeHello()))
            }
        } catch {
            fail("handshake impossible")
        }
    }

    private func receive(on connection: NWConnection, generation current: Int) {
        connection.receive(minimumIncompleteLength: 1, maximumLength: 8192) { [weak self] data, _, isComplete, error in
            guard let self, current == self.generation else { return }
            if let data, !data.isEmpty {
                do {
                    for body in try self.decoder.append(data) {
                        guard current == self.generation else { return }
                        try self.handle(body)
                    }
                } catch {
                    self.fail("message refusé")
                    return
                }
            }
            guard current == self.generation else { return }
            if isComplete || error != nil {
                self.fail("connexion fermée")
                return
            }
            self.receive(on: connection, generation: current)
        }
    }

    private func handle(_ body: Data) throws {
        // 1. Appairage : on attend uniquement le résultat.
        if let pairing {
            let result = try Wire.decodePlaintext(body, expected: .pairResult, as: PairingResult.self)
            self.pairing = nil
            teardown()
            state = .idle
            pairing.completion(.success(result))
            return
        }
        // 2. Handshake : on attend uniquement ServerHello.
        if let client = handshake, let session {
            let reply = try Wire.decodePlaintext(body, expected: .serverHello, as: ServerHello.self)
            let (finish, keys) = try client.handle(reply)   // vérifie la signature du Mac (usurpation)
            handshake = nil
            try sendRaw(Wire.plaintextFrame(.clientFinish, finish))
            let iphoneID = DeviceID.of(session.identity.publicKey)
            sealer = RecordSealer(key: keys.sending, sender: iphoneID, direction: .clientToServer)
            opener = RecordOpener(key: keys.receiving, expectedSender: session.centrale.macID, direction: .serverToClient)
            transcript = keys.transcriptHash
            failures = 0
            state = .established
            startRekeyTimer()
            Log.net.info("Session chiffrée établie")
            onEstablished?()
            return
        }
        // 3. Session établie : seuls des messages chiffrés et authentifiés sont acceptés.
        guard state == .established, var opener else { throw RobAirError.unexpectedMessage }
        let (type, payload) = try opener.open(body)   // anti-rejeu + horodatage + intégrité
        self.opener = opener
        switch type {
        case .challenge:
            onChallenge?(try StrictJSON.decode(MacChallenge.self, from: payload))
        case .mailboxConfig:
            onMailbox?(try StrictJSON.decode(MailboxConfig.self, from: payload))
        case .encryptionKeyUpdate:
            onEncryptionKey?(try StrictJSON.decode(SignedEncryptionKey.self, from: payload))
        case .rekeyAck:
            guard let initiator = rekey, let previous = transcript else { throw RobAirError.unexpectedMessage }
            let keys = try initiator.finish(ack: StrictJSON.decode(RekeyMessage.self, from: payload), previousTranscript: previous)
            self.sealer?.rotate(to: keys.clientToServer)
            self.opener?.rotate(to: keys.serverToClient)
            transcript = keys.transcriptHash
            rekey = nil
            Log.net.info("Clés de session renouvelées")
        default:
            throw RobAirError.unexpectedMessage
        }
    }

    // MARK: Renouvellement des clés (15 min)

    private func startRekeyTimer() {
        rekeyTimer?.invalidate()
        rekeyTimer = Timer.scheduledTimer(withTimeInterval: RobAirConstants.sessionRekeyInterval, repeats: true) { [weak self] _ in
            guard let self, self.state == .established, self.rekey == nil else { return }
            let initiator = RekeyInitiator()
            self.rekey = initiator
            if !self.send(.rekey, initiator.message) { self.rekey = nil }
        }
    }

    // MARK: Utilitaires

    private func sendRaw(_ frame: Data) throws {
        guard let connection else { throw PlainExchange.Failure(reason: "pas de connexion") }
        connection.send(content: frame, completion: .contentProcessed { [weak self] error in
            if error != nil { self?.fail("envoi échoué") }
        })
    }

    private func fail(_ reason: String) {
        Log.net.error("Canal fermé : \(reason, privacy: .public)")
        let pairingCompletion = pairing?.completion
        pairing = nil
        teardown()
        state = .failed(reason)
        pairingCompletion?(.failure(PlainExchange.Failure(reason: reason)))
        scheduleReconnect()
    }

    private func teardown() {
        generation += 1
        connection?.cancel()
        connection = nil
        handshake = nil
        sealer = nil     // SÉCURITÉ : les clés de session sont oubliées avec la connexion
        opener = nil
        transcript = nil
        rekey = nil
        rekeyTimer?.invalidate()
        rekeyTimer = nil
    }

    /// Quelques reconnexions automatiques (le LAContext Face ID est encore valable) ; ensuite, il faudra
    /// une nouvelle action de l'utilisateur, donc un nouveau Face ID.
    private func scheduleReconnect() {
        guard let session, failures < 3 else { return }
        failures += 1
        reconnectWork?.cancel()
        let work = DispatchWorkItem { [weak self] in self?.connect(to: session.centrale.serviceName) }
        reconnectWork = work
        DispatchQueue.main.asyncAfter(deadline: .now() + 3, execute: work)
    }
}
