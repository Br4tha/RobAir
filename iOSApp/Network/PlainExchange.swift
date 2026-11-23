// PlainExchange.swift (iPhone)
// Rôle : un échange « une question, une réponse » avec le Mac SANS session chiffrée.
// Utilisé pour deux messages qui sont protégés AUTREMENT que par la session :
//   - la télémétrie : enveloppe HPKE + signature K_tel (§3.5) → réponse : accusé prouvé par ackSecret ;
//   - le déverrouillage de secours : défi de l'iPhone (rien de secret) → réponse signée par K_id_Mac (§3.8).
// Pourquoi pas la session ? En alerte, elle est détruite (§3.5, étape 1), et en rouvrir une exige
// Face ID (K_id_iPhone), justement indisponible (voleur, ou Face ID en échec).
// Fail-safe : délai dépassé, trame invalide ou mauvais type → erreur, rien n'est accepté.

import os
import Foundation
import Network
import RobAirKit

enum PlainExchange {
    struct Failure: LocalizedError {
        let reason: String
        var errorDescription: String? { reason }
    }

    /// Ouvre une connexion vers la centrale (Bonjour), envoie `frame`, attend UNE trame du type attendu.
    static func exchange(serviceName: String, frame: Data, expecting: MessageType, timeout: TimeInterval) async throws -> Data {
        let queue = DispatchQueue(label: "robair.plain-exchange")
        let endpoint = NWEndpoint.service(name: serviceName, type: RobAirConstants.bonjourServiceType, domain: "local.", interface: nil)
        let connection = NWConnection(to: endpoint, using: .tcp)
        let once = Once()

        return try await withCheckedThrowingContinuation { continuation in
            func finish(_ result: Result<Data, Error>) {
                guard once.claim() else { return }
                connection.cancel()
                continuation.resume(with: result)
            }
            var decoder = FrameDecoder()
            func receive() {
                connection.receive(minimumIncompleteLength: 1, maximumLength: 8192) { data, _, isComplete, error in
                    if let data, !data.isEmpty {
                        do {
                            for body in try decoder.append(data) {
                                guard try Wire.messageType(of: body) == expecting else { throw RobAirError.unexpectedMessage }
                                finish(.success(body))
                                return
                            }
                        } catch {
                            finish(.failure(error))
                            return
                        }
                    }
                    if isComplete || error != nil { finish(.failure(Failure(reason: "connexion fermée"))) } else { receive() }
                }
            }
            connection.stateUpdateHandler = { state in
                switch state {
                case .ready:
                    connection.send(content: frame, completion: .contentProcessed { error in
                        if error != nil { finish(.failure(Failure(reason: "envoi impossible"))) }
                    })
                    receive()
                case .failed, .waiting:
                    finish(.failure(Failure(reason: "centrale injoignable")))
                default:
                    break
                }
            }
            connection.start(queue: queue)
            queue.asyncAfter(deadline: .now() + timeout) { finish(.failure(Failure(reason: "délai dépassé"))) }
        }
    }
}

/// Garantit qu'une continuation n'est reprise qu'une seule fois.
private final class Once {
    private var done = false
    private let lock = NSLock()
    func claim() -> Bool {
        lock.lock(); defer { lock.unlock() }
        if done { return false }
        done = true
        return true
    }
}
