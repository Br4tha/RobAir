// RelayAPI.swift
// Rôle : contrat d'API du relais aveugle (extension P2, J1 §2.3 et §3.6 ; J2 §9) + client HTTPS épinglé.
// Le relais est une simple boîte aux lettres : il stocke des messages OPAQUES (enveloppes HPKE signées)
// et ne peut ni les lire ni en fabriquer de valides.
//
//   POST   /v1/mailboxes                      Bearer <clé d'enrôlement> → {mailboxID, writeToken, readToken}
//   POST   /v1/mailboxes/{id}/messages        Bearer <writeToken>       → {messageID}
//   GET    /v1/mailboxes/{id}/messages        Bearer <readToken>        → {messages: [...]}
//   DELETE /v1/mailboxes/{id}/messages/{mid}  Bearer <readToken>        (accusé : suppression)
//   DELETE /v1/mailboxes/{id}                 Bearer <readToken>        (fermeture de la boîte)
//
// Sécurité réseau : TLS 1.3 (certificat Let's Encrypt) ET épinglage de la clé publique du serveur.
// Même si le TLS tombait, le chiffrement de bout en bout tient.

import Foundation
import CryptoKit

public enum RelayAPI {
    /// Identifiants et jetons : base64url, entre 16 et 64 caractères (128 à 256 bits d'aléa côté serveur).
    public static func validateIdentifier(_ value: String, field: String) throws {
        let allowed = Set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")
        guard (16...64).contains(value.count), value.allSatisfy(allowed.contains) else { throw RobAirError.malformed(field) }
    }

    public struct CreatedMailbox: WireMessage, Equatable {
        public let mailboxID: String
        public let writeToken: String
        public let readToken: String

        public func validate() throws {
            try validateIdentifier(mailboxID, field: "mailboxID")
            try validateIdentifier(writeToken, field: "writeToken")
            try validateIdentifier(readToken, field: "readToken")
            guard writeToken != readToken else { throw RobAirError.malformed("tokens") }
        }
    }

    public struct PostMessage: WireMessage, Equatable {
        public let message: String      // base64 de l'enveloppe de télémétrie

        public init(message: String) { self.message = message }
    }

    public struct PostedMessage: WireMessage, Equatable {
        public let messageID: String

        public func validate() throws { try validateIdentifier(messageID, field: "messageID") }
    }

    public struct StoredMessage: WireMessage, Equatable {
        public let messageID: String
        public let message: String
        public let receivedAtMs: UInt64

        public func validate() throws {
            try validateIdentifier(messageID, field: "messageID")
            guard let data = Data(base64Encoded: message), data.count <= RobAirConstants.maxMessageSize else {
                throw RobAirError.malformed("message")
            }
        }

        public var payload: Data { Data(base64Encoded: message) ?? Data() }
    }

    public struct MessageList: WireMessage, Equatable {
        public let messages: [StoredMessage]

        public func validate() throws {
            guard messages.count <= 200 else { throw RobAirError.messageTooLarge }
            try messages.forEach { try $0.validate() }
        }
    }
}

/// Épinglage (§3.6) : empreinte = SHA-256 de la clé publique du certificat du serveur, en base64.
/// Pour une clé ECDSA P-256 (recommandée, voir relay/README.md), ce sont les 65 octets X9.63
/// renvoyés par SecKeyCopyExternalRepresentation ; le script relay/tools/pin.sh calcule la même valeur.
public enum RelayPin {
    public static func pin(ofPublicKey bytes: Data) -> String {
        Data(SHA256.hash(data: bytes)).base64EncodedString()
    }

    public static func matches(publicKey bytes: Data, pin: String) -> Bool {
        guard let expected = Data(base64Encoded: pin) else { return false }
        // Comparaison en temps constant (HMAC sur deux valeurs publiques : seul l'égalité compte).
        let key = SymmetricKey(size: .bits256)
        return HMAC<SHA256>.isValidAuthenticationCode(HMAC<SHA256>.authenticationCode(for: expected, using: key),
                                                      authenticating: Data(SHA256.hash(data: bytes)), using: key)
    }
}

#if canImport(Security) && (os(iOS) || os(macOS))
import Security

/// Client HTTPS du relais : chaîne de certificats valide (Let's Encrypt) ET clé publique épinglée.
public final class RelayClient: NSObject, URLSessionDelegate {
    private let baseURL: URL
    private let pin: String

    /// Une session par requête, invalidée ensuite : URLSession retient son délégué (sinon cycle de références).
    private func makeSession() -> URLSession {
        let config = URLSessionConfiguration.ephemeral          // ni cache, ni cookies sur disque
        config.timeoutIntervalForRequest = 10
        config.tlsMinimumSupportedProtocolVersion = .TLSv13
        config.httpCookieStorage = nil
        config.urlCache = nil
        return URLSession(configuration: config, delegate: self, delegateQueue: nil)
    }

    public init(info: RelayInfo) throws {
        try info.validate()
        guard let url = URL(string: info.url) else { throw RobAirError.malformed("relay.url") }
        baseURL = url
        pin = info.pin
    }

    // MARK: Épinglage

    public func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge,
                           completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
              let trust = challenge.protectionSpace.serverTrust,
              SecTrustEvaluateWithError(trust, nil),                                  // 1. chaîne valide
              let leaf = (SecTrustCopyCertificateChain(trust) as? [SecCertificate])?.first,
              let key = SecCertificateCopyKey(leaf),
              let bytes = SecKeyCopyExternalRepresentation(key, nil) as Data?,
              RelayPin.matches(publicKey: bytes, pin: pin) else {                     // 2. bonne clé
            completionHandler(.cancelAuthenticationChallenge, nil)                    // fail-safe : on coupe
            return
        }
        completionHandler(.useCredential, URLCredential(trust: trust))
    }

    // MARK: API

    public func createMailbox(enrollmentKey: String) async throws -> RelayAPI.CreatedMailbox {
        try await call("POST", "v1/mailboxes", token: enrollmentKey, body: Optional<RelayAPI.PostMessage>.none, expect: 201)
    }

    public func post(envelope: Data, mailboxID: String, writeToken: String) async throws -> RelayAPI.PostedMessage {
        try await call("POST", "v1/mailboxes/\(mailboxID)/messages", token: writeToken,
                       body: RelayAPI.PostMessage(message: envelope.base64EncodedString()), expect: 201)
    }

    public func fetch(mailboxID: String, readToken: String) async throws -> [RelayAPI.StoredMessage] {
        let list: RelayAPI.MessageList = try await call("GET", "v1/mailboxes/\(mailboxID)/messages", token: readToken,
                                                        body: Optional<RelayAPI.PostMessage>.none, expect: 200)
        return list.messages
    }

    public func delete(messageID: String, mailboxID: String, readToken: String) async throws {
        try await callNoContent("DELETE", "v1/mailboxes/\(mailboxID)/messages/\(messageID)", token: readToken)
    }

    public func closeMailbox(mailboxID: String, readToken: String) async throws {
        try await callNoContent("DELETE", "v1/mailboxes/\(mailboxID)", token: readToken)
    }

    private func request(_ method: String, _ path: String, token: String, body: Data?) throws -> URLRequest {
        try RelayAPI.validateIdentifier(token, field: "token")
        var request = URLRequest(url: baseURL.appendingPathComponent(path))
        request.httpMethod = method
        request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        if let body {
            request.httpBody = body
            request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        }
        return request
    }

    private func call<B: WireMessage, R: WireMessage>(_ method: String, _ path: String, token: String,
                                                      body: B?, expect: Int) async throws -> R {
        let encoded = try body.map { try StrictJSON.encode($0) }
        let session = makeSession()
        defer { session.finishTasksAndInvalidate() }
        let (data, response) = try await session.data(for: request(method, path, token: token, body: encoded))
        let status = (response as? HTTPURLResponse)?.statusCode ?? 0
        guard status == expect else { throw RobAirError.relay(status) }
        return try StrictJSON.decode(R.self, from: data)
    }

    private func callNoContent(_ method: String, _ path: String, token: String) async throws {
        let session = makeSession()
        defer { session.finishTasksAndInvalidate() }
        let (_, response) = try await session.data(for: request(method, path, token: token, body: nil))
        let status = (response as? HTTPURLResponse)?.statusCode ?? 0
        guard status == 204 || status == 404 else { throw RobAirError.relay(status) }   // 404 : déjà supprimé
    }
}
#endif
