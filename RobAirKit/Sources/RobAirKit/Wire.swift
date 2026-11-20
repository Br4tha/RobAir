// Wire.swift
// Rôle : découpage du flux TCP en trames + décodage STRICT des messages (§3.4).
// Trame         : [longueur u32 big-endian][corps]
// Corps en clair : [version u8][type u8][JSON]
// Corps chiffré  : voir Record.swift
// Validation stricte (§3.4) :
//   - 4 Ko maximum, rejet AVANT allocation ;
//   - décodage typé (Codable) puis contrôle des bornes (validate()) ;
//   - TOUT CHAMP INCONNU FAIT REJETER LE MESSAGE (JSONDecoder, lui, les ignore par défaut).
// Menaces : T3 (entrées malformées), D2 (trames géantes).

import Foundation

public enum MessageType: UInt8, CaseIterable {
    // En clair : avant la session, ou contenu déjà protégé autrement (signé et/ou chiffré HPKE)
    case pairRequest = 0x01
    case pairResult = 0x02
    case clientHello = 0x10
    case serverHello = 0x11
    case clientFinish = 0x12
    case telemetry = 0x30          // enveloppe HPKE + signature K_tel (§3.5)
    case telemetryAck = 0x31
    case emergencyRequest = 0x40   // défi de l'iPhone, rien de secret (§3.8)
    case emergencyGrant = 0x41     // réponse signée par K_id_Mac
    // Chiffrés AES-GCM : uniquement dans une session établie (§3.3)
    case status = 0x20
    case challenge = 0x21
    case challengeResponse = 0x22
    case mailboxConfig = 0x23
    case encryptionKeyUpdate = 0x24
    case rekey = 0x25
    case rekeyAck = 0x26

    /// SÉCURITÉ : un type « chiffré » n'est jamais accepté en clair, et inversement.
    public var isEncrypted: Bool { (0x20...0x2F).contains(rawValue) }
}

/// Un message du protocole : décodé strictement, puis validé (bornes, tailles).
public protocol WireMessage: Codable {
    func validate() throws
}

public extension WireMessage {
    func validate() throws {}
}

public enum StrictJSON {
    public static func encode<T: Encodable>(_ value: T) throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        return try encoder.encode(value)
    }

    /// Décode `data` en `T` et REJETTE tout champ que `T` ne déclare pas, à tous les niveaux.
    public static func decode<T: WireMessage>(_ type: T.Type, from data: Data) throws -> T {
        guard data.count <= RobAirConstants.maxMessageSize else { throw RobAirError.messageTooLarge }
        let value: T
        let tree: Any
        do {
            tree = try JSONSerialization.jsonObject(with: data)
            value = try JSONDecoder().decode(T.self, from: data)
        } catch {
            throw RobAirError.malformed(String(describing: T.self))
        }
        try checkKnownFields(json: tree, value: value, path: String(describing: T.self))
        try value.validate()
        return value
    }

    /// Compare récursivement les clés JSON aux propriétés de la structure décodée.
    /// Les noms de propriétés Swift sont les noms JSON (aucun CodingKeys personnalisé dans le protocole).
    static func checkKnownFields(json: Any, value: Any, path: String) throws {
        let mirror = Mirror(reflecting: value)
        if mirror.displayStyle == .optional {
            guard let wrapped = mirror.children.first?.value else { return }
            try checkKnownFields(json: json, value: wrapped, path: path)
            return
        }
        if let object = json as? [String: Any], mirror.displayStyle == .struct {
            var children: [String: Any] = [:]
            for child in mirror.children { if let label = child.label { children[label] = child.value } }
            for (key, sub) in object {
                guard let childValue = children[key] else { throw RobAirError.unknownField("\(path).\(key)") }
                try checkKnownFields(json: sub, value: childValue, path: "\(path).\(key)")
            }
        } else if let array = json as? [Any], let values = value as? [Any] {
            for (index, pair) in zip(array, values).enumerated() {
                try checkKnownFields(json: pair.0, value: pair.1, path: "\(path)[\(index)]")
            }
        }
    }
}

public enum Wire {
    /// Ajoute le préfixe de longueur.
    public static func frame(_ body: Data) throws -> Data {
        guard !body.isEmpty, body.count <= RobAirConstants.maxMessageSize else { throw RobAirError.messageTooLarge }
        var out = Data()
        out.appendUInt32BE(UInt32(body.count))
        out.append(body)
        return out
    }

    /// Trame complète pour un message en clair encodé en JSON.
    public static func plaintextFrame<T: WireMessage>(_ type: MessageType, _ value: T) throws -> Data {
        guard !type.isEncrypted else { throw RobAirError.unexpectedMessage }
        var body = Data([RobAirConstants.protocolVersion, type.rawValue])
        body.append(try StrictJSON.encode(value))
        return try frame(body)
    }

    /// Lit la version et le type d'un corps de trame (en clair ou chiffré).
    public static func messageType(of body: Data) throws -> MessageType {
        guard body.count >= 2 else { throw RobAirError.malformed("header") }
        guard body.byte(at: 0) == RobAirConstants.protocolVersion else { throw RobAirError.unsupportedVersion }
        guard let type = MessageType(rawValue: body.byte(at: 1)) else { throw RobAirError.unexpectedMessage }
        return type
    }

    /// Décode un message en clair en vérifiant qu'il est bien du type attendu.
    public static func decodePlaintext<T: WireMessage>(_ body: Data, expected: MessageType, as: T.Type) throws -> T {
        let type = try messageType(of: body)
        guard type == expected, !type.isEncrypted else { throw RobAirError.unexpectedMessage }
        return try StrictJSON.decode(T.self, from: body.bytes(2..<body.count))
    }
}

/// Reconstitue les trames à partir des morceaux reçus du réseau (TCP ne préserve pas les limites de messages).
public struct FrameDecoder {
    private var buffer = Data()

    public init() {}

    public mutating func append(_ chunk: Data) throws -> [Data] {
        buffer.append(chunk)
        var frames: [Data] = []
        while buffer.count >= 4 {
            let length = Int(buffer.readUInt32BE(at: 0))
            // SÉCURITÉ : on rejette AVANT d'attendre ou d'allouer quoi que ce soit (menace D2).
            guard length > 0 else { buffer.removeAll(); throw RobAirError.malformed("length") }
            guard length <= RobAirConstants.maxMessageSize else { buffer.removeAll(); throw RobAirError.messageTooLarge }
            guard buffer.count >= 4 + length else { break }
            frames.append(buffer.bytes(4..<(4 + length)))
            buffer = buffer.bytes((4 + length)..<buffer.count)
        }
        return frames
    }
}
