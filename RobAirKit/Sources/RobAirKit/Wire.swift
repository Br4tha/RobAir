// Wire.swift
// Rôle : découpage du flux TCP en trames et encodage des messages en clair (appairage, handshake).
// Format d'une trame : [longueur u32 big-endian][corps]
// Corps en clair     : [version u8][type u8][JSON]
// Corps chiffré      : [version u8][type u8][compteur u64][chiffré][tag 16]   (voir Record.swift)
// Menaces : T3 (entrées malformées), D2 (trames géantes).

import Foundation

public enum MessageType: UInt8 {
    // En clair (avant l'établissement de la session)
    case pairRequest = 0x01
    case pairResult = 0x02
    case clientHello = 0x10
    case serverHello = 0x11
    case clientFinish = 0x12
    // Chiffrés (uniquement après le handshake)
    case status = 0x20
    case alert = 0x21
    case sensitiveEvent = 0x22
    case ack = 0x23

    /// SÉCURITÉ : un type « chiffré » n'est jamais accepté en clair, et inversement.
    public var isEncrypted: Bool { rawValue >= 0x20 }
}

public enum RobAirJSON {
    public static func encode<T: Encodable>(_ value: T) throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        return try encoder.encode(value)
    }

    public static func decode<T: Decodable>(_ type: T.Type, from data: Data) throws -> T {
        guard data.count <= RobAirConstants.maxFrameSize else { throw RobAirError.frameTooLarge }
        do {
            return try JSONDecoder().decode(type, from: data)
        } catch {
            throw RobAirError.malformed(String(describing: T.self))
        }
    }
}

public enum Wire {
    /// Ajoute le préfixe de longueur.
    public static func frame(_ body: Data) throws -> Data {
        guard !body.isEmpty, body.count <= RobAirConstants.maxFrameSize else {
            throw RobAirError.frameTooLarge
        }
        var out = Data()
        out.appendUInt32BE(UInt32(body.count))
        out.append(body)
        return out
    }

    /// Trame complète pour un message en clair encodé en JSON.
    public static func plaintextFrame<T: Encodable>(_ type: MessageType, _ value: T) throws -> Data {
        guard !type.isEncrypted else { throw RobAirError.unexpectedMessage }
        var body = Data([RobAirConstants.protocolVersion, type.rawValue])
        body.append(try RobAirJSON.encode(value))
        return try frame(body)
    }

    /// Lit la version et le type d'un corps de trame (en clair ou chiffré).
    public static func messageType(of body: Data) throws -> MessageType {
        guard body.count >= 2 else { throw RobAirError.malformed("header") }
        guard body.byte(at: 0) == RobAirConstants.protocolVersion else { throw RobAirError.unsupportedVersion }
        guard let type = MessageType(rawValue: body.byte(at: 1)) else { throw RobAirError.unexpectedMessage }
        return type
    }

    /// Décode un message en clair en vérifiant qu'il est bien du type attendu à cette étape.
    public static func decodePlaintext<T: Decodable>(_ body: Data, expected: MessageType, as: T.Type) throws -> T {
        let type = try messageType(of: body)
        guard type == expected, !type.isEncrypted else { throw RobAirError.unexpectedMessage }
        return try RobAirJSON.decode(T.self, from: body.bytes(2..<body.count))
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
            // SÉCURITÉ : on rejette AVANT d'attendre/allouer quoi que ce soit (menace D2).
            guard length > 0 else { buffer.removeAll(); throw RobAirError.malformed("length") }
            guard length <= RobAirConstants.maxFrameSize else { buffer.removeAll(); throw RobAirError.frameTooLarge }
            guard buffer.count >= 4 + length else { break }
            frames.append(buffer.bytes(4..<(4 + length)))
            buffer = buffer.bytes((4 + length)..<buffer.count)
        }
        return frames
    }
}
