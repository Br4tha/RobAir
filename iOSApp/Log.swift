// Log.swift (iPhone)
// Règle de revue : jamais de print(). Logger avec confidentialité : seuls les messages
// explicitement marqués `privacy: .public` apparaissent en clair, et ils ne contiennent JAMAIS
// de clé, jeton, nonce, défi, signature ni RSSI (menace I2).

import os

enum Log {
    static let app = Logger(subsystem: "robair.ios", category: "app")
    static let ble = Logger(subsystem: "robair.ios", category: "ble")
    static let net = Logger(subsystem: "robair.ios", category: "network")
}
