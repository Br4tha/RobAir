// Log.swift (Mac). Même règle que sur l'iPhone : aucun secret dans les logs, jamais de print().

import os

enum Log {
    static let app = Logger(subsystem: "robair.mac", category: "app")
    static let ble = Logger(subsystem: "robair.mac", category: "ble")
    static let net = Logger(subsystem: "robair.mac", category: "network")
}
