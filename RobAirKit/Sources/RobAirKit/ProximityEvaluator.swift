// ProximityEvaluator.swift
// Rôle : décide « proche / éloigné » à partir des signaux BLE. Logique pure, sans CoreBluetooth → testable.
// Règle (J2 §6) : éloigné dès que l'une de ces conditions est vraie :
//   1. déconnexion BLE
//   2. défi sans réponse valide dans les temps
//   3. RSSI moyen sous le seuil (avec hystérésis pour éviter le clignotement)
// Fail-safe : sans preuve valide récente, on n'est JAMAIS « proche ».

import Foundation

public struct ProximityEvaluator {
    public struct Config {
        public var rssiWindow = RobAirConstants.rssiWindow
        public var leaveThreshold = RobAirConstants.rssiLeaveThreshold
        public var enterThreshold = RobAirConstants.rssiEnterThreshold
        public var proofMaxAge = RobAirConstants.proofMaxAge
        public var challengeTimeout = RobAirConstants.challengeTimeout
        public init() {}
    }

    public private(set) var state: ProximityState = .unknown
    public private(set) var lastAwayReason: AlertReason?
    private var connected = false
    private var samples: [Int] = []
    private var lastValidProof: Date?
    private let config: Config

    public init(config: Config = Config()) { self.config = config }

    @discardableResult
    public mutating func connectionChanged(_ isConnected: Bool, now: Date) -> ProximityState {
        connected = isConnected
        guard isConnected else {
            samples.removeAll()
            lastValidProof = nil
            return transition(to: .away, reason: .bleDisconnected)
        }
        return state   // connecté ne suffit pas : il faut une preuve
    }

    @discardableResult
    public mutating func recordRSSI(_ rssi: Int, now: Date) -> ProximityState {
        guard rssi < 0 else { return state }   // CoreBluetooth renvoie 127 quand la mesure est indisponible
        samples.append(rssi)
        if samples.count > config.rssiWindow { samples.removeFirst() }
        return evaluate(now: now)
    }

    @discardableResult
    public mutating func recordProof(valid: Bool, latency: TimeInterval, now: Date) -> ProximityState {
        guard valid, latency <= config.challengeTimeout else {
            lastValidProof = nil
            return transition(to: .away, reason: .proofFailed)
        }
        lastValidProof = now
        return evaluate(now: now)
    }

    /// À appeler régulièrement : fait expirer une preuve trop ancienne.
    @discardableResult
    public mutating func tick(now: Date) -> ProximityState {
        evaluate(now: now)
    }

    private mutating func evaluate(now: Date) -> ProximityState {
        guard connected else { return transition(to: .away, reason: .bleDisconnected) }
        guard let proof = lastValidProof, now.timeIntervalSince(proof) <= config.proofMaxAge else {
            return state == .near ? transition(to: .away, reason: .proofFailed) : state
        }
        guard !samples.isEmpty else { return state }
        let average = samples.reduce(0, +) / samples.count
        // Hystérésis : pour RESTER proche il suffit de -80, pour le DEVENIR il faut -70.
        let threshold = state == .near ? config.leaveThreshold : config.enterThreshold
        return average >= threshold
            ? transition(to: .near, reason: nil)
            : transition(to: .away, reason: .signalWeak)
    }

    private mutating func transition(to newState: ProximityState, reason: AlertReason?) -> ProximityState {
        if newState == .away, state != .away { lastAwayReason = reason }
        state = newState
        return state
    }
}
