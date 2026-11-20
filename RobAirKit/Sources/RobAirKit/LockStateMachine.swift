// LockStateMachine.swift
// Rôle : machine à états du verrou de l'iPhone (J2 §7). Logique pure → testable.
// Principe « échouer en sécurité » : état initial = verrouillé ; tout événement inattendu = verrouillé.
// Le SEUL chemin vers « déverrouillé » : Face ID validé ET proximité prouvée.

import Foundation

public struct LockStateMachine {
    public enum Event {
        case unlockAuthorized(proximity: ProximityState)   // Face ID OK (vérifié par l'appelant)
        case proximityChanged(ProximityState)
        case backgroundElapsed(TimeInterval)
        case failure
        case manualLock
    }

    public private(set) var status: LockStatus = .locked

    public init() {}

    @discardableResult
    public mutating func handle(_ event: Event) -> LockStatus {
        switch event {
        case .unlockAuthorized(let proximity):
            status = proximity == .near ? .unlocked : .locked
        case .proximityChanged(let proximity):
            if proximity != .near { status = .locked }
        case .backgroundElapsed(let seconds):
            if seconds >= RobAirConstants.backgroundLockDelay { status = .locked }
        case .failure, .manualLock:
            status = .locked
        }
        return status
    }
}
