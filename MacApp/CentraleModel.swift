// CentraleModel.swift (Mac)
// Rôle : chef d'orchestre de la centrale (J1 §2.2) : appairage, supervision, télémétrie (locale et relais),
// défis Mac → iPhone (§3.7), autorité de déverrouillage de secours (§3.8), rotation de K_enc_Mac, journal.
// Fail-safe côté Mac : sans message valide récent (30 s) ni session, l'état est « NON VÉRIFIÉ » —
// jamais « tout va bien » par défaut. L'alerte du Mac ne se termine que par une preuve de l'iPhone
// (défi « fin d'alerte » signé après Face ID) ou par un acquittement de l'opérateur, journalisé comme tel.

import Combine
import os
import SwiftUI
import AppKit
import CoreLocation
import CryptoKit
import LocalAuthentication
import RobAirKit

enum CentraleDisplay: Equatable {
    case notPaired, unverified, disarmed, armed, alert

    var title: String {
        switch self {
        case .notPaired: return "AUCUN IPHONE APPAIRÉ"
        case .unverified: return "NON VÉRIFIÉ"
        case .disarmed: return "DÉSARMÉ"
        case .armed: return "ARMÉ · balise présente"
        case .alert: return "ALERTE · VOL PROBABLE"
        }
    }

    var color: Color {
        switch self {
        case .notPaired, .disarmed: return .gray
        case .unverified: return .orange
        case .armed: return .green
        case .alert: return .red
        }
    }

    var symbol: String {
        switch self {
        case .notPaired: return "iphone.slash"
        case .unverified: return "questionmark.diamond.fill"
        case .disarmed: return "shield.slash"
        case .armed: return "lock.shield.fill"
        case .alert: return "exclamationmark.triangle.fill"
        }
    }
}

struct TelemetryPoint: Identifiable, Equatable {
    let id: UInt64
    let coordinate: CLLocationCoordinate2D
    let accuracy: Double?
    let date: Date
    let trigger: TelemetryTrigger
    let via: String

    static func == (a: TelemetryPoint, b: TelemetryPoint) -> Bool { a.id == b.id }
}

struct PendingPairing {
    let fingerprint: String
    let request: PairingRequest
    let invitation: PairingInvitation
    let connection: ServerConnection
}

struct PendingEmergency {
    let request: EmergencyRequest
    let connection: ServerConnection?   // nil si la demande a été lue par QR code
}

final class CentraleModel: ObservableObject {
    @Published private(set) var display: CentraleDisplay = .notPaired
    @Published private(set) var paired: PairedDevice?
    @Published private(set) var lastStatus: StatusPayload?
    @Published private(set) var lastSeen: Date?
    @Published private(set) var sessionActive = false
    @Published private(set) var alertActive = false
    @Published private(set) var lastTrigger: TelemetryTrigger?
    @Published private(set) var points: [TelemetryPoint] = []
    @Published private(set) var entries: [JournalEntry] = []
    @Published private(set) var integrity: EventJournal.Integrity?
    @Published private(set) var keyStorage = ""
    @Published private(set) var serviceName = ""
    @Published private(set) var encryptionEpoch: UInt32?
    @Published private(set) var invitation: PairingInvitation?
    @Published private(set) var pendingPairing: PendingPairing?
    @Published private(set) var pendingEmergency: PendingEmergency?
    @Published private(set) var emergencyGrantQR: String?
    @Published private(set) var pendingChallenge: ChallengeAction?
    @Published private(set) var operatorUnlockedUntil: Date?
    @Published private(set) var relaySettings: RelaySettings?
    @Published private(set) var relayStatus = "Non configuré"
    @Published var errorMessage: String?

    private var identity: MacIdentity?
    private var keyring = EncryptionKeyring()
    private var server: ChannelServer?
    private var journal: JournalStore?
    private let pairedStore = PairedDeviceStore()
    private let relayStore = RelaySettingsStore()
    private let issuer = ChallengeIssuer()
    private var operatorContext: LAContext?
    private var lastRejectionLogged = Date.distantPast
    private var emergencyRequests: [Date] = []
    private var timer: Timer?
    private var relayTimer: Timer?

    init() {
        boot()
        timer = Timer.scheduledTimer(withTimeInterval: 1, repeats: true) { [weak self] _ in self?.tick() }
        relayTimer = Timer.scheduledTimer(withTimeInterval: RobAirConstants.relayPollInterval, repeats: true) { [weak self] _ in
            guard let self, self.alertActive else { return }   // §2.2 : interrogation toutes les 30 s pendant une alerte
            self.pollRelay()
        }
    }

    private func boot() {
        do {
            let identity = try MacIdentity.loadOrCreate()
            self.identity = identity
            journal = try JournalStore()
            keyStorage = identity.storageDescription
            serviceName = "RobAir-" + DeviceID.short(identity.macID)
            paired = pairedStore.load()
            relaySettings = relayStore.load()
            encryptionEpoch = keyring.current?.epoch

            let server = ChannelServer(macID: identity.macID)
            server.delegate = self
            server.pairedIPhoneKey = try? paired?.identity()
            try server.start(serviceName: serviceName)
            self.server = server
        } catch {
            errorMessage = "Initialisation impossible : \(error.localizedDescription)"
        }
        refreshRelayStatus()
        refreshJournal()
        recomputeDisplay()
        if paired?.mailbox != nil { pollRelay() }   // des alertes ont pu arriver pendant que le Mac était éteint
    }

    // MARK: - Session opérateur (Touch ID)

    var isOperatorUnlocked: Bool { operatorContext != nil && (operatorUnlockedUntil ?? .distantPast) > Date() }

    /// Touch ID une fois → la centrale accepte les sessions de l'iPhone pendant 30 min.
    /// Profite de ce Touch ID pour faire la rotation hebdomadaire de K_enc_Mac si elle est due.
    func unlockCentrale() {
        Task { @MainActor in
            guard let identity, let context = await OperatorAuth.authenticate("Déverrouiller la centrale RobAir") else { return }
            operatorContext = context
            operatorUnlockedUntil = Date().addingTimeInterval(30 * 60)
            if keyring.rotationDue { rotateEncryptionKey(signer: try? identity.signer(context: context)) }
        }
    }

    func lockCentrale() {
        operatorContext?.invalidate()
        operatorContext = nil
        operatorUnlockedUntil = nil
    }

    private func rotateEncryptionKey(signer: SigningIdentity?) {
        guard let signer, let signed = try? keyring.rotate(signer: signer) else {
            errorMessage = "Rotation de la clé de chiffrement impossible."
            return
        }
        encryptionEpoch = signed.epoch
        journal?.append(.keyRotation, device: "-", detail: "Nouvelle clé de chiffrement HPKE (époque \(signed.epoch)), signée par la clé maîtresse")
        server?.active?.send(.encryptionKeyUpdate, signed)
        refreshJournal()
    }

    // MARK: - Appairage (§3.2)

    func beginPairing() {
        guard let identity else { return }
        guard isOperatorUnlocked, let encryption = keyring.current?.signed else {
            errorMessage = "Déverrouillez d'abord la centrale (Touch ID) : une clé de chiffrement est nécessaire."
            return
        }
        let session = PairingSession(serviceName: serviceName, macIdentityKey: identity.publicKey,
                                     encryptionKey: encryption, relay: relaySettings?.info)
        server?.pairingSession = session
        invitation = session.invitation
    }

    func cancelPairing() {
        if let pending = pendingPairing { pending.connection.completePairing(PairingResult(accepted: false, signature: Data())) }
        pendingPairing = nil
        invitation = nil
        server?.pairingSession = nil
    }

    /// L'opérateur a comparé l'empreinte. Accepter exige un Touch ID FRAIS (signature de la confirmation).
    func confirmPairing(_ accepted: Bool) {
        guard let pending = pendingPairing, let identity else { return }
        guard accepted else {
            journal?.append(.anomaly, device: "-", detail: "Appairage refusé par l'opérateur (empreintes différentes ?)")
            cancelPairing()
            refreshJournal()
            return
        }
        Task { @MainActor in
            guard let context = await OperatorAuth.authenticate("Confirmer l'appairage de l'iPhone") else { return }
            do {
                let result = try PairingCrypto.makeResult(accepted: true, request: pending.request, invitation: pending.invitation,
                                                          macIdentity: identity.signer(context: context))
                if let old = paired { closeMailbox(of: old) }
                let device = PairedDevice(identityKey: pending.request.identityKey, telemetryKey: pending.request.telemetryKey,
                                          pairedAtMs: Date().millisecondsSince1970)
                try pairedStore.save(device)
                paired = device
                points = []
                alertActive = false
                server?.pairedIPhoneKey = try device.identity()
                server?.active?.close("nouvel appairage")
                lastStatus = nil
                lastSeen = nil
                journal?.append(.paired, device: device.shortName, detail: "Appairage confirmé par l'opérateur (empreinte \(pending.fingerprint))")
                pending.connection.completePairing(result)
                createMailbox()
            } catch {
                errorMessage = "Appairage impossible : \(error.localizedDescription)"
            }
            pendingPairing = nil
            invitation = nil
            server?.pairingSession = nil
            refreshJournal()
            recomputeDisplay()
        }
    }

    func forgetIPhone() {
        guard let device = paired else { return }
        closeMailbox(of: device)
        server?.active?.close("iPhone oublié")
        pairedStore.wipe()
        server?.pairedIPhoneKey = nil
        paired = nil
        points = []
        alertActive = false
        journal?.append(.unpaired, device: device.shortName, detail: "iPhone oublié par l'opérateur")
        refreshJournal()
        recomputeDisplay()
    }

    // MARK: - Défis Mac → iPhone (§3.7)

    func request(_ action: ChallengeAction) {
        guard let active = server?.active else {
            errorMessage = "Aucune session avec l'iPhone : il doit être ouvert et connecté (Face ID)."
            return
        }
        let challenge = issuer.issue(action)
        active.send(.challenge, challenge)
        pendingChallenge = action
        DispatchQueue.main.asyncAfter(deadline: .now() + RobAirConstants.macChallengeLifetime) { [weak self] in
            if self?.pendingChallenge == action { self?.pendingChallenge = nil }
        }
    }

    /// Acquittement local, SANS preuve de l'iPhone : journalisé comme tel (non-répudiation de l'opérateur).
    func acknowledgeAlertLocally() {
        alertActive = false
        journal?.append(.alert, device: paired?.shortName ?? "-", detail: "Alerte acquittée par l'opérateur du Mac (sans preuve de l'iPhone)")
        refreshJournal()
        recomputeDisplay()
    }

    // MARK: - Déverrouillage de secours (§3.8)

    /// Demande lue par la webcam (QR code affiché par l'iPhone), quand le réseau local ne passe pas.
    func receiveEmergency(qrText: String) {
        do {
            let request = try QRPayload.decode(qrText, prefix: QRPayload.emergencyRequestPrefix, as: EmergencyRequest.self)
            try acceptEmergencyRequest(request, connection: nil)
        } catch {
            errorMessage = "QR code de secours invalide."
        }
    }

    private func acceptEmergencyRequest(_ request: EmergencyRequest, connection: ServerConnection?) throws {
        guard let paired, request.iphoneID == paired.iphoneID else { throw RobAirError.unknownDevice }
        emergencyRequests = emergencyRequests.filter { Date().timeIntervalSince($0) < 60 } + [Date()]
        guard emergencyRequests.count <= 3, pendingEmergency == nil else { throw RobAirError.messageTooLarge }
        pendingEmergency = PendingEmergency(request: request, connection: connection)
        emergencyGrantQR = nil
        NSSound.beep()
    }

    /// L'opérateur vérifie le code à 6 chiffres, puis s'authentifie : Touch ID FRAIS à chaque fois.
    func grantEmergency() {
        guard let pending = pendingEmergency, let identity, let paired else { return }
        Task { @MainActor in
            guard let context = await OperatorAuth.authenticate("Autoriser le déverrouillage de secours de l'iPhone") else { return }
            do {
                let grant = try EmergencyCrypto.grant(pending.request, pairedIPhoneID: paired.iphoneID, signer: identity.signer(context: context))
                pending.connection?.completeEmergency(grant)
                emergencyGrantQR = try QRPayload.encode(grant, prefix: QRPayload.emergencyGrantPrefix)
                journal?.append(.emergencyUnlock, device: paired.shortName,
                                detail: "Déverrouillage de secours accordé (code \(pending.request.shortCode))", evidence: grant.signature)
            } catch {
                errorMessage = "Déverrouillage de secours impossible : \(error.localizedDescription)"
            }
            refreshJournal()
        }
    }

    func dismissEmergency() {
        if pendingEmergency != nil, emergencyGrantQR == nil {
            journal?.append(.anomaly, device: paired?.shortName ?? "-", detail: "Demande de déverrouillage de secours refusée par l'opérateur")
            refreshJournal()
        }
        pendingEmergency?.connection?.close("secours refusé")
        pendingEmergency = nil
        emergencyGrantQR = nil
    }

    // MARK: - Télémétrie (§3.5)

    /// Déchiffre, vérifie et enregistre. Renvoie l'ackSecret (preuve de réception pour l'iPhone).
    private func processTelemetry(_ envelope: TelemetryEnvelope, via: String) throws -> Data {
        guard let identity, var device = paired, envelope.iphoneID == device.iphoneID else { throw RobAirError.unknownDevice }
        let payload = try TelemetryCrypto.open(envelope, privateKey: keyring.privateKey(epoch: envelope.epoch),
                                               macID: identity.macID, telemetryKey: device.telemetryPublicKey())
        switch device.telemetry.accept(payload) {
        case .accepted:
            break
        case .duplicate:
            return payload.ackSecret   // doublon : accusé quand même
        case .outOfWindow:
            // Faille RT-1 corrigée : authentique (signature K_tel vérifiée) mais hors fenêtre.
            // On l'acquitte pour débloquer la file de l'iPhone, sans l'afficher comme position actuelle.
            logRejection("position authentique mais hors fenêtre de 72 h (seq \(payload.seq)) : acquittée, non affichée")
            return payload.ackSecret
        }
        try pairedStore.save(device)
        paired = device

        var detail = "\(payload.trigger.label) · via \(via)"
        // Position restée en file : on affiche sa date RÉELLE, pas l'heure de réception (J2 écart 4).
        let sentAt = Date(millisecondsSince1970: payload.timestampMs)
        if Date().timeIntervalSince(sentAt) > 60 {
            detail += " · émise le \(sentAt.formatted(date: .abbreviated, time: .shortened)) (différée)"
        }
        if let lat = payload.lat, let lon = payload.lon {
            detail += String(format: " · position %.5f, %.5f", lat, lon)
            if let accuracy = payload.accuracy { detail += String(format: " (±%.0f m)", accuracy) }
            points.append(TelemetryPoint(id: payload.seq, coordinate: CLLocationCoordinate2D(latitude: lat, longitude: lon),
                                         accuracy: payload.accuracy, date: Date(millisecondsSince1970: payload.timestampMs),
                                         trigger: payload.trigger, via: via))
        } else {
            detail += " · position pas encore connue"
        }
        if let battery = payload.battery { detail += String(format: " · batterie %.0f %%", battery * 100) }

        // Toute télémétrie réelle (pas un test) signifie que l'iPhone est en alerte.
        let startsAlert = payload.trigger != .test && !alertActive
        if startsAlert {
            alertActive = true
            NSSound.beep()
        }
        if payload.trigger != .periodic { lastTrigger = payload.trigger }
        journal?.append(startsAlert ? .alert : .telemetry, device: device.shortName, detail: detail)
        lastSeen = Date()
        refreshJournal()
        recomputeDisplay()
        return payload.ackSecret
    }

    // MARK: - Relais aveugle (extension P2)

    func saveRelaySettings(url: String, pin: String, enrollmentKey: String) {
        let settings = RelaySettings(url: url.trimmingCharacters(in: .whitespaces), pin: pin.trimmingCharacters(in: .whitespaces),
                                     enrollmentKey: enrollmentKey.trimmingCharacters(in: .whitespaces))
        do {
            try settings.info.validate()
            try RelayAPI.validateIdentifier(settings.enrollmentKey, field: "enrollmentKey")
            try relayStore.save(settings)
            relaySettings = settings
            journal?.append(.relay, device: "-", detail: "Relais configuré : \(settings.url)")
            refreshJournal()
            refreshRelayStatus()
            if paired != nil, paired?.mailbox == nil { createMailbox() }
        } catch {
            errorMessage = "Réglages du relais invalides (URL https, pin base64 de 32 octets, clé d'enrôlement)."
        }
    }

    func createMailbox() {
        guard let settings = relaySettings, let client = try? RelayClient(info: settings.info) else { return }
        Task { @MainActor in
            do {
                let created = try await client.createMailbox(enrollmentKey: settings.enrollmentKey)
                guard var device = paired else { return }
                device.mailbox = created
                try pairedStore.save(device)
                paired = device
                journal?.append(.relay, device: device.shortName, detail: "Boîte aux lettres créée sur le relais")
                // §3.2 étape 4 : le jeton d'ÉCRITURE part vers l'iPhone par le canal chiffré ; le Mac garde la lecture.
                server?.active?.send(.mailboxConfig, MailboxConfig(mailboxID: created.mailboxID, writeToken: created.writeToken))
            } catch {
                journal?.append(.anomaly, device: "-", detail: "Création de la boîte sur le relais impossible (\(error.localizedDescription))")
            }
            refreshJournal()
            refreshRelayStatus()
        }
    }

    func pollRelay() {
        guard let settings = relaySettings, let mailbox = paired?.mailbox, let client = try? RelayClient(info: settings.info) else { return }
        Task { @MainActor in
            do {
                let messages = try await client.fetch(mailboxID: mailbox.mailboxID, readToken: mailbox.readToken)
                for message in messages {
                    do {
                        _ = try processTelemetry(TelemetryEnvelope.parse(message.payload), via: "relais")
                    } catch {
                        logRejection("message du relais refusé (\(error.localizedDescription))")
                    }
                    // Acquitté (ou invalide) → supprimé du relais.
                    try? await client.delete(messageID: message.messageID, mailboxID: mailbox.mailboxID, readToken: mailbox.readToken)
                }
                relayStatus = "Interrogé à \(Date().formatted(date: .omitted, time: .standard)) · \(messages.count) message(s)"
            } catch {
                relayStatus = "Injoignable (\(error.localizedDescription))"
            }
        }
    }

    private func closeMailbox(of device: PairedDevice) {
        guard let mailbox = device.mailbox, let settings = relaySettings, let client = try? RelayClient(info: settings.info) else { return }
        Task { try? await client.closeMailbox(mailboxID: mailbox.mailboxID, readToken: mailbox.readToken) }
    }

    private func refreshRelayStatus() {
        guard let settings = relaySettings else { relayStatus = "Non configuré"; return }
        relayStatus = paired?.mailbox != nil ? "Boîte active sur \(settings.url)" : "Configuré, pas encore de boîte"
    }

    // MARK: - Journal

    func verifyJournal() { integrity = journal?.verify() }

    private func refreshJournal() {
        entries = Array((journal?.journal.entries ?? []).reversed())
        integrity = nil
    }

    private func logRejection(_ reason: String) {
        // Au plus une entrée toutes les 5 s : une inondation ne remplit pas le journal (déni de service).
        guard Date().timeIntervalSince(lastRejectionLogged) > 5 else { return }
        lastRejectionLogged = Date()
        journal?.append(.anomaly, device: "-", detail: "Rejeté : \(reason)")
        refreshJournal()
    }

    // MARK: - Réinitialisation (fin de séance sur un Mac prêté)

    func resetCentrale() {
        cancelPairing()
        if let device = paired { closeMailbox(of: device) }
        lockCentrale()
        server?.stop()
        MacIdentity.wipe()
        keyring.wipe()
        pairedStore.wipe()
        relayStore.wipe()
        JournalStore.wipe()
        identity = nil
        server = nil
        journal = nil
        paired = nil
        points = []
        lastStatus = nil
        lastSeen = nil
        sessionActive = false
        alertActive = false
        boot()
        journal?.append(.reset, device: "-", detail: "Centrale réinitialisée : nouvelles clés, ancien journal effacé")
        refreshJournal()
    }

    // MARK: - État affiché

    private func tick() {
        if let until = operatorUnlockedUntil, until <= Date() { lockCentrale() }
        recomputeDisplay()
    }

    private func recomputeDisplay() {
        let newDisplay: CentraleDisplay
        if paired == nil {
            newDisplay = .notPaired
        } else if alertActive {
            newDisplay = .alert
        } else if let status = lastStatus, let seen = lastSeen, sessionActive,
                  Date().timeIntervalSince(seen) < RobAirConstants.statusInterval * 3 {
            switch status.protectionState {
            case .alert: newDisplay = .alert
            case .armed: newDisplay = status.beacon == .present ? .armed : .unverified
            case .disarmed: newDisplay = .disarmed
            }
        } else {
            newDisplay = .unverified
        }
        if newDisplay != display {
            if newDisplay == .alert || (display == .armed && newDisplay == .unverified) { NSSound.beep() }
            display = newDisplay
        }
    }
}

// MARK: - Messages reçus de l'iPhone

extension CentraleModel: ChannelServerDelegate {
    func serverReceivedPairing(_ request: PairingRequest, from connection: ServerConnection) {
        guard let invitation else { return }
        pendingPairing = PendingPairing(fingerprint: PairingCrypto.shortFingerprint(invitation: invitation, request: request),
                                        request: request, invitation: invitation, connection: connection)
    }

    func serverHandshakeSigner() -> SigningIdentity? {
        guard isOperatorUnlocked, let operatorContext, let identity else {
            logRejection("session refusée : centrale verrouillée (Touch ID requis sur le Mac)")
            return nil
        }
        return try? identity.signer(context: operatorContext)
    }

    func serverSessionEstablished(_ connection: ServerConnection) {
        sessionActive = true
        journal?.append(.sessionOpened, device: paired?.shortName ?? "?", detail: "Session chiffrée ouverte (Face ID sur l'iPhone)")
        if let signed = keyring.current?.signed { connection.send(.encryptionKeyUpdate, signed) }
        if let mailbox = paired?.mailbox {
            connection.send(.mailboxConfig, MailboxConfig(mailboxID: mailbox.mailboxID, writeToken: mailbox.writeToken))
        }
        refreshJournal()
        recomputeDisplay()
    }

    func serverSessionEnded(_ connection: ServerConnection, reason: String) {
        sessionActive = false
        journal?.append(.sessionClosed, device: paired?.shortName ?? "?", detail: "Session fermée : \(reason)")
        refreshJournal()
        recomputeDisplay()
    }

    func serverRejected(reason: String) { logRejection(reason) }

    func serverReceivedTelemetry(_ envelope: TelemetryEnvelope, via: String) throws -> Data {
        try processTelemetry(envelope, via: via)
    }

    func serverReceivedEmergency(_ request: EmergencyRequest, from connection: ServerConnection) throws {
        try acceptEmergencyRequest(request, connection: connection)
    }

    func server(_ connection: ServerConnection, received type: MessageType, payload: Data) throws {
        guard let paired, let identity else { throw RobAirError.unknownDevice }
        switch type {
        case .status:
            let status = try StrictJSON.decode(StatusPayload.self, from: payload)
            if status != lastStatus {
                journal?.append(.status, device: paired.shortName,
                                detail: "\(status.protectionState.label) · balise \(status.beacon.label) · coffre \(status.vaultOpen ? "ouvert" : "fermé")")
            }
            if status.protectionState.isAlert { alertActive = true }
            lastStatus = status
            lastSeen = Date()

        case .challengeResponse:
            let response = try StrictJSON.decode(ChallengeResponse.self, from: payload)
            // SÉCURITÉ : signature K_id_iPhone (Face ID), défi à usage unique, action et identifiants liés.
            let action = try issuer.verify(response, iphoneKey: paired.identity(), macID: identity.macID)
            pendingChallenge = nil
            journal?.append(.challenge, device: paired.shortName,
                            detail: "\(action.label) : confirmé par Face ID sur l'iPhone (signature vérifiée)", evidence: response.signature)
            if action == .endAlert || action == .disarm { alertActive = false }
            lastSeen = Date()

        default:
            throw RobAirError.unexpectedMessage
        }
        refreshJournal()
        recomputeDisplay()
    }
}
