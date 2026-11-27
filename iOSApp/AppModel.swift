// AppModel.swift (iPhone, mode Capteur)
// Rôle : chef d'orchestre du capteur. Relie balise BLE, état de protection, coffre, télémétrie,
// session avec le Mac et déverrouillage de secours. Aucune primitive crypto ici : seulement des
// décisions, toutes « fail-safe » (dans le doute : alerte / verrouillage).
//
// Règles appliquées (J1 §1.2, §3.5, §3.7, §3.8 ; J2 §8) :
//   - armer exige la balise PRÉSENTE (preuve HMAC) ; l'état armé/alerte survit à un redémarrage ;
//   - armé + rupture → ALERTE : coffre fermé et effacé de la mémoire, session détruite, alarme,
//     première alerte envoyée IMMÉDIATEMENT (même sans position), puis positions toutes les 15 s ;
//   - sortir de l'alerte : Face ID, ou déverrouillage de secours signé par le Mac après 3 échecs ;
//   - après une levée de verrouillage : nouvelle session (nouveau handshake signé) ;
//   - le coffre exige TOUJOURS Face ID, et jamais en alerte ;
//   - changer la configuration de protection (oublier ou remplacer la balise, oublier la centrale)
//     exige d'être DÉSARMÉ et un Face ID frais (audit Red Team, faille RT-2).

import Combine
import os
import SwiftUI
import UIKit
import AudioToolbox
import UserNotifications
import LocalAuthentication
import CryptoKit
import RobAirKit

@MainActor
final class AppModel: ObservableObject {
    enum PairingPhase: Equatable {
        case idle
        case waitingForMac(fingerprint: String)
        case failed(String)
    }

    @Published private(set) var centrale: CentraleConfig?
    @Published private(set) var beaconPaired = false
    @Published private(set) var beacon: BeaconStatus = .unpaired
    @Published private(set) var protection: ProtectionState
    @Published private(set) var channel: ChannelClient.State = .idle
    @Published private(set) var pairingPhase: PairingPhase = .idle
    @Published private(set) var vaultOpen = false
    @Published var vaultText = ""
    @Published private(set) var pendingChallenge: MacChallenge?
    @Published private(set) var faceIDFailures = 0
    @Published private(set) var emergency: EmergencyUnlockSession?
    @Published private(set) var emergencyMessage: String?
    @Published private(set) var queuedTelemetry = 0
    @Published private(set) var lastDelivery: String?
    @Published var errorMessage: String?

    private let identity = DeviceIdentity()
    private let centraleStore = CentraleStore()
    private let beaconStore = BeaconKeyStore(service: "robair.ios.paired-beacon")
    private let stateStore = StateStore()
    private let vault = VaultStore()
    private let client = ChannelClient()
    private let location = LocationTracker()
    private let telemetry: TelemetrySender
    private var link: BeaconLink?
    private var machine: AlertStateMachine
    private var vaultKey: SymmetricKey?
    private var sessionContext: LAContext?
    private var statusTimer: Timer?
    private var alertTimer: Timer?
    private var watchdog: Timer?
    private var armedSince = Date()
    private var rewritingPasteboard = false

    init() {
        let restored = stateStore.loadProtection()
        machine = AlertStateMachine(state: restored)
        protection = restored
        telemetry = TelemetrySender(identity: identity, state: stateStore)
        telemetry.onQueueChange = { [weak self] count in self?.queuedTelemetry = count }
        telemetry.onDelivered = { [weak self] route in self?.lastDelivery = "Dernier envoi : \(route), \(Date().formatted(date: .omitted, time: .standard))" }
        queuedTelemetry = telemetry.queuedCount

        client.onStateChange = { [weak self] in self?.channel = $0 }
        client.onEstablished = { [weak self] in self?.sendStatus() }
        client.onChallenge = { [weak self] in self?.pendingChallenge = $0 }
        client.onMailbox = { [weak self] in self?.storeMailbox($0) }
        client.onEncryptionKey = { [weak self] in self?.storeEncryptionKey($0) }

        UIDevice.current.isBatteryMonitoringEnabled = true
        centrale = centraleStore.load()
        startBeaconLink()
        watchPasteboard()

        statusTimer = Timer.scheduledTimer(withTimeInterval: RobAirConstants.statusInterval, repeats: true) { [weak self] _ in
            Task { @MainActor in self?.sendStatus() }
        }
        // Chien de garde : armé mais balise jamais confirmée (ex. app relancée loin de la balise) → alerte.
        watchdog = Timer.scheduledTimer(withTimeInterval: 1, repeats: true) { [weak self] _ in
            Task { @MainActor in self?.checkArmedWithoutBeacon() }
        }
        if case .alert(let reason) = restored { resumeAlert(reason) }
        if restored == .armed { location.prepareForArming() }
    }

    var iphoneShortID: String { identity.iphoneID.map(DeviceID.short) ?? "-" }

    // MARK: - Appairage avec le Mac (§3.2)

    func startPairing(qrCode: String) {
        do {
            let invitation = try PairingInvitation.decode(qrCode: qrCode)   // format, signature K_enc, expiration
            client.stop()
            let keys = try identity.regenerate()                             // nouvelles K_id et K_tel
            let request = PairingCrypto.makeRequest(invitation: invitation, identityKey: keys.identity, telemetryKey: keys.telemetry)
            pairingPhase = .waitingForMac(fingerprint: PairingCrypto.shortFingerprint(invitation: invitation, request: request))
            client.pair(serviceName: invitation.serviceName, request: request) { [weak self] result in
                Task { @MainActor in self?.finishPairing(result, invitation: invitation, request: request) }
            }
        } catch {
            pairingPhase = .failed(error.localizedDescription)
        }
    }

    private func finishPairing(_ result: Result<PairingResult, Error>, invitation: PairingInvitation, request: PairingRequest) {
        guard case .success(let response) = result,
              PairingCrypto.verify(result: response, request: request, invitation: invitation) else {
            identity.wipe()
            if case .success(let response) = result, !response.accepted {
                pairingPhase = .failed("Appairage refusé sur le Mac (empreintes différentes ?).")
            } else {
                pairingPhase = .failed("Confirmation du Mac absente ou invalide.")
            }
            return
        }
        let config = CentraleConfig(macIdentityKey: invitation.macIdentityKey, macID: invitation.macID,
                                    serviceName: invitation.serviceName, encryptionKey: invitation.encryptionKey,
                                    relay: invitation.relay, mailbox: nil)
        do {
            try centraleStore.save(config)
        } catch {
            identity.wipe()
            pairingPhase = .failed("Enregistrement impossible.")
            return
        }
        centrale = config
        pairingPhase = .idle
        Log.app.info("Appairage avec la centrale terminé")
    }

    func resetPairingPhase() { pairingPhase = .idle }

    /// Faille RT-2 corrigée : avant, ce bouton désarmait SANS Face ID (contournement de « Désarmer »).
    func forgetCentrale() async {
        guard await authorizeConfigurationChange("Oublier la centrale") else { return }
        disarmImmediately()
        client.stop()
        closeVault(save: false)
        identity.wipe()
        centraleStore.wipe()
        vault.wipe()
        telemetry.clear()
        centrale = nil
    }

    // MARK: - Appairage de la balise (§3.9)

    func pairBeacon(qrText: String) async {
        // Remplacer la balise pendant la surveillance = la désactiver : même règle que « Désarmer ».
        guard await authorizeConfigurationChange("Changer de balise") else { return }
        do {
            let code = try BeaconPairingCode.parse(qrText: qrText)
            try beaconStore.save(code)
            startBeaconLink()
        } catch {
            errorMessage = "QR code de balise invalide."
        }
    }

    /// Faille RT-2 corrigée : avant, « Oublier la balise » désarmait SANS Face ID. Un tiers qui tenait
    /// le téléphone déverrouillé pouvait couper la surveillance en un geste, sans alerte.
    func forgetBeacon() async {
        guard await authorizeConfigurationChange("Oublier la balise") else { return }
        disarmImmediately()
        link?.stop()
        link = nil
        beaconStore.wipe()
        beaconPaired = false
        beacon = .unpaired
    }

    private func startBeaconLink() {
        link?.stop()
        guard let code = beaconStore.load() else {
            beaconPaired = false
            beacon = .unpaired
            return
        }
        beaconPaired = true
        let link = BeaconLink(code: code)
        link.onChange = { [weak self] state in Task { @MainActor in self?.beaconChanged(state) } }
        link.start()
        self.link = link
        beacon = .unknown
    }

    // MARK: - Session avec le Mac (§3.3)

    /// Face ID débloque K_id_iPhone pour signer le handshake. Le contexte sert aussi aux
    /// reconnexions tant que l'app est au premier plan.
    func connectToCentrale() async {
        guard let centrale, !protection.isAlert else { return }
        guard let context = await authenticate("Se connecter à la centrale") else { return }
        openSession(context: context, centrale: centrale)
    }

    private func openSession(context: LAContext, centrale: CentraleConfig) {
        do {
            sessionContext = context
            client.startSession(identity: try identity.loadIdentity(context: context), centrale: centrale)
        } catch {
            errorMessage = "Identité introuvable : refaites l'appairage."
        }
    }

    private func sendStatus() {
        client.send(.status, StatusPayload(state: protection, vaultOpen: vaultOpen, beacon: beacon))
    }

    private func storeMailbox(_ mailbox: MailboxConfig) {
        guard var config = centrale, config.mailbox != mailbox else { return }
        config.mailbox = mailbox
        if (try? centraleStore.save(config)) != nil { centrale = config }
    }

    /// Rotation hebdomadaire de K_enc_Mac : acceptée seulement si signée par la clé épinglée ET plus récente.
    private func storeEncryptionKey(_ key: SignedEncryptionKey) {
        guard var config = centrale, let macKey = try? config.macKey(), (try? key.verified(by: macKey)) != nil,
              key.isNewer(than: config.encryptionKey) else { return }
        config.encryptionKey = key
        if (try? centraleStore.save(config)) != nil { centrale = config }
    }

    // MARK: - Défi du Mac (§3.7)

    func respondToChallenge() async {
        guard let challenge = pendingChallenge, let centrale else { return }
        pendingChallenge = nil
        // Face ID À CHAQUE défi : c'est ce qui en fait une authentification forte.
        guard let context = await authenticate(challenge.action.label) else { return }
        do {
            let signer = try identity.loadIdentity(context: context)
            let response = try ChallengeCrypto.respond(to: challenge, signer: signer, macID: centrale.macID)
            guard client.send(.challengeResponse, response) else {
                errorMessage = "Centrale injoignable : réponse non envoyée."
                return
            }
            apply(machine.handle(.macAuthorized(challenge.action)))
        } catch {
            errorMessage = "Défi expiré ou signature impossible."
        }
    }

    func declineChallenge() { pendingChallenge = nil }

    // MARK: - Armement / désarmement

    func arm() {
        guard centrale != nil, let link else { return }
        guard link.state == .present else {
            errorMessage = "La balise doit être présente (preuve vérifiée) pour armer."
            return
        }
        location.prepareForArming()   // autorisation demandée AU BON MOMENT (moindre privilège)
        UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound]) { _, _ in }
        armedSince = Date()
        apply(machine.handle(.arm(beacon: link.state)))
    }

    func disarm() async {
        guard protection == .armed, await authenticate("Désarmer RobAir") != nil else { return }
        apply(machine.handle(.ownerAuthenticated))
    }

    private func disarmImmediately() {
        machine = AlertStateMachine()
        apply(.disarmed)
    }

    private func beaconChanged(_ state: RuptureDetector.State) {
        beacon = state.beaconStatus
        apply(machine.handle(.beaconChanged(state)))
    }

    private func checkArmedWithoutBeacon() {
        guard protection == .armed, link?.state != .present, Date().timeIntervalSince(armedSince) > 20 else { return }
        if link?.state == .unknown || link == nil { apply(machine.handle(.failure)) }
    }

    /// Point unique de changement d'état : persiste, déclenche ou termine l'alerte, prévient le Mac.
    private func apply(_ new: ProtectionState) {
        let old = protection
        guard new != old else { return }
        protection = new
        stateStore.saveProtection(new)
        if case .alert(let reason) = new, !old.isAlert { enterAlert(reason) }
        if old.isAlert, !new.isAlert { leaveAlert() }
        if new == .disarmed { location.release() }
        if new == .armed { armedSince = Date() }
        sendStatus()
    }

    // MARK: - Alerte (§3.5)

    private func enterAlert(_ reason: TelemetryTrigger) {
        Log.app.notice("ALERTE déclenchée")
        // 1. Fermeture du coffre + destruction des sessions (secrets effacés au mieux).
        closeVault(save: false)
        client.stop()
        sessionContext?.invalidate()
        sessionContext = nil
        // 2. Alarme locale (son + notification, lisibles même écran verrouillé).
        soundAlarm()
        // 3. PREMIÈRE alerte tout de suite, sans attendre le GPS : c'est la dernière chance avant
        //    que le voleur n'éteigne le téléphone ou ne passe en mode avion.
        sendTelemetry(reason)
        resumeAlert(reason)
    }

    /// Partie de l'alerte qui doit aussi reprendre après un redémarrage de l'app.
    private func resumeAlert(_ reason: TelemetryTrigger) {
        location.onLocation = { [weak self] _ in Task { @MainActor in self?.flushTelemetry() } }
        location.startTracking()
        alertTimer?.invalidate()
        alertTimer = Timer.scheduledTimer(withTimeInterval: RobAirConstants.telemetryInterval, repeats: true) { [weak self] _ in
            Task { @MainActor in self?.sendTelemetry(.periodic) }
        }
    }

    private func leaveAlert() {
        alertTimer?.invalidate()
        alertTimer = nil
        location.stopTracking()
        emergency = nil
        emergencyMessage = nil
        faceIDFailures = 0
        flushTelemetry()   // ce qui reste en file part quand même
    }

    private func sendTelemetry(_ trigger: TelemetryTrigger) {
        guard let centrale else { return }
        let fix = location.latest
        let battery = UIDevice.current.batteryLevel
        telemetry.enqueue(trigger: trigger,
                          lat: fix?.coordinate.latitude, lon: fix?.coordinate.longitude,
                          accuracy: fix.map { min($0.horizontalAccuracy, 100_000) },
                          battery: battery >= 0 ? Double(battery) : nil,
                          centrale: centrale)
    }

    private func flushTelemetry() {
        if let centrale { telemetry.flush(centrale: centrale) }
    }

    func sendTestTelemetry() { sendTelemetry(.test) }

    private func soundAlarm() {
        for delay in [0.0, 1.2, 2.4] {
            DispatchQueue.main.asyncAfter(deadline: .now() + delay) { AudioServicesPlayAlertSound(SystemSoundID(1005)) }
        }
        let content = UNMutableNotificationContent()
        content.title = "RobAir : alerte"
        content.body = "La balise n'est plus à portée. Le coffre est fermé."
        content.sound = .default
        UNUserNotificationCenter.current().add(UNNotificationRequest(identifier: "robair.alert", content: content, trigger: nil))
    }

    // MARK: - Lever l'alerte

    /// Face ID du propriétaire. Après 3 échecs, le déverrouillage de secours est proposé.
    func liftAlertWithFaceID() async {
        guard protection.isAlert else { return }
        let context: LAContext
        switch await evaluateFaceID("Lever l'alerte RobAir") {
        case .success(let validated): context = validated
        case .failed: faceIDFailures += 1; return   // seul un vrai échec rapproche du secours (RT-3)
        case .cancelled: return
        }
        apply(machine.handle(.ownerAuthenticated))
        // §3.3 : nouvelle négociation après chaque levée de verrouillage, avec ce même Face ID.
        if let centrale { openSession(context: context, centrale: centrale) }
    }

    var emergencyAvailable: Bool { protection.isAlert && faceIDFailures >= RobAirConstants.faceIDFailuresBeforeEmergency }

    /// §3.8 : défi envoyé au Mac par le réseau local ET affiché en QR code.
    func startEmergencyUnlock() {
        guard emergencyAvailable, let centrale, let iphoneID = identity.iphoneID else { return }
        let session = EmergencyUnlockSession(iphoneID: iphoneID)
        emergency = session
        emergencyMessage = "Demande envoyée à la centrale… Le code \(session.request.shortCode) doit s'afficher sur le Mac."
        Task { @MainActor in
            do {
                let frame = try Wire.plaintextFrame(.emergencyRequest, session.request)
                let reply = try await PlainExchange.exchange(serviceName: centrale.serviceName, frame: frame, expecting: .emergencyGrant,
                                                             timeout: RobAirConstants.emergencyChallengeLifetime)
                self.acceptEmergencyGrant(try Wire.decodePlaintext(reply, expected: .emergencyGrant, as: EmergencyGrant.self))
            } catch {
                if self.emergency === session, self.protection.isAlert {
                    self.emergencyMessage = "Réseau local indisponible : faites scanner le QR code au Mac, puis scannez sa réponse."
                }
            }
        }
    }

    func acceptEmergencyGrant(qrText: String) {
        do {
            acceptEmergencyGrant(try QRPayload.decode(qrText, prefix: QRPayload.emergencyGrantPrefix, as: EmergencyGrant.self))
        } catch {
            emergencyMessage = "QR code de réponse invalide."
        }
    }

    private func acceptEmergencyGrant(_ grant: EmergencyGrant) {
        guard let session = emergency, let macKey = try? centrale?.macKey() else { return }
        do {
            try session.verify(grant, macKey: macKey)   // signature K_id_Mac, défi en attente, non expiré
            apply(machine.handle(.emergencyUnlocked))
        } catch {
            emergencyMessage = "Réponse refusée (\(error.localizedDescription))"
        }
    }

    // MARK: - Coffre

    func openVault() async {
        guard machine.canOpenVault else { return }
        guard let context = await authenticate("Ouvrir le coffre") else { return }
        do {
            let opened = try vault.open(context: context)
            vaultKey = opened.key
            vaultText = opened.text
            vaultOpen = true
            sendStatus()
        } catch {
            errorMessage = "Ouverture du coffre refusée."
        }
    }

    func saveVault() {
        guard vaultOpen, let vaultKey else { return }
        do { try vault.save(vaultText, key: vaultKey) } catch { errorMessage = "Enregistrement impossible." }
    }

    func closeVault(save: Bool) {
        if save { saveVault() }
        // SÉCURITÉ : on oublie la clé et le texte déchiffré (effacement au mieux, voir SecureWipe).
        vaultKey = nil
        vaultText = ""
        if vaultOpen {
            vaultOpen = false
            sendStatus()
        }
    }

    // MARK: - Cycle de vie et presse-papiers

    func scenePhaseChanged(_ phase: ScenePhase) {
        switch phase {
        case .background:
            closeVault(save: true)
            sessionContext?.invalidate()   // plus de reconnexion sans un nouveau Face ID
            sessionContext = nil
        case .active:
            flushTelemetry()
        default:
            break
        }
    }

    /// MASVS-PLATFORM : ce qui est copié depuis le coffre reste LOCAL à l'appareil (pas de presse-papiers
    /// universel vers le Mac ou l'iPad) et expire au bout de 60 s.
    private func watchPasteboard() {
        NotificationCenter.default.addObserver(forName: UIPasteboard.changedNotification, object: nil, queue: .main) { [weak self] _ in
            Task { @MainActor in
                guard let self, self.vaultOpen, !self.rewritingPasteboard else { return }
                self.rewritingPasteboard = true
                let items = UIPasteboard.general.items
                UIPasteboard.general.setItems(items, options: [.localOnly: true, .expirationDate: Date().addingTimeInterval(60)])
                self.rewritingPasteboard = false
            }
        }
    }

    // MARK: - Face ID

    /// Configuration de protection : seulement DÉSARMÉ, et avec un Face ID frais (RT-2).
    private func authorizeConfigurationChange(_ reason: String) async -> Bool {
        guard protection == .disarmed else {
            errorMessage = "Désarmez d'abord la surveillance (Face ID)."
            return false
        }
        return await authenticate(reason) != nil
    }

    private enum FaceIDResult {
        case success(LAContext)
        case failed      // visage refusé ou biométrie bloquée : un VRAI échec
        case cancelled   // « Annuler », app en arrière-plan, autre interruption : PAS un échec
    }

    /// Faille RT-3 corrigée : avant, « Annuler » comptait comme un échec de Face ID. Un voleur pouvait
    /// donc atteindre le déverrouillage de secours en appuyant 3 fois sur « Annuler ».
    /// Biométrie seule : le code de l'appareil ne suffit pas (pas de bouton de repli).
    private func evaluateFaceID(_ reason: String) async -> FaceIDResult {
        let context = LAContext()
        context.localizedCancelTitle = "Annuler"
        context.localizedFallbackTitle = ""   // masque « Saisir le code »
        do {
            let ok = try await context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: reason)
            return ok ? .success(context) : .failed
        } catch let error as LAError {
            switch error.code {
            case .authenticationFailed, .biometryLockout: return .failed
            default: return .cancelled
            }
        } catch {
            return .cancelled
        }
    }

    /// Renvoie un LAContext validé par Face ID, ou nil (échec ou annulation).
    private func authenticate(_ reason: String) async -> LAContext? {
        if case .success(let context) = await evaluateFaceID(reason) { return context }
        return nil
    }
}
