// DashboardView.swift (Mac) : tableau de bord de la centrale (J1 §2.2).
// État du capteur, carte des positions reçues, actions (défis Face ID, secours), journal d'audit.

import SwiftUI
import MapKit
import RobAirKit

struct DashboardView: View {
    @EnvironmentObject private var model: CentraleModel
    @State private var confirmReset = false
    @State private var showRelay = false
    @State private var scanningEmergency = false

    var body: some View {
        VStack(spacing: 0) {
            StatusBanner(display: model.display, trigger: model.lastTrigger)
            HStack(alignment: .top, spacing: 16) {
                ScrollView {
                    SidePanel(confirmReset: $confirmReset, showRelay: $showRelay, scanningEmergency: $scanningEmergency)
                }
                .frame(width: 320)
                VStack(spacing: 12) {
                    PositionsMap(points: model.points)
                    JournalView()
                }
            }
            .padding()
        }
        .sheet(isPresented: Binding(get: { model.invitation != nil }, set: { if !$0 { model.cancelPairing() } })) {
            PairingSheet().environmentObject(model)
        }
        .sheet(isPresented: Binding(get: { model.pendingEmergency != nil }, set: { if !$0 { model.dismissEmergency() } })) {
            EmergencySheet().environmentObject(model)
        }
        .sheet(isPresented: $showRelay) { RelaySettingsSheet().environmentObject(model) }
        .sheet(isPresented: $scanningEmergency) {
            QRWebcamScanner { text in
                scanningEmergency = false
                model.receiveEmergency(qrText: text)
            }
            .frame(width: 520, height: 420)
        }
        .confirmationDialog("Réinitialiser la centrale ?", isPresented: $confirmReset, titleVisibility: .visible) {
            Button("Effacer clés, appairage, relais et journal", role: .destructive) { model.resetCentrale() }
        } message: {
            Text("À faire en fin de séance sur un Mac prêté. L'iPhone devra être réappairé.")
        }
        .alert("Erreur", isPresented: Binding(get: { model.errorMessage != nil }, set: { if !$0 { model.errorMessage = nil } })) {
            Button("OK", role: .cancel) {}
        } message: {
            Text(model.errorMessage ?? "")
        }
    }
}

private struct StatusBanner: View {
    let display: CentraleDisplay
    let trigger: TelemetryTrigger?

    var body: some View {
        HStack(spacing: 16) {
            Image(systemName: display.symbol).font(.system(size: 40))
            VStack(alignment: .leading) {
                Text(display.title).font(.system(size: 28, weight: .bold))
                if display == .alert, let trigger { Text("Cause : \(trigger.label)").font(.title3) }
            }
            Spacer()
        }
        .foregroundStyle(.white)
        .padding(24)
        .background(display.color)
    }
}

private struct SidePanel: View {
    @EnvironmentObject private var model: CentraleModel
    @Binding var confirmReset: Bool
    @Binding var showRelay: Bool
    @Binding var scanningEmergency: Bool

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            GroupBox("Centrale") {
                VStack(alignment: .leading, spacing: 6) {
                    row("Nom Bonjour", model.serviceName)
                    row("Clé maîtresse", model.keyStorage)
                    row("Clé HPKE", model.encryptionEpoch.map { "époque \($0)" } ?? "à créer (Touch ID)")
                    row("Relais", model.relayStatus)
                    if model.isOperatorUnlocked {
                        Label("Déverrouillée : sessions acceptées", systemImage: "lock.open").foregroundStyle(.green)
                        Button("Verrouiller") { model.lockCentrale() }
                    } else {
                        Label("Verrouillée : sessions refusées", systemImage: "lock").foregroundStyle(.orange)
                        Button("Déverrouiller (Touch ID)") { model.unlockCentrale() }
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
            }

            GroupBox("iPhone appairé") {
                VStack(alignment: .leading, spacing: 6) {
                    if let paired = model.paired {
                        row("Pseudonyme", paired.shortName)
                        row("Session chiffrée", model.sessionActive ? "Établie" : "Aucune")
                        row("Surveillance", model.lastStatus?.protectionState.label ?? "-")
                        row("Balise", model.lastStatus?.beacon.label ?? "-")
                        row("Dernier message", model.lastSeen.map { $0.formatted(date: .omitted, time: .standard) } ?? "-")
                        row("Positions reçues", "\(model.points.count)")
                    } else {
                        Text("Aucun iPhone appairé.").foregroundStyle(.secondary)
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
            }

            if model.paired != nil {
                GroupBox("Actions (Face ID sur l'iPhone)") {
                    VStack(alignment: .leading, spacing: 8) {
                        if let pending = model.pendingChallenge {
                            ProgressView("En attente de Face ID : \(pending.label)")
                        }
                        Button("Fin d'alerte (téléphone retrouvé)") { model.request(.endAlert) }
                            .disabled(!model.sessionActive)
                        Button("Désarmer la surveillance") { model.request(.disarm) }
                            .disabled(!model.sessionActive)
                        Divider()
                        Button("Lire une demande de secours (webcam)") { scanningEmergency = true }
                        Button("Interroger le relais maintenant") { model.pollRelay() }
                            .disabled(model.paired?.mailbox == nil)
                        if model.display == .alert {
                            Button("Acquitter l'alerte sans preuve…") { model.acknowledgeAlertLocally() }
                                .foregroundStyle(.orange)
                        }
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                }
            }

            Button {
                model.beginPairing()
            } label: {
                Label(model.paired == nil ? "Appairer un iPhone" : "Réappairer un iPhone", systemImage: "qrcode")
                    .frame(maxWidth: .infinity)
            }
            .buttonStyle(.borderedProminent)

            Button("Réglages du relais…") { showRelay = true }
            if model.paired != nil {
                Button("Oublier cet iPhone", role: .destructive) { model.forgetIPhone() }
            }
            Button(role: .destructive) {
                confirmReset = true
            } label: {
                Label("Réinitialiser la centrale", systemImage: "trash").frame(maxWidth: .infinity)
            }
        }
    }

    private func row(_ title: String, _ value: String) -> some View {
        HStack(alignment: .top) {
            Text(title).foregroundStyle(.secondary)
            Spacer()
            Text(value).multilineTextAlignment(.trailing).textSelection(.enabled)
        }
    }
}

private struct PositionsMap: View {
    let points: [TelemetryPoint]

    var body: some View {
        GroupBox("Positions reçues (alerte uniquement)") {
            if points.isEmpty {
                Text("Aucune position. Elles n'apparaissent qu'en cas d'alerte (RGPD : minimisation).")
                    .foregroundStyle(.secondary)
                    .frame(maxWidth: .infinity, minHeight: 200)
            } else {
                Map(initialPosition: .automatic) {
                    ForEach(points) { point in
                        Marker(point.date.formatted(date: .omitted, time: .shortened), coordinate: point.coordinate)
                            .tint(point.id == points.last?.id ? .red : .orange)
                    }
                    if points.count > 1 {
                        MapPolyline(coordinates: points.map(\.coordinate)).stroke(.red, lineWidth: 2)
                    }
                }
                .frame(minHeight: 240)
                .id(points.count)   // recadre la carte à chaque nouvelle position
            }
        }
    }
}

private struct JournalView: View {
    @EnvironmentObject private var model: CentraleModel

    var body: some View {
        GroupBox {
            VStack(alignment: .leading) {
                HStack {
                    Text("Journal d'audit (chaîné, signé, chiffré)").font(.headline)
                    Spacer()
                    switch model.integrity {
                    case .intact?:
                        Label("Intact", systemImage: "checkmark.seal.fill").foregroundStyle(.green)
                    case .broken(let index)?:
                        Label("Rupture à l'entrée \(index)", systemImage: "xmark.seal.fill").foregroundStyle(.red)
                    case .truncated(let count)?:
                        Label("Tronqué (\(count) entrées attendues)", systemImage: "xmark.seal.fill").foregroundStyle(.red)
                    case nil:
                        EmptyView()
                    }
                    Button("Vérifier l'intégrité") { model.verifyJournal() }
                }
                List(model.entries) { entry in
                    HStack(alignment: .top) {
                        Text(entry.date.formatted(date: .abbreviated, time: .standard))
                            .font(.caption.monospacedDigit()).foregroundStyle(.secondary)
                            .frame(width: 150, alignment: .leading)
                        Image(systemName: icon(for: entry.kind)).foregroundStyle(color(for: entry.kind))
                        VStack(alignment: .leading) {
                            Text(entry.detail)
                            Text("#\(entry.index) · \(entry.device)\(entry.evidence != nil ? " · preuve signée" : "")")
                                .font(.caption).foregroundStyle(.secondary)
                        }
                    }
                }
            }
        }
    }

    private func icon(for kind: JournalEntry.Kind) -> String {
        switch kind {
        case .paired: return "link"
        case .unpaired: return "link.badge.plus"
        case .sessionOpened: return "lock.shield"
        case .sessionClosed: return "bolt.horizontal.circle"
        case .status: return "dot.radiowaves.left.and.right"
        case .alert: return "exclamationmark.triangle.fill"
        case .telemetry: return "location.fill"
        case .challenge: return "faceid"
        case .emergencyUnlock: return "key.fill"
        case .keyRotation: return "arrow.triangle.2.circlepath"
        case .relay: return "server.rack"
        case .anomaly: return "xmark.octagon.fill"
        case .reset: return "arrow.counterclockwise"
        }
    }

    private func color(for kind: JournalEntry.Kind) -> Color {
        switch kind {
        case .alert, .anomaly: return .red
        case .telemetry, .emergencyUnlock: return .orange
        case .challenge: return .blue
        default: return .secondary
        }
    }
}
