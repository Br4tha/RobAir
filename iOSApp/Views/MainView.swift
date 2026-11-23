// MainView.swift (iPhone, Capteur) : état, armement, balise, centrale, coffre.

import os
import SwiftUI
import RobAirKit

struct MainView: View {
    @EnvironmentObject private var model: AppModel
    @AppStorage("robair.mode") private var modeRaw = ""
    @State private var scanningBeacon = false
    @State private var confirmForgetCentrale = false

    var body: some View {
        List {
            Section("Protection") {
                StatusRow(title: "Surveillance", value: model.protection.label,
                          color: model.protection == .armed ? .green : .secondary)
                StatusRow(title: "Balise", value: model.beacon.label, color: model.beacon == .present ? .green : .orange)
                if model.protection == .armed {
                    Button("Désarmer (Face ID)") { Task { await model.disarm() } }
                } else {
                    Button("Armer la surveillance") { model.arm() }
                        .disabled(model.beacon != .present)
                }
            }

            Section {
                StatusRow(title: "Canal", value: model.channel.label, color: model.channel == .established ? .green : .orange)
                if model.channel != .established {
                    Button("Se connecter (Face ID)") { Task { await model.connectToCentrale() } }
                }
                StatusRow(title: "Télémétrie en attente", value: "\(model.queuedTelemetry)", color: .secondary)
                if let last = model.lastDelivery { Text(last).font(.caption).foregroundStyle(.secondary) }
            } header: {
                Text("Centrale (Mac)")
            } footer: {
                Text("Centrale : \(model.centrale?.serviceName ?? "-") · cet iPhone : \(model.iphoneShortID)")
            }

            Section("Coffre") {
                if model.vaultOpen {
                    TextEditor(text: $model.vaultText)
                        .frame(minHeight: 160)
                        .privacySensitive()
                    Button("Enregistrer") { model.saveVault() }
                    Button("Fermer le coffre", role: .destructive) { model.closeVault(save: true) }
                } else {
                    Button {
                        Task { await model.openVault() }
                    } label: {
                        Label("Ouvrir avec Face ID", systemImage: "faceid")
                    }
                }
            }

            Section("Balise") {
                if model.beaconPaired {
                    Button("Oublier la balise", role: .destructive) { model.forgetBeacon() }
                } else {
                    Button("Scanner le QR code de la balise") { scanningBeacon = true }
                }
            }

            Section("Avancé") {
                Button("Envoyer une télémétrie de test") { model.sendTestTelemetry() }
                Button("Oublier cette centrale", role: .destructive) { confirmForgetCentrale = true }
                Button("Changer le rôle de cet iPhone") { modeRaw = "" }
                    .disabled(model.protection != .disarmed)
            }
        }
        .sheet(isPresented: $scanningBeacon) {
            QRScannerView { code in
                scanningBeacon = false
                model.pairBeacon(qrText: code)
            }
            .ignoresSafeArea()
        }
        .confirmationDialog("Oublier la centrale ? Les clés, le coffre et la file de télémétrie seront effacés.",
                            isPresented: $confirmForgetCentrale, titleVisibility: .visible) {
            Button("Oublier et effacer", role: .destructive) { model.forgetCentrale() }
        }
    }
}

struct StatusRow: View {
    let title: String
    let value: String
    let color: Color

    var body: some View {
        HStack {
            Text(title)
            Spacer()
            Text(value).foregroundStyle(color).multilineTextAlignment(.trailing)
        }
    }
}

/// Défi du Mac (§3.7) : l'utilisateur voit l'action demandée et confirme avec Face ID.
struct ChallengeView: View {
    @EnvironmentObject private var model: AppModel

    var body: some View {
        VStack(spacing: 20) {
            Image(systemName: "desktopcomputer").font(.system(size: 56))
            Text("La centrale demande").font(.title2.bold())
            Text(model.pendingChallenge?.action.label ?? "").font(.title3)
            Text("Confirmez seulement si c'est vous qui l'avez demandé sur le Mac.")
                .multilineTextAlignment(.center).foregroundStyle(.secondary)
            Button {
                Task { await model.respondToChallenge() }
            } label: {
                Label("Confirmer avec Face ID", systemImage: "faceid").frame(maxWidth: .infinity)
            }
            .buttonStyle(.borderedProminent)
            Button("Refuser", role: .cancel) { model.declineChallenge() }
        }
        .padding(32)
    }
}
