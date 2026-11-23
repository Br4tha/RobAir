// BeaconModeView.swift (iPhone, mode Balise)
// Le QR code contient la clé K_balise : il n'est affiché qu'à la demande, 60 s au plus, avec un avertissement.

import os
import SwiftUI
import RobAirKit

struct BeaconModeView: View {
    @StateObject private var model = BeaconModel()
    @AppStorage("robair.mode") private var modeRaw = ""
    @State private var showCode = false
    @State private var confirmRegenerate = false

    var body: some View {
        NavigationStack {
            List {
                Section("Balise de confiance") {
                    StatusRow(title: "Capteur connecté", value: model.connectedCount > 0 ? "Oui" : "Non",
                              color: model.connectedCount > 0 ? .green : .orange)
                    StatusRow(title: "Dernière preuve envoyée",
                              value: model.lastAnswer.map { $0.formatted(date: .omitted, time: .standard) } ?? "-",
                              color: .secondary)
                    Text("Gardez cet iPhone sur vous, app ouverte. Si le capteur s'éloigne, il passe en alerte.")
                        .font(.footnote).foregroundStyle(.secondary)
                }

                Section("Appairage avec le capteur") {
                    if showCode {
                        QRCodeImage(text: model.qrText).frame(maxWidth: .infinity).frame(height: 240)
                        Text("Ce QR code contient la clé secrète de la balise : ne le montrez qu'au capteur.")
                            .font(.footnote).foregroundStyle(.orange)
                        Button("Masquer") { showCode = false }
                    } else {
                        Button("Afficher le QR code d'appairage") {
                            showCode = true
                            DispatchQueue.main.asyncAfter(deadline: .now() + 60) { showCode = false }
                        }
                    }
                    Button("Générer une nouvelle clé", role: .destructive) { confirmRegenerate = true }
                }

                Section {
                    Button("Changer le rôle de cet iPhone") {
                        model.stop()
                        modeRaw = ""
                    }
                }
            }
            .navigationTitle("RobAir · Balise")
        }
        .onAppear { model.start() }
        .confirmationDialog("Nouvelle clé : le capteur devra scanner le nouveau QR code.",
                            isPresented: $confirmRegenerate, titleVisibility: .visible) {
            Button("Générer", role: .destructive) { model.regenerate() }
        }
    }
}
