// AlertView.swift (iPhone, Capteur) : écran d'alerte plein écran et opaque (J1 §1.2, §2.1, §3.8).
// Fermer cet écran n'ouvre rien : le coffre exige K_vault, donc Face ID (J1 §4, ligne E).
// Sortie : Face ID du propriétaire, ou déverrouillage de secours signé par le Mac après 3 échecs.

import os
import SwiftUI
import RobAirKit

struct AlertView: View {
    @EnvironmentObject private var model: AppModel
    @State private var scanningGrant = false

    var body: some View {
        ScrollView {
            VStack(spacing: 20) {
                Image(systemName: "exclamationmark.triangle.fill").font(.system(size: 72))
                Text("ALERTE RobAir").font(.largeTitle.bold())
                if case .alert(let reason) = model.protection {
                    Text("Cause : \(reason.label)").multilineTextAlignment(.center)
                }
                Text("Le coffre est fermé. La centrale a été prévenue.")
                    .multilineTextAlignment(.center)

                Button {
                    Task { await model.liftAlertWithFaceID() }
                } label: {
                    Label("Lever l'alerte avec Face ID", systemImage: "faceid").frame(maxWidth: .infinity)
                }
                .buttonStyle(.borderedProminent)
                .tint(.white)
                .foregroundStyle(.red)

                if model.faceIDFailures > 0 {
                    Text("Échecs Face ID : \(model.faceIDFailures)").font(.footnote)
                }

                if model.emergencyAvailable {
                    emergencySection
                }
            }
            .padding(28)
        }
        .foregroundStyle(.white)
        .background(Color.red.ignoresSafeArea())
        .interactiveDismissDisabled()
        .sheet(isPresented: $scanningGrant) {
            QRScannerView { code in
                scanningGrant = false
                model.acceptEmergencyGrant(qrText: code)
            }
            .ignoresSafeArea()
        }
    }

    @ViewBuilder
    private var emergencySection: some View {
        VStack(spacing: 14) {
            Divider().background(.white)
            Text("Déverrouillage de secours").font(.headline)
            Text("Lève le verrouillage de RobAir (pas celui d'iOS). Le coffre exigera toujours Face ID.")
                .font(.footnote).multilineTextAlignment(.center)
            if let session = model.emergency {
                Text("Code à comparer sur le Mac : \(session.request.shortCode)").bold()
                if let qr = try? QRPayload.encode(session.request, prefix: QRPayload.emergencyRequestPrefix) {
                    QRCodeImage(text: qr)
                        .frame(width: 220, height: 220)
                        .padding(8)
                        .background(.white)
                }
                if let message = model.emergencyMessage { Text(message).font(.footnote).multilineTextAlignment(.center) }
                Button("Scanner la réponse du Mac") { scanningGrant = true }
                    .buttonStyle(.bordered)
                    .tint(.white)
            } else {
                Button("Demander le déverrouillage à la centrale") { model.startEmergencyUnlock() }
                    .buttonStyle(.bordered)
                    .tint(.white)
            }
        }
    }
}
