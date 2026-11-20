// RootView.swift (iPhone) : aiguillage du mode Capteur + écrans communs (choix du mode, masquage, QR).

import SwiftUI
import CoreImage.CIFilterBuiltins
import RobAirKit

struct RootView: View {
    @EnvironmentObject private var model: AppModel

    var body: some View {
        NavigationStack {
            Group {
                if model.centrale == nil {
                    PairingView()
                } else {
                    MainView()
                }
            }
            .navigationTitle("RobAir")
        }
        // L'écran d'alerte est plein écran et opaque : impossible de revenir au contenu sans le lever.
        .fullScreenCover(isPresented: .constant(model.protection.isAlert)) {
            AlertView().environmentObject(model)
        }
        .sheet(isPresented: Binding(get: { model.pendingChallenge != nil && !model.protection.isAlert },
                                    set: { if !$0 { model.declineChallenge() } })) {
            ChallengeView().environmentObject(model)
        }
        .alert("Attention", isPresented: Binding(get: { model.errorMessage != nil },
                                                 set: { if !$0 { model.errorMessage = nil } })) {
            Button("OK", role: .cancel) {}
        } message: {
            Text(model.errorMessage ?? "")
        }
    }
}

struct ModeChoiceView: View {
    let choose: (AppMode) -> Void

    var body: some View {
        VStack(spacing: 24) {
            Image(systemName: "lock.shield.fill").font(.system(size: 64))
            Text("RobAir").font(.largeTitle.bold())
            Text("Quel rôle joue cet iPhone ?").foregroundStyle(.secondary)
            Button {
                choose(.capteur)
            } label: {
                Label("Capteur : le téléphone à protéger", systemImage: "iphone.gen3")
                    .frame(maxWidth: .infinity)
            }
            .buttonStyle(.borderedProminent)
            Button {
                choose(.balise)
            } label: {
                Label("Balise : le téléphone que je garde sur moi", systemImage: "dot.radiowaves.left.and.right")
                    .frame(maxWidth: .infinity)
            }
            .buttonStyle(.bordered)
        }
        .padding(32)
    }
}

struct PrivacyCover: View {
    var body: some View {
        ZStack {
            Color(uiColor: .systemBackground)
            VStack(spacing: 12) {
                Image(systemName: "lock.shield.fill").font(.system(size: 64))
                Text("RobAir").font(.title2.bold())
            }
        }
        .ignoresSafeArea()
    }
}

/// Affiche un texte en QR code (généré localement par CoreImage, aucune image conservée).
struct QRCodeImage: View {
    let text: String

    var body: some View {
        if let image = Self.render(text) {
            Image(uiImage: image).interpolation(.none).resizable().scaledToFit()
        } else {
            Text("QR code indisponible").foregroundStyle(.secondary)
        }
    }

    static func render(_ text: String) -> UIImage? {
        let filter = CIFilter.qrCodeGenerator()
        filter.message = Data(text.utf8)
        filter.correctionLevel = "M"
        guard let output = filter.outputImage?.transformed(by: CGAffineTransform(scaleX: 10, y: 10)),
              let cg = CIContext().createCGImage(output, from: output.extent) else { return nil }
        return UIImage(cgImage: cg)
    }
}
