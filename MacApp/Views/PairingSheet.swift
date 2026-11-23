// PairingSheet.swift (Mac) : QR code d'invitation, puis empreinte courte à comparer (J1 §3.2).
// EmergencySheet : demande de déverrouillage de secours à autoriser par Touch ID (J1 §3.8).
// RelaySettingsSheet : réglages du relais aveugle (extension P2).

import os
import SwiftUI
import AppKit
import CoreImage.CIFilterBuiltins
import RobAirKit

struct PairingSheet: View {
    @EnvironmentObject private var model: CentraleModel

    var body: some View {
        VStack(spacing: 20) {
            if let pending = model.pendingPairing {
                Text("Comparez les empreintes").font(.title2.bold())
                Text("L'iPhone doit afficher exactement la même empreinte.").foregroundStyle(.secondary)
                Text(pending.fingerprint).font(.system(size: 56, weight: .bold, design: .monospaced))
                Text("Empreintes différentes = quelqu'un s'interpose : refusez.").font(.callout).foregroundStyle(.orange)
                HStack {
                    Button("Refuser", role: .destructive) { model.confirmPairing(false) }
                    Button("Identiques : confirmer (Touch ID)") { model.confirmPairing(true) }
                        .buttonStyle(.borderedProminent)
                        .keyboardShortcut(.defaultAction)
                }
            } else if let invitation = model.invitation {
                Text("Scannez ce QR code avec RobAir (mode Capteur)").font(.title2.bold())
                if let text = try? invitation.encodedForQRCode() {
                    QRImage(text: text).frame(width: 300, height: 300)
                }
                TimelineView(.periodic(from: .now, by: 1)) { context in
                    let remaining = Int(Date(millisecondsSince1970: invitation.expiresAtMs).timeIntervalSince(context.date))
                    Text(remaining > 0 ? "Expire dans \(remaining) s · usage unique" : "Invitation expirée")
                        .foregroundStyle(remaining > 0 ? Color.secondary : Color.red)
                }
                Button("Annuler") { model.cancelPairing() }
            }
        }
        .padding(32)
        .frame(minWidth: 440)
    }
}

struct EmergencySheet: View {
    @EnvironmentObject private var model: CentraleModel

    var body: some View {
        VStack(spacing: 18) {
            Image(systemName: "key.fill").font(.system(size: 44))
            Text("Demande de déverrouillage de secours").font(.title2.bold())
            if let pending = model.pendingEmergency {
                Text("Vérifiez que l'iPhone affiche ce code :")
                Text(pending.request.shortCode).font(.system(size: 48, weight: .bold, design: .monospaced))
                Text("Une demande réseau peut être forgée : n'autorisez que si vous voyez l'iPhone et le même code.")
                    .font(.callout).foregroundStyle(.orange).multilineTextAlignment(.center)
            }
            if let grant = model.emergencyGrantQR {
                Text("Accordé. Si l'iPhone ne l'a pas reçu par le réseau, faites-lui scanner ce QR code :")
                    .multilineTextAlignment(.center)
                QRImage(text: grant).frame(width: 260, height: 260)
                Button("Fermer") { model.dismissEmergency() }
            } else {
                HStack {
                    Button("Refuser", role: .destructive) { model.dismissEmergency() }
                    Button("Autoriser (Touch ID)") { model.grantEmergency() }
                        .buttonStyle(.borderedProminent)
                }
            }
        }
        .padding(32)
        .frame(minWidth: 460)
    }
}

struct RelaySettingsSheet: View {
    @EnvironmentObject private var model: CentraleModel
    @Environment(\.dismiss) private var dismiss
    @State private var url = ""
    @State private var pin = ""
    @State private var enrollmentKey = ""

    var body: some View {
        Form {
            Section {
                TextField("URL (https://…)", text: $url)
                TextField("Pin TLS (sortie de relay/tools/pin.sh)", text: $pin)
                SecureField("Clé d'enrôlement (sortie de « robair_relay.py init »)", text: $enrollmentKey)
            } header: {
                Text("Relais aveugle (extension P2)")
            } footer: {
                Text("Le relais ne voit que des messages chiffrés pour ce Mac et signés par l'iPhone. Il ne peut ni les lire ni les falsifier.")
            }
            HStack {
                Button("Annuler") { dismiss() }
                Spacer()
                Button("Enregistrer") {
                    model.saveRelaySettings(url: url, pin: pin, enrollmentKey: enrollmentKey)
                    dismiss()
                }
                .buttonStyle(.borderedProminent)
            }
        }
        .padding(24)
        .frame(width: 520)
        .onAppear {
            url = model.relaySettings?.url ?? ""
            pin = model.relaySettings?.pin ?? ""
        }
    }
}

struct QRImage: View {
    let text: String

    var body: some View {
        if let image = render() {
            Image(nsImage: image).interpolation(.none).resizable()
        }
    }

    private func render() -> NSImage? {
        let filter = CIFilter.qrCodeGenerator()
        filter.message = Data(text.utf8)
        filter.correctionLevel = "M"
        guard let output = filter.outputImage?.transformed(by: CGAffineTransform(scaleX: 10, y: 10)) else { return nil }
        let rep = NSCIImageRep(ciImage: output)
        let image = NSImage(size: rep.size)
        image.addRepresentation(rep)
        return image
    }
}
