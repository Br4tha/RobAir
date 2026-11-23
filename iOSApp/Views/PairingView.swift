// PairingView.swift (iPhone, Capteur) : scan du QR code du Mac, puis empreinte courte à comparer (§3.2).

import SwiftUI

struct PairingView: View {
    @EnvironmentObject private var model: AppModel
    @State private var scanning = false

    var body: some View {
        VStack(spacing: 24) {
            Image(systemName: "qrcode.viewfinder").font(.system(size: 72))
            Text("Appairer avec la centrale").font(.title2.bold())
            Text("Sur le Mac, cliquez sur « Appairer un iPhone », puis scannez le QR code affiché.")
                .multilineTextAlignment(.center)
                .foregroundStyle(.secondary)

            switch model.pairingPhase {
            case .idle:
                Button("Scanner le QR code du Mac") { scanning = true }
                    .buttonStyle(.borderedProminent)
            case .waitingForMac(let fingerprint):
                VStack(spacing: 12) {
                    Text("Vérifiez que le Mac affiche la même empreinte :")
                    Text(fingerprint).font(.system(size: 44, weight: .bold, design: .monospaced))
                    Text("Empreintes différentes = quelqu'un s'interpose : refusez sur le Mac.")
                        .font(.footnote).foregroundStyle(.orange).multilineTextAlignment(.center)
                    ProgressView("Confirmez sur le Mac…")
                }
            case .failed(let message):
                Text(message).foregroundStyle(.red).multilineTextAlignment(.center)
                Button("Réessayer") {
                    model.resetPairingPhase()
                    scanning = true
                }
                .buttonStyle(.borderedProminent)
            }
        }
        .padding()
        .sheet(isPresented: $scanning) {
            QRScannerView { code in
                scanning = false
                model.startPairing(qrCode: code)
            }
            .ignoresSafeArea()
        }
    }
}
