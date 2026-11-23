// RobAirApp.swift (iPhone)
// Point d'entrée. Deux modes, choisis au premier lancement :
//   - Capteur : le téléphone protégé (balise surveillée, coffre, alerte, télémétrie vers le Mac) ;
//   - Balise  : le 2e iPhone porté par l'utilisateur (balise BLE de confiance).
// Le mode n'est pas un secret : il est rangé dans UserDefaults (aucun secret n'y est jamais stocké).
// Masque l'écran dès que l'app n'est plus active (aperçu multitâche, MASVS-PLATFORM).

import SwiftUI

enum AppMode: String {
    case capteur, balise
}

@main
struct RobAirApp: App {
    @AppStorage("robair.mode") private var modeRaw = ""
    @Environment(\.scenePhase) private var scenePhase

    var body: some Scene {
        WindowGroup {
            Group {
                switch AppMode(rawValue: modeRaw) {
                case .capteur: CapteurRoot()
                case .balise: BeaconModeView()
                case nil: ModeChoiceView { modeRaw = $0.rawValue }
                }
            }
            .overlay {
                // SÉCURITÉ : la capture de l'aperçu multitâche est prise en état .inactive
                if scenePhase != .active { PrivacyCover() }
            }
        }
    }
}

/// Le modèle du capteur n'est créé QUE dans ce mode (pas de Bluetooth central ni de localisation sur la balise).
struct CapteurRoot: View {
    @StateObject private var model = AppModel()
    @Environment(\.scenePhase) private var scenePhase

    var body: some View {
        RootView()
            .environmentObject(model)
            .onChange(of: scenePhase) { _, phase in model.scenePhaseChanged(phase) }
    }
}
