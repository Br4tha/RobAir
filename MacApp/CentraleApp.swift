// CentraleApp.swift (Mac) : point d'entrée de la centrale RobAir (supervision, alertes, journal, secours).

import SwiftUI

@main
struct CentraleApp: App {
    @StateObject private var model = CentraleModel()

    var body: some Scene {
        WindowGroup("RobAir · Centrale") {
            DashboardView()
                .environmentObject(model)
                .frame(minWidth: 1000, minHeight: 680)
        }
    }
}
