// LocationTracker.swift (iPhone, mode Capteur)
// Rôle : positions GPS pour la télémétrie (J1 §2.1, §3.5).
// RGPD / moindre privilège :
//   - autorisation « Lors de l'utilisation » seulement (pas « Toujours »), demandée AU MOMENT D'ARMER ;
//   - pendant que la surveillance est armée, une CLBackgroundActivitySession (iOS 17) permet de démarrer
//     la localisation depuis l'arrière-plan si une alerte survient. iOS affiche alors l'indicateur bleu :
//     l'utilisateur voit que RobAir est armé ;
//   - les positions ne sont collectées et transmises QU'EN ALERTE ; aucune n'est stockée en clair.

import Foundation
import CoreLocation

final class LocationTracker: NSObject, CLLocationManagerDelegate {
    var onLocation: ((CLLocation) -> Void)?
    private(set) var latest: CLLocation?

    private let manager = CLLocationManager()
    private var backgroundSession: CLBackgroundActivitySession?

    override init() {
        super.init()
        manager.delegate = self
        manager.desiredAccuracy = kCLLocationAccuracyBest
        manager.distanceFilter = 10
        manager.pausesLocationUpdatesAutomatically = false
    }

    /// À l'armement (premier plan) : demande l'autorisation et ouvre la session d'arrière-plan.
    func prepareForArming() {
        if manager.authorizationStatus == .notDetermined { manager.requestWhenInUseAuthorization() }
        if backgroundSession == nil { backgroundSession = CLBackgroundActivitySession() }
    }

    var isAuthorized: Bool {
        [.authorizedWhenInUse, .authorizedAlways].contains(manager.authorizationStatus)
    }

    /// Alerte : localisation précise en continu (garde aussi l'app active en arrière-plan pour l'envoi).
    func startTracking() {
        manager.allowsBackgroundLocationUpdates = true
        manager.showsBackgroundLocationIndicator = true
        manager.startUpdatingLocation()
    }

    func stopTracking() {
        manager.stopUpdatingLocation()
        manager.allowsBackgroundLocationUpdates = false
        latest = nil
    }

    /// Désarmement : plus aucune activité de localisation possible en arrière-plan.
    func release() {
        stopTracking()
        backgroundSession?.invalidate()
        backgroundSession = nil
    }

    func locationManager(_ manager: CLLocationManager, didUpdateLocations locations: [CLLocation]) {
        guard let location = locations.last, location.horizontalAccuracy >= 0 else { return }
        latest = location
        onLocation?(location)
    }

    func locationManager(_ manager: CLLocationManager, didFailWithError error: Error) {
        Log.app.notice("Localisation indisponible")
    }
}
