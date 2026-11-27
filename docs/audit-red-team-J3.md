# Audit Red Team du MVP (J3)

> **Auditeur (Red Team) :** Manaia Logologofolau, chef de projet · **Date :** 27/11/2026
> **Code audité :** branche `chore/xcode-project` (commit `46cea3d`), c'est-à-dire `feat/refonte-code` plus le projet Xcode.
> **Corrections :** branche `fix/audit-red-team`, à relire par l'architecte sécurité (J1 §6.1 : tout code crypto ou réseau).
> **Limite :** pas de tests sur appareil. Le compte iCloud ne peut pas être connecté sur le Mac de l'école et il faut deux iPhone (J2 §14). L'audit repose sur la **revue du code** et les **tests automatiques** du module (105 tests verts).

## 1. Résumé

| Id | Faille | Gravité | État |
|---|---|---|---|
| RT-1 | La file de télémétrie de l'iPhone se **bloque pour toujours** après une coupure du Mac de plus de 5 min | **Élevée** (l'alerte n'arrive plus) | ✅ corrigée + test |
| RT-2 | « Oublier la balise » et « Oublier la centrale » **désarment sans Face ID** | **Élevée** (contournement du désarmement) | ✅ corrigée |
| RT-3 | Appuyer sur « Annuler » compte comme un **échec de Face ID** : le secours devient accessible en 3 appuis | Moyenne | ✅ corrigée |
| R-1 | La balise diffuse un **identifiant Bluetooth fixe** : on peut suivre la personne qui la porte | Moyenne (vie privée) | documentée, correction proposée |
| R-2 | **Attaque par relais radio** : un complice retransmet le signal de la vraie balise | Moyenne | limite assumée (J2 §14) |
| R-3 | **Déni de service sur le Wi-Fi local** : saturer la centrale ou usurper son nom Bonjour | Faible | documentée |
| R-4 | Mac : repli possible vers l'**ancien Keychain** si l'app n'a pas le droit au Keychain moderne | À vérifier | à tester quand l'app Mac sera compilée |
| R-5 | L'identifiant de l'app est **écrit en dur** dans le projet Xcode, et la **cible Mac** n'y est pas | Organisation | signalé dans la PR #8 |

Aucune faille n'a été inventée : les trois corrections portent sur des défauts réels du code, décrits ci-dessous avec un scénario reproductible.

## 2. Stratégie d'audit (à savoir expliquer à l'oral)

**Idée générale : penser comme l'attaquant du J1 §4, pas comme le développeur.** Pour chaque attaquant (voleur, personne sur le même Wi-Fi, faux appareil, proche qui a accès au téléphone), on cherche le chemin le moins cher vers son objectif : désactiver la protection, lire le coffre, faire taire l'alerte ou tromper la centrale.

1. **Cartographier la surface d'attaque.** Tout ce qui entre dans l'app depuis l'extérieur :
   - les QR codes scannés ;
   - les trames Wi-Fi reçues par le Mac et par l'iPhone ;
   - les écritures Bluetooth reçues par la balise ;
   - les boutons de l'interface quand le téléphone est **déverrouillé mais dans d'autres mains**.
2. **Appliquer STRIDE à chaque entrée** (usurpation, altération, répudiation, divulgation, déni de service, élévation de privilège) et la cible du J3 : rejeu, clonage BLE, logs, stockage.
3. **Vérifier les contrôles cryptographiques par les tests** : 105 tests automatiques jouent les attaques (faux Mac, rejeu, bit modifié, balise clonée, clé X25519 de faible ordre…). Un test qui passe prouve que l'attaque échoue.
4. **Relire la logique applicative, là où les tests ne vont pas.** C'est là qu'on a trouvé les trois failles : la crypto était correcte, mais les **décisions** autour (qui a le droit de désarmer, que faire d'un message refusé) avaient des trous. C'est le point clé de l'audit : **une crypto solide ne suffit pas si un bouton la contourne.**
5. **Pour chaque faille :** un scénario d'attaque concret, sa gravité (impact × facilité), une correction minimale, puis un test quand c'est possible (la logique pure se teste, l'interface demande un appareil).

## 3. Failles corrigées

### RT-1 · Blocage définitif de la file de télémétrie (élevée)

- **Où :** `TelemetryReceiver.accept` (RobAirKit), `CentraleModel.processTelemetry` (Mac), `TelemetrySender.flush` (iPhone).
- **Scénario :**
  1. Le téléphone est volé pendant que le Mac est éteint ou hors du Wi-Fi depuis plus de 5 minutes.
  2. L'alerte reste dans la file de l'iPhone (comportement voulu).
  3. Quand le Mac revient, il trouve l'alerte « trop vieille » (fenêtre de ±300 s) et la **refuse sans accusé de réception**.
  4. L'iPhone envoie sa file **dans l'ordre** et s'arrête au premier échec. Il renvoie donc la même alerte à chaque essai, et **toutes les positions suivantes restent bloquées derrière**. La centrale ne reçoit plus rien, alors que l'attaquant n'a rien eu à faire.
- **Gravité :** élevée. C'est la fonction principale (retrouver le téléphone) qui tombe, sans action de l'attaquant.
- **Correction :**
  - **Mac :** un message **authentique** (déchiffré et signé par K_tel) mais hors fenêtre est maintenant **acquitté** et journalisé, mais **pas affiché** comme position actuelle. Acquitter ne fait courir aucun risque : seul le Mac a pu lire l'`ackSecret`, et un message rejoué est toujours ignoré grâce à `seq`.
  - **Fenêtre :** la décision de l'architecte (J2, écart 4) est appliquée : on accepte jusqu'à **72 h** dans le passé et **300 s** dans le futur. Le Mac affiche la **date réelle** d'émission (« émise le …, différée »).
  - **iPhone (défense en profondeur) :** un message de plus de 72 h est retiré de la file.
- **Preuve :** les tests `testStaleMessageDoesNotBlockTheQueue` et `testDeferredTelemetryWindowIsAsymmetric`.

### RT-2 · Désarmement sans Face ID (élevée)

- **Où :** `AppModel.forgetBeacon`, `forgetCentrale` et `pairBeacon`, ainsi que `MainView` (iPhone).
- **Scénario :** le téléphone est armé et déverrouillé, posé sur une table ou pris par un proche. « Désarmer » exige bien Face ID. Mais un appui sur **« Oublier la balise »** appelait `disarmImmediately()` **sans aucune authentification**. Résultat : surveillance coupée, sans alerte ni trace côté utilisateur. « Oublier la centrale » faisait de même (une simple confirmation), et scanner une autre balise remplaçait la clé pendant la surveillance.
- **Gravité :** élevée. Contournement complet du contrôle d'accès (STRIDE E, MASVS-AUTH) : la protection la plus forte (Face ID sur « Désarmer ») était contournée par un bouton voisin.
- **Correction :** toute modification de la configuration de protection exige désormais d'être **désarmé** et un **Face ID frais** (`authorizeConfigurationChange`). Les boutons sont grisés tant que la surveillance est armée, et le contrôle est **aussi fait dans le modèle** : on ne fait pas confiance à l'interface seule.
- **Preuve :** revue de code. À vérifier sur appareil : armé, le bouton est grisé ; désarmé, Face ID est demandé.

### RT-3 · « Annuler » comptait comme un échec de Face ID (moyenne)

- **Où :** `AppModel.liftAlertWithFaceID` et `authenticate`.
- **Scénario :** sur l'écran d'alerte, le voleur appuie trois fois sur « Annuler » dans la fenêtre Face ID. Le compteur d'échecs atteint 3 et le **déverrouillage de secours** s'affiche. Le secours exige toujours le Touch ID de l'opérateur du Mac, mais cette porte ne devait s'ouvrir qu'après de **vrais** échecs du propriétaire (J1 §3.8). Elle ouvre aussi la voie à de l'ingénierie sociale (« c'est moi, accepte la demande »).
- **Correction :** seuls `authenticationFailed` (visage refusé) et `biometryLockout` (biométrie bloquée) comptent. « Annuler », une interruption ou le passage en arrière-plan ne comptent plus. Le bouton « Saisir le code » est masqué : la biométrie seule est exigée.
- **Preuve :** revue de code. À vérifier sur appareil avec *Features > Face ID > Non-matching Face* dans le simulateur.

## 4. Risques résiduels (non corrigés dans le code)

| Id | Description | Pourquoi pas corrigé | Recommandation |
|---|---|---|---|
| R-1 | La balise annonce toujours le **même UUID de service** : un scanner BLE peut suivre son porteur. | La correction touche les deux appareils et le scan en arrière-plan : impossible à valider sans deux iPhone. | UUID **tournant** dérivé de K_balise et de l'heure (par exemple `HMAC(K_balise, quart d'heure)`), le capteur cherchant l'UUID courant et le précédent. À prévoir au J4. |
| R-2 | **Relais radio** : un complice près de la victime retransmet le signal au voleur ; le défi HMAC est relayé et réussit. | Indétectable sans mesure du temps de vol (*distance bounding*). | Délai de réponse court (2 s, déjà en place) et seuil RSSI. Limite assumée au J1 §10 et au J2 §14. |
| R-3 | Sur le même Wi-Fi, un attaquant peut **occuper les 4 connexions** non authentifiées de la centrale, ou **annoncer le même nom Bonjour**. | C'est une attaque de **disponibilité** seulement : il ne peut ni lire, ni modifier, ni acquitter (pas d'`ackSecret`). Les positions restent en file et repartent ensuite. | Limiter par adresse IP sur le Mac. Ne jamais faire confiance au nom Bonjour, ce qui est déjà le cas puisque tout est signé. |
| R-4 | Sur macOS, `KeychainStore` se replie sur l'**ancien Keychain** si l'entitlement manque. Les options `ThisDeviceOnly` y sont alors moins strictes. | L'app Mac n'est pas encore compilée (pas de cible dans le projet Xcode). | Le vérifier au premier lancement de la centrale et noter le résultat dans le J2 §15. |
| R-5 | `PRODUCT_BUNDLE_IDENTIFIER` est écrit en dur (`fr.m2.samueld.RobAir`) et la cible Mac est absente du projet. | Ce n'est pas une faille, mais cela empêche les autres membres de signer, donc de tester. | Brancher `Config/Base.xcconfig` et ajouter la cible `RobAirCentrale` (PR #8). |

## 5. Attaques tentées qui ont échoué (protections vérifiées)

Ces attaques sont rejouées automatiquement par les tests du module (`swift test`) :

| Attaque (J1 §4) | Résultat | Test |
|---|---|---|
| Faux Mac sur le Wi-Fi (S1) | refusé : signature invalide | `testFakeMacIsRejected` |
| Faux iPhone qui copie l'identifiant (S3) | refusé au `ClientFinish` | `testImpostorWithCopiedIDFailsAtFinish` |
| Homme du milieu à l'appairage sans le QR | refusé : jeton HMAC | `testWrongTokenIsRejected`, `testShortFingerprintCoversAllKeys` |
| Clé X25519 de faible ordre (secret nul) | refusée (bug réel trouvé par ce test pendant le développement) | `testLowOrderEphemeralIsRejected` |
| Rejeu d'une trame de session | refusé (`seq`) | `testReplayIsRejected`, `testOlderMessageIsRejectedAfterNewer` |
| Un bit modifié dans une trame | refusé (AES-GCM) | `testAnyBitFlipIsDetected` |
| Fausse télémétrie chiffrée avec la clé publique du Mac | refusée : pas de signature K_tel | `testForgedTelemetryIsRejected` |
| Balise clonée (même UUID, mauvaise clé) | rupture → alerte | `testClonedBeaconFails`, `testInvalidOrSlowProofIsRupture` |
| Réponse de balise enregistrée puis rejouée | inutile : nouveau défi | `testOldResponseDoesNotMatchNewChallenge` |
| Transformer « désarmer » en « fin d'alerte » | refusé : l'action est signée | `testActionCannotBeSwapped` |
| Rejouer un déverrouillage de secours capturé | inutile : défi consommé | `testCapturedGrantForOldChallengeIsUseless` |
| Supprimer les dernières entrées du journal | détecté (ancre) | `testTruncationIsDetectedByAnchor` |
| Champ JSON inconnu ou message de 4 Mo | refusé avant traitement | `testUnknownFieldIsRejected`, `testOversizedLengthIsRejectedImmediately` |

Contrôles vérifiés par relecture :
- **Logs :** aucun `print()` ; `os.Logger` ne rend publics que des textes fixes, jamais une clé, un jeton ou une position.
- **Aperçu multitâche :** l'écran est masqué dès que l'app n'est plus active.
- **Presse-papiers :** ce qui est copié du coffre reste local à l'appareil et expire en 60 s.
- **Stockage :** tout est en `ThisDeviceOnly`. K_vault et K_id exigent Face ID, avec `biometryCurrentSet` : ajouter un visage invalide la clé.

## 6. À refaire sur appareil (quand on aura deux iPhone)

1. RT-2 : armé, vérifier que « Oublier la balise » et « Oublier la centrale » sont grisés. Désarmé, vérifier que Face ID est demandé.
2. RT-3 : en alerte, appuyer trois fois sur « Annuler » ; le secours ne doit **pas** apparaître. Trois visages refusés : il doit apparaître.
3. RT-1 : couper le Mac 10 min pendant une alerte, puis le rallumer. Toutes les positions doivent arriver, avec la mention « différée ».
4. R-4 : au premier lancement de la centrale, vérifier quel Keychain est utilisé.
