# Installer et lancer RobAir pour tester (sur un Mac)

> Ce guide va de « Mac prêté vierge » à « alerte reçue sur la centrale ». Compter environ **45 min la première fois**, puis environ **10 min par séance**.
> Le premier projet Xcode se crée une seule fois : voir [xcode-setup.md](xcode-setup.md). Ce guide y renvoie à l'étape 3.

## 0. Ce qu'il faut avoir

| Matériel | Rôle dans le test | Indispensable ? |
|---|---|---|
| Un Mac avec **Xcode 15.3 ou plus récent** et macOS 14 | compile tout, fait tourner la **centrale** | oui |
| **iPhone A** (iOS 17 ou plus récent) | **Capteur** : le téléphone protégé | oui |
| **iPhone B** (iOS 17 ou plus récent) | **Balise** : le téléphone qu'on garde sur soi | oui pour tester la rupture BLE |
| Un câble USB-C ou Lightning | première installation sur chaque iPhone | oui |
| Un **identifiant Apple** (compte gratuit) | signature des apps | oui |
| Le même réseau Wi-Fi pour le Mac et l'iPhone A | canal local chiffré | oui |

**Avec le simulateur seul**, on ne peut tester que l'interface. Il n'a pas de caméra pour scanner les QR codes, pas de Bluetooth, pas de Secure Enclave et pas de Face ID. L'appairage, la balise et l'alerte demandent de **vrais iPhone**.

## 1. Préparer le Mac (à chaque séance)

```bash
git clone <url-du-dépôt> RobAir
cd RobAir
sh scripts/setup.sh
```

`setup.sh` vérifie qu'Xcode est installé, puis demande deux choses :

1. **Team ID**. Dans *Xcode > Settings > Accounts*, ajouter son identifiant Apple, sélectionner « Personal Team » et copier l'identifiant à 10 caractères. On le voit aussi dans *Signing & Capabilities* une fois le projet ouvert.
2. **Préfixe d'identifiant**, par exemple `fr.m2.prenomnom`. Il doit être **unique** : deux membres qui signent avec le même préfixe sur des comptes différents se bloquent mutuellement.

Le script crée ensuite `Config/Signing.local.xcconfig`. Ce fichier est ignoré par git, et c'est voulu : il ne doit jamais être commité. Puis le script lance les tests du module.

**Résultat attendu :** `Tests OK.`, avec 103 tests exécutés. En cas d'échec, s'arrêter là et noter la sortie dans le journal IA.

## 2. Vérifier le module seul (facultatif, rapide)

```bash
cd RobAirKit && swift test          # 103 tests, toute la crypto et la logique de sécurité```

## 3. Ouvrir le projet Xcode

- **Le dépôt contient déjà `RobAir.xcodeproj` :** double-cliquer dessus.
- **Il ne le contient pas encore :** suivre une fois [xcode-setup.md](xcode-setup.md), puis commiter le projet comme indiqué dans ce guide.

Dans Xcode, il y a deux **schémas** (menu en haut à gauche) : `RobAir` pour l'iPhone et `RobAirCentrale` pour le Mac.

## 4. Lancer la centrale sur le Mac

1. Choisir le schéma **RobAirCentrale** et la destination **My Mac**, puis faire **⌘R**.
2. Au premier lancement, macOS demande d'**autoriser les connexions réseau entrantes** : accepter. Il demandera aussi l'accès à la **caméra**, mais seulement au premier scan d'une demande de secours.
3. Dans le panneau de gauche, sous « Centrale » :
   - « Clé maîtresse » affiche **Secure Enclave** ou **repli logiciel**. **Noter la valeur** dans le J2 §15.
   - Cliquer sur **Déverrouiller (Touch ID)**. Sans Touch ID, macOS demande le mot de passe de la session. La centrale accepte les sessions pendant 30 min.
   - « Clé HPKE » indique « à créer (Touch ID) » : elle sera créée à l'appairage.

## 5. Installer l'app sur les deux iPhone

À faire pour **chaque** iPhone :

1. Brancher l'iPhone au Mac, le déverrouiller et répondre **« Se fier à cet ordinateur »**.
2. Activer le **mode développeur** sur l'iPhone : *Réglages > Confidentialité et sécurité > Mode développeur*, puis redémarrer. Cette option n'apparaît qu'une fois l'iPhone branché à Xcode.
3. Dans Xcode, choisir le schéma **RobAir** et sélectionner l'iPhone comme destination, puis faire **⌘R**.
4. Au premier lancement, iOS refuse d'ouvrir l'app (« développeur non approuvé ») : aller dans *Réglages > Général > VPN et gestion de l'appareil*, choisir son identifiant Apple puis **Faire confiance**. Relancer ensuite avec ⌘R.
5. Accepter les autorisations quand elles apparaissent : **Bluetooth**, **réseau local**, **caméra**, **localisation (« Lorsque l'app est active »)** et **Face ID**. Un refus bloque la fonction correspondante. Pour corriger, aller dans *Réglages > RobAir*.

Au lancement, l'app demande « Quel rôle joue cet iPhone ? » :
- **iPhone A** : **Capteur : le téléphone à protéger** ;
- **iPhone B** : **Balise : le téléphone que je garde sur moi**.

> Avec un compte gratuit, une app installée **expire après 7 jours**, et on est limité à 3 apps par appareil. **Réinstaller la veille de chaque démo** (J1 §7).

## 6. Appairer le Capteur avec la centrale

| Sur le Mac | Sur l'iPhone A (Capteur) |
|---|---|
| Cliquer sur **Appairer un iPhone** : un QR code s'affiche. | Appuyer sur **Scanner le QR code du Mac** et viser l'écran. |
| Le Mac affiche une **empreinte courte**. | L'iPhone affiche une empreinte. |
| Si les deux empreintes sont **identiques**, cliquer sur **Identiques : confirmer (Touch ID)**. | L'appairage se termine et l'écran principal s'affiche. |

Si les empreintes sont différentes, cliquer sur **Refuser** : c'est le scénario d'attaque de l'homme du milieu (J1 §3.2).

Ensuite, sur l'iPhone A, appuyer sur **Se connecter (Face ID)**. Sur le Mac, « Session chiffrée » doit passer à **Établie**.

## 7. Appairer la Balise avec le Capteur

1. Sur l'**iPhone B (Balise)**, appuyer sur **Afficher le QR code d'appairage**. Ce QR code contient la clé secrète de la balise : ne le montrer qu'au capteur, puis le **Masquer**.
2. Sur l'**iPhone A (Capteur)**, dans la section « Balise de confiance », appuyer sur **Scanner le QR code de la balise**.
3. Sur l'iPhone B, laisser l'app **ouverte, au premier plan**.

## 8. Scénarios de test

Faire les tests dans l'ordre. Chaque résultat va dans la **grille du J2 §14**.

| # | Action | Résultat attendu |
|---|---|---|
| 1 | Sur l'iPhone A, appuyer sur **Armer la surveillance**, les deux iPhone côte à côte. | Sur le Mac, « Surveillance » passe à l'état armé et « Balise » indique que la balise est présente. Le journal ajoute des entrées. |
| 2 | Éloigner l'iPhone A d'environ 10 à 15 m, ou mettre la Balise dans une boîte métallique. | Après environ 3 s sous −85 dBm, l'iPhone A affiche **ALERTE RobAir** et le coffre se ferme. Le Mac passe au **rouge** et des positions apparaissent sur la carte. |
| 3 | Rapprocher les deux iPhone. | L'alerte **reste active** : le retour de la balise ne la lève pas. |
| 4 | Sur l'iPhone A, appuyer sur **Lever l'alerte avec Face ID**. | Retour à l'état normal. |
| 5 | Sur le Mac, cliquer sur **Fin d'alerte (téléphone retrouvé)**, puis sur l'iPhone A **Confirmer avec Face ID**. | Le défi Mac → iPhone est accepté et une entrée « challenge » apparaît dans le journal. Essayer aussi avec **Refuser**. |
| 6 | Sur l'iPhone A, appuyer sur **Envoyer une télémétrie de test**. | Une position arrive sur le Mac. |
| 7 | Couper le Wi-Fi du Mac, puis déclencher une alerte. | Les positions attendent dans la file de l'iPhone. Elles arrivent au retour du Wi-Fi, si elles ont 72 h au plus (J2 §3, écart 4). |
| 8 | Sur l'iPhone A en alerte, échouer plusieurs fois Face ID, puis appuyer sur **Demander le déverrouillage à la centrale**. | Un QR code s'affiche. Sur le Mac, cliquer sur **Lire une demande de secours (webcam)**, comparer le code à 6 chiffres puis cliquer sur **Autoriser (Touch ID)**. L'iPhone scanne la réponse avec **Scanner la réponse du Mac**. |
| 9 | Sur le Mac, cliquer sur **Vérifier l'intégrité** du journal. | Le résultat affiché est **Intact**. |
| 10 | Sur le Mac, cliquer sur **Verrouiller**, puis sur l'iPhone A **Se connecter**. | La session est refusée : la centrale est verrouillée. |

## 9. Voir les journaux de l'app

Dans Xcode, la **console** affiche les logs en bas de l'écran pendant un lancement avec ⌘R. Pour les logs sans câble, ouvrir l'app **Console** de macOS, sélectionner l'iPhone et filtrer sur `robair`. Les logs ne contiennent ni clé ni position : c'est voulu.

## 10. Problèmes fréquents

| Symptôme | Cause probable | Solution |
|---|---|---|
| « Signing for RobAir requires a development team » | `setup.sh` n'a pas été lancé, ou le xcconfig n'est pas branché | relancer `sh scripts/setup.sh` ; vérifier l'étape 3 de [xcode-setup.md](xcode-setup.md) |
| « Failed to register bundle identifier » | le préfixe est déjà pris par un autre compte | changer de préfixe dans `setup.sh` |
| « No such module 'RobAirKit' » | le package local n'est pas ajouté à la cible | faire *General > Frameworks*, **+**, puis ajouter `RobAirKit` |
| L'app ne s'ouvre pas sur l'iPhone | le développeur n'est pas approuvé, ou le mode développeur est désactivé | voir l'étape 5, points 2 et 4 |
| L'iPhone ne trouve pas la centrale | le Mac et l'iPhone sont sur des Wi-Fi différents, le réseau local est refusé, ou le Wi-Fi isole les clients (fréquent sur le Wi-Fi de l'école) | même réseau ; *Réglages > RobAir > Réseau local* ; sinon utiliser le partage de connexion d'un des iPhone |
| « Session refusée » | la centrale est verrouillée | cliquer sur **Déverrouiller (Touch ID)** sur le Mac |
| La balise n'est jamais détectée | l'app Balise est en arrière-plan, ou le Bluetooth est refusé | laisser la Balise ouverte au premier plan ; vérifier *Réglages > RobAir > Bluetooth* |
| Fausse alerte en intérieur | le RSSI est très variable selon l'environnement | noter les mesures et ajuster les seuils (`RobAirConstants`) **après discussion en équipe** |
| L'app a disparu après une semaine | le compte gratuit limite la signature à 7 jours | réinstaller avec ⌘R |

## 11. Fin de séance sur un Mac prêté

1. Dans l'app Mac, cliquer sur **Réinitialiser la centrale**. Cela efface les clés, l'appairage et le journal. Il faudra réappairer l'iPhone à la prochaine séance.
2. Lancer `sh scripts/cleanup.sh`. Le script supprime `Signing.local.xcconfig`, les builds et les DerivedData.
3. Faire `git push` de son travail.
4. Dans *Xcode > Settings > Accounts*, **retirer son identifiant Apple**.
