# Journal des prompts IA (commenté)

> Livrable obligatoire (sujet, slides 8 et 20 ; J1 §8). On consigne chaque prompt utile, avec un **commentaire critique**.
> Règles : aucun secret ni aucune donnée réelle dans un prompt ; aucun code crypto fusionné sans relecture humaine ; aucune dépendance non vérifiée.
> Les entrées #01 à #03 sont antérieures à ce format : leur prompt exact n'a pas été conservé, il est résumé fidèlement.

## Modèle d'entrée (J1 §8)

```markdown
### Entrée #NN - [Date : JJ/MM/AAAA]
* **Rôle demandeur :**
* **Tâche visée :**
* **Prompt exact utilisé :**
* **Code proposé par l'IA :** analyse de la proposition
* **Corrections humaines :**
* **Validation et tests :**
* **Relecteur :**
```

---

### Entrée #01 - [Date : 19/11/2026]
* **Rôle demandeur :** chef de projet
* **Tâche visée :** analyse du sujet et planification des jalons J1 et J2.
* **Prompt exact utilisé :** non conservé. Résumé fidèle : analyser le sujet (PDF de 20 slides) et la note de cadrage, puis établir le plan des jalons J1 et J2, avec des explications à transmettre à l'équipe.
* **Code proposé par l'IA :** pas de code. Synthèse du sujet, rappel des obligations liées à l'IA, plan des livrables.
* **Corrections humaines :** _à compléter_
* **Validation et tests :** comparaison avec les slides 8, 12 et 20.
* **Relecteur :** _à compléter_

### Entrée #02 - [Date : 19/11/2026]
* **Rôle demandeur :** chef de projet
* **Tâche visée :** premier dossier J1/J2 et premier code (ancienne architecture : le Mac servait de balise BLE).
* **Prompt exact utilisé :** non conservé. Résumé fidèle : structurer le cadrage et le STRIDE, produire l'architecture et les choix crypto, puis le code du MVP.
* **Code proposé par l'IA :** module `AntivolKit` (handshake signé, trames AES-GCM, appairage QR, preuve BLE, journal chaîné, 62 tests), apps iPhone et Mac.
* **Corrections humaines :** cette architecture a été **remplacée** par le cadrage BleSentry de l'équipe (entrée #06). Le code reste consultable sur la branche `feat/robairkit`.
* **Validation et tests :** jamais compilé ni testé à l'époque (constat de l'entrée #04).
* **Relecteur :** _à compléter_

### Entrée #03 - [Date : 19/11/2026]
* **Rôle demandeur :** chef de projet
* **Tâche visée :** environnement de développement sur des Mac prêtés (un Mac différent à chaque séance).
* **Prompt exact utilisé :** non conservé. Résumé fidèle : choisir comment réinstaller l'environnement à chaque séance (conteneur ou autre).
* **Code proposé par l'IA :** Docker écarté (pas de macOS ni d'Xcode en conteneur). Proposition : dépôt git autonome sans dépendance tierce + scripts `setup.sh` / `cleanup.sh` (écrits à l'entrée #06). Conséquence : réappairage à chaque nouveau Mac.
* **Corrections humaines :** _à compléter_
* **Validation et tests :** _à compléter (version d'Xcode des Mac de l'école)._
* **Relecteur :** _à compléter_

### Entrée #04 - [Date : 20/11/2026]
* **Rôle demandeur :** _à compléter_
* **Tâche visée :** point d'étape sur l'état du projet.
* **Prompt exact utilisé :**
  > « Je ne sais plus ou on en est. Re analyse bien le projet. Fais moi une bonne analyse de projet sous format pdf. »
* **Code proposé par l'IA :** `docs/analyse-projet-2026-11-20.pdf`. Il relevait que le code n'avait jamais été compilé, qu'il n'y avait ni projet Xcode ni dépôt git, et que le journal IA était incomplet. **Ce document décrit l'ancienne architecture** et a été rendu obsolète par l'entrée #06.
* **Corrections humaines :** _à compléter_
* **Validation et tests :** _à compléter_
* **Relecteur :** _à compléter_

### Entrée #05 - [Date : 20/11/2026]
* **Rôle demandeur :** _à compléter_
* **Tâche visée :** renommage du projet et procédure git.
* **Prompt exact utilisé :**
  > « Pour commencer change le nom du projet dans tous les docs et code, on l'a nommé "RobAir" qui est un jeu de mot avec le verbe rob en anglais et Air pour le coté apple. Et pour après fais moi la liste des commandes git pour faire un depot propre et professionnels. »
* **Code proposé par l'IA :** renommage Antivol → RobAir (dossiers, types, service Bonjour `_robair._tcp`, étiquettes crypto, Keychain, logs, docs), puis liste des commandes git (branche par lot, PR relue, `main` protégée, tags de jalons).
* **Corrections humaines :** dépôt créé par l'équipe ; `Projet M2.pdf` exclu du dépôt.
* **Validation et tests :** _à compléter_
* **Relecteur :** _à compléter_

### Entrée #06 - [Date : 20/11/2026]
* **Rôle demandeur :** _à compléter_
* **Tâche visée :** remettre tout le dépôt (docs, module, apps, relais) en conformité avec le cadrage J1 de l'équipe (ex-BleSentry).
* **Prompt exact utilisé :**
  > « Le readme est faux, verifie tout le projet. Notre projet est lié aux appareils comme Apple Watch...etc. Voici ci-joint un résumé qui n'est pas celui que l'on a actuellement. Repare tout en te basant sur ce fichier. »

  Fichier joint : le cadrage J1 de l'équipe. Réponses données à l'IA : garder le nom **RobAir** ; portée **« tout, relais compris »**.
* **Code proposé par l'IA :**
  - `docs/J1-cadrage.md` = cadrage de l'équipe, seul le nom est changé.
  - `docs/J2-architecture.md` réécrit, avec **14 écarts et précisions par rapport au J1** à valider (§3).
  - `RobAirKit` réécrit : session X25519 signée + renouvellement dans la session, enveloppe §3.4, décodage strict, appairage avec K_enc signée, télémétrie HPKE signée + `ackSecret`, défi Mac → iPhone, secours, balise HMAC, détection de rupture, machine à états, journal signé + ancre, client relais épinglé. **103 tests.**
  - App iPhone à deux modes (Capteur / Balise), app Mac (session opérateur Touch ID, carte, secours, webcam, relais).
  - Relais en Python, bibliothèque standard uniquement. **15 tests**, déploiement durci.
* **Corrections humaines :** _à compléter. Décider pour chaque écart du J2 §3 : gardé, modifié ou rejeté. En particulier la question ouverte n°4 (fenêtre de 300 s pour la télémétrie en file)._
* **Validation et tests :**
  - 103 tests `RobAirKit` exécutés par l'IA sous Linux avec `swift-crypto` (portage officiel de CryptoKit), hors du dépôt.
  - Un test a révélé un **vrai défaut** : une clé X25519 de faible ordre donnait un secret nul sans erreur. Il a été corrigé par une vérification explicite.
  - 15 tests du relais exécutés.
  - Les apps iPhone et Mac n'ont **pas** pu être compilées par l'IA (pas de macOS) : seules les API du module qu'elles utilisent ont été vérifiées par compilation.
  - _À faire : `swift test` sur Mac, build Xcode, tests manuels du J2 §14._
* **Relecteur :** _à compléter (code crypto et réseau : deux relecteurs dont l'architecte sécurité, J1 §6.1)._

### Entrée #07 - [Date : 20/11/2026]
* **Rôle demandeur :** _à compléter_
* **Tâche visée :** vérifier l'affirmation du J1 §1.3 sur les AirPods et l'Apple Watch.
* **Prompt exact utilisé :**
  > « Pour le J1-cadrage.md, tu dis que les airpods, apple watch ne sont pas exposés aux apps tierces mais on peut accéder aux appareils via le bluetooth normalement ? »
* **Code proposé par l'IA :** pas de code. Explication : CoreBluetooth ne gère que le BLE GATT. Les AirPods utilisent le Bluetooth classique pour l'audio, et iOS filtre leurs annonces BLE propriétaires. Une app peut seulement voir leur connexion via la sortie audio (`AVAudioSession`), sans RSSI, sans défi cryptographique et avec des faux positifs. L'Apple Watch n'apparaît pas dans CoreBluetooth, et `WatchConnectivity` reste joignable via le Wi-Fi même à distance. Reformulation de la ligne du J1 §1.3, et proposition d'utiliser la déconnexion des AirPods comme signal secondaire (P2).
* **Corrections humaines :** l'équipe avait raison de nuancer : la formulation initiale (« pas exposés aux apps tierces ») était trop absolue. Reformulation acceptée.
* **Validation et tests :** _à faire sur appareil : scan CoreBluetooth avec des AirPods connectés (attendu : invisibles) ; `routeChangeNotification` en retirant les AirPods (attendu : `oldDeviceUnavailable`)._
* **Relecteur :** _à compléter_

### Entrée #08 - [Date : 20/11/2026]
* **Rôle demandeur :** _à compléter_
* **Tâche visée :** guide d'installation et de test sur Mac.
* **Prompt exact utilisé :**
  > « Fais moi un fichier, pour comprendre l'installation et le lancement de l'appli pour tester sur le mac. »
* **Code proposé par l'IA :** `docs/installation-et-test.md`. Il couvre le matériel, `setup.sh`, le lancement de la centrale, l'installation sur les deux iPhone (mode développeur, approbation du développeur), l'appairage Mac ↔ Capteur puis Capteur ↔ Balise, 10 scénarios de test, les logs, le dépannage et la fin de séance. Le guide est lié depuis `README.md` et `docs/xcode-setup.md`. Les libellés des boutons ont été recopiés depuis le code des vues.
* **Corrections humaines :** _à compléter après un premier passage réel sur Mac (le guide n'a pas pu être exécuté par l'IA)._
* **Validation et tests :** _à faire : suivre le guide pas à pas et corriger les écarts constatés._
* **Relecteur :** _à compléter_

### Entrée #09 - [Date : 20/11/2026]
* **Rôle demandeur :** chef de projet
* **Tâche visée :** état du dépôt git et processus de revue (2 approbations, architecte sur le code crypto).
* **Prompt exact utilisé :**
  > « Fais un etat actuel du git et dis moi quoi faire pour que tout soit a jour sachant que le developpeurs et architecte doivent approuvé notamment lors des MR. »

  Puis : « Voici les deux autres membres : Rayouuuuuu : Developper, Samuel-DD07 : Architecte, Moi : Chef de projet. »
* **Code proposé par l'IA :** état du dépôt (refonte non commitée, `feat/robairkit` à ne pas fusionner) ; découpage en 3 PR empilées (docs, code, relais) ; réglages GitHub (ruleset sur `main` : 2 approbations, Code Owners, pas de contournement, merge commit uniquement) ; `.github/CODEOWNERS` et `.github/pull_request_template.md`. Mise à jour des rôles dans le J1 §6 et le README. Inversion de la Red Team J2/J3 pour respecter la règle « jamais sur son propre travail » : l'architecte ne peut pas attaquer sa propre architecture.
* **Corrections humaines :** _à compléter (valider l'inversion de la Red Team)._
* **Validation et tests :** _à faire : vérifier sur GitHub qu'une PR sans 2 approbations ne peut pas être fusionnée, même par le propriétaire._
* **Relecteur :** _à compléter_
