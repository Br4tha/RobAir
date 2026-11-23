# J1 · RobAir : alerte anti-vol par rupture de proximité BLE et centrale de secours Mac

> **Cadre :** Projet de groupe · Master 2 Cybersécurité
> **Équipe :** Samuel Dorismond · Rayann Bouheddou · Manaia Logologofolau
> **Mission :** Faire de l'iPhone un équipement de sécurité physique et numérique
> **Contraintes :** 0 € de licence Apple (compte développeur gratuit), 1 iPhone (le capteur), 1 Mac (la centrale et l'atelier)
> **Document de référence :** `Projet M2.pdf` (non versionné : support de l'enseignant)
> **Nom :** *RobAir*, jeu de mots entre *rob* (« voler » en anglais) et *Air*, clin d'œil à la gamme Apple. Nom de travail précédent : BleSentry.
> **Suite :** les protocoles sont formalisés dans [J2-architecture.md](J2-architecture.md), qui liste aussi les écarts et précisions apportés à ce cadrage.

---

## 1. Fiche d'identité et cadrage du projet (Jalon 1)

### 1.1 Problématique et contexte
Le vol d'iPhone « à l'arraché » dans l'espace public (souvent commis à vélo ou à trottinette) vise des téléphones **déjà déverrouillés** dans la main de la victime. Dans ce scénario :
* le voleur n'a pas à franchir Face ID ni le code ;
* il accède aussitôt aux données ouvertes sur le téléphone ;
* il active le mode avion ou éteint l'appareil avant que le propriétaire ait pu réagir via *Localiser*.

### 1.2 La solution : RobAir
**RobAir** fait de l'iPhone un capteur de proximité adossé à une **balise BLE de confiance** que l'utilisateur porte sur lui, et supervisé par un Mac qui sert de centrale.

* **Détection du vol :** l'iPhone reste connecté à la balise et surveille la rupture de connexion et la chute du signal (RSSI).
* **Verrouillage réflexe de l'application :** à la rupture, RobAir ferme son coffre chiffré, efface au mieux les secrets de sa mémoire vive et affiche un écran d'alerte qui exige Face ID.
* **Alerte et télémétrie :** l'iPhone envoie immédiatement une alerte puis ses positions GPS, signées par la **Secure Enclave** et chiffrées pour le Mac. Sur le Wi-Fi local, elles passent par le canal direct ; hors de portée, par un **relais Internet aveugle** (§3.6).
* **Déverrouillage de secours par le Mac :** en cas de fausse alerte et d'échec répété de Face ID, le Mac appairé peut lever le verrouillage **de l'application** par un défi-réponse signé (§3.8).

### 1.3 Périmètre et limites assumées (iOS, compte gratuit)
Ces limites sont posées dès le J1 pour ne pas surpromettre à la soutenance :

| Limite | Conséquence pour RobAir |
| :--- | :--- |
| Une app ne peut pas verrouiller iOS, ni empêcher l'extinction, le mode avion ou la sortie de l'app. | RobAir protège **ses propres données** (coffre) et donne l'alerte. Pour bloquer tout le téléphone, l'utilisateur doit avoir activé l'*Accès guidé* d'iOS à la main : c'est documenté comme une option, pas comme une garantie. |
| AirPods et Apple Watch ne sont pas accessibles comme périphériques BLE par CoreBluetooth : impossible de lire leur RSSI ou de leur envoyer un défi cryptographique. Une app peut seulement savoir si des AirPods sont connectés (sortie audio, `AVAudioSession`), ce qui ne donne ni distance ni preuve d'identité et provoque des faux positifs (boîtier, batterie). La liaison de l'Apple Watch, gérée par le système, reste « joignable » via le Wi-Fi même à distance. | La déconnexion des AirPods pourra servir de **signal secondaire** (P2) pour déclencher l'alerte, jamais pour la lever. La balise de confiance est le **mode « Balise »** de RobAir, lancé sur un second iPhone que porte l'utilisateur (celui d'un membre de l'équipe pour la démo). Ce mode expose un service GATT propre avec `CBPeripheralManager`. Coût : 0 €, sans matériel en plus, avec le même code Swift. Plus tard, une carte ESP32 (≈ 5 €) pourra remplacer ce second téléphone. |
| En arrière-plan, iOS limite le BLE et suspend les apps. | On active les modes d'arrière-plan `bluetooth-central` et `location` : l'événement de déconnexion est livré même en arrière-plan, et la localisation en continu garde l'app active pour l'envoi. |
| Téléphone éteint ou en mode avion : plus aucun envoi. | La première alerte part **dès la rupture**, en priorité absolue : c'est la dernière position connue qui compte. |
| Pas d'APNs ni d'iCloud avec un compte gratuit. | Aucune notification push : le Mac **interroge** le relais à intervalle régulier (§3.6). |
| L'app installée expire au bout de 7 jours. | Réinstallation depuis Xcode avant chaque démo et chaque séance d'audit (§7). |

### 1.4 Écart au sujet à faire valider au J1 (extension, priorité P2)
Le sujet prévoit un canal iPhone ↔ Mac **sur le Wi-Fi local**, et ce canal reste le socle du projet (§11). **En extension seulement**, une fois le socle imposé terminé, nous proposons d'ajouter un **relais Internet aveugle** pour la télémétrie hors de portée. Le relais ne voit que des messages chiffrés de bout en bout et signés. Il ne peut ni les lire ni les falsifier. Il est intégré à la STRIDE (§4) et à l'audit MASVS (§5). **Si l'encadrant refuse cet écart**, le repli prévu : les positions sont gardées dans une file locale chiffrée et renvoyées dès que le Mac redevient joignable.

---

## 2. Architecture matérielle et rôles

```
 [Balise BLE de confiance]        [iPhone : le capteur]                [Mac : la centrale]
  (2e iPhone en mode Balise)
          │                                │                                    │
          │ 1. Connexion GATT + défi HMAC  │                                    │
          │◄──────────────────────────────►│                                    │
          │                                │                                    │
          │ 2. Rupture (vol / éloignement) │                                    │
          x - - - - - - - - - - - - - - - >│                                    │
                                           │ 3. VERROUILLAGE DE L'APP           │
                                           │  - coffre fermé, écran d'alerte    │
                                           │  - effacement mémoire (au mieux)   │
                                           │  - alarme sonore + GPS             │
                                           │                                    │
                                           │ 4a. Télémétrie, Wi-Fi local        │
                                           ├───────────────────────────────────►│
                                           │  (session E2E éphémère, AES-GCM)   │
                                           │                                    │
                                           │ 4b. Hors de portée : HTTPS         │
                                           ├────────►[Relais : mini-serveur]◄───┤ (le Mac interroge)
                                           │  (HPKE + signature Secure Enclave) │
                                           │                                    │
                                           │ 5. Déverrouillage de secours       │
                                           │◄──────────────────────────────────►│ (défi de l'iPhone,
                                           │  (Wi-Fi local ou QR code)          │  signé par le Mac)
```

### 2.1 iPhone (le capteur) : Swift / SwiftUI
* **`CoreBluetooth` :** connexion à la balise, lecture du RSSI au premier plan, détection de déconnexion en arrière-plan, défi HMAC périodique contre le clonage de balise.
* **`CoreLocation` :** localisation en continu, déclenchée en état d'alerte seulement.
* **`LocalAuthentication` :** Face ID pour ouvrir le coffre et pour chaque opération sensible.
* **`Security` et `CryptoKit` :** clés non exportables dans la **Secure Enclave**, Keychain `ThisDeviceOnly`, AES-GCM, HKDF, HPKE.
* **`Network.framework` :** canal local vers le Mac, découverte Bonjour.
* **Écran d'alerte :** plein écran opaque qui exige Face ID ou le déverrouillage de secours. L'*Accès guidé* est conseillé à l'utilisateur, mais reste optionnel.

### 2.2 Mac (la centrale et l'atelier) : app macOS SwiftUI
* **Même langage que l'iPhone :** le code du protocole (format des messages, crypto, validation) est mis en commun dans un **Swift Package partagé**, `RobAirKit`. On n'a qu'une implémentation à relire et à tester.
* **Appairage :** affichage du QR code et comparaison d'une empreinte courte (§3.2).
* **Tableau de bord :** état du capteur (armé, en alerte, verrouillé), carte des positions reçues.
* **Journal d'audit :** ajout seul et chaîné par hash (chaque entrée contient le hash de la précédente), ce qui rend toute altération détectable.
* **Autorité de secours :** détient la clé maîtresse, non exportable, dans la Secure Enclave du Mac (puce Apple M). Chaque signature exige Touch ID ou le mot de passe de session.
* **Interrogation du relais :** toutes les 30 s pendant une alerte.

### 2.3 Relais aveugle (mini-serveur auto-hébergé), extension P2
* Simple boîte aux lettres : il stocke des messages opaques, avec une durée de vie limitée.
* **Hébergement :** le mini-serveur de l'équipe est exposé sur Internet par une redirection du **port 443 seul** sur la box.
  * **Prérequis à vérifier :** une IP publique, pas de partage d'IP entre abonnés chez l'opérateur (CGNAT), et un nom de domaine. Un DNS dynamique gratuit peut servir de nom de domaine.
* **Durcissement :**
  * utilisateur système dédié ;
  * pare-feu qui n'ouvre que le port 443 ;
  * SSH fermé côté Internet ;
  * mises à jour automatiques ;
  * relais isolé du reste du réseau domestique si la box le permet.
* HTTPS en TLS 1.3, certificat Let's Encrypt. Le **pinning** de la clé publique du serveur est fait dans les apps.
* Stack à trancher au J2. Critère : le **minimum de dépendances**, toutes vérifiées.

---

## 3. Protocoles cryptographiques et réseau (Zero Trust)

Le Wi-Fi local, Internet et le relais sont tous considérés comme **non fiables**.

### 3.1 Inventaire des clés

| Clé | Type | Où | Protection | Usage |
| :--- | :--- | :--- | :--- | :--- |
| `K_id_iPhone` | P-256 signature | Secure Enclave iPhone | `WhenUnlockedThisDeviceOnly` + `biometryCurrentSet` (Face ID) | Défi-réponse (§3.7), signature des poignées de main (§3.3) |
| `K_tel_iPhone` | P-256 signature | Secure Enclave iPhone | `AfterFirstUnlockThisDeviceOnly`, sans biométrie | Signature de la **télémétrie seulement** |
| `K_vault` | AES-256 | Keychain iPhone | `WhenUnlockedThisDeviceOnly` + `biometryCurrentSet` | Chiffrement du coffre local |
| `K_id_Mac` | P-256 signature | Secure Enclave du Mac (puce Apple M) | Touch ID / mot de passe | Clé maîtresse : poignées de main, déverrouillage de secours |
| `K_enc_Mac` | X25519 | Keychain du Mac | Rotation hebdomadaire, nouvelle clé publique signée par `K_id_Mac` | Réception HPKE de la télémétrie |
| Clés de session | X25519 éphémères | RAM | Détruites à la fin de la session | Canal local avec forward secrecy |

**Pourquoi deux clés de signature côté iPhone.** La télémétrie doit partir alors que le téléphone est **verrouillé** et que le voleur le tient, donc sans Face ID. Sa clé est donc `AfterFirstUnlock`. On limite le risque en la réservant à un seul usage : elle ne signe que des messages de type `TELEMETRY`, que le Mac refuse pour toute autre action.

**Fichiers.** Tous les fichiers sont en `NSFileProtectionComplete`, comme l'exige le sujet. **Une seule exception**, justifiée : la file d'envoi de télémétrie est en `CompleteUnlessOpen`, parce qu'elle doit pouvoir être écrite téléphone verrouillé. Elle ne contient que des messages **déjà chiffrés pour le Mac**, que l'iPhone ne peut lui-même pas relire.

### 3.2 Appairage initial (QR code + empreinte)
1. Le Mac génère `K_id_Mac` et `K_enc_Mac`. Il affiche un QR code contenant `{mac_id, pk_id_Mac, pk_enc_Mac, url_relais, empreinte_tls_relais, jeton_appairage (usage unique, 5 min)}`.
2. L'iPhone scanne le QR code, génère `K_id_iPhone` et `K_tel_iPhone` dans la Secure Enclave, puis envoie ses clés publiques au Mac sur le réseau local, avec le jeton d'appairage.
3. Les deux écrans affichent une **empreinte courte** (6 chiffres, calculée par SHA-256 sur toutes les clés publiques échangées). L'utilisateur vérifie qu'elle est identique sur les deux. C'est ce qui bloque l'homme du milieu.
4. Le Mac crée la boîte aux lettres sur le relais. Il transmet à l'iPhone son jeton d'écriture par le canal chiffré (§3.3), et garde pour lui le jeton de lecture.

### 3.3 Session locale avec forward secrecy
À chaque connexion iPhone ↔ Mac :
1. Chaque côté génère une paire **X25519 éphémère** et **signe sa clé publique éphémère** avec sa clé d'identité. La signature porte aussi sur les deux identifiants et un aléa de 32 octets fourni par chaque côté.
2. Chaque côté vérifie la signature de l'autre avec la clé publique enregistrée à l'appairage.
3. Clés de session : `HKDF-SHA256(ECDH(éphémères), salt = hash de toute la transcription)`. On en dérive **deux clés AES-256-GCM, une par sens**.
4. Les clés éphémères sont jetées. Une clé d'identité volée plus tard ne permet donc pas de déchiffrer les sessions passées : c'est la **forward secrecy**.
5. Nouvelle négociation à chaque reconnexion, toutes les 15 min, et après chaque levée de verrouillage.

### 3.4 Format des messages et règles de réception
```
Enveloppe = { version, type, sender_id, seq, timestamp, ciphertext, tag }
```
* L'en-tête est authentifié comme **données associées** (AAD) d'AES-GCM.
* **Nonce GCM** = préfixe de sens + compteur. Il n'est jamais réutilisé.
* **Anti-rejeu :** le message est refusé si `seq ≤ dernier seq accepté`, ou si l'horodatage s'écarte de plus de 30 s (300 s pour la télémétrie différée via le relais).
* **Validation stricte des entrées :**
  * taille maximale de 4 Ko par message ;
  * décodage typé (`Codable`) avec des types et des bornes vérifiés (latitude dans [−90, 90]…) ;
  * tout champ inconnu fait rejeter le message.
* **Erreur = rejet silencieux, plus une entrée au journal.** On ne renvoie jamais de détail à l'émetteur.

### 3.5 Protocole d'urgence et télémétrie
Dès que la rupture BLE est confirmée (§3.9) :
1. **Fermeture du coffre :** `K_vault` n'est plus chargée et les sessions sont détruites. Les secrets que nous gérons sont écrasés avec `memset_s`, dans des tampons que nous allouons nous-mêmes. **Limite :** Swift ne garantit pas l'absence de copies en mémoire, donc l'effacement est fait *au mieux*. La vraie protection, c'est que les clés sont non exportables (Secure Enclave) et que le coffre exige Face ID.
2. **Contenu du message :**
   $$\text{Payload} = \{\text{type}: \text{TELEMETRY}, \text{iphone\_id}, \text{seq}, \text{timestamp}, \text{lat}, \text{lon}, \text{accuracy}, \text{battery}, \text{trigger}\}$$
3. **Signature :** `K_tel_iPhone`, dans la Secure Enclave.
4. **Chiffrement pour le Mac :** **HPKE** (X25519, HKDF-SHA256, AES-256-GCM, CryptoKit, iOS 17 et plus) avec la clé publique `K_enc_Mac` en vigueur. Il marche **sans session ouverte**, donc aussi via le relais. Le champ `info` d'HPKE lie le message à `iphone_id` et `mac_id`.
5. **Acheminement :** le canal local si le Mac est joignable, sinon `POST` HTTPS vers la boîte aux lettres du relais. En cas d'échec, le message reste dans la file locale (100 entrées au plus) et part dès que le réseau revient.
6. **Réception sur le Mac :** déchiffrement HPKE, vérification de la signature `K_tel_iPhone`, contrôle de `seq` et de l'horodatage, ajout au journal chaîné, puis acquittement. Une fois acquitté, le message est supprimé du relais et de la file.

**Forward secrecy de la télémétrie :** elle est limitée à la période de rotation de `K_enc_Mac` (une semaine). Ce compromis est documenté pour le J2.

### 3.6 Relais aveugle : sécurité
* **Ce qu'il voit :** des messages chiffrés, leur taille, l'heure et l'IP d'origine. **Ce qu'il ne voit pas :** les positions. Il ne peut pas non plus fabriquer un message valide, faute des clés privées.
* **Contrôle d'accès :** un identifiant de boîte aléatoire de 128 bits, plus des jetons d'écriture (iPhone) et de lecture (Mac) distincts, rangés dans le Keychain.
* **Limites :** 4 Ko par message, 60 requêtes par minute et par boîte, durée de vie de 72 h, aucune journalisation des contenus, IP conservées 24 h au plus.
* **Pinning TLS :** l'empreinte de la clé publique du relais est fournie à l'appairage. Même si le TLS tombait, le chiffrement de bout en bout tient.

### 3.7 Authentification forte par défi-réponse (Mac → iPhone), conforme au sujet p.18
Elle sert aux actions sensibles vues depuis le Mac : fin d'alerte (« j'ai retrouvé mon téléphone »), désarmement, changement de configuration.
1. Le Mac envoie un **défi aléatoire** de 32 octets, à usage unique, valable 30 s.
2. L'iPhone demande **Face ID**, ce qui débloque `K_id_iPhone` dans la Secure Enclave. Il signe ensuite `{défi, mac_id, iphone_id, action}`.
3. Le Mac vérifie avec la clé publique enregistrée à l'appairage, puis consomme le défi. La signature, liée à l'action et aux identifiants, ne peut pas resservir ailleurs.

### 3.8 Déverrouillage de secours (iPhone → Mac → iPhone)
**Périmètre :** il lève le verrouillage de **RobAir**, pas celui d'iOS. Si iOS lui-même est verrouillé, l'utilisateur doit d'abord le déverrouiller avec son code : aucune app ne peut contourner ça.
1. L'iPhone, en état d'alerte, génère un **défi** `c` de 32 octets, stocké, à usage unique, valable 120 s. Il l'envoie au Mac sur le réseau local et l'affiche aussi en QR code.
2. L'opérateur du Mac s'authentifie (Touch ID ou mot de passe). Le Mac signe `{action: EMERGENCY_UNLOCK, c, iphone_id, timestamp}` avec `K_id_Mac`.
3. La réponse revient par le réseau local, **ou** le Mac l'affiche en QR code et l'iPhone la scanne. L'écran d'alerte est l'app elle-même, au premier plan, donc la caméra est accessible.
4. L'iPhone vérifie la signature, que `c` est bien le défi en attente, et qu'il n'a pas expiré. Il consomme ensuite `c` : **un ordre capturé ne sert à rien**.
5. Le verrouillage est levé. Le coffre exige malgré tout Face ID ou le code de l'appareil pour charger `K_vault`, et une nouvelle session est négociée.

### 3.9 Détection de rupture BLE (contre les faux positifs et le clonage)
* **Déclenchement :** déconnexion confirmée, **ou** RSSI en moyenne glissante sur 5 s sous un seuil calibré pendant plus de 3 s (hystérésis).
* **Contre le clonage de balise :** toutes les 10 s, l'iPhone envoie un défi à la balise, qui répond `HMAC-SHA256(K_balise, défi)`. La clé `K_balise` est partagée à l'appairage. Une réponse invalide ou absente compte comme une rupture.

---

## 4. Modélisation des menaces : matrice STRIDE

| STRIDE | Composant | Scénario d'attaque | Contre-mesure |
| :--- | :--- | :--- | :--- |
| **S** Usurpation | iPhone | Un attaquant sur le Wi-Fi se fait passer pour le Mac et envoie un faux déverrouillage. | Réponse signée par `K_id_Mac` **sur un défi émis par l'iPhone** (§3.8), clé publique fixée à l'appairage. |
| **S** Usurpation | Balise BLE | Le voleur clone ou relaie l'annonce de la balise pour que l'iPhone se croie toujours à côté. | Défi HMAC périodique avec `K_balise` (§3.9). |
| **S** Usurpation | Appairage | Homme du milieu pendant l'échange des clés. | Clés transmises par QR code + comparaison humaine de l'empreinte courte (§3.2). |
| **S** Usurpation | Relais | Faux relais par DNS ou interception TLS. | Pinning de la clé publique + chiffrement de bout en bout : un faux relais ne lit ni ne fabrique rien. |
| **T** Altération | Réseau | Modification des coordonnées GPS en transit. | AEAD (AES-GCM / HPKE) + signature Secure Enclave du contenu. |
| **T** Altération | Mac | Modification du journal d'audit après coup. | Journal en ajout seul, **chaîné par hash**, et entrées signées. |
| **R** Répudiation | Tous | Contestation d'une alerte (« ce n'est jamais arrivé », « fausse alerte »). | Signatures Secure Enclave non exportables + `seq` + horodatage + journal chaîné. |
| **I** Divulgation | Wi-Fi | Écoute passive des positions. | Session éphémère E2E avec forward secrecy (§3.3). |
| **I** Divulgation | Relais | Relais compromis ou hébergeur curieux. | Il ne voit que des messages chiffrés. Métadonnées (IP, heure) limitées par une durée de conservation courte. **Risque résiduel accepté.** |
| **I** Divulgation | iPhone | Secrets ou positions dans les logs, le presse-papiers ou l'aperçu multitâche. | `os.Logger` en `privacy: .private`, aucune donnée sensible dans les logs. Presse-papiers local à l'appareil, expiration à 60 s. Masquage de l'aperçu multitâche. |
| **I** Divulgation | iPhone | Lecture des fichiers sur un téléphone volé et verrouillé. | `NSFileProtectionComplete`. Seule la file d'envoi fait exception, et elle ne contient que des messages déjà chiffrés pour le Mac (§3.1). |
| **D** Déni de service | BLE | Brouillage pour provoquer des verrouillages intempestifs. | Hystérésis. En cas de doute, l'app verrouille (échec sécurisé, *fail-safe*), et Face ID réarme. |
| **D** Déni de service | Relais | Saturation de la boîte aux lettres. | Limitation de débit, taille maximale, quota par boîte, jetons d'écriture. |
| **D** Déni de service | iPhone | Le voleur éteint le téléphone ou active le mode avion. | **Limite assumée :** l'alerte part dès la rupture, avant toute action du voleur. |
| **E** Élévation | iPhone | Contourner l'écran d'alerte pour ouvrir le coffre. | Le coffre exige `K_vault`, qui exige Face ID (`biometryCurrentSet`). Fermer l'écran n'ouvre rien. |
| **E** Élévation | Mac | Vol ou usage abusif de la clé maîtresse. | Secure Enclave du Mac ou Keychain + Touch ID à chaque signature. Révocation : **nouvel appairage physique**, qui invalide les anciennes clés côté iPhone. |

---

## 5. Préparation de l'audit croisé : les 8 domaines OWASP MASVS

1. **MASVS-STORAGE :**
   * fichiers en `NSFileProtectionComplete`, avec la seule exception justifiée au §3.1 ;
   * Keychain `ThisDeviceOnly`, accès conditionné à Face ID pour `K_vault` et `K_id_iPhone` ;
   * aucun secret dans `UserDefaults`.
2. **MASVS-CRYPTO :**
   * uniquement CryptoKit (P-256 ECDSA, X25519, HKDF-SHA256, AES-256-GCM, HPKE) ;
   * une clé par usage ;
   * nonces jamais réutilisés ;
   * aucun algorithme obsolète.
3. **MASVS-AUTH :** Face ID pour le coffre, défi-réponse Mac → iPhone signé par la Secure Enclave (§3.7), défi iPhone → Mac pour le secours (§3.8).
4. **MASVS-NETWORK :**
   * canal local E2E avec forward secrecy ;
   * relais en HTTPS TLS 1.3 avec pinning, ATS laissé actif sans exception ;
   * aucune donnée en clair sur aucun réseau.
5. **MASVS-PLATFORM :**
   * permissions demandées au bon moment, avec un texte clair ;
   * aperçu multitâche masqué ;
   * presse-papiers local à l'appareil, avec expiration.
6. **MASVS-CODE :**
   * aucun secret écrit en dur ;
   * validation stricte des entrées réseau et BLE (§3.4) ;
   * zéro dépendance tierce côté iPhone et Mac ;
   * relais avec des dépendances minimales et vérifiées.
7. **MASVS-RESILIENCE :** échec sécurisé (perte de lien ou doute ⇒ verrouillage), journal d'audit chaîné.
8. **MASVS-PRIVACY :**
   * positions collectées et transmises **seulement en alerte** ;
   * durée de vie limitée sur le relais ;
   * aucune donnée personnelle dans les logs ;
   * consentement explicite pour la localisation et le Bluetooth.

---

## 6. Organisation de l'équipe et rôles

Le rôle de **Red Team** tourne à chaque jalon. Chaque membre doit pouvoir expliquer **tout le code** à l'oral individuel.

| Rôle | Responsabilités | Membre (GitHub) |
| :--- | :--- | :--- |
| **Chef de projet** | Planning, backlog, dépôt Git, jalons, journal de prompts IA | Manaia Logologofolau (`@Br4tha`) |
| **Architecte sécurité** | STRIDE, choix crypto et leur justification, revues sécurité, relecture obligatoire de tout code crypto | Samuel Dorismond (`@Samuel-DD07`) |
| **Développeur iOS** | Swift / SwiftUI, CoreBluetooth, CoreLocation, `RobAirKit`, app macOS | Rayann Bouheddou (`@Rayouuuuuu`) |

**Rotation de la Red Team** (en plus de son rôle principal, et jamais sur son propre travail) :

| Jalon | Red Team | Cible |
| :---: | :--- | :--- |
| J1 | Rayann Bouheddou | Attaque de la STRIDE et du cadrage |
| J2 | Manaia Logologofolau | Attaque de l'architecture et du protocole |
| J3 | Samuel Dorismond | Attaque du MVP (rejeu, clonage de balise, logs, stockage) |
| J4 | Toute l'équipe | Audit croisé MASVS de l'app d'un autre groupe |

### 6.1 Règles Git et revues
* Branche `main` protégée : on y fusionne seulement par *pull request*, avec **2 approbations** (les deux membres qui ne sont pas l'auteur). Les propriétaires de chaque dossier sont dans `.github/CODEOWNERS`.
* **Un humain valide chaque fusion.** Le code crypto ou réseau exige **deux** relecteurs, dont l'architecte sécurité.
* L'historique des revues fait partie du livrable : on ne fait pas de *squash* qui effacerait les discussions.

---

## 7. Contraintes du compte gratuit : procédure

* **Expiration à 7 jours :** on réinstalle depuis Xcode **la veille** de chaque démo, audit ou soutenance. Le chef de projet le note au planning.
* **Capacités utilisées :** BLE, localisation en arrière-plan, Keychain, Secure Enclave, Face ID, réseau local, notifications locales. Ce sont celles autorisées par le sujet (p.4).
* **Capacités exclues :** APNs, iCloud/CloudKit, Core NFC, AutoFill, domaines associés.
* **Limites de provisioning gratuit** (nombre d'apps et d'identifiants d'app) : à vérifier sur le compte réel dès le J1, pour ne pas être bloqués avant une démo.

---

## 8. Règles avec l'IA et modèle de journal de prompts

Conformément à la partie 1 du cadre pédagogique :
* **Interdit :** coller des secrets ou des données réelles dans une IA, fusionner du code crypto sans relecture humaine, ajouter une dépendance non vérifiée (paquets inventés par l'IA).
* **Obligatoire :** tenir le journal `JOURNAL_IA.md` dans le dépôt Git, avec un commentaire critique pour chaque entrée.

### Modèle d'entrée du journal de prompts
```markdown
### Entrée #01 - [Date : JJ/MM/AAAA]
* **Rôle demandeur :** Développeur iOS
* **Tâche visée :** Gestionnaire CoreBluetooth surveillant la connexion et le RSSI de la balise BLE.
* **Prompt exact utilisé :**
  > "Écris une classe Swift CBCentralManagerDelegate qui se connecte à un périphérique exposant le service UUID <UUID>, lit le RSSI toutes les secondes au premier plan, calcule une moyenne glissante sur 5 secondes et émet un événement si elle reste sous -85 dBm pendant 3 secondes ou si le périphérique se déconnecte."
* **Code proposé par l'IA :** analyse de la proposition, vérification des API dépréciées et du comportement en arrière-plan.
* **Corrections humaines :** gestion de la désactivation du Bluetooth, correction d'un cycle de références (`[weak self]`), suppression d'un `print` qui exposait l'identifiant du périphérique.
* **Validation et tests :** testé sur un iPhone physique, avec un second iPhone en mode Balise, au premier plan et en arrière-plan.
* **Relecteur :** [NOM]
```

---

## 9. Calendrier des 5 jalons

| Jalon | Intitulé | Objectif et livrable | Échéance |
| :---: | :--- | :--- | :---: |
| **J1** | **Cadrage** | Sujet validé, **écart « relais » validé ou refusé**, STRIDE initiale, rôles, dépôt Git créé | lun. 23/11/2026 |
| **J2** | **Architecture** | Schéma réseau, protocoles §3 formalisés, justification des choix crypto, choix de la stack du relais | lun. 30/11/2026 |
| **J3** | **MVP** | Socle P0 + P1 (§11) : appairage QR, canal local chiffré, rupture BLE, écran d'alerte, télémétrie signée vers le Mac | lun. 07/12/2026 |
| **J4** | **Audit croisé** | Audit MASVS de l'app d'un autre groupe, rapport de failles et correctifs sur notre app | jeu. 10/12/2026 |
| **J5** | **Soutenance** | Démo en direct (rupture, alerte, déverrouillage de secours, plus le relais s'il est prêt) et oral individuel | **mar. 15/12/2026 (date limite)** |

La date limite du 15/12 est fixée par la promotion. Les dates intermédiaires sont **proposées** et laissent environ 3 semaines et demie au total. Il faut réinstaller l'app le **14/12** à cause de l'expiration à 7 jours (§7).

---

## 10. Risques et questions ouvertes

| Risque | Probabilité | Impact | Parade |
| :--- | :---: | :---: | :--- |
| Écart « relais Internet » refusé | Moyenne | Moyen | Repli : file locale chiffrée et renvoi plus tard (§1.4) |
| BLE peu fiable en arrière-plan (faux positifs ou détection tardive) | Haute | Haut | Calibrer au J3, s'appuyer sur la déconnexion, hystérésis |
| Effacement mémoire impossible à garantir en Swift | Certaine | Faible | Présenté comme fait *au mieux*. La protection repose sur la Secure Enclave et Face ID |
| App expirée le jour de la démo | Moyenne | Haut | Procédure §7 |
| Clé maîtresse du Mac perdue | Faible | Haut | Nouvel appairage physique. Pas de sauvegarde de la clé, par choix de sécurité |
| Mini-serveur injoignable depuis Internet (CGNAT, box) | Moyenne | Faible | Le relais est en P2 : le socle imposé n'en dépend pas, et le repli §1.4 s'applique |
| Planning serré (≈ 3,5 semaines) | Haute | Haut | Ordre P0 → P1 → P2 imposé (§11). On coupe P2 avant de toucher au socle |
| Le 2e iPhone (balise) suspend la publicité BLE en arrière-plan | Moyenne | Moyen | Une fois connecté, le service GATT continue de répondre (mode `bluetooth-peripheral`). En démo, l'app Balise reste au premier plan |

---

## 11. Ordre de réalisation : les exigences imposées d'abord

On ne commence un niveau que lorsque le précédent fonctionne et a été relu.

**P0 : imposé par le sujet (non négociable)**
1. Dépôt Git, `main` protégée, `JOURNAL_IA.md`, rôles. *(p.8, p.11, p.20)*
2. Package partagé `RobAirKit` : format des messages, validation stricte, horodatage, `seq`. *(p.5, p.9)*
3. Clés Secure Enclave + Keychain `ThisDeviceOnly` avec Face ID, fichiers en `Complete`. *(p.4, p.19)*
4. Appairage par QR code avec comparaison d'empreinte. *(p.5, p.17)*
5. Canal Wi-Fi local chiffré et authentifié, chaque message signé et horodaté, anti-rejeu. *(p.5, p.17)*
6. Défi-réponse Mac → iPhone signé après Face ID. *(p.18)*
7. Hygiène MASVS : logs sans secret, aperçu multitâche masqué, presse-papiers. *(p.9, p.19)*
8. Dossier sécurité : STRIDE et choix crypto. *(J1, J2)*

**P1 : cœur de RobAir (prérequis : P0)**
9. Mode Balise (2e iPhone) + détection de rupture avec hystérésis + défi HMAC.
10. Écran d'alerte, fermeture du coffre, effacement mémoire au mieux.
11. Télémétrie signée par `K_tel_iPhone` et chiffrée en HPKE vers le Mac, sur le canal local + file d'attente.
12. Déverrouillage de secours par défi de l'iPhone. Tableau de bord et journal chaîné sur le Mac.

**P2 : extension (prérequis : P1 et écart validé au J1)**
13. Relais aveugle sur le mini-serveur, pinning TLS, interrogation par le Mac.
