# Comment marche RobAir : connexions, protocoles et outils

> Fiche de révision pour l'oral. Chaque section répond à « quoi », « comment » et « pourquoi ce choix ».

## 1. Vue d'ensemble : trois appareils, trois liens

```
 [Balise : 2e iPhone]  ── Bluetooth LE ──►  [Capteur : iPhone protégé]  ── Wi-Fi local (TCP) ──►  [Centrale : Mac]
   sur l'utilisateur      défi HMAC          dans la poche / sur la table   canal chiffré E2E       au bureau / maison
                          toutes les 10 s                                  └─ HTTPS ─► [Relais aveugle] ◄─ le Mac interroge
                                                                              (extension, hors de portée du Wi-Fi)
 Appairages : par QR code (canal visuel), une seule fois.
```

| Lien | Technologie | Rôle | Pourquoi |
|---|---|---|---|
| Balise ↔ Capteur | **Bluetooth Low Energy** (CoreBluetooth, GATT) | Savoir si le propriétaire est **à côté** | Courte portée (≈ 10 m), mesure de signal (RSSI), aucun réseau nécessaire, faible consommation |
| Capteur ↔ Mac | **Wi-Fi local** : TCP via Network.framework, découverte **Bonjour** (`_robair._tcp`) | Transporter **ce qui se passe** (état, alerte, positions) | Débit, portée d'un bâtiment, le Mac n'a pas besoin d'être près du téléphone |
| Capteur → Relais → Mac | **HTTPS** (TLS 1.3, clé du serveur épinglée) | Positions quand le Mac est hors de portée | Extension P2 ; le relais ne voit que du chiffré |
| Appairages | **QR codes** | Échanger les clés publiques et les secrets la première fois | Canal **visuel** : impossible à intercepter à distance |

## 2. « Pourquoi le Bluetooth ET le Wi-Fi ? »

**Réponse courte : ils ne font pas le même travail.** Le Bluetooth est un **capteur de proximité**, le Wi-Fi est un **canal de données**.

- **Le Bluetooth répond à une question :** « le téléphone est-il encore près de son propriétaire ? ». Sa portée courte est justement ce qu'on veut : quand le lien se coupe ou que le signal faiblit, c'est que le téléphone s'est éloigné. Il fonctionne sans aucun réseau, dans la rue comme dans un train.
- **Le Wi-Fi répond à une autre question :** « que s'est-il passé et où est le téléphone ? ». Il faut un lien qui porte loin (le Mac reste au bureau), avec du débit, pour l'alerte, les positions GPS, l'état et les défis.
- **Utiliser le Bluetooth pour tout ne marcherait pas :** le Mac devrait rester à 10 m du téléphone, ce qui n'est pas le cas d'usage. **Utiliser le Wi-Fi pour la proximité ne marcherait pas non plus :** il porte trop loin, donc on ne détecterait pas l'éloignement, et le Wi-Fi d'une ville n'est pas le vôtre.
- **Moindre privilège :** le Mac n'utilise plus le Bluetooth du tout (droit retiré), puisque la balise est le 2e iPhone.

## 3. Le lien Bluetooth : balise et détection de rupture

**Outils :** CoreBluetooth. La balise est un **périphérique** (`CBPeripheralManager`), le capteur un **central** (`CBCentralManager`).

1. **Appairage capteur ↔ balise :** la balise tire au hasard un UUID de service et une clé **K_balise** (32 octets), et les affiche dans un QR code. Le capteur le scanne : seul lui connaît la clé.
2. **Connexion :** le capteur cherche ce service, se connecte et s'abonne à une caractéristique GATT (écriture et notification).
3. **Défi-réponse anti-clonage**, toutes les 10 s :
   - le capteur écrit 16 octets aléatoires ;
   - la balise répond `HMAC-SHA256(K_balise, "robair-beacon-proof-v1" ‖ défi)` ;
   - le capteur vérifie en temps constant. Pas de réponse valide en moins de 2 s : **rupture**.
   - Un clone copie l'annonce Bluetooth, mais pas K_balise.
4. **Détection de rupture** (logique pure `RuptureDetector`, testée) :
   - déconnexion ;
   - **ou** preuve HMAC invalide ou trop vieille (plus de 15 s) ;
   - **ou** signal moyen (RSSI sur 5 s) sous −85 dBm pendant 3 s. Il faut remonter au-dessus de −75 dBm pour en sortir (**hystérésis** : pas d'oscillation).
5. **Fail-safe :** sans preuve valide récente, la balise n'est **jamais** « présente ». Bluetooth coupé = rupture.

**Pourquoi un HMAC (clé partagée) et pas une signature ?** C'est plus rapide et plus court (32 octets dans une notification BLE). Les deux appareils sont à nous et appairés par QR, donc une clé partagée suffit.

**Pourquoi pas les AirPods ou l'Apple Watch ?** CoreBluetooth n'y donne accès ni au signal ni à un défi cryptographique (J1 §1.3).

## 4. Le lien Wi-Fi : session chiffrée de bout en bout

**Outils :** Network.framework (TCP), Bonjour pour trouver le Mac sans adresse IP, CryptoKit.
Il n'y a pas de TLS ici : le chiffrement est fait **par nous**, de bout en bout, avec des clés **épinglées à l'appairage**. On ne dépend d'aucune autorité de certification, et le Wi-Fi est considéré comme hostile (Zero Trust).

### 4.1 Appairage iPhone ↔ Mac

1. Le Mac affiche un QR code : sa clé publique d'identité (P-256), sa clé de chiffrement HPKE et un **jeton à usage unique** (5 min).
2. L'iPhone crée ses clés **dans la Secure Enclave** et envoie ses clés publiques avec un **HMAC du jeton** : c'est la preuve qu'il a vu le QR code.
3. Les deux écrans affichent une **empreinte à 6 chiffres** calculée sur toutes les clés. L'utilisateur compare, puis confirme par **Touch ID** : c'est ce qui bloque l'homme du milieu.

### 4.2 Handshake de session (à chaque connexion)

| Étape | Message | Contenu |
|---|---|---|
| 1 | iPhone → Mac `ClientHello` | identifiant, clé **X25519 éphémère**, aléa |
| 2 | Mac → iPhone `ServerHello` | sa clé éphémère, son aléa, **signature ECDSA** de la transcription |
| 3 | iPhone → Mac `ClientFinish` | **signature** de la transcription (Face ID) |

- **Transcription :** H = SHA-256 de tous les champs ; les signatures portent sur H, donc rien ne peut être modifié en route.
- **Clés :** ECDH X25519, puis HKDF-SHA256 avec H comme sel, ce qui donne **une clé AES-256 par sens**.
- **Forward secrecy :** les clés éphémères sont jetées. Voler une clé plus tard ne permet pas de déchiffrer le passé. Renouvellement toutes les 15 min, dans la session.

### 4.3 Messages de session

- **Chiffrement :** AES-256-**GCM** (chiffrement + intégrité). L'en-tête (version, type, expéditeur, `seq`, heure) est authentifié comme AAD.
- **Nonce :** préfixe de sens + compteur. Il n'est jamais réutilisé.
- **Anti-rejeu :** `seq` strictement croissant et heure à ±30 s.
- **Validation stricte :** 4 Ko maximum, JSON sans champ inconnu, bornes vérifiées.

## 5. Alerte et positions : HPKE + signature

Pourquoi un autre mécanisme que la session ? En alerte, la session est **détruite**, et la rouvrir demande Face ID, que le voleur n'a pas.

1. **Contenu :** type, `seq`, heure, latitude/longitude, batterie, cause, `ackSecret`.
2. **Signature** avec **K_tel**, une clé Secure Enclave **sans biométrie**, pour fonctionner téléphone verrouillé dans la poche du voleur. Elle ne sert qu'à la télémétrie.
3. **Chiffrement HPKE** (RFC 9180 : X25519 + HKDF-SHA256 + AES-256-GCM) avec la clé publique du Mac. Il fonctionne **sans session**, donc aussi en différé ou via le relais.
4. **Envoi :** Wi-Fi local si le Mac est joignable, sinon le relais, sinon la **file** sur l'iPhone. La file est déjà chiffrée : même l'iPhone ne peut plus la relire.
5. **Réception sur le Mac :** déchiffrement, vérification de la signature, de `seq` et de l'âge (72 h au plus), journal, puis **accusé** : le Mac renvoie l'`ackSecret` qu'il est seul à pouvoir lire. Un attaquant ne peut donc pas faire vider la file.

## 6. Défis-réponses et secours

- **Mac → iPhone** (fin d'alerte, désarmement) :
  - le Mac envoie 32 octets aléatoires, valables 30 s et à usage unique ;
  - l'iPhone affiche l'action, demande **Face ID** et signe {défi, Mac, iPhone, **action**}.
  - Une réponse « désarmer » ne peut pas servir de « fin d'alerte ».
- **Déverrouillage de secours** (fausse alerte et vrais échecs de Face ID) :
  - l'iPhone crée un défi (120 s) et l'envoie par le Wi-Fi ou en QR code ;
  - l'opérateur compare le code à 6 chiffres, s'authentifie par **Touch ID**, et le Mac signe ;
  - l'iPhone vérifie puis consomme le défi : une réponse capturée ne sert plus.

## 7. Stockage et clés

| Clé | Où | Protection | Usage |
|---|---|---|---|
| K_id_iPhone | Secure Enclave | Face ID à chaque usage (`biometryCurrentSet`) | handshake, défis |
| K_tel_iPhone | Secure Enclave | après le 1er déverrouillage, sans biométrie | télémétrie seulement |
| K_vault | Keychain | Face ID, `WhenUnlockedThisDeviceOnly` | coffre (AES-GCM) |
| K_balise | Keychain des deux iPhone | `AfterFirstUnlockThisDeviceOnly` | HMAC de la balise |
| K_id_Mac | Secure Enclave du Mac | Touch ID ou mot de passe | handshakes, secours, appairage |
| K_enc_Mac | Keychain du Mac | rotation hebdomadaire, signée par K_id_Mac | HPKE (déchiffrer la télémétrie) |

**Secure Enclave :** une puce séparée. La clé privée n'en sort jamais : on lui demande de **signer**, elle ne donne pas la clé.
**ThisDeviceOnly :** jamais dans les sauvegardes iCloud ni sur un autre appareil.

## 8. Outils (frameworks Apple uniquement)

| Framework | Sert à |
|---|---|
| CryptoKit | AES-GCM, X25519, P-256/ECDSA, HKDF, HMAC, SHA-256, HPKE, Secure Enclave |
| Security (Keychain) | stocker clés et secrets avec contrôle d'accès |
| LocalAuthentication | Face ID / Touch ID (`LAContext`) |
| CoreBluetooth | balise (périphérique) et capteur (central) |
| Network | TCP, Bonjour (`NWListener`, `NWConnection`) |
| CoreLocation | positions GPS, seulement en alerte |
| AVFoundation, CoreImage | scanner et générer les QR codes |
| MapKit | carte des positions sur le Mac |
| os.Logger | journaux sans données sensibles |

Le relais est en Python avec la **bibliothèque standard** seulement : moins de dépendances, moins de surface d'attaque.

## 9. Questions probables du prof

- **« Pourquoi le Bluetooth et le Wi-Fi ? »** Voir la section 2 : le Bluetooth mesure la proximité, le Wi-Fi transporte les données vers le Mac, qui est loin.
- **« Pourquoi pas TLS sur le Wi-Fi ? »** Il faudrait une autorité de certification ou un certificat auto-signé à épingler de toute façon. Notre handshake signé fait la même chose (authentification mutuelle, forward secrecy) avec les clés de l'appairage, et reste testable dans le module.
- **« Pourquoi deux clés sur l'iPhone ? »** Séparation des usages. K_id (Face ID) autorise ; K_tel (sans biométrie) ne fait que **signaler**, car il doit marcher dans la main du voleur. Une K_tel volée ne permet pas de désarmer.
- **« Et si le voleur passe en mode avion ? »** La première alerte part **dès la rupture**, avant qu'il ait le temps de le faire. Ensuite plus rien ne sort : c'est une limite assumée.
- **« Et si quelqu'un relaie le Bluetooth ? »** C'est indétectable sans mesure du temps de vol ; le délai court (2 s) et le seuil RSSI limitent le risque (audit, R-2).
- **« Qu'a trouvé la Red Team ? »** Voir [audit-red-team-J3.md](audit-red-team-J3.md). Trois failles dans la **logique** autour de la crypto : la crypto elle-même a tenu.
