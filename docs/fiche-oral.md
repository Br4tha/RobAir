# Fiche d'oral : ce que tout le monde doit savoir expliquer

> Chacun doit pouvoir expliquer l'ensemble du projet et du code (slide 11). Voici les questions probables, des réponses courtes, et **où regarder dans le code**.

## Le projet en 30 secondes

Le vol « à l'arraché » vise des iPhone **déjà déverrouillés**. RobAir surveille en BLE une **balise de confiance que l'utilisateur porte sur lui** (un 2e iPhone en mode Balise). Si le téléphone s'en éloigne, RobAir passe en **alerte** :
- le coffre se ferme et les secrets sont effacés de la mémoire ;
- un écran d'alerte exige Face ID ;
- une alerte puis des positions GPS partent **immédiatement**, signées et chiffrées pour le Mac (la centrale), par le Wi-Fi local ou, hors de portée, par un relais Internet qui ne peut rien lire.

## Questions sur le concept

**Q : Pourquoi pas une Apple Watch ou des AirPods comme balise ?**
iOS ne les expose pas aux apps tierces comme périphériques BLE surveillables. Un 2e iPhone en mode Balise ne coûte rien, utilise le même code Swift, et sait répondre à un défi cryptographique. Une carte ESP32 à 5 € pourrait le remplacer.

**Q : Pourquoi pas un simple iBeacon ?**
Un iBeacon se clone en quelques secondes. Notre balise répond à un **défi aléatoire** par un HMAC avec une clé secrète (K_balise), ce qu'un clone ne sait pas faire. → `Beacon.swift`

**Q : RobAir peut-il verrouiller l'iPhone ?**
Non : aucune app ne le peut sous iOS. RobAir protège **ses propres données** (le coffre) et donne l'alerte. Pour bloquer tout le téléphone, il faut l'*Accès guidé* d'iOS, activé à la main.

## Les mots-clés

| Terme | En une phrase |
|---|---|
| **STRIDE** | Six catégories de menaces : usurpation, altération, répudiation, divulgation, déni de service, élévation de privilèges. |
| **Secure Enclave** | Puce séparée qui crée et utilise des clés privées sans jamais les laisser sortir. |
| **X25519 / ECDH** | Deux appareils échangent leurs clés publiques et calculent le même secret, sans qu'il circule. |
| **Forward secrecy** | Clés éphémères détruites : une clé volée demain ne déchiffre pas les sessions d'hier. |
| **HKDF** | Transforme un secret brut en vraies clés, une par usage et par sens. |
| **AES-GCM** | Chiffre **et** authentifie. Ne jamais réutiliser un nonce avec la même clé. |
| **AAD** | Données authentifiées mais non chiffrées (notre en-tête). |
| **HPKE** | Chiffrement standard (RFC 9180) pour une clé publique, **sans session** : c'est ce qui sert pour la télémétrie et le relais. |
| **ECDSA** | Signature : prouve qui a envoyé, vérifiable avec la clé publique. |
| **HMAC** | « Signature » à clé secrète partagée (balise, preuve d'appairage). |
| **Épinglage (pinning)** | On mémorise la clé publique attendue (du Mac à l'appairage, du relais dans l'app). Seule celle-là est acceptée. |
| **Empreinte courte** | 6 chiffres calculés sur toutes les clés échangées : l'humain compare, et c'est ce qui bloque l'homme du milieu. |
| **Fail-safe** | En cas de doute ou d'erreur : alerte et verrouillage, jamais l'inverse. |
| **Non-répudiation** | Preuve qu'on ne peut pas contester : signatures Secure Enclave jointes au journal. |

## Questions pièges

**Q : Pourquoi deux clés de signature sur l'iPhone ?**
La télémétrie part quand le **voleur** tient le téléphone verrouillé : pas de Face ID possible, d'où **K_tel** (sans biométrie). Pour limiter le risque, elle ne signe **que** de la télémétrie, et le Mac la refuse pour toute autre action. **K_id** (Face ID) signe tout ce qui est sensible : sessions et réponses aux défis. → `DeviceIdentity.swift`

**Q : Le handshake exige Face ID. Et en arrière-plan ?**
La session n'est ouverte qu'au premier plan. Son renouvellement toutes les 15 min se fait **dans** la session (nouvel échange X25519), sans Face ID. Et surtout, **la télémétrie n'a pas besoin de session** : HPKE chiffre directement pour la clé du Mac. → J2 §3 point 1, `Handshake.swift` (`RekeyInitiator`)

**Q : Le relais peut-il lire ou falsifier les positions ?**
Non. Elles sont **signées** par K_tel puis **chiffrées** en HPKE pour le Mac. Le relais ne voit que du chiffré, la taille, l'heure et l'IP, et nous ne journalisons même pas l'IP. → `Telemetry.swift`, `relay/`

**Q : Comment empêchez-vous le rejeu ?**
- **Session :** `seq` strictement croissant, horodatage à ±30 s, clés neuves à chaque session.
- **Télémétrie :** `seq` persisté et horodatage à ±300 s.
- **Défis et secours :** défi aléatoire **à usage unique**, consommé dès la première présentation.

→ `Record.swift`, `Challenges.swift`

**Q : Un attaquant forge un accusé de réception pour faire vider la file de l'iPhone ?**
Impossible : l'accusé doit contenir `ackSecret`, un aléa caché **dans** le message chiffré. Seul le Mac a pu le lire. → `TelemetrySender.swift`

**Q : Et si le voleur coupe le Wi-Fi ou passe en mode avion ?**
La première alerte part **dès la rupture**, avant qu'il ait le temps d'agir. Sinon, les messages restent en file et partent au retour du réseau, par le canal local ou par le relais.

**Q : Que se passe-t-il si on brouille le Bluetooth ?**
Le brouillage provoque une déconnexion, donc une rupture, donc une alerte. Brouiller **déclenche** l'alerte au lieu de la cacher.

**Q : Quelle attaque ne bloquez-vous pas ?**
Le **relais BLE** : un complice retransmet la radio entre la balise et le téléphone. Il faudrait mesurer le temps de vol, ce qu'un iPhone ne permet pas. Autre limite : en arrière-plan, iOS suspend nos minuteries, donc la détection repose sur la déconnexion. → J2 §15

**Q : « Ne pas inventer sa crypto », mais votre protocole est fait maison ?**
Les primitives sont toutes standard (CryptoKit). L'assemblage reprend des schémas publiés : le handshake de TLS 1.3 / SIGMA, et HPKE (RFC 9180). Nous couvrons le risque par 103 tests, dont des tests d'attaque. L'un d'eux a d'ailleurs **trouvé un vrai défaut** (clé X25519 de faible ordre), que nous avons corrigé.

**Q : Pourquoi P-256 pour les signatures mais X25519 pour l'échange ?**
La Secure Enclave ne gère que P-256 pour les clés d'identité. X25519 sert aux clés **éphémères**, qui vivent en mémoire et n'ont pas besoin de la Secure Enclave. C'est le choix du J1.

**Q : Que fait le déverrouillage de secours ?**
Après 3 échecs Face ID, l'iPhone génère un défi. Le Mac le signe après Touch ID de l'opérateur, qui vérifie d'abord un code à 6 chiffres. La réponse revient par le réseau ou par QR code. Cela lève l'alerte **de RobAir** seulement, et le coffre exige toujours Face ID. → `Challenges.swift`

**Q : Et l'IA dans tout ça ?**
L'IA propose, l'équipe décide. Chaque prompt figure dans `JOURNAL_IA.md`, avec ce que nous avons gardé ou corrigé. Le J2 §3 liste 14 écarts au J1 relevés en formalisant, à valider par l'équipe.

## Démo (J5) : scénario minuté

1. *(la veille)* Réinstaller les deux apps depuis Xcode (expiration à 7 jours), lancer le relais.
2. Mac : déverrouiller la centrale (Touch ID). Montrer « Clé maîtresse : Secure Enclave ».
3. Montrer l'appairage déjà fait. Sinon, QR code + comparaison de l'empreinte.
4. iPhone capteur : balise « Présente », armer, ouvrir le coffre (Face ID).
5. **S'éloigner avec le capteur** : alerte, coffre fermé, bip sur le Mac, position sur la carte.
6. Couper le Wi-Fi du capteur : la position suivante arrive **via le relais**.
7. Lever l'alerte par Face ID. Ou montrer 3 échecs, puis le secours avec le code à 6 chiffres.
8. Sur le Mac : « Fin d'alerte », confirmée par Face ID sur l'iPhone. Puis « Vérifier l'intégrité » du journal.
9. Attaque en direct : balise clonée (nRF Connect), qui provoque une alerte.
