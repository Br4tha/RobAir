# Fiche d'oral : ce que tout le monde doit savoir expliquer

> Chacun doit pouvoir expliquer l'ensemble du projet (slide 11). Voici les questions probables et des réponses courtes.

## Le projet
**Q : Qu'est-ce que vous faites ?**
L'iPhone vérifie en permanence qu'il est près du Mac appairé. S'il s'éloigne, il verrouille sa zone protégée et alerte le Mac par un canal chiffré.

**Q : Pourquoi le Mac sert-il de balise, et pas un iBeacon ?**
Un iBeacon se clone en quelques secondes. Le Mac, lui, **signe** une réponse à un défi aléatoire avec sa clé privée, ce qu'un clone ne peut pas faire. De plus, l'iBeacon exige la permission de localisation, ce qui va contre le moindre privilège et le RGPD.

## Les mots-clés à maîtriser
| Terme | En une phrase |
|---|---|
| **STRIDE** | Six catégories de menaces : usurpation, altération, répudiation, divulgation, déni de service, élévation de privilèges. |
| **Secure Enclave** | Puce séparée qui crée et utilise des clés privées sans jamais les laisser sortir, même vers notre app. |
| **ECDH** | Deux appareils échangent leurs clés *publiques* et calculent chacun le *même* secret, sans qu'il circule sur le réseau. |
| **Éphémère** | Clé jetable, créée pour une session puis détruite. |
| **Confidentialité persistante** | Si une clé fuit demain, les sessions d'hier restent indéchiffrables, car leurs clés éphémères n'existent plus. |
| **HKDF** | Transforme le secret ECDH brut en vraies clés AES, une par sens. |
| **AES-GCM** | Chiffre **et** authentifie : le moindre bit modifié est détecté. |
| **Nonce** | Nombre à usage unique. En GCM, ne **jamais** réutiliser le même nonce avec la même clé. |
| **AAD** | Données authentifiées mais non chiffrées (notre en-tête). |
| **ECDSA** | Signature : prouve qui a envoyé, vérifiable avec la clé publique. |
| **Épinglage** | On mémorise la clé publique du pair à l'appairage, et seule celle-là est acceptée ensuite. |
| **Homme du milieu** | Un attaquant s'intercale entre les deux appareils. Notre parade : clé du Mac lue dans le QR code + handshake signé. |
| **Fail-safe** | En cas de doute ou d'erreur, on verrouille au lieu d'ouvrir. |
| **Non-répudiation** | Preuve qu'on ne peut pas contester. Chez nous, signature avec la clé Face ID. |

## Questions pièges probables
**Q : AES-GCM authentifie déjà, pourquoi signer en plus ?**
GCM prouve que le message vient de quelqu'un qui a la clé de session. Le Mac l'a aussi, il pourrait donc forger le message. Seule la signature avec la clé Face ID de l'iPhone est une preuve opposable.

**Q : Pourquoi deux clés de signature sur l'iPhone ?**
L'iPhone doit établir des sessions en arrière-plan, sans Face ID. Les actions sensibles, elles, exigent Face ID. On sépare donc la clé de routine et la clé biométrique.

**Q : Comment empêchez-vous le rejeu ?**
Par trois mécanismes : un compteur strictement croissant, des clés neuves à chaque session et un horodatage avec une fenêtre de ±60 s.

**Q : Vous dites « ne pas inventer sa crypto », mais votre protocole est fait maison ?**
Les primitives sont toutes standard (CryptoKit). L'assemblage reprend le schéma du handshake TLS 1.3 : Diffie-Hellman éphémère signé, transcript, HKDF. Nous reconnaissons le risque et le couvrons par des tests d'attaque.

**Q : Pourquoi P-256 et pas Curve25519 ?**
La Secure Enclave ne gère que P-256.

**Q : Que se passe-t-il si on brouille le Bluetooth ?**
Le brouillage ressemble à un éloignement : l'iPhone se verrouille et le Mac affiche `NON VÉRIFIÉ`. Brouiller déclenche l'alerte au lieu de la cacher.

**Q : Quelle attaque ne bloquez-vous pas ?**
Le relais BLE : un complice retransmet la radio. Il faudrait mesurer le temps de vol, ce que l'iPhone ne permet pas. Nous l'atténuons par un délai de réponse court et un seuil RSSI, et nous le documentons.

**Q : Et l'IA dans tout ça ?**
L'IA propose et l'équipe décide. Chaque prompt utile figure dans le journal avec ce que nous avons gardé ou corrigé. Exemple : nous avons repéré et corrigé le conflit entre la protection `Complete` et le fonctionnement en arrière-plan.
