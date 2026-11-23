# J1 · Cadrage et modèle de menaces STRIDE

> Livrable du jalon 1 : sujet validé + modèle de menaces STRIDE.
> Nom du projet : **RobAir**. Jeu de mots entre *rob* (« voler » en anglais) et *Air*, clin d'œil à la gamme Apple.

---

## 1. Le projet en une phrase

L'iPhone surveille en permanence sa **proximité Bluetooth (BLE) avec le Mac de confiance**. Dès qu'il s'en éloigne, perd la liaison ou ne parvient plus à prouver que c'est bien *ce* Mac, il **verrouille sa zone protégée** (fail-safe) et **alerte le Mac** (la centrale) par un canal chiffré et authentifié sur le Wi-Fi local.

Cas d'usage type : on laisse son iPhone sur le bureau à côté du Mac. Quelqu'un le prend et s'éloigne. L'app se verrouille, le Mac affiche une alerte et l'inscrit dans un journal infalsifiable. Pour déverrouiller, il faut Face ID **et** être de nouveau à portée du Mac appairé.

## 2. Périmètre

### Ce que fait l'iPhone (le capteur)
- Se connecte en BLE au Mac et mesure la proximité : force du signal (RSSI), détection de la déconnexion, **preuve que la balise est bien le Mac appairé** (réponse HMAC à un défi aléatoire, avec un secret partagé à l'appairage).
- Verrouille sa zone protégée en cas d'éloignement, de perte de liaison ou d'anomalie.
- Exige Face ID pour toute action sensible (déverrouillage, désarmement).
- Répond aux défis du Mac pour les actions sensibles, après Face ID.
- Conserve ses clés dans la Secure Enclave (non exportables) et ses données dans le Keychain (`ThisDeviceOnly`) et dans des fichiers protégés.

### Ce que fait le Mac (la centrale)
- Sert de **balise BLE de confiance** : c'est lui que l'iPhone doit « sentir » à proximité.
- Reçoit les états et les alertes chiffrés, vérifie leur authenticité et leur fraîcheur (anti-rejeu).
- Affiche l'état : `PROCHE` / `ÉLOIGNÉ` / `VERROUILLÉ` / `NON VÉRIFIÉ`.
- Tient un **journal d'événements chiffré et chaîné** (toute modification est détectable), sans aucun secret.
- Gère l'appairage par QR code.

> **Choix de cadrage : le Mac sert à la fois de balise et de centrale.** Le sujet fournit un seul iPhone et un seul Mac par groupe. Une balise BLE du commerce (iBeacon) se clone en quelques secondes avec une app gratuite. Le Mac, lui, peut calculer un **HMAC** avec un secret partagé à l'appairage, donc prouver son identité.

### Hors périmètre (limites assumées)
| Limite | Raison |
|---|---|
| Verrouiller l'iPhone lui-même (écran système) | Impossible pour une app tierce sous iOS. On verrouille **l'état de l'app**. |
| Notifications push, iCloud, NFC, AutoFill | Réservés aux comptes Apple payants (slide 4). |
| Fonctionnement si l'utilisateur force la fermeture de l'app | iOS ne relance pas une app tuée par l'utilisateur. Le Mac le détecte quand même (perte BLE, plus de heartbeat) et passe en `NON VÉRIFIÉ`. |
| Distance exacte | Le RSSI est bruité. On détecte une tendance (« s'éloigne »), pas des mètres. |
| Localisation GPS | Inutile au besoin, donc non collectée (minimisation RGPD). |
| App installée valable 7 jours | Compte gratuit : réinstaller depuis Xcode avant chaque démo. |

## 3. Ce qu'on protège (actifs)

| # | Actif | Pourquoi c'est sensible | Propriété à garantir |
|---|---|---|---|
| A1 | Clés privées d'identité (iPhone et Mac) | Qui les vole peut se faire passer pour l'appareil | Confidentialité, non-exportabilité |
| A2 | Clés de session (Wi-Fi) | Elles déchiffrent les messages de la session | Confidentialité, durée de vie courte |
| A3 | État de sécurité (proche, verrouillé…) | Un faux « tout va bien » désactive la protection | Intégrité, authenticité, fraîcheur |
| A4 | Contenu de la zone protégée de l'app | C'est ce que RobAir protège | Confidentialité |
| A5 | Journal d'événements du Mac | Preuve en cas de litige (« ce n'est pas moi ») | Intégrité, non-répudiation |
| A6 | Clés publiques des pairs (appairage) | Les remplacer = faire accepter un faux appareil | Intégrité |

## 4. Qui attaque (sources de menace)

| Attaquant | Capacités supposées |
|---|---|
| **Voleur opportuniste** | Prend l'iPhone (déverrouillé ou non) et s'éloigne. Pas d'outillage. |
| **Attaquant réseau local** | Sur le même Wi-Fi : écoute, modifie, rejoue, injecte des paquets, se fait passer pour le Mac. |
| **Attaquant radio BLE** | Clone une balise, rejoue des trames BLE, brouille le signal, voire relaie le signal à distance. |
| **Initié ou utilisateur de mauvaise foi** | Conteste une action (« ce n'est pas moi qui ai désarmé »), tente de modifier le journal. |
| **Auditeur d'un autre groupe (J4)** | A le code source et l'app, cherche des failles. |

**Hypothèses de confiance (Zero Trust) :**
- Le **réseau Wi-Fi n'est pas de confiance**, même à la maison.
- Le **canal BLE n'est pas de confiance** : tout le monde peut voir et imiter une annonce BLE.
- Le **canal visuel (QR code affiché sur l'écran du Mac)** est de confiance au moment de l'appairage : il faut être physiquement devant le Mac.
- iOS, macOS et la Secure Enclave sont de confiance. Un appareil jailbreaké est hors modèle.

## 5. Modèle de menaces STRIDE

| STRIDE | Menace concrète | Contre-mesures | Actifs |
|---|---|---|---|
| **S** · Usurpation | **S1.** Un faux Mac se présente comme la centrale sur le Wi-Fi. | Appairage par QR code : l'iPhone mémorise (« épingle ») la clé publique du Mac. Chaque session commence par un échange de clés **signé** par les clés d'identité. Un faux Mac ne peut pas produire la signature. | A3, A6 |
| | **S2.** Une fausse balise BLE (clone de l'annonce du Mac) fait croire à l'iPhone qu'il est toujours à proximité. | **Défi-réponse BLE par HMAC-SHA256** avec une clé K_ble partagée à l'appairage. Au premier plan, toutes les 10 s, l'iPhone envoie un nombre aléatoire et le Mac doit renvoyer le HMAC. Pas de réponse valide sous 2 s : on considère le Mac absent. En arrière-plan, la déconnexion BLE déclenche le verrouillage. | A3 |
| | **S3.** Un faux iPhone envoie de faux états « tout va bien » au Mac. | Le Mac n'accepte que la clé publique de l'iPhone enregistrée à l'appairage. L'appairage est prouvé par un jeton à usage unique présent uniquement dans le QR code. | A3 |
| **T** · Altération | **T1.** Modification en transit d'une alerte ou d'un état. | Chiffrement authentifié **AES-GCM** : un seul bit modifié et le déchiffrement échoue. L'en-tête est lui aussi authentifié (données associées, AAD). | A3 |
| | **T2.** Modification ou suppression d'entrées du journal sur le Mac. | Journal **chaîné par hachage** (chaque entrée contient le SHA-256 de la précédente) et scellé par HMAC. Toute modification casse la chaîne. Une **tête de chaîne scellée**, stockée à part dans le Keychain, détecte aussi la troncature (suppression des dernières entrées). | A5 |
| | **T3.** Paquet malformé visant un plantage ou un comportement inattendu. | Validation stricte : taille maximale de trame (4 Ko), version, type, champs obligatoires. Tout ce qui est invalide est rejeté avant traitement. | A3 |
| **R** · Répudiation | **R1.** « Ce n'est pas moi qui ai déverrouillé ou désarmé. » | Les actions sensibles demandées par le Mac passent par un **défi-réponse** (slide 18) : défi aléatoire à usage unique, signé par une clé Secure Enclave utilisable uniquement après Face ID, liée à l'action et aux deux appareils. Le Mac vérifie et archive la signature. | A5 |
| | **R2.** « Cette alerte n'a jamais été envoyée. » | Messages horodatés, numérotés et journalisés côté Mac. Journal chaîné (voir T2). | A5 |
| **I** · Divulgation | **I1.** Écoute du Wi-Fi. | Tout est chiffré en AES-GCM avec des clés de session éphémères. | A2, A3 |
| | **I2.** Secrets dans les logs, l'aperçu multitâche ou le presse-papiers. | Aucun secret dans les logs (`os.Logger` en mode privé). Écran masqué en arrière-plan. Aucune donnée copiée dans le presse-papiers. | A1, A4 |
| | **I3.** Lecture des fichiers ou du Keychain sur un iPhone volé. | Keychain `ThisDeviceOnly` (jamais dans les sauvegardes). Fichiers en protection `Complete`. Clés privées dans la Secure Enclave, donc jamais extractibles. | A1, A4 |
| | **I4.** Traçage de l'utilisateur via l'annonce BLE. | L'annonce BLE ne contient ni nom ni identifiant personnel, seulement un UUID de service générique. | (RGPD) |
| **D** · Déni de service | **D1.** Brouillage BLE ou coupure Wi-Fi pour masquer l'éloignement. | **Fail-safe** : perte de liaison = verrouillage côté iPhone et `NON VÉRIFIÉ` côté Mac. Brouiller déclenche donc l'alerte au lieu de la masquer. | A3, A4 |
| | **D2.** Inondation du Mac de fausses alertes ou de connexions. | Une seule connexion non authentifiée à la fois. Délai maximal de 5 s pour le handshake. Limite de débit. Rejet immédiat des trames trop grandes ou invalides. | A3 |
| **E** · Élévation de privilèges | **E1.** Déverrouiller la zone protégée sans Face ID ni preuve de proximité. | Déverrouillage = Face ID **et** défi BLE réussi. La clé de déchiffrement de la zone protégée est elle-même conditionnée à la biométrie dans le Keychain. | A4 |
| | **E2.** Ajouter son propre visage dans Face ID pour passer le contrôle. | Clés biométriques créées avec `biometryCurrentSet` : la moindre modification des visages enregistrés invalide la clé. | A1, A4 |
| | **E3.** Contourner la logique (exception, état incohérent). | Verrouillé par défaut. Toute erreur ou tout état inconnu ramène à `VERROUILLÉ`. | A4 |

## 6. Risques résiduels (assumés et documentés)

| Risque | Pourquoi on ne le couvre pas entièrement | Atténuation |
|---|---|---|
| **Attaque par relais BLE** : un complice relaie la radio entre le Mac et l'iPhone volé | Il faudrait mesurer la distance par le temps de vol (*distance bounding*), ce qu'un iPhone grand public ne sait pas faire | Délai de réponse au défi très court (2 s), seuil RSSI, défi régulier |
| Vol de l'iPhone **et** contrainte de l'utilisateur pour obtenir Face ID | Hors de portée technique | Journal horodaté côté Mac |
| App tuée par l'utilisateur | Limite d'iOS | Le Mac détecte l'absence et passe en `NON VÉRIFIÉ` |
| Appareil jailbreaké | Hors modèle de confiance | Les clés Secure Enclave restent non extractibles |
| **Initié avec accès à la session macOS** | Il peut lire K_journal dans le Keychain du Mac | Le HMAC protège contre un attaquant extérieur, pas contre l'administrateur du Mac |
| **Réinitialisation de la centrale** | Elle efface le journal, donc la preuve | Export proposé avant l'effacement |
| **En arrière-plan, le Mac ne peut pas prouver que le lien BLE vient de l'iPhone appairé** | Pas de message authentifié régulier quand l'app est suspendue | Le Mac affiche `NON VÉRIFIÉ` ; la protection reste côté iPhone |
| **Empreinte de l'iPhone visible en clair** dans le `HELLO` Wi-Fi | Le Mac doit savoir quelle clé publique utiliser avant le chiffrement | Pseudonyme, pas de donnée personnelle |
| **Secret K_ble présent sur les deux appareils** | Un HMAC suppose un secret partagé | Stocké en `ThisDeviceOnly` ; qui le vole sur le Mac a déjà le Mac |

## 7. RGPD et minimisation

- **Données collectées :** état de proximité (proche ou éloigné), événements (alerte, verrouillage, déverrouillage), horodatages, identifiant d'appareil sous forme d'empreinte de clé, donc un pseudonyme.
- **Non collectées :** position GPS, historique RSSI, nom de l'utilisateur, images.
- **Caméra :** utilisée uniquement pendant l'appairage, pour lire le QR code. Aucune image n'est stockée.
- **Conservation :** journal du Mac limité (par exemple 30 jours), effaçable par l'utilisateur.

## 8. Règles de développement et d'IA (rappel du sujet)

- Journal des prompts tenu à jour : [journal-ia.md](journal-ia.md).
- Boucle : **spécifier → générer → relire ligne à ligne → tester → attaquer**. Une faille trouvée renvoie à « spécifier ».
- Revue humaine obligatoire avant chaque merge.
- Aucun secret ni donnée réelle dans les prompts.
- **Aucune dépendance tierce** : uniquement les frameworks Apple (CryptoKit, CoreBluetooth, Network, LocalAuthentication, AVFoundation, CoreImage). Cela élimine le risque de « dépendances fantômes ».
- Chaque membre sait expliquer l'ensemble du code et des choix crypto.
