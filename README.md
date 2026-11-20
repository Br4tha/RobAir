# RobAir · alerte anti-vol par rupture de proximité BLE

Projet M2 « Faire de l'iPhone un équipement de sécurité ». *RobAir* : jeu de mots entre *rob* (« voler » en anglais) et *Air*, clin d'œil à la gamme Apple.

Le vol « à l'arraché » vise des iPhone **déjà déverrouillés**. RobAir surveille en Bluetooth Low Energy une **balise de confiance que l'utilisateur porte sur lui**. AirPods et Apple Watch ne sont pas utilisables par une app tierce : la balise est donc un **2e iPhone en mode Balise**, en attendant une carte ESP32.

Quand le téléphone s'éloigne de la balise, ou que celle-ci ne prouve plus son identité (défi HMAC), RobAir passe en **alerte** :
- son **coffre chiffré se ferme** et les secrets sont effacés de la mémoire ;
- un **écran d'alerte exige Face ID** ;
- une **alerte puis les positions GPS** partent aussitôt, **signées** par la Secure Enclave et **chiffrées** pour le Mac (la centrale). Elles passent par le Wi-Fi local ou, hors de portée, par un **relais Internet aveugle**.

En cas de fausse alerte et d'échec répété de Face ID, le Mac peut lever le verrouillage de l'app par un **défi-réponse signé**.

```
[Balise : 2e iPhone] ──BLE + défi HMAC──► [iPhone : capteur] ──Wi-Fi local, E2E──► [Mac : centrale]
                                                      └──HTTPS, HPKE──► [Relais aveugle] ◄── le Mac interroge
```

## Documents

| Jalon (échéance proposée) | Document | État |
|---|---|---|
| J1 · Cadrage (lun. 23/11) | [docs/J1-cadrage.md](docs/J1-cadrage.md) : problématique, périmètre, protocoles, STRIDE, MASVS, rôles, calendrier | ✅ à valider (écart « relais ») |
| J2 · Architecture (lun. 30/11) | [docs/J2-architecture.md](docs/J2-architecture.md) : protocoles formalisés, choix crypto, **écarts au J1 à valider**, tests | ✅ rédigé |
| J3 · MVP (lun. 07/12) | Code ci-dessous | 🟠 écrit et testé (module, relais) ; apps à compiler sur Mac |
| J4 · Audit croisé (jeu. 10/12) | — | à venir |
| J5 · Soutenance (mar. 15/12) | [docs/fiche-oral.md](docs/fiche-oral.md) : questions, réponses, scénario de démo | amorcé |
| Transverse | [JOURNAL_IA.md](JOURNAL_IA.md) : journal des prompts commenté | en continu |

`docs/analyse-projet-2026-11-20.pdf` décrit l'**ancienne** architecture, celle où le Mac servait de balise : il est conservé pour l'historique.

## Organisation du dépôt

| Dossier | Contenu | Tests |
|---|---|---|
| [RobAirKit/](RobAirKit) | Package Swift partagé : **toute la crypto et toute la logique de sécurité**, sans interface | `cd RobAirKit && swift test` (103) |
| [iOSApp/](iOSApp) | App iPhone, deux modes : **Capteur** (surveillance, coffre, alerte, télémétrie) et **Balise** | sur appareil (J2 §14) |
| [MacApp/](MacApp) | App macOS : centrale (tableau de bord, carte, journal, défis, secours, relais) | sur appareil |
| [relay/](relay) | Relais aveugle (extension P2), Python bibliothèque standard, déploiement durci | `cd relay && python3 -m unittest` (15) |
| [Config/](Config), [scripts/](scripts) | Réglages Xcode communs ; `setup.sh` / `cleanup.sh` pour les Mac prêtés | — |

**Aucune dépendance tierce** côté iPhone et Mac : uniquement les frameworks Apple (CryptoKit, Security, LocalAuthentication, CoreBluetooth, CoreLocation, Network, AVFoundation, CoreImage, MapKit).

## Démarrer une séance sur un Mac prêté

1. `git clone` puis `sh scripts/setup.sh`. Le script demande le Team ID du compte gratuit et lance les tests du module.
2. Créer le projet Xcode une seule fois, puis le versionner : voir [docs/xcode-setup.md](docs/xcode-setup.md).
   Installer sur le Mac et les iPhone, appairer et dérouler les scénarios de test : **[docs/installation-et-test.md](docs/installation-et-test.md)**.
3. En fin de séance : bouton « Réinitialiser la centrale » dans l'app Mac, `sh scripts/cleanup.sh`, puis `git push`.

L'app installée avec un compte gratuit **expire après 7 jours** : il faut la réinstaller **la veille** de chaque démo (J1 §7).

## Équipe et rôles (J1 §6)

| Rôle | Membre | GitHub |
|---|---|---|
| Chef de projet | Manaia Logologofolau | `@Br4tha` |
| Architecte sécurité | Samuel Dorismond | `@Samuel-DD07` |
| Développeur iOS | Rayann Bouheddou | `@Rayouuuuuu` |
| Red team | tourne à chaque jalon (J1 §6) | |

## Règles du dépôt (J1 §6.1)

- `main` protégée : on y fusionne seulement par *pull request*, avec **2 approbations** (les deux membres qui ne sont pas l'auteur). **Un humain valide chaque fusion.** Propriétaires par dossier : [.github/CODEOWNERS](.github/CODEOWNERS).
- Le code crypto ou réseau exige **deux relecteurs**, dont l'architecte sécurité.
- **Pas de *squash*** : l'historique des revues fait partie du livrable.
- Aucun secret dans le code ni dans les prompts. Chaque prompt utile va dans `JOURNAL_IA.md`.
