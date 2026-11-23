# RobAir · l'iPhone comme capteur de proximité de confiance

Projet M2 « Faire de l'iPhone un équipement de sécurité ».

L'iPhone surveille sa proximité BLE avec le Mac appairé. S'il s'éloigne, perd la liaison ou ne parvient plus à vérifier l'identité du Mac, il **verrouille sa zone protégée** et **alerte le Mac** (la centrale) par un canal chiffré et authentifié sur le Wi-Fi local.

## Documents

| Jalon | Document | État |
|---|---|---|
| J1 · Cadrage | [docs/J1-cadrage.md](docs/J1-cadrage.md) : périmètre, actifs, attaquants, STRIDE, RGPD | ✅ |
| J2 · Architecture | [docs/J2-architecture.md](docs/J2-architecture.md) : schémas, protocole, choix crypto, tests | ✅ |
| J3 · MVP | — | à venir |
| J4 · Audit croisé | — | à venir |
| J5 · Soutenance | — | à venir |
| Transverse | [docs/journal-ia.md](docs/journal-ia.md) : journal des prompts commenté | en continu |

## Équipe et rôles

| Rôle | Membre |
|---|---|
| Chef de projet | Rayann Bouheddou |
| Architecte sécurité | Samuel Dorismond |
| Développeur iOS | Manaia Logologofolau |

**Red team : rotation à chaque jalon**, en plus du rôle principal. Personne n'attaque son propre travail.

| Jalon | Red team | Cible |
|---|---|---|
| J1 | Manaia Logologofolau | Cadrage et STRIDE (rédigés par l'architecte) |
| J2 | Rayann Bouheddou | Architecture et protocole (conçus par l'architecte) |
| J3 | Samuel Dorismond | MVP : rejeu, clonage BLE, logs, stockage (code du dev iOS) |
| J4 | Toute l'équipe | Audit croisé MASVS de l'app d'un autre groupe |

## Règles du dépôt

- Une branche par fonctionnalité et une revue humaine **avant chaque merge** (historique de revues demandé).
- Aucun secret dans le code ni dans les prompts. Aucune dépendance tierce : frameworks Apple uniquement.
- Tout code crypto est relu ligne à ligne et testé avant d'être fusionné.
- Chaque prompt IA utile est consigné dans `docs/journal-ia.md`.

## Contraintes techniques

- Compte Apple gratuit : l'app expire après 7 jours, **réinstaller depuis Xcode avant chaque démo**.
- Pas d'APNs, d'iCloud ni de NFC.
