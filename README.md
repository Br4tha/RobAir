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
| Chef de projet | |
| Architecte sécurité | |
| Développeur iOS | |
| Red team (tourne à chaque jalon) | |

## Règles du dépôt

- Une branche par fonctionnalité et une revue humaine **avant chaque merge** (historique de revues demandé).
- Aucun secret dans le code ni dans les prompts. Aucune dépendance tierce : frameworks Apple uniquement.
- Tout code crypto est relu ligne à ligne et testé avant d'être fusionné.
- Chaque prompt IA utile est consigné dans `docs/journal-ia.md`.

## Contraintes techniques

- Compte Apple gratuit : l'app expire après 7 jours, **réinstaller depuis Xcode avant chaque démo**.
- Pas d'APNs, d'iCloud ni de NFC.
