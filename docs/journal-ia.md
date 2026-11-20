# Journal des prompts IA (commenté)

> Livrable obligatoire (slides 8 et 20). On consigne **les prompts utiles et pertinents** : ceux qui ont produit du contenu ou du code conservé, ou une décision.
> La rubrique « Demande » est un **résumé fidèle** de ce qui a été demandé, reformulé en registre neutre. Elle n'ajoute aucune consigne qui n'a pas été donnée.
> Règle : aucun secret, aucune clé, aucune donnée réelle dans les prompts.

## Modèle d'entrée

```
### P-XX · <titre court>
- Date · jalon · auteur :
- Outil :
- Contexte fourni :
- Demande (résumé fidèle) :
- Sortie de l'IA :
- Décision de l'équipe (gardé / modifié / rejeté) + justification :
- Vérification humaine (relecture, test, source consultée) :
- Validé par :
```

---

### P-01 · Analyse du sujet et planification des jalons J1 et J2
- **Date · jalon · auteur :** 2026-11-19 · J1 · chef de projet
- **Outil :** assistant IA de code (Claude)
- **Contexte fourni :** sujet du projet (PDF de 20 slides), note de cadrage de l'équipe validée par l'enseignant.
- **Demande (résumé fidèle) :** analyser le sujet, établir le plan de travail des jalons J1 (cadrage, STRIDE) et J2 (architecture, choix crypto), avec des explications suffisantes pour que le chef de projet puisse les transmettre à l'équipe.
- **Sortie de l'IA :** synthèse du sujet, rappel des obligations liées à l'IA (journal des prompts, revue humaine avant merge), plan des livrables J1 et J2.
- **Décision de l'équipe :** plan retenu.
- **Vérification humaine :** comparaison avec les slides 8, 12 et 20 du sujet.
- **Validé par :** _à compléter_

### P-02 · Relecture critique du cadrage J1 et rédaction du dossier d'architecture J2
- **Date · jalon · auteur :** 2026-11-19 · J1 et J2 · chef de projet
- **Outil :** assistant IA de code (Claude)
- **Contexte fourni :** note de cadrage et premier modèle STRIDE de l'équipe.
- **Demande (résumé fidèle) :** structurer le cadrage J1 et le modèle STRIDE en suivant le cadre du sujet, puis produire le livrable J2 (architecture iPhone ↔ Mac, choix cryptographiques justifiés).
- **Sortie de l'IA :** `J1-cadrage.md` (actifs, attaquants, STRIDE détaillé, risques résiduels, RGPD), `J2-architecture.md` (schémas, appairage, handshake, format de trame, BLE, machine à états, stockage, tableau des choix crypto, permissions, plan de tests) et `fiche-oral.md`.
- **Écarts relevés par rapport à notre J1 initial :**
  1. **Usurpation de balise (S2) non couverte.** La parade QR + ECDSA protégeait le Wi-Fi, pas le BLE, alors qu'une balise BLE se clone facilement. → Ajout d'un **défi-réponse BLE signé**, et le Mac fait office de balise.
  2. **Face ID à chaque signature : incompatible avec l'arrière-plan.** → **Deux clés** : K_id_I (routine) et K_bio_I (actions sensibles, Face ID).
  3. **Conflit entre la protection de fichiers `Complete` et le fonctionnement en arrière-plan.** → Les données utiles en arrière-plan restent en mémoire, seul le contenu protégé est en `Complete`.
  4. **Attaque par relais BLE non identifiée.** → Ajoutée en risque résiduel, avec des atténuations.
  5. **Non-répudiation** : AES-GCM seul ne prouve rien face au Mac, qui possède la même clé. → Signature K_bio_I sur les événements sensibles.
- **Décision de l'équipe :** _à compléter après relecture en équipe (gardé, modifié, rejeté pour chaque point)._
- **Vérification humaine :** _à compléter (ex. : doc Apple CryptoKit `SecureEnclave.P256`, `SecAccessControlCreateFlags.biometryCurrentSet`, CoreBluetooth background modes)._
- **Validé par :** _à compléter_

### P-03 · Environnement de développement sur Mac prêtés et impact sur l'appairage
- **Date · jalon · auteur :** 2026-11-19 · J2 · chef de projet
- **Outil :** assistant IA de code (Claude)
- **Contexte fourni :** un MacBook différent est prêté à chaque séance.
- **Demande (résumé fidèle) :** choisir la méthode la plus efficace pour réinstaller l'environnement à chaque séance (conteneur ou autre). Mise en œuvre reportée.
- **Sortie de l'IA :** Docker écarté (pas de macOS ni d'Xcode en conteneur, et les VM macOS sont trop lourdes). Proposition : dépôt git autonome, sans dépendance tierce, avec des scripts `setup.sh` et `cleanup.sh`. Conséquence ajoutée au J2 : **réappairage à chaque nouveau Mac** (la clé privée du Mac n'est pas exportable) et effacement des clés en fin de séance.
- **Décision de l'équipe :** _à compléter_
- **Vérification humaine :** _à compléter (vérifier la version d'Xcode installée sur les Mac de l'école)._
- **Validé par :** _à compléter_

### P-04 · Analyse de l'état du projet (point d'étape)
- **Date · jalon · auteur :** 2026-11-20 · J3 · chef de projet
- **Outil :** assistant IA de code (Claude)
- **Contexte fourni :** tout le dépôt (sujet PDF, docs J1/J2, code RobAirKit (ex-AntivolKit), iOSApp, MacApp, tests).
- **Demande (résumé fidèle) :** réanalyser le projet pour savoir où on en est, et produire une analyse sous forme de PDF.
- **Sortie de l'IA :** `docs/analyse-projet-2026-11-20.pdf` : état des jalons, inventaire, relecture du code (4 bloquants, 5 points importants, 9 mineurs), traçabilité STRIDE → code → test, plan d'action.
- **Décision de l'équipe :** _à compléter_
- **Vérification humaine :** _à compléter (vérifier chaque constat dans le code, en particulier I1 à I5)._
- **Validé par :** _à compléter_

### P-05 · Renommage du projet en RobAir
- **Date · jalon · auteur :** 2026-11-20 · J3 · chef de projet
- **Outil :** assistant IA de code (Claude)
- **Contexte fourni :** nom choisi par l'équipe : « RobAir » (*rob* = voler en anglais, *Air* = clin d'œil Apple).
- **Demande (résumé fidèle) :** remplacer le nom de travail « Antivol » par « RobAir » dans toute la documentation et tout le code.
- **Sortie de l'IA :** renommage des dossiers (`RobAirKit`, `RobAirKitTests`), du fichier `RobAirApp.swift`, des types (`RobAirConstants`, `RobAirError`, `RobAirJSON`), du service Bonjour (`_robair._tcp`), des étiquettes de séparation de domaine (`robair-…-v1`), des services Keychain et des sous-systèmes de logs. Les entrées précédentes de ce journal ne sont pas réécrites (historique).
- **Décision de l'équipe :** _à compléter_
- **Vérification humaine :** _à compléter (recompiler et relancer les tests : le renommage touche le nom du module importé partout)._
- **Validé par :** _à compléter_
