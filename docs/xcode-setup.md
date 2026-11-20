# Créer le projet Xcode (une seule fois, puis le versionner)

> Pourquoi un guide et pas un `.xcodeproj` tout fait ? Le fichier projet d'Xcode est un format interne que l'IA n'a pas pu ouvrir ni tester (pas de macOS). Le créer dans Xcode prend environ 10 minutes. Une fois commité, les séances suivantes n'ont plus qu'à faire `git clone` puis `scripts/setup.sh`.
> Requis : Xcode 15.3 ou plus récent (Swift 5.10), iOS 17 et macOS 14.

## 1. Projet et cible iPhone

1. *File > New > Project > iOS > App*. Nom du produit : `RobAir`, interface : SwiftUI, langage : Swift. Enregistrer à la **racine du dépôt**, en décochant « Create Git repository ».
2. Supprimer les fichiers générés (`ContentView.swift`, `RobAirApp.swift` créé par Xcode). Glisser le dossier `iOSApp/` dans la cible **RobAir**, avec « Create groups » et sans copier.
3. *Project > Info > Configurations* : pour Debug et Release, choisir `Config/Base.xcconfig` au niveau du **projet**.
4. Cible RobAir, onglet *Build Settings* :
   - `Product Bundle Identifier` = `$(ROBAIR_BUNDLE_PREFIX).robair`
   - `Info.plist File` = `iOSApp/Info.plist`. Garder `Generate Info.plist File` = Yes : Xcode fusionne les deux.
5. Onglet *General > Frameworks* : **+** puis *Add Other > Add Package Dependency… > Add Local…*, choisir le dossier `RobAirKit/` et ajouter le produit `RobAirKit`.
6. Onglet *Signing & Capabilities* : équipe = Personal Team (renseignée par `setup.sh`). Les modes d'arrière-plan sont déjà dans `iOSApp/Info.plist`.

## 2. Cible Mac

1. *File > New > Target > macOS > App*. Nom : `RobAirCentrale`, interface : SwiftUI.
2. Supprimer les fichiers générés, puis glisser `MacApp/` dans cette cible.
3. *Build Settings* :
   - `Product Bundle Identifier` = `$(ROBAIR_BUNDLE_PREFIX).centrale`
   - `Info.plist File` = `MacApp/Info.plist`
   - `Code Signing Entitlements` = `MacApp/Centrale.entitlements`
4. Ajouter le produit `RobAirKit` à cette cible aussi (*General > Frameworks*).

## 3. Vérifier

> La procédure complète (installation sur iPhone, appairage, scénarios de test, dépannage) est dans [installation-et-test.md](installation-et-test.md).


- `Product > Test` sur le schéma du package `RobAirKit` : **103 tests verts**.
- Lancer RobAir sur **deux iPhone** : l'un choisit « Capteur », l'autre « Balise ». Lancer `RobAirCentrale` sur le Mac.
- Le **simulateur** convient pour l'interface (clés logicielles), mais **pas** pour le BLE, la Secure Enclave ni Face ID.
- Dans l'app Mac, noter ce qu'affiche « Clé maîtresse » : *Secure Enclave* ou *repli logiciel*. Le reporter dans le J2 §15 (point à vérifier au J3).

## 4. Versionner

```bash
git switch -c chore/xcode-project
git add RobAir.xcodeproj
git commit -m "chore: projet Xcode (cibles iPhone et Mac, package local RobAirKit)"
git push -u origin chore/xcode-project
```

Ne **jamais** commiter `xcuserdata/` ni `Config/Signing.local.xcconfig` : ils sont déjà dans `.gitignore`.
