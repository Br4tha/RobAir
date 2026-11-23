## Objet

<!-- Ce que fait cette PR, en deux ou trois phrases. Lien vers la section du J1/J2 concernée. -->

## Type

- [ ] Documentation
- [ ] Code crypto ou réseau (`RobAirKit/`, `Network/`, `Security/`, `relay/`) : **l'architecte sécurité doit approuver**
- [ ] Interface ou autre code
- [ ] Configuration ou scripts

## Vérifications de l'auteur

- [ ] `cd RobAirKit && swift test` : tous les tests sont verts (nombre : ___)
- [ ] Build Xcode des deux cibles sans erreur (si du code des apps est modifié)
- [ ] `cd relay && python3 -m unittest` (si `relay/` est modifié)
- [ ] Aucun secret, aucune donnée réelle, aucun `Signing.local.xcconfig` dans le diff
- [ ] Aucune dépendance tierce ajoutée (frameworks Apple ou bibliothèque standard Python uniquement)
- [ ] Pas de `print()` ; les logs ne contiennent ni clé, ni jeton, ni position
- [ ] Les prompts IA utilisés sont dans `JOURNAL_IA.md` (prompt exact)
- [ ] Je suis capable d'expliquer chaque ligne de ce diff à l'oral

## Pour les relecteurs

- [ ] J'ai relu **commit par commit** et posé mes questions en commentaire
- [ ] Pour le code crypto : nonce unique, clés jamais loggées, comparaison en temps constant, erreurs muettes, entrées validées
- [ ] Le champ « Relecteur » des entrées concernées de `JOURNAL_IA.md` est rempli
- [ ] Fusion par **merge commit** (pas de squash, J1 §6.1)
