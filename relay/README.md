# Relais aveugle RobAir (extension P2)

> Référence : J1 §1.4, §2.3, §3.6 et J2 §9. **À réaliser seulement si l'écart « relais » est validé au J1**, après le socle P0/P1.

Le relais est une **boîte aux lettres**. Quand le Mac n'est pas joignable sur le Wi-Fi local, l'iPhone y dépose sa télémétrie, et le Mac vient la chercher toutes les 30 s pendant une alerte. Les messages sont **chiffrés pour le Mac (HPKE) et signés par l'iPhone**. Le relais ne peut donc **ni lire les positions, ni fabriquer un message valide**.

## Choix de la stack

**Python 3, bibliothèque standard uniquement** (`http.server`, `ssl`, `sqlite3`, `secrets`).

- **Zéro dépendance tierce**, donc zéro risque de « dépendance fantôme » (slide 9). Python 3 est déjà installé sur la plupart des serveurs Linux.
- **Limite assumée :** `http.server` n'est pas un serveur web industriel. Nous l'avons durci : délais de 10 s, 64 connexions simultanées au plus, handshake TLS fait hors de la boucle d'acceptation, limites de débit, taille maximale, et service systemd confiné. Un attaquant déterminé peut quand même le saturer. **C'est acceptable**, car le relais est une **extension de secours** : le socle (canal local) n'en dépend pas, et une saturation ne compromet ni la confidentialité ni l'intégrité des données.

## API

| Méthode | Chemin | Jeton | Effet |
|---|---|---|---|
| POST | `/v1/mailboxes` | clé d'enrôlement | crée une boîte → `{mailboxID, writeToken, readToken}` |
| POST | `/v1/mailboxes/{id}/messages` | écriture (iPhone) | dépose `{message: base64}` (≤ 4 Ko) |
| GET | `/v1/mailboxes/{id}/messages` | lecture (Mac) | liste les messages |
| DELETE | `/v1/mailboxes/{id}/messages/{mid}` | lecture (Mac) | accusé = suppression |
| DELETE | `/v1/mailboxes/{id}` | lecture (Mac) | ferme la boîte |

- **Les jetons d'écriture et de lecture sont distincts.** Un voleur qui extrairait le jeton d'écriture de l'iPhone ne pourrait pas lire les positions. Les jetons sont **stockés hachés** (SHA-256) et comparés en temps constant.
- **Limites :** 4 Ko par message, 100 messages par boîte, 72 h de durée de vie, 60 requêtes/min par boîte et 120 par IP.
- **Vie privée :** aucune journalisation des contenus ni des IP. Les IP ne restent qu'**en mémoire**, moins de 2 min, pour la limite de débit : c'est plus strict que les 24 h prévues au J1. Les messages supprimés sont écrasés sur disque (`secure_delete`).
- **Erreurs génériques** (`{"error":"refused"}`) : aucun détail n'est renvoyé.

## Tests

```bash
cd relay && python3 -m unittest -v test_relay
```

15 tests couvrent : le cycle complet, la clé d'enrôlement, les jetons non interchangeables et liés à leur boîte, les routes inconnues et la traversée de chemin, la validation stricte (champ inconnu, base64, tailles), le quota, la limite de débit, la purge à 72 h, les jetons hachés en base, les erreurs muettes, **TLS 1.3 obligatoire (TLS 1.2 refusé)** et la cohérence du *pin* entre `tools/pin.sh` et iOS.

## Déploiement sur le mini-serveur

**Prérequis à vérifier** (J1 §2.3) : une IP publique et **pas de CGNAT** chez l'opérateur. Sinon le relais est injoignable : le repli §1.4 s'applique (file locale, envoi différé). Il faut aussi un nom de domaine, et un DNS dynamique gratuit suffit.

```bash
# 1. Utilisateur système dédié, dossiers
sudo useradd --system --no-create-home --shell /usr/sbin/nologin robair-relay
sudo install -d -o robair-relay -g robair-relay -m 700 /var/lib/robair-relay
sudo install -d -m 755 /opt/robair-relay /etc/robair-relay/tls
sudo install -m 644 robair_relay.py /opt/robair-relay/

# 2. Certificat Let's Encrypt : clé ECDSA P-256 RÉUTILISÉE au renouvellement, sinon le pin change tous les 60 jours
sudo certbot certonly --standalone -d relais.exemple.fr --key-type ecdsa --elliptic-curve secp256r1 --reuse-key
sudo cp -L /etc/letsencrypt/live/relais.exemple.fr/{fullchain,privkey}.pem /etc/robair-relay/tls/
sudo chown root:robair-relay /etc/robair-relay/tls/*.pem && sudo chmod 640 /etc/robair-relay/tls/*.pem

# 3. Pin TLS et clé d'enrôlement : à saisir dans l'app Mac (« Réglages du relais »)
sh tools/pin.sh /etc/robair-relay/tls/fullchain.pem
sudo -u robair-relay python3 /opt/robair-relay/robair_relay.py init --data-dir /var/lib/robair-relay

# 4. Service durci + pare-feu (seul le 443 ouvert ; SSH depuis le réseau local seulement)
sudo cp deploy/robair-relay.service /etc/systemd/system/ && sudo systemctl enable --now robair-relay
sudo cp deploy/nftables.conf /etc/nftables.conf && sudo systemctl enable --now nftables
```

Ensuite, sur la box : rediriger **uniquement le port 443** vers le mini-serveur. Activer les mises à jour automatiques (`unattended-upgrades` sous Debian ou Ubuntu). Isoler le serveur du reste du réseau domestique si la box le permet (réseau invité, DMZ).

**Après chaque renouvellement de certificat** (hook certbot) : recopier les fichiers PEM, puis faire `systemctl restart robair-relay`. Grâce à `--reuse-key`, le pin ne change pas.
