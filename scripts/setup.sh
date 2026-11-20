#!/bin/sh
# setup.sh — à lancer au début de chaque séance sur un Mac prêté (J1 §7).
# Crée Config/Signing.local.xcconfig (ignoré par git) avec VOTRE Team ID et un préfixe d'identifiant unique.
# Aucun secret n'est écrit dans le dépôt.
set -eu
cd "$(dirname "$0")/.."

command -v xcodebuild >/dev/null || { echo "Xcode n'est pas installé sur ce Mac." >&2; exit 1; }
echo "Xcode : $(xcodebuild -version | head -1)"

printf "Team ID (Xcode > Settings > Accounts, compte gratuit « Personal Team ») : "
read -r TEAM
printf "Préfixe d'identifiant (ex. fr.m2.prenomnom) : "
read -r PREFIX
case "$PREFIX" in *[!a-zA-Z0-9.-]*|"") echo "Préfixe invalide." >&2; exit 1 ;; esac

cat > Config/Signing.local.xcconfig <<CONF
// Généré par scripts/setup.sh — NE PAS COMMITER (ignoré par .gitignore).
DEVELOPMENT_TEAM = $TEAM
ROBAIR_BUNDLE_PREFIX = $PREFIX
CONF
echo "OK : Config/Signing.local.xcconfig créé."

echo "Tests du module partagé (RobAirKit)…"
(cd RobAirKit && swift test) && echo "Tests OK."
echo "Rappel : l'app installée avec un compte gratuit expire après 7 jours (réinstaller la veille d'une démo)."
