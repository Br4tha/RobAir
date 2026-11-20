#!/bin/sh
# cleanup.sh — à lancer en FIN de séance sur un Mac prêté.
# Avant : dans l'app Mac, bouton « Réinitialiser la centrale » (efface clés, appairage, relais, journal).
# Ce script efface ensuite les traces locales de build et de signature.
set -eu
cd "$(dirname "$0")/.."
rm -f Config/Signing.local.xcconfig
rm -rf RobAirKit/.build
rm -rf "$HOME/Library/Developer/Xcode/DerivedData"/RobAir-*
echo "Nettoyé. Pensez à : git push, puis vous déconnecter de votre compte Apple dans Xcode > Settings > Accounts."
