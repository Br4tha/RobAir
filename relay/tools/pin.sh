#!/bin/sh
# Calcule le « pin » TLS du relais à mettre dans l'app Mac (Réglages du relais).
# pin = base64(SHA-256(clé publique X9.63 de 65 octets)) : exactement ce que calcule iOS/macOS
# (SecKeyCopyExternalRepresentation). Valable pour une clé ECDSA P-256 uniquement (voir README).
# Usage : sh tools/pin.sh /etc/letsencrypt/live/<domaine>/cert.pem
set -eu
[ $# -eq 1 ] || { echo "usage : $0 cert.pem" >&2; exit 1; }
openssl x509 -in "$1" -pubkey -noout \
  | openssl pkey -pubin -outform DER \
  | tail -c 65 \
  | openssl dgst -sha256 -binary \
  | openssl base64 -A
echo
