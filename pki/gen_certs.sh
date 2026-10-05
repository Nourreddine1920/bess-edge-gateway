#!/usr/bin/env bash
# Generates a small demo PKI:
#   - an offline-style Root CA
#   - a broker server certificate
#   - one client certificate per edge gateway (identity = certificate CN)
#   - a client certificate for the cloud service
#   - an Ed25519 key pair the cloud uses to SIGN commands (end-to-end, independent of the broker)
#   - a "rogue" CA + certificate, used only by attack_demo.py to show impersonation is rejected
#
# In production: root key stays offline/in an HSM, an intermediate CA signs device certs,
# and device keys are generated inside a secure element / TPM and never leave the hardware.
set -euo pipefail
cd "$(dirname "$0")"
OUT=out
rm -rf "$OUT" && mkdir -p "$OUT"
DAYS=825

echo "[pki] Root CA"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
  -keyout "$OUT/ca.key" -out "$OUT/ca.crt" -days 3650 \
  -subj "/O=BESS Edge Demo/CN=BESS Demo Root CA" 2>/dev/null

issue() {  # issue <name> <CN> <extfile-content>
  local name=$1 cn=$2 ext=$3
  openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
    -keyout "$OUT/$name.key" -out "$OUT/$name.csr" -subj "/O=BESS Edge Demo/CN=$cn" 2>/dev/null
  printf "%b" "$ext" > "$OUT/$name.ext"
  openssl x509 -req -in "$OUT/$name.csr" -CA "$OUT/ca.crt" -CAkey "$OUT/ca.key" -CAcreateserial \
    -out "$OUT/$name.crt" -days $DAYS -extfile "$OUT/$name.ext" 2>/dev/null
  rm -f "$OUT/$name.csr" "$OUT/$name.ext"
  echo "[pki] issued $name (CN=$cn)"
}

issue broker broker "subjectAltName=DNS:localhost,DNS:mosquitto,IP:127.0.0.1\nextendedKeyUsage=serverAuth\nkeyUsage=digitalSignature"
issue gw-site-01 gw-site-01 "extendedKeyUsage=clientAuth\nkeyUsage=digitalSignature"
issue gw-site-02 gw-site-02 "extendedKeyUsage=clientAuth\nkeyUsage=digitalSignature"
issue cloud-service cloud-service "extendedKeyUsage=clientAuth\nkeyUsage=digitalSignature"

echo "[pki] command-signing key (Ed25519)"
openssl genpkey -algorithm ed25519 -out "$OUT/cmd-signing.key" 2>/dev/null
openssl pkey -in "$OUT/cmd-signing.key" -pubout -out "$OUT/cmd-signing.pub" 2>/dev/null

echo "[pki] rogue CA + forged 'gw-site-01' cert (for attack_demo.py only)"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
  -keyout "$OUT/rogue-ca.key" -out "$OUT/rogue-ca.crt" -days 30 -subj "/CN=Rogue CA" 2>/dev/null
openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
  -keyout "$OUT/rogue.key" -out "$OUT/rogue.csr" -subj "/CN=gw-site-01" 2>/dev/null
openssl x509 -req -in "$OUT/rogue.csr" -CA "$OUT/rogue-ca.crt" -CAkey "$OUT/rogue-ca.key" \
  -CAcreateserial -out "$OUT/rogue.crt" -days 30 2>/dev/null
rm -f "$OUT/rogue.csr"

chmod 644 "$OUT"/*   # demo only: lets the broker container read the keys
echo "[pki] done -> pki/out/"
