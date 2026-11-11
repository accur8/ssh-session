#!/usr/bin/env bash
# Live check of the account CA service (sign@ca.intra) for this machine's key.
#
#   bash tests/live-account-ca.sh [USER@HOST]
#   KEY=path/to/key bash tests/live-account-ca.sh   # another key (a throwaway enrolled for the test)
#
# Asks sign@ca.intra for a 1-hour certificate for the key ssh-session would
# send (the first of ~/.ssh/id_ed25519, id_ecdsa, id_rsa), then checks:
#   - the service issued one
#   - it certifies this key, and is signed by the account CA
#   - it names principals and is valid now
# With USER@HOST it also logs in there with key + certificate alone (no agent).
#
# It never writes in ~/.ssh and never touches the ssh-agent: the certificate
# lives in a scratch directory that is removed on exit. The service records
# the issuance in its ledger, as for every certificate.
set -uo pipefail

SERVICE=sign@ca.intra
ACCOUNT_CA_FP="SHA256:VnkR6O5xZGPrNTMkzqI4ALHFFRRTOaa64NvcZhAS23w"   # tier0 .docs/06-inventory.md
TARGET=${1:-}

fails=0
ok()   { printf '  ok    %s\n' "$*"; }
bad()  { printf '  FAIL  %s\n' "$*"; fails=$((fails + 1)); }
info() { printf '        %s\n' "$*"; }

key=${KEY:-}
[ -n "$key" ] || for k in id_ed25519 id_ecdsa id_rsa; do
  if [ -f "$HOME/.ssh/$k" ] && [ -f "$HOME/.ssh/$k.pub" ]; then key="$HOME/.ssh/$k"; break; fi
done
if [ -z "$key" ]; then
  echo "no key: none of ~/.ssh/id_ed25519, id_ecdsa, id_rsa has both halves"; exit 1
fi
key_fp=$(ssh-keygen -lf "$key.pub" | awk '{print $2}')
echo "key:     $key ($key_fp)"
echo "service: $SERVICE"

scratch=$(mktemp -d "$HOME/.ssh-session-ca-test.XXXXXX")
trap 'rm -rf "$scratch"' EXIT
cert="$scratch/key-cert.pub"

echo
echo "1. issue"
if ! ssh -o IdentitiesOnly=yes -o ConnectTimeout=10 -i "$key" "$SERVICE" 1h \
       < "$key.pub" > "$scratch/out" 2> "$scratch/err"; then
  bad "the service refused: $(tr '\n' ' ' < "$scratch/err")"
  info "Permission denied = this key has no line on $SERVICE (an admin enrols it);"
  info "a timeout = ca.intra is not reachable from here (NetBird?)"
  exit 1
fi
grep -- "-cert-v01@openssh.com " "$scratch/out" > "$cert" || true
if [ -s "$cert" ]; then ok "a certificate came back"; else bad "no certificate in the reply"; exit 1; fi

echo
echo "2. check"
listing=$(ssh-keygen -L -f "$cert")
cert_key_fp=$(awk '/Public key:/ {print $4}' <<<"$listing")
ca_fp=$(awk '/Signing CA:/ {print $4}' <<<"$listing")
principals=$(awk '/Principals:/ {f=1; next} f && /^[[:space:]]+[^[:space:]]+$/ && !/Critical/ {gsub(/^[[:space:]]+/, ""); p = p (p ? "," : "") $0; next} f {exit} END {print p}' <<<"$listing")
valid=$(awk -F'Valid: ' '/Valid:/ {print $2}' <<<"$listing")

[ "$cert_key_fp" = "$key_fp" ] && ok "certifies this key" || bad "certifies $cert_key_fp, not this key ($key_fp)"
[ "$ca_fp" = "$ACCOUNT_CA_FP" ] && ok "signed by the account CA" || bad "signed by $ca_fp, not the account CA ($ACCOUNT_CA_FP)"
[ -n "$principals" ] && ok "principals: $principals" || bad "names no principals"
info "valid:  $valid"

if [ -n "$TARGET" ]; then
  echo
  echo "3. log in to $TARGET with the certificate alone"
  if ssh -o IdentitiesOnly=yes -o IdentityAgent=none -o ConnectTimeout=10 \
         -o CertificateFile="$cert" -i "$key" "$TARGET" true 2> "$scratch/err"; then
    ok "logged in"
  else
    bad "login refused: $(tr '\n' ' ' < "$scratch/err")"
    info "the host must trust the account CA and map one of: $principals"
  fi
fi

echo
if [ "$fails" -eq 0 ]; then echo "account CA: PASS"; else echo "account CA: $fails FAIL"; exit 1; fi
