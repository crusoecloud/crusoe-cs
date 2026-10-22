#!/usr/bin/env bash
# Build-time check: every root PEM shipped in roles/emudhra_ca/files/certs/
# must hash (SHA-256 over the DER encoding) to exactly the fingerprint pinned
# in roles/emudhra_ca/vars/main.yml. Guards against cert/fingerprint drift:
# a mismatched pair would pass every e2e (injection uses the shipped certs)
# and silently no-op in production.
#
# Usage: tests/e2e/emudhra-ca/check-certs.sh [role-path]   (default: roles/emudhra_ca)
set -euo pipefail

ROLE="${1:-roles/emudhra_ca}"
VARS="${ROLE}/vars/main.yml"
CERTS="${ROLE}/files/certs"

[[ -f "$VARS" ]] || { echo "check-certs: $VARS not found" >&2; exit 1; }
[[ -d "$CERTS" ]] || { echo "check-certs: $CERTS not found" >&2; exit 1; }

failures=0
checked=0

# Parse the pinned list: pairs of (cert, sha256) from emudhra_ca_bad_roots.
while IFS=$'\t' read -r cert pinned; do
  [[ -n "$cert" && -n "$pinned" ]] || continue
  pem="${CERTS}/${cert}"
  checked=$((checked + 1))
  if [[ ! -f "$pem" ]]; then
    echo "FAIL: ${cert}: PEM missing at ${pem}" >&2
    failures=$((failures + 1))
    continue
  fi
  actual="$(openssl x509 -in "$pem" -noout -fingerprint -sha256 \
    | tr -d ':' | awk -F= '{print toupper($2)}')"
  if [[ "$actual" != "$pinned" ]]; then
    echo "FAIL: ${cert}: pinned ${pinned} but PEM hashes to ${actual}" >&2
    failures=$((failures + 1))
  else
    echo "OK: ${cert}: ${pinned}"
  fi
done < <(python3 -c "
import yaml
with open('${VARS}') as f:
    data = yaml.safe_load(f)
for root in data['emudhra_ca_bad_roots']:
    print(f\"{root['cert']}\t{root['sha256']}\")
")

echo "check-certs: ${checked} checked, ${failures} failed"
[[ $failures -eq 0 ]] || exit 1
[[ $checked -gt 0 ]] || { echo "check-certs: no roots found in $VARS" >&2; exit 1; }
