#!/usr/bin/env bash
# End-to-end test of the CLI against a real single-node chain: full domain
# lifecycle (register -> lookup -> verify -> verify-offline -> rotate -> revoke).
set -euo pipefail

cd "$(dirname "$0")/.."

WORKDIR=$(mktemp -d)
NODE_PID=""
cleanup() {
    [[ -n "$NODE_PID" ]] && kill "$NODE_PID" 2>/dev/null || true
    rm -rf "$WORKDIR"
}
trap cleanup EXIT

make build >/dev/null
CLI=./bin/dpki-cli
DOMAIN=test.example.com
export CMTHOME="$WORKDIR/node"

echo "==> init + start node"
./bin/dpkid init --chain-id e2e-chain >/dev/null
./bin/dpkid start --no-verify >"$WORKDIR/node.log" 2>&1 &
NODE_PID=$!

for _ in $(seq 1 30); do
    $CLI status >/dev/null 2>&1 && break
    sleep 1
done
$CLI status

echo "==> keys generate + show"
$CLI keys generate --output "$WORKDIR/owner.priv"
$CLI keys generate --output "$WORKDIR/new.priv" >/dev/null
$CLI keys show --keyfile "$WORKDIR/owner.priv"

echo "==> register"
$CLI register --domain "$DOMAIN" --keyfile "$WORKDIR/owner.priv" --skip-challenge

echo "==> lookup (saving proof bundle + certificate)"
$CLI lookup --domain "$DOMAIN" --save-proof "$WORKDIR/proof.json" --save-cert "$WORKDIR/cert.json"

echo "==> verify (online)"
$CLI verify --domain "$DOMAIN"

echo "==> verify-offline against the recorded root"
ROOT=$(sed -n 's/.*"app_hash": "\([0-9a-f]*\)".*/\1/p' "$WORKDIR/proof.json")
$CLI verify-offline --proof "$WORKDIR/proof.json" --root "$ROOT" --cert "$WORKDIR/cert.json"

echo "==> verify-offline must reject a wrong root"
if $CLI verify-offline --proof "$WORKDIR/proof.json" --root "$(printf '0%.0s' {1..64})" >/dev/null 2>&1; then
    echo "ERROR: a wrong root was accepted" >&2
    exit 1
fi

echo "==> rotate"
$CLI rotate --domain "$DOMAIN" --keyfile "$WORKDIR/owner.priv" --new-keyfile "$WORKDIR/new.priv"

echo "==> revoke (signed with the new key)"
$CLI revoke --domain "$DOMAIN" --keyfile "$WORKDIR/new.priv" --reason "e2e test"

echo "==> lookup shows the revocation"
# grep -q would close the pipe early and kill lookup with SIGPIPE under pipefail
LOOKUP_OUT=$($CLI lookup --domain "$DOMAIN")
grep -q REVOKED <<<"$LOOKUP_OUT"

echo
echo "ALL E2E CHECKS PASSED"
