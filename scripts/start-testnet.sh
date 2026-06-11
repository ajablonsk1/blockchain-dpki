#!/usr/bin/env bash
# Start all validators of a local testnet initialized with `dpkid testnet init`.
# Extra arguments are passed through to every `dpkid start` (e.g. --no-verify).
#
#   ./scripts/start-testnet.sh [--no-verify ...]
#
# Override the data directory with TESTNET_DIR (default ./testnet-data).
set -euo pipefail

cd "$(dirname "$0")/.."

TESTNET_DIR="${TESTNET_DIR:-./testnet-data}"

if [[ ! -d "$TESTNET_DIR" ]]; then
    echo "ERROR: $TESTNET_DIR does not exist — run ./bin/dpkid testnet init first" >&2
    exit 1
fi
if pgrep -f "dpkid start --home $TESTNET_DIR" >/dev/null; then
    echo "ERROR: testnet nodes are already running — ./scripts/stop-testnet.sh first" >&2
    exit 1
fi

make build >/dev/null

STARTED=0
PORTS=()
for home in "$TESTNET_DIR"/node*; do
    name=$(basename "$home")
    log="$home/node.log"
    ./bin/dpkid start --home "$home" "$@" >"$log" 2>&1 &
    echo "started $name (pid $!), log: $log"
    PORTS+=("$((26657 + 10 * STARTED))")
    STARTED=$((STARTED + 1))
done

echo
echo "testnet running with $STARTED validators"
echo "RPC ports: ${PORTS[*]}"
echo "stop with ./scripts/stop-testnet.sh"
