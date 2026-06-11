#!/usr/bin/env bash
# Multi-node testnet test harness: block production, state replication,
# determinism under load, and BFT fault tolerance (1 failure tolerated, 2
# failures halt, recovery by replay + blocksync).
#
# Each scenario's transcript is saved under docs/testnet/logs/ — empirical
# material for the security-analysis chapter of the thesis.
set -euo pipefail

cd "$(dirname "$0")/.."

TESTNET_DIR=./testnet-data
LOG_DIR=docs/testnet/logs
CLI=./bin/dpki-cli
PORTS=(26657 26667 26677 26687)

mkdir -p "$LOG_DIR"
WORKDIR=$(mktemp -d)
cleanup() {
    ./scripts/stop-testnet.sh >/dev/null 2>&1 || true
    rm -rf "$WORKDIR"
}
trap cleanup EXIT

# --- helpers -----------------------------------------------------------------

LOG_FILE=""
log() { echo "$@" | tee -a "$LOG_FILE"; }

begin_test() {
    LOG_FILE="$LOG_DIR/$1.log"
    : >"$LOG_FILE"
    log "=== $2 ($(date -u '+%Y-%m-%d %H:%M:%S UTC')) ==="
}

height() { $CLI status --node "http://localhost:$1" 2>/dev/null | sed -n 's/Latest height: *//p'; }

# app_hash_at PORT HEIGHT — the AppHash field of the header at HEIGHT.
app_hash_at() {
    curl -s "http://localhost:$1/header?height=$2" | tr -d ' \n' |
        sed -n 's/.*"app_hash":"\([^"]*\)".*/\1/p'
}

# wait_height PORT HEIGHT TIMEOUT_S — wait until the node reaches HEIGHT.
wait_height() {
    local port=$1 want=$2 timeout=$3 h
    for _ in $(seq 1 "$timeout"); do
        h=$(height "$port" || true)
        [[ -n "$h" && "$h" -ge "$want" ]] && return 0
        sleep 1
    done
    log "TIMEOUT: node on port $port did not reach height $want"
    return 1
}

node_home() { echo "$TESTNET_DIR/node$1"; }

start_node() {
    ./bin/dpkid start --home "$(node_home "$1")" --no-verify >>"$(node_home "$1")/node.log" 2>&1 &
}

kill_node() { pkill -f "dpkid start --home $TESTNET_DIR/node$1" ; }

# --- setup -------------------------------------------------------------------

echo "==> fresh testnet"
./scripts/stop-testnet.sh >/dev/null 2>&1 || true
sleep 1
rm -rf "$TESTNET_DIR"
make build >/dev/null
./bin/dpkid testnet init --output-dir "$TESTNET_DIR"
./scripts/start-testnet.sh --no-verify

$CLI keys generate --output "$WORKDIR/key.priv" >/dev/null

# --- test 1: block production ------------------------------------------------

begin_test test-1-block-production "All 4 validators produce blocks"
for p in "${PORTS[@]}"; do wait_height "$p" 3 30; done
for p in "${PORTS[@]}"; do
    log "node :$p at height $(height "$p") ✓"
done
log "PASS: all validators are producing blocks"

# --- test 2: state replication -----------------------------------------------

begin_test test-2-state-replication "Tx sent to node0 is readable from every node"
$CLI register --domain replicated.example.com --keyfile "$WORKDIR/key.priv" \
    --node http://localhost:26657 --skip-challenge | tee -a "$LOG_FILE"
for p in "${PORTS[@]:1}"; do
    if ! $CLI lookup --domain replicated.example.com --node "http://localhost:$p" |
        tee -a "$LOG_FILE" | grep -q "Status:       Active"; then
        log "FAIL: node :$p does not see the domain"
        exit 1
    fi
    log "node :$p sees the domain ✓"
done
$CLI verify --domain replicated.example.com \
    --nodes "http://localhost:26657,http://localhost:26667,http://localhost:26677,http://localhost:26687" |
    tee -a "$LOG_FILE" | grep -q "verified by 4/4" || { log "FAIL: cross-node verify"; exit 1; }
log "PASS: state replicated and proven on all 4 nodes"

# --- test 3: determinism under load --------------------------------------------

begin_test test-3-determinism "50 transactions -> identical app hash on every node"
for i in $(seq 1 50); do
    port=${PORTS[$((i % 4))]}
    $CLI register --domain "load$i.example.com" --keyfile "$WORKDIR/key.priv" \
        --node "http://localhost:$port" --skip-challenge >/dev/null
done
log "sent 50 RegisterTx round-robin across the 4 nodes"
sleep 3

H=$(height 26657)
for p in "${PORTS[@]}"; do wait_height "$p" "$H" 30; done
declare -a HASHES=()
for p in "${PORTS[@]}"; do
    hash=$(app_hash_at "$p" "$H")
    HASHES+=("$hash")
    log "node :$p app hash at height $H: $hash"
done
UNIQUE=$(printf '%s\n' "${HASHES[@]}" | sort -u | wc -l | tr -d ' ')
if [[ "$UNIQUE" != 1 || -z "${HASHES[0]}" ]]; then
    log "FAIL: app hashes diverge"
    exit 1
fi
log "PASS: one unique app hash across all validators after 50 txs"

# --- test 4: one validator down — consensus continues ---------------------------

begin_test test-4-one-node-failure "BFT tolerates 1 of 4 validators failing"
kill_node 0
log "killed node0; 3 of 4 validators remain (>2/3 voting power)"
sleep 3
BEFORE=$(height 26667)
sleep 10
AFTER=$(height 26667)
log "height on node1: $BEFORE -> $AFTER over 10s"
if [[ "$AFTER" -le "$BEFORE" ]]; then
    log "FAIL: consensus stalled with only 1 failure"
    exit 1
fi
$CLI register --domain after-failure.example.com --keyfile "$WORKDIR/key.priv" \
    --node http://localhost:26667 --skip-challenge | tee -a "$LOG_FILE"
log "PASS: blocks and writes continue with 3/4 validators"

# --- test 5: two validators down — consensus halts ------------------------------

begin_test test-5-two-node-failure "Consensus halts with 2 of 4 validators down"
kill_node 1
log "killed node1; 2 of 4 validators remain (<2/3 voting power)"
sleep 5
BEFORE=$(height 26677)
sleep 15
AFTER=$(height 26677)
log "height on node2: $BEFORE -> $AFTER over 15s"
if [[ "$AFTER" -ne "$BEFORE" ]]; then
    log "FAIL: consensus continued without a 2/3 majority"
    exit 1
fi
log "PASS: consensus halted, no block can be finalized (safety over liveness)"

# --- test 6: recovery ------------------------------------------------------------

begin_test test-6-recovery "Restarted validators replay, sync and rejoin consensus"
start_node 0
start_node 1
log "restarted node0 and node1 (in-memory state rebuilt by block replay)"
TARGET=$((AFTER + 5))
for p in "${PORTS[@]}"; do wait_height "$p" "$TARGET" 60; done
H=$(height 26657)
for p in "${PORTS[@]}"; do wait_height "$p" "$H" 30; done
declare -a RHASHES=()
for p in "${PORTS[@]}"; do
    hash=$(app_hash_at "$p" "$H")
    RHASHES+=("$hash")
    log "node :$p app hash at height $H: $hash"
done
UNIQUE=$(printf '%s\n' "${RHASHES[@]}" | sort -u | wc -l | tr -d ' ')
if [[ "$UNIQUE" != 1 || -z "${RHASHES[0]}" ]]; then
    log "FAIL: app hashes diverge after recovery"
    exit 1
fi
$CLI lookup --domain replicated.example.com --node http://localhost:26657 |
    tee -a "$LOG_FILE" | grep -q "Status:       Active" || { log "FAIL: replayed state misses old domain"; exit 1; }
log "PASS: full recovery — consensus resumed, state identical on all 4 validators"

echo
echo "ALL TESTNET TESTS PASSED — transcripts in $LOG_DIR/"
