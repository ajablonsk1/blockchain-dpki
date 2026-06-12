#!/usr/bin/env bash
# Run the full Phase-7 measurement campaign: network benchmarks against a
# fresh 4-validator testnet, in-process state/proof benchmarks, and the
# security test suite. Everything lands in results/<timestamp>/ — the raw
# material for thesis chapters 7 and 8.
set -euo pipefail

cd "$(dirname "$0")/.."

RESULTS_DIR="results/$(date +%Y%m%d_%H%M%S)"
mkdir -p "$RESULTS_DIR"

cleanup() { ./scripts/stop-testnet.sh >/dev/null 2>&1 || true; }
trap cleanup EXIT

make build >/dev/null

{
    echo "date: $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
    echo "uname: $(uname -a)"
    echo "cpu: $(sysctl -n machdep.cpu.brand_string 2>/dev/null || echo unknown)"
    echo "ram: $(($(sysctl -n hw.memsize 2>/dev/null || echo 0) / 1073741824)) GB"
    echo "go: $(go version)"
    echo "cometbft: $(grep 'github.com/cometbft/cometbft ' go.mod | awk '{print $2}')"
    echo "commit: $(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
} > "$RESULTS_DIR/environment.txt"
cat "$RESULTS_DIR/environment.txt"

echo "==> fresh 4-validator testnet"
./scripts/stop-testnet.sh >/dev/null 2>&1 || true
rm -rf testnet-data
./bin/dpkid testnet init >/dev/null
./scripts/start-testnet.sh --no-verify >/dev/null

echo "==> warmup (15s)"   # first blocks are not representative
sleep 15

echo "==> throughput suite"
./bin/benchmark --suite throughput --node http://localhost:26657 \
    --output "$RESULTS_DIR/throughput.json"

echo "==> latency suite"
./bin/benchmark --suite latency --node http://localhost:26657 \
    --output "$RESULTS_DIR/latency.json"

./scripts/stop-testnet.sh >/dev/null

echo "==> state suite (in-process)"
./bin/benchmark --suite state --output "$RESULTS_DIR/state.json"

echo "==> proof suite (in-process)"
./bin/benchmark --suite proof --output "$RESULTS_DIR/proof.json"

echo "==> security test suite"
go test -count=1 -v -run 'TestSTRIDE|TestFrontRunning' ./internal/app \
    > "$RESULTS_DIR/security-tests.log" 2>&1
grep -c -- "--- PASS" "$RESULTS_DIR/security-tests.log" |
    xargs -I{} echo "security: {} scenarios passed"

echo
echo "DONE — results in $RESULTS_DIR/"
ls -la "$RESULTS_DIR"
