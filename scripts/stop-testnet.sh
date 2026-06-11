#!/usr/bin/env bash
# Stop all local testnet validators started by start-testnet.sh.
set -uo pipefail

TESTNET_DIR="${TESTNET_DIR:-./testnet-data}"

if pkill -f "dpkid start --home $TESTNET_DIR"; then
    echo "testnet stopped"
else
    echo "no testnet nodes were running"
fi
