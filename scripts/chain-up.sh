#!/usr/bin/env bash
# Start a fresh private regtest chain (Zebra 7.0.0 + Zaino) and activate NU5..NU6.3.
# `--reset` wipes chain state and the demo's wallets/keys in .state/.
set -euo pipefail
cd "$(dirname "$0")/.."
# Placeholder transparent miner address until `zescrow setup` points coinbase at the buyer's
# shielded address (from ZcashFoundation/z3's regtest example).
export MINER_ADDRESS="${MINER_ADDRESS:-tmSRd1r8gs77Ja67Fw1JcdoXytxsyrLTPJm}"
if [[ "${1:-}" == "--reset" ]]; then
  docker compose -f chain/compose.yaml down -v
  rm -rf .state
fi
docker compose -f chain/compose.yaml up -d
rpc() { curl -s -X POST -H 'Content-Type: application/json' -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$1\",\"params\":${2:-[]}}" http://127.0.0.1:18232; }
for _ in $(seq 1 60); do rpc getblockcount | grep -q result && break; sleep 1; done
height=$(rpc getblockcount | sed 's/.*"result":\([0-9]*\).*/\1/')
if (( height < 2 )); then rpc generate "[$((2 - height))]" >/dev/null; fi
rpc getblockchaininfo | python3 -c 'import json,sys; d=json.load(sys.stdin)["result"]; print("regtest height", d["blocks"], "branch", d["consensus"]["chaintip"], "(37a5165b = NU6.3 Ironwood)")'
