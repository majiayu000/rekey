#!/usr/bin/env bash
# P-05 focused connector contract gate. The same required security job runs
# P0 opaque and P2 GitHub release-process gates around this check.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

cargo test -p rekey-connector --test contract
cargo test -p rekey-broker --test connector_contract

if cargo tree -p rekey-connector -e normal \
  | rg 'tokio|tracing|reqwest|rusqlite|aes-gcm|argon2|rekey-vault|rekey-broker'; then
  echo "rekey-connector crossed its pure contract dependency boundary" >&2
  exit 1
fi

if cargo tree -p rekey-cli -e normal | rg 'rekey-connector'; then
  echo "rekey-cli must remain independent of rekey-connector" >&2
  exit 1
fi

echo "P-05 connector SDK contract gate passed"
