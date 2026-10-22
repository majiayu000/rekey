#!/usr/bin/env bash
# Rebuild the released-format fixture vaults used by
# crates/rekey-vault/tests/migrate.rs. Each fixture is created by the tagged
# release's own rekeyd/rekey binaries with synthetic credentials only.
#
#   scripts/make-migration-fixtures.sh <v0.3.0-alpha.2 checkout> <v0.4.0-alpha.1 checkout>
#
# Both checkouts must already be built (`cargo build --bins -p rekey-broker
# -p rekey-cli -p rekey-policy`). Requires openssl and python3. The fixture
# password is public test data: migration-fixture-password.
set -euo pipefail

V03=${1:?v0.3.0-alpha.2 checkout}
V04=${2:?v0.4.0-alpha.1 checkout}
ROOT=$(cd "$(dirname "$0")/.." && pwd)
OUT=$ROOT/crates/rekey-vault/tests/fixtures/migrate
PW=migration-fixture-password
WORK=$(mktemp -d)
DAEMON=
cleanup() {
    [[ -n $DAEMON ]] && kill "$DAEMON" 2>/dev/null || true
    rm -rf "$WORK"
}
trap cleanup EXIT

start() { # bin state
    printf '{"port":%s}' "$((40000 + RANDOM % 20000))" >"$2/service.json"
    chmod 600 "$2/service.json"
    "$1/rekeyd" serve --state-dir "$2" >"$WORK/serve.log" 2>&1 &
    DAEMON=$!
    for _ in $(seq 50); do
        [[ -S $2/runtime/admin.sock ]] && break
        sleep 0.1
    done
    printf '%s\n' "$PW" | "$1/rekey" --state-dir "$2" unlock --password-stdin >/dev/null
}

stop() { # state
    kill "$DAEMON"
    wait "$DAEMON" 2>/dev/null || true
    DAEMON=
    rm -rf "$1/runtime" "$1/ssh-agent.sock" "$1/service.json" "$1/.desktop-runtime-active" \
        "$1/vault.sqlite3-shm"
}

add_credential() { # bin state label value -> id
    printf '%s\n%s\n' "$PW" "$4" | "$1/rekey" --state-dir "$2" credential add "$3" --stdin-secrets |
        python3 -I -c 'import json,sys; print(json.load(sys.stdin)["id"])'
}

populate() { # bin state
    local id
    id=$(add_credential "$1" "$2" openai-fixture sk-fixture-openai-0001)
    printf '%s\n%s\n' "$PW" sk-fixture-openai-0002 |
        "$1/rekey" --state-dir "$2" credential rotate "$id" --stdin-secrets >/dev/null
    id=$(add_credential "$1" "$2" revoked-fixture fixture-revoked-token)
    printf '%s\n' "$PW" | "$1/rekey" --state-dir "$2" credential revoke "$id" --password-stdin >/dev/null
    add_credential "$1" "$2" github-fixture ghp_fixture_github_token
}

init() { # bin state
    mkdir -m 700 "$2"
    printf '%s\n' "$PW" | "$1/rekeyd" init --mode team --state-dir "$2" --password-stdin >/dev/null
}

save() { # state name
    rm -rf "${OUT:?}/$2"
    mkdir -p "$OUT/$2"
    cp "$1/vault.sqlite3" "$1/generation" "$OUT/$2/"
    [[ -f $1/vault.sqlite3-wal ]] && cp "$1/vault.sqlite3-wal" "$OUT/$2/"
    chmod 600 "$OUT/$2"/*
}

# vault25 / policy6: credentials only (0.3 policy had no Connections).
B=$V03/target/debug
S=$WORK/v25
init "$B" "$S"
start "$B" "$S"
populate "$B" "$S" >/dev/null
stop "$S"
save "$S" v25

# vault26 / policy7: credentials, an SSH key and a signed team policy with a
# Connection and an SSH key rule (no approver/session budget in policy7).
B=$V04/target/debug
S=$WORK/v26
init "$B" "$S"
start "$B" "$S"
GITHUB=$(populate "$B" "$S")
SSH=$(printf '%s\n' "$PW" | "$B/rekey" --state-dir "$S" ssh-agent generate fixture-ssh \
    --mode ed25519-software --password-stdin)
PRESET=$("$B/rekey" --state-dir "$S" connection preset github-pat)
openssl genpkey -algorithm ed25519 -outform DER -out "$WORK/signer.der" 2>/dev/null
chmod 600 "$WORK/signer.der"
python3 -I - "$GITHUB" "$PRESET" "$SSH" >"$WORK/draft.json" <<'PY'
import json, sys, uuid
github, preset, ssh = sys.argv[1], json.loads(sys.argv[2]), json.loads(sys.argv[3])
preset = preset.get("preset", preset)
connection = {
    "name": "github", "preset": preset["name"], "credential_id": github,
    "origin": preset["origin"], "auth": preset["auth"], "enabled": True, "grade": "T0",
    "rules": preset["rules"], "bindings": {}, "caller_overrides": {},
    "limits": {"requests_per_hour": 600, "max_request_bytes": 1048576, "max_response_bytes": 4194304},
    "allowed_headers": preset["allowed_headers"], "fixed_headers": preset["fixed_headers"],
    "allowed_response_headers": preset["allowed_response_headers"],
    "query_allowlist": preset["query_allowlist"], "operations": preset["operations"],
    "llm": None, "oauth": None,
}
ssh_key = {
    "name": "fixture-ssh", "credential_id": ssh["credential"]["id"],
    "user_public_key": ssh["public_key"], "hosts": [], "git_signing": "allow",
}
print(json.dumps({
    "format_version": 7, "version": 1, "expires_at_ms": 4102444800000,
    "approvers": [], "workload_identities": [], "profiles": [],
    "connections": [connection], "ssh_keys": [ssh_key], "derived_credentials": [],
    "bindings": [], "rules": [],
}))
PY
DIGEST=$("$B/rekey-policy-sign" review "$WORK/draft.json" |
    python3 -I -c 'import json,sys; print(json.load(sys.stdin)["reviewed_sha256"])')
SIGNER=$(python3 -I -c 'import uuid; print(uuid.uuid4())')
"$B/rekey-policy-sign" sign "$WORK/draft.json" --reviewed-sha256 "$DIGEST" --signer-id "$SIGNER" \
    --key-file "$WORK/signer.der" --output "$WORK/signed" >/dev/null
printf '%s\n' "$PW" | "$B/rekey" --state-dir "$S" policy trust install \
    --file "$WORK/signed/trust.json" --step-up-stdin >/dev/null
STATUS=$("$B/rekey" --state-dir "$S" policy status)
VAULT=$(python3 -I -c 'import json,sys; print(json.loads(sys.argv[1])["vault_id"])' "$STATUS")
TRUST=$(python3 -I -c 'import json,sys; print(json.loads(sys.argv[1])["trust_sha256"])' "$STATUS")
printf '%s\n' "$PW" | "$B/rekey" --state-dir "$S" policy activate --file "$WORK/signed/policy.json" \
    --expected-vault-id "$VAULT" --expected-trust-sha256 "$TRUST" --step-up-stdin >/dev/null
stop "$S"
save "$S" v26
echo "fixtures written to $OUT"
