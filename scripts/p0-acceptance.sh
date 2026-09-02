#!/usr/bin/env bash
# P0 clean-install acceptance: release binaries, no FakeTransport.
# Proves every public P0 CLI command through release binaries on this machine:
# init → serve → unlock/lock → credential add/list/rotate/revoke → action
# create/list/disable → session create/revoke → execute → backup → shutdown →
# restore. The successful execute uses the production HTTPS transport.
#
# Execute uses the production ReqwestUpstreamTransport against
# https://1.1.1.1/cdn-cgi/trace (public HTTPS GET with an IP SAN). The literal
# public IP keeps this gate valid on hosts whose TUN/fake-IP DNS maps every
# domain into the blocked 198.18.0.0/15 range. Override with
# REKEY_ACCEPTANCE_ORIGIN / REKEY_ACCEPTANCE_PATH if needed.
# Set REKEY_ACCEPTANCE_SKIP_EXECUTE=1 to skip the network hop.
set -euo pipefail
umask 000

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN_DIR="${BIN_DIR:-$ROOT/target/release}"
REKEY="${BIN_DIR}/rekey"
REKEYD="${BIN_DIR}/rekeyd"
PASSWORD="${REKEY_ACCEPTANCE_PASSWORD:-acceptance horse battery staple}"
SECRET_V1="acceptance-credential-canary-v1"
SECRET_V2="acceptance-credential-canary-v2"
ORIGIN="${REKEY_ACCEPTANCE_ORIGIN:-https://1.1.1.1}"
EXACT_PATH="${REKEY_ACCEPTANCE_PATH:-/cdn-cgi/trace}"

if [[ ! -x "$REKEY" || ! -x "$REKEYD" ]]; then
  if [[ "${REKEY_ACCEPTANCE_REQUIRE_BINARIES:-}" == "1" ]]; then
    echo "required release binaries are missing from BIN_DIR: $BIN_DIR" >&2
    exit 1
  fi
  echo "building release binaries…"
  cargo build --release -p rekey-cli -p rekey-broker
fi

# macOS sockaddr_un is ~104 bytes; keep state-dir names tiny.
WORKDIR="$(mktemp -d "/tmp/rk.XXXXXX")"
STATE="$WORKDIR/s"
cleanup() {
  if [[ -n "${FLOOD_PID:-}" ]]; then
    kill "$FLOOD_PID" 2>/dev/null || true
    wait "$FLOOD_PID" 2>/dev/null || true
  fi
  if [[ -n "${SERVE_PID:-}" ]]; then
    kill "$SERVE_PID" 2>/dev/null || true
    wait "$SERVE_PID" 2>/dev/null || true
  fi
  rm -rf "$WORKDIR"
}
trap cleanup EXIT

json_field() {
  python3 -c 'import json,sys; print(json.load(sys.stdin)['"$1"'])'
}

echo "== init"
printf '%s\n' "$PASSWORD" | "$REKEY" --state-dir "$STATE" init --password-stdin >/dev/null

echo "== delegated exit codes (usage=2, storage/state=5)"
set +e
"$REKEY" --state-dir "$STATE" serve --idle-lock 1s >/dev/null 2>&1
usage_rc=$?
printf '%s\n' "$PASSWORD" | "$REKEY" --state-dir "$STATE" init --password-stdin >/dev/null 2>&1
state_rc=$?
set -e
[[ "$usage_rc" -eq 2 ]] || { echo "expected invalid idle exit 2, got $usage_rc"; exit 1; }
[[ "$state_rc" -eq 5 ]] || { echo "expected second init exit 5, got $state_rc"; exit 1; }

echo "== serve"
"$REKEY" --state-dir "$STATE" serve --idle-lock 15m >/dev/null 2>&1 &
SERVE_PID=$!
for _ in $(seq 1 100); do
  [[ -S "$STATE/runtime/admin.sock" ]] && break
  sleep 0.05
done
[[ -S "$STATE/runtime/admin.sock" ]] || { echo "broker did not start"; exit 1; }

echo "== wrong password"
set +e
printf 'wrong-password\n' | "$REKEY" --state-dir "$STATE" unlock --password-stdin >/dev/null 2>&1
unlock_rc=$?
set -e
[[ "$unlock_rc" -eq 3 ]] || { echo "expected unlock exit 3, got $unlock_rc"; exit 1; }

echo "== unlock"
printf '%s\n' "$PASSWORD" | "$REKEY" --state-dir "$STATE" unlock --password-stdin >/dev/null

echo "== credential add"
cred_json="$(printf '%s\n%s\n' "$PASSWORD" "$SECRET_V1" | "$REKEY" --state-dir "$STATE" credential add acceptance --stdin-secrets)"
cred_id="$(printf '%s\n' "$cred_json" | json_field '"id"')"

echo "== credential list"
credential_list="$("$REKEY" --state-dir "$STATE" credential list)"
printf '%s\n' "$credential_list" | grep -q acceptance
[[ "$credential_list" != *"$SECRET_V1"* ]] || { echo "credential list leaked secret"; exit 1; }

echo "== credential rotate"
printf '%s\n%s\n' "$PASSWORD" "$SECRET_V2" | "$REKEY" --state-dir "$STATE" credential rotate "$cred_id" --stdin-secrets >/dev/null

echo "== owner-only runtime and SQLite modes under umask 000"
python3 - "$STATE" <<'PY'
import os, pathlib, stat, sys
root = pathlib.Path(sys.argv[1])
expected = {
    root: 0o700,
    root / "vault.sqlite3": 0o600,
    root / "vault.sqlite3-wal": 0o600,
    root / "vault.sqlite3-shm": 0o600,
    root / "broker.lock": 0o600,
    root / "runtime": 0o700,
    root / "runtime" / "admin.sock": 0o600,
    root / "runtime" / "agent.sock": 0o600,
}
for path, wanted in expected.items():
    if not path.exists():
        raise SystemExit(f"required runtime path missing: {path.name}")
    got = stat.S_IMODE(os.stat(path).st_mode)
    if got != wanted:
        raise SystemExit(f"wrong mode for {path.name}: {oct(got)} != {oct(wanted)}")
PY

echo "== action create"
action_file="$WORKDIR/action.json"
cat >"$action_file" <<EOF
{
  "name": "acceptance-get",
  "credential_id": "$cred_id",
  "origin": "$ORIGIN",
  "method": "GET",
  "exact_path": "$EXACT_PATH",
  "auth_header": "authorization",
  "auth_prefix": "Bearer ",
  "timeout_ms": 15000,
  "request_max_bytes": 1024,
  "allowed_extra_headers": [],
  "response_max_bytes": 65536,
  "allowed_response_headers": ["content-type"]
}
EOF
action_json="$(printf '%s\n' "$PASSWORD" | "$REKEY" --state-dir "$STATE" action create --file "$action_file" --password-stdin)"
action_id="$(printf '%s\n' "$action_json" | json_field '"id"')"
action_ver="$(printf '%s\n' "$action_json" | json_field '"version"')"
action_ref="${action_id}@${action_ver}"

echo "== action list"
action_list="$("$REKEY" --state-dir "$STATE" action list)"
printf '%s\n' "$action_list" | grep -q acceptance-get

echo "== action update + retired-version denial"
action_update_json="$(printf '%s\n' "$PASSWORD" | "$REKEY" --state-dir "$STATE" action update "$action_id" --file "$action_file" --password-stdin)"
action_ver="$(printf '%s\n' "$action_update_json" | json_field '"version"')"
[[ "$action_ver" -eq 2 ]] || { echo "expected updated action version 2, got $action_ver"; exit 1; }
set +e
printf '%s\n' "$PASSWORD" | "$REKEY" --state-dir "$STATE" session create --action "$action_ref" --ttl 10m --max-uses 1 --password-stdin >/dev/null 2>&1
retired_rc=$?
set -e
[[ "$retired_rc" -eq 4 ]] || { echo "expected retired action exit 4, got $retired_rc"; exit 1; }
action_ref="${action_id}@${action_ver}"

echo "== session create"
session_json="$(printf '%s\n' "$PASSWORD" | "$REKEY" --state-dir "$STATE" session create --action "$action_ref" --ttl 10m --max-uses 5 --password-stdin)"
session_id="$(printf '%s\n' "$session_json" | json_field '"session_id"')"
revoked_token="$(printf '%s\n' "$session_json" | json_field '"capability_token"')"

echo "== session revoke + denied replay"
printf '%s\n' "$PASSWORD" | "$REKEY" --state-dir "$STATE" session revoke "$session_id" --password-stdin >/dev/null
set +e
"$REKEY" --state-dir "$STATE" execute "$action_ref" --capability "$revoked_token" >/dev/null 2>&1
revoked_rc=$?
set -e
[[ "$revoked_rc" -eq 4 ]] || { echo "expected revoked session exit 4, got $revoked_rc"; exit 1; }

echo "== fresh session"
session_json="$(printf '%s\n' "$PASSWORD" | "$REKEY" --state-dir "$STATE" session create --action "$action_ref" --ttl 10m --max-uses 5 --password-stdin)"
token="$(printf '%s\n' "$session_json" | json_field '"capability_token"')"
principal_id="$(printf '%s\n' "$session_json" | json_field '"principal_id"')"

echo "== activate typed authorization policy"
policy_file="$WORKDIR/policy.json"
python3 - "$policy_file" "$action_id" "$action_ver" "$principal_id" <<'PY'
import json, pathlib, sys, time, uuid
path, action_id, action_version, principal_id = sys.argv[1:]
resource = {"type": "fixed-http-action", "id": action_id}
pathlib.Path(path).write_text(json.dumps({
    "format_version": 2,
    "version": 1,
    "expires_at_ms": int(time.time() * 1000) + 600000,
    "approvers": [],
    "bindings": [{
        "action_id": action_id,
        "version": int(action_version),
        "resource": resource,
        "parameter_schema_id": "p0-empty/v1",
        "parameter_schema": {"type": "null"},
    }],
    "rules": [{
        "id": str(uuid.uuid4()),
        "effect": "permit",
        "principal_id": principal_id,
        "action_id": action_id,
        "version": int(action_version),
        "resource": resource,
        "parameters": {"kind": "any_validated"},
    }],
}))
PY
python3 "$ROOT/scripts/sign-test-policy.py" policy --key-dir "$WORKDIR/policy-key" \
  --snapshot "$policy_file" --bundle "$WORKDIR/policy-bundle.json" \
  --trust "$WORKDIR/policy-trust.json"
printf '%s\n' "$PASSWORD" | "$REKEY" --state-dir "$STATE" policy trust install \
  --file "$WORKDIR/policy-trust.json" --step-up-stdin >/dev/null
printf '%s\n' "$PASSWORD" | "$REKEY" --state-dir "$STATE" policy activate \
  --file "$WORKDIR/policy-bundle.json" --step-up-stdin >/dev/null
"$REKEY" --state-dir "$STATE" policy status | grep -q '"version": 1'

if [[ "${REKEY_ACCEPTANCE_SKIP_EXECUTE:-}" != "1" ]]; then
  echo "== execute (production HTTPS transport, origin $ORIGIN$EXACT_PATH)"
  set +e
  exec_out="$("$REKEY" --state-dir "$STATE" execute "$action_ref" --capability "$token" 2>"$WORKDIR/exec.err")"
  exec_rc=$?
  set -e
  if [[ "$exec_rc" -ne 0 ]]; then
    echo "execute failed (rc=$exec_rc). This harness does not inject FakeTransport."
    echo "stderr:"
    cat "$WORKDIR/exec.err" || true
    echo "stdout:"
    printf '%s\n' "$exec_out"
    exit "$exec_rc"
  fi
  echo "$exec_out" | head -n 5
else
  echo "== execute skipped (REKEY_ACCEPTANCE_SKIP_EXECUTE=1)"
fi

echo "== action disable + denied execution"
printf '%s\n' "$PASSWORD" | "$REKEY" --state-dir "$STATE" action disable "$action_id" --password-stdin >/dev/null
set +e
"$REKEY" --state-dir "$STATE" execute "$action_ref" --capability "$token" >/dev/null 2>&1
disabled_rc=$?
set -e
[[ "$disabled_rc" -eq 4 ]] || { echo "expected disabled action exit 4, got $disabled_rc"; exit 1; }

echo "== credential revoke"
printf '%s\n' "$PASSWORD" | "$REKEY" --state-dir "$STATE" credential revoke "$cred_id" --password-stdin >/dev/null

echo "== explicit lock + unlock"
flood_ready="$WORKDIR/agent-flood-ready"
python3 - "$STATE/runtime/agent.sock" "$flood_ready" <<'PY' &
import pathlib, signal, socket, sys
sockets = []
for _ in range(128):
    conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    conn.connect(sys.argv[1])
    sockets.append(conn)
pathlib.Path(sys.argv[2]).touch()
signal.pause()
PY
FLOOD_PID=$!
for _ in $(seq 1 100); do
  [[ -f "$flood_ready" ]] && break
  sleep 0.02
done
[[ -f "$flood_ready" ]] || { echo "agent connection flood did not start"; exit 1; }
"$REKEY" --state-dir "$STATE" status >/dev/null
"$REKEY" --state-dir "$STATE" lock >/dev/null
kill "$FLOOD_PID" 2>/dev/null || true
wait "$FLOOD_PID" 2>/dev/null || true
FLOOD_PID=""
locked_status="$("$REKEY" --state-dir "$STATE" status)"
printf '%s\n' "$locked_status" | grep -q locked
printf '%s\n' "$PASSWORD" | "$REKEY" --state-dir "$STATE" unlock --password-stdin >/dev/null

echo "== reject backup overlap with live state"
ln -s "$STATE" "$WORKDIR/state-alias"
for protected_output in \
  "$STATE/vault.sqlite3" \
  "$STATE/broker.lock" \
  "$STATE/runtime/admin.sock" \
  "$WORKDIR/state-alias/vault.sqlite3"; do
  set +e
  printf '%s\n' "$PASSWORD" | "$REKEY" --state-dir "$STATE" backup --output "$protected_output" --password-stdin >/dev/null 2>&1
  protected_rc=$?
  set -e
  [[ "$protected_rc" -eq 5 ]] || {
    echo "expected protected backup output exit 5, got $protected_rc: $protected_output"
    exit 1
  }
done
set +e
"$REKEYD" serve --state-dir "$STATE" --idle-lock 15m >/dev/null 2>&1
second_serve_rc=$?
set -e
[[ "$second_serve_rc" -eq 5 ]] || {
  echo "expected second broker exit 5 after rejected lock overwrite, got $second_serve_rc"
  exit 1
}
"$REKEY" --state-dir "$STATE" credential list | grep -q acceptance

echo "== backup"
backup="$WORKDIR/out.rkbackup"
backup_json="$(printf '%s\n' "$PASSWORD" | "$REKEY" --state-dir "$STATE" backup --output "$backup" --password-stdin)"
hash="$(printf '%s\n' "$backup_json" | json_field '"sha256_hex"')"

echo "== shutdown"
printf '%s\n' "$PASSWORD" | "$REKEY" --state-dir "$STATE" shutdown --password-stdin >/dev/null
wait "$SERVE_PID" 2>/dev/null || true
SERVE_PID=""

echo "== restore"
restored="$WORKDIR/r"
bad_restore="$WORKDIR/bad"
set +e
printf 'wrong-password\n' | "$REKEY" --state-dir "$bad_restore" restore --input "$backup" --sha256 "$hash" --password-stdin >/dev/null 2>&1
auth_rc=$?
set -e
[[ "$auth_rc" -eq 3 ]] || { echo "expected wrong restore proof exit 3, got $auth_rc"; exit 1; }
printf '%s\n' "$PASSWORD" | "$REKEY" --state-dir "$restored" restore --input "$backup" --sha256 "$hash" --password-stdin >/dev/null

echo "== restored serve + list"
"$REKEY" --state-dir "$restored" serve --idle-lock 15m >/dev/null 2>&1 &
SERVE_PID=$!
for _ in $(seq 1 100); do
  [[ -S "$restored/runtime/admin.sock" ]] && break
  sleep 0.05
done
[[ -S "$restored/runtime/admin.sock" ]] || { echo "restored broker did not start"; exit 1; }
printf '%s\n' "$PASSWORD" | "$REKEY" --state-dir "$restored" unlock --password-stdin >/dev/null
list="$("$REKEY" --state-dir "$restored" credential list)"
printf '%s\n' "$list" | grep -q acceptance
printf '%s\n' "$PASSWORD" | "$REKEY" --state-dir "$restored" shutdown --password-stdin >/dev/null
wait "$SERVE_PID" 2>/dev/null || true
SERVE_PID=""

echo "== disk secret canary"
printf '%s\n%s\n' "$SECRET_V1" "$SECRET_V2" | python3 -c '
import pathlib, sys
root = pathlib.Path(sys.argv[1])
needles = [line.rstrip(b"\n") for line in sys.stdin.buffer if line.rstrip(b"\n")]
for path in root.rglob("*"):
    if path.is_file():
        data = path.read_bytes()
        if any(needle in data for needle in needles):
            raise SystemExit(f"plaintext credential found in {path}")
' "$STATE"

echo "P0 acceptance passed in $WORKDIR"
