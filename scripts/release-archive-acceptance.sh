#!/usr/bin/env bash
# Exercise downloaded-archive rekey/rekeyd for capabilities beyond P0.
# Never cargo-builds. Exercises only the default personal build.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN_DIR="${BIN_DIR:?BIN_DIR must point at unpacked archive binaries}"
REKEY="${BIN_DIR}/rekey"
REKEYD="${BIN_DIR}/rekeyd"
SIGNER="$ROOT/scripts/sign-test-policy.py"
PASSWORD="${REKEY_ARCHIVE_PASSWORD:-archive horse battery staple}"
NEW_PASSWORD="${REKEY_ARCHIVE_NEW_PASSWORD:-archive correct battery staple}"
SECRET="archive-credential-canary-secret"
ORIGIN="${REKEY_ACCEPTANCE_ORIGIN:-https://1.1.1.1}"
EXACT_PATH="${REKEY_ACCEPTANCE_PATH:-/cdn-cgi/trace}"
command -v python3 >/dev/null || { echo "python3 is required" >&2; exit 1; }
command -v openssl >/dev/null || { echo "openssl is required" >&2; exit 1; }
command -v rg >/dev/null || { echo "ripgrep is required" >&2; exit 1; }

for name in rekey rekeyd rekey-mcp rekey-policy-sign rekey-approval-sign; do
  [[ -x "$BIN_DIR/$name" ]] || { echo "required archive executable is missing: $name" >&2; exit 1; }
done
for name in rekey-policy-sign rekey-approval-sign; do
  "$BIN_DIR/$name" --help >/dev/null
done
for command in metrics oidc-login; do
  if "$REKEY" "$command" --help >/dev/null 2>&1; then
    echo "lab command unexpectedly present in default archive: $command" >&2
    exit 1
  fi
done

echo "release-archive-acceptance: BIN_DIR=$BIN_DIR"
echo "release-archive-acceptance: rekey=$REKEY ($("$REKEY" --version))"
echo "release-archive-acceptance: rekeyd=$REKEYD ($("$REKEYD" --version))"

WORKDIR="$(mktemp -d /tmp/rkarch.XXXXXX)"
STATE="$WORKDIR/s"
AGENT_RUN="$WORKDIR/a"
SERVE_PID=""

cleanup() {
  if [[ -n "${SERVE_PID:-}" ]]; then
    kill "$SERVE_PID" 2>/dev/null || true
    wait "$SERVE_PID" 2>/dev/null || true
  fi
  rm -rf "$WORKDIR"
}
failure() {
  local rc=$?
  [[ ! -f "$WORKDIR/broker.err" ]] || cat "$WORKDIR/broker.err" >&2
  echo "release-archive-acceptance failed at line $1 (exit $rc)" >&2
  exit "$rc"
}
trap cleanup EXIT
trap 'failure "$LINENO"' ERR

json_field() {
  python3 -c 'import json,sys; print(json.load(sys.stdin)[sys.argv[1]])' "$1"
}

capture_cmd() {
  CAPTURE_RC=0
  CAPTURE_OUT="$("$@" 2>&1)" || CAPTURE_RC=$?
}

expect_exit() {
  local expected="$1"
  shift
  capture_cmd "$@"
  [[ "$CAPTURE_RC" -eq "$expected" ]] || {
    echo "expected exit $expected, got $CAPTURE_RC: $CAPTURE_OUT" >&2
    exit 1
  }
}

assert_status() {
  python3 -c 'import json,sys; v,_=json.JSONDecoder().raw_decode(sys.stdin.read().lstrip());
assert v["upstream_status"]==200, v'
}

write_action() {
  cat >"$WORKDIR/action.json" <<EOF
{
  "name": "archive-trace",
  "credential_id": "$1",
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
}

write_permit_policy() {
  python3 - "$WORKDIR/policy.json" "$action_id" "$action_ver" "$principal_id" "$1" <<'PY'
import json, pathlib, sys, time, uuid
path, action_id, action_version, principal_id, version = sys.argv[1:]
resource = {"type": "fixed-http-action", "id": action_id}
pathlib.Path(path).write_text(json.dumps({
    "format_version": 6,
    "version": int(version),
    "expires_at_ms": int(time.time() * 1000) + 600000,
    "approvers": [],
    "profiles": [], "workload_identities": [],
    "bindings": [{
        "action_id": action_id,
        "version": int(action_version),
        "resource": resource,
        "parameter_schema_id": "archive-empty/v1",
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
}

activate_snapshot() {
  python3 "$SIGNER" policy --key-dir "$WORKDIR/policy-key" \
    --snapshot "$WORKDIR/policy.json" --bundle "$WORKDIR/policy-bundle.json" \
    --trust "$WORKDIR/policy-trust.json"
  if [[ "${1:-}" == "install-trust" ]]; then
    printf '%s\n' "$PASSWORD" | "$REKEY" --state-dir "$STATE" policy trust install \
      --file "$WORKDIR/policy-trust.json" --step-up-stdin >/dev/null
  fi
  read -r POLICY_TARGET_VAULT POLICY_TARGET_TRUST < <("$REKEY" --state-dir "$STATE" policy status | python3 -c 'import json,sys; s=json.load(sys.stdin); print(s["vault_id"], s["trust_sha256"])')
  printf '%s\n' "$PASSWORD" | "$REKEY" --state-dir "$STATE" policy activate --expected-vault-id "$POLICY_TARGET_VAULT" --expected-trust-sha256 "$POLICY_TARGET_TRUST" \
    --file "$WORKDIR/policy-bundle.json" --step-up-stdin >/dev/null
  # Policy replacement revokes every old capability; issue a fresh one.
  token="$(printf '%s\n' "$PASSWORD" | "$REKEY" --state-dir "$STATE" session create \
    --action "$action_ref" --principal "$principal_id" --ttl 10m --max-uses 20 \
    --password-stdin | json_field 'capability_token')"
}

echo "== init, serve, unlock, format v22"
init_out="$(printf '%s\n' "$PASSWORD" | "$REKEYD" init --mode team --state-dir "$STATE" --password-stdin)"
printf '%s\n' "$init_out" | rg -q '^RKREC1-' || {
  echo "init did not print a recovery key" >&2
  exit 1
}
recovery="$(printf '%s\n' "$init_out" | rg '^RKREC1-')"
"$REKEYD" serve --state-dir "$STATE" --idle-lock 15m \
  >"$WORKDIR/broker.out" 2>"$WORKDIR/broker.err" &
SERVE_PID=$!
for _ in $(seq 1 200); do
  [[ -S "$STATE/runtime/admin.sock" ]] && break
  sleep 0.05
done
[[ -S "$STATE/runtime/admin.sock" ]] || { echo "broker did not start"; exit 1; }
printf '%s\n' "$PASSWORD" | "$REKEY" --state-dir "$STATE" unlock --password-stdin >/dev/null
status="$("$REKEY" --state-dir "$STATE" status)"
printf '%s\n' "$status" | python3 -c 'import json,sys; sys.exit(0 if json.load(sys.stdin)["format_version"] == 25 else 1)' || {
  echo "expected format_version 25: $status" >&2
  exit 1
}

pipe_secret() {
  local secret="$1"
  shift
  printf '%s\n' "$secret" | "$@"
}

echo "== password change invalidates the old factor"
old_password="$PASSWORD"
printf '%s\n%s\n' "$old_password" "$NEW_PASSWORD" | "$REKEY" --state-dir "$STATE" \
  password change --stdin-secrets | rg -q '"changed": true'
PASSWORD="$NEW_PASSWORD"
"$REKEY" --state-dir "$STATE" lock >/dev/null
expect_exit 3 pipe_secret "$old_password" "$REKEY" --state-dir "$STATE" unlock --password-stdin
pipe_secret "$PASSWORD" "$REKEY" --state-dir "$STATE" unlock --password-stdin >/dev/null

echo "== recovery rotate invalidates the previous recovery key"
rotate_out="$(pipe_secret "$PASSWORD" "$REKEY" --state-dir "$STATE" recovery rotate --password-stdin)"
new_recovery="$(printf '%s\n' "$rotate_out" | rg '^RKREC1-')"
[[ "$new_recovery" != "$recovery" ]]
"$REKEY" --state-dir "$STATE" lock >/dev/null
expect_exit 3 pipe_secret "$recovery" "$REKEY" --state-dir "$STATE" \
  unlock --recovery --password-stdin
pipe_secret "$new_recovery" "$REKEY" --state-dir "$STATE" \
  unlock --recovery --password-stdin >/dev/null

echo "== credential, action, admin session"
cred_json="$(printf '%s\n%s\n' "$PASSWORD" "$SECRET" | "$REKEY" --state-dir "$STATE" \
  credential add archive-canary --stdin-secrets)"
cred_id="$(printf '%s\n' "$cred_json" | json_field id)"
write_action "$cred_id"
action_json="$(printf '%s\n' "$PASSWORD" | "$REKEY" --state-dir "$STATE" action create \
  --file "$WORKDIR/action.json" --password-stdin)"
action_id="$(printf '%s\n' "$action_json" | json_field id)"
action_ver="$(printf '%s\n' "$action_json" | json_field version)"
action_ref="${action_id}@${action_ver}"
session_json="$(printf '%s\n' "$PASSWORD" | "$REKEY" --state-dir "$STATE" session create \
  --action "$action_ref" --ttl 10m --max-uses 20 --password-stdin)"
token="$(printf '%s\n' "$session_json" | json_field capability_token)"
principal_id="$(printf '%s\n' "$session_json" | json_field principal_id)"

echo "== packaged MCP initialize and discovery"
printf '%s\n' "$session_json" >"$WORKDIR/mcp-session.json"
chmod 0600 "$WORKDIR/mcp-session.json"
python3 - "$BIN_DIR/rekey-mcp" "$STATE/runtime/agent.sock" "$WORKDIR" <<'PY'
import json, pathlib, subprocess, sys
binary, socket, work = sys.argv[1:]
root = pathlib.Path(work)
manifest = root / 'mcp.json'
manifest.write_text(json.dumps({'agent_socket': socket,
    'session_file': str(root / 'mcp-session.json'), 'tools': []}))
manifest.chmod(0o600)
messages = [
    {'jsonrpc': '2.0', 'id': 1, 'method': 'initialize',
     'params': {'protocolVersion': '2025-06-18', 'capabilities': {},
                'clientInfo': {'name': 'archive-acceptance', 'version': '1'}}},
    {'jsonrpc': '2.0', 'method': 'notifications/initialized'},
    {'jsonrpc': '2.0', 'id': 2, 'method': 'tools/list'},
]
result = subprocess.run([binary, '--manifest', str(manifest)],
    input=''.join(json.dumps(item) + '\n' for item in messages),
    text=True, capture_output=True, timeout=10, check=True)
replies = [json.loads(line) for line in result.stdout.splitlines()]
assert len(replies) == 2
assert replies[0]['id'] == 1 and replies[0]['result']['protocolVersion'] == '2025-06-18'
assert replies[1]['id'] == 2 and replies[1]['result']['tools'] == []
assert not result.stderr
print('archive MCP initialize/discovery: PASS (empty exposure list; no upstream IO)')
PY

echo "== signed policy activate, unauthorized deny, authorized execute, unlock reload"
write_permit_policy 1
activate_snapshot install-trust
"$REKEY" --state-dir "$STATE" policy status | rg -q '"status": "active"'
expect_exit 4 "$REKEY" --state-dir "$STATE" execute "$action_ref" --capability "not-a-token"
if [[ "${REKEY_ACCEPTANCE_SKIP_EXECUTE:-}" != "1" ]]; then
  "$REKEY" --state-dir "$STATE" execute "$action_ref" --capability "$token" | assert_status
fi
"$REKEY" --state-dir "$STATE" lock >/dev/null
"$REKEY" --state-dir "$STATE" policy status | rg -q '"status": "unavailable"'
printf '%s\n' "$PASSWORD" | "$REKEY" --state-dir "$STATE" unlock --password-stdin >/dev/null
"$REKEY" --state-dir "$STATE" policy status | rg -q '"status": "active"'
session_json="$(printf '%s\n' "$PASSWORD" | "$REKEY" --state-dir "$STATE" session create \
  --action "$action_ref" --ttl 10m --max-uses 20 --password-stdin)"
token="$(printf '%s\n' "$session_json" | json_field capability_token)"
principal_id="$(printf '%s\n' "$session_json" | json_field principal_id)"

echo "== one-person approval success and replay deny"
python3 "$SIGNER" approval-identity --key-dir "$WORKDIR/approver-1-key" >"$WORKDIR/approver-1.json"
python3 - "$WORKDIR/policy.json" "$action_id" "$action_ver" "$principal_id" \
  "$WORKDIR/approver-1.json" <<'PY'
import json, pathlib, sys, time, uuid
path, action_id, action_version, principal_id, approver_path = sys.argv[1:]
approver = json.loads(pathlib.Path(approver_path).read_text())
resource = {"type": "fixed-http-action", "id": action_id}
pathlib.Path(path).write_text(json.dumps({
    "format_version": 6,
    "version": 2,
    "expires_at_ms": int(time.time() * 1000) + 600000,
    "approvers": [approver],
    "profiles": [], "workload_identities": [],
    "bindings": [{
        "action_id": action_id,
        "version": int(action_version),
        "resource": resource,
        "parameter_schema_id": "archive-empty/v1",
        "parameter_schema": {"type": "null"},
    }],
    "rules": [{
        "id": str(uuid.uuid4()),
        "effect": "require-approval",
        "principal_id": principal_id,
        "action_id": action_id,
        "version": int(action_version),
        "resource": resource,
        "parameters": {"kind": "any_validated"},
        "approver": {"kind": "ed25519", "keys": [approver["public_key"]], "threshold": 1},
        "approval": {
            "mode": "one-time",
            "max_uses": 1,
        },
    }],
}))
PY
activate_snapshot
"$REKEY" --state-dir "$STATE" policy status | rg -q '"version": 2'
printf '%s\n' "$token" | "$REKEY" --state-dir "$STATE" approval prepare "$action_ref" \
  --capability - >"$WORKDIR/challenge.json"
python3 "$SIGNER" approval-sign --key-dir "$WORKDIR/approver-1-key" \
  --challenge "$WORKDIR/challenge.json" --output "$WORKDIR/grant.json" \
  --max-uses 1 --validity-ms 60000
if [[ "${REKEY_ACCEPTANCE_SKIP_EXECUTE:-}" != "1" ]]; then
  printf '%s\n' "$token" | "$REKEY" --state-dir "$STATE" execute "$action_ref" \
    --capability - --approval "$WORKDIR/grant.json" | assert_status
fi
expect_exit 4 bash -c 'printf "%s\n" "$1" | "$2" --state-dir "$3" execute "$4" --capability - --approval "$5"' \
  _ "$token" "$REKEY" "$STATE" "$action_ref" "$WORKDIR/grant.json"

echo "== audit list/export records lifecycle events and omits secrets"
"$REKEY" --state-dir "$STATE" audit list --limit 100 >"$WORKDIR/audit.json"
rg -q '"event_type": "vault.password_changed"' "$WORKDIR/audit.json"
rg -q '"event_type": "policy.activated"' "$WORKDIR/audit.json"
"$REKEY" --state-dir "$STATE" audit export --output "$WORKDIR/audit.jsonl" >/dev/null
rg -q '"record_type":"rekey.audit.export.v2"' "$WORKDIR/audit.jsonl"
if rg -aF -- "$SECRET" "$WORKDIR/audit.json" "$WORKDIR/audit.jsonl" "$WORKDIR/broker.out" \
  "$WORKDIR/broker.err"; then
  echo "credential canary leaked into audit or logs" >&2
  exit 1
fi
if rg -aF -- "$token" "$WORKDIR/audit.json" "$WORKDIR/audit.jsonl"; then
  echo "capability token leaked into audit" >&2
  exit 1
fi

printf '%s\n' "$PASSWORD" | "$REKEY" --state-dir "$STATE" shutdown --password-stdin >/dev/null
SERVE_PID=""

if [[ "$(uname -s)" == Darwin ]]; then
  echo "== macOS experimental Seatbelt launcher"
  mkdir -p "$AGENT_RUN"
  printf '%s\n' "$PASSWORD" | "$REKEYD" init --mode team --state-dir "$WORKDIR/macos" --password-stdin >/dev/null
  "$REKEYD" serve --state-dir "$WORKDIR/macos" --idle-lock 15m --agent-runtime-dir "$AGENT_RUN" \
    >"$WORKDIR/macos.out" 2>"$WORKDIR/macos.err" &
  SERVE_PID=$!
  for _ in $(seq 1 200); do
    [[ -S "$WORKDIR/macos/runtime/admin.sock" && -S "$AGENT_RUN/agent.sock" ]] && break
    sleep 0.05
  done
  [[ -S "$AGENT_RUN/agent.sock" ]] || { echo "disjoint agent socket missing"; exit 1; }
  "$REKEY" --state-dir "$WORKDIR/macos" --agent-socket "$AGENT_RUN/agent.sock" \
    agent-run -- /bin/echo archive-seatbelt-launch-ok | rg -q '^archive-seatbelt-launch-ok$'
  printf '%s\n' "$PASSWORD" | "$REKEY" --state-dir "$WORKDIR/macos" shutdown --password-stdin >/dev/null
  SERVE_PID=""
fi

echo "release-archive-acceptance: PASS"
echo "release-archive-acceptance: proved=password-change,recovery-rotate,audit-list-export,policy-activate,approval-grant,mcp-initialize-discovery"
echo "release-archive-acceptance: lab features excluded"
