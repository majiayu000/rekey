#!/usr/bin/env bash
# Exercise downloaded-archive rekey/rekeyd for capabilities beyond P0.
# Never cargo-builds. Fixture daemons are not used; Vault execute is not claimed.
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
ISSUER="https://issuer.example"
AUDIENCE="rekey://archive-acceptance"
KID="archive-workload-key"
VAULT_TOKEN_ONE="hvs.archive-vault-token-one"
VAULT_TOKEN_TWO="hvs.archive-vault-token-two"

command -v python3 >/dev/null || { echo "python3 is required" >&2; exit 1; }
command -v openssl >/dev/null || { echo "openssl is required" >&2; exit 1; }
command -v rg >/dev/null || { echo "ripgrep is required" >&2; exit 1; }

if [[ ! -x "$REKEY" || ! -x "$REKEYD" ]]; then
  echo "required archive binaries are missing from BIN_DIR: $BIN_DIR" >&2
  exit 1
fi

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
    "format_version": 3,
    "version": int(version),
    "expires_at_ms": int(time.time() * 1000) + 600000,
    "approvers": [],
    "workload_identities": [],
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
  printf '%s\n' "$PASSWORD" | "$REKEY" --state-dir "$STATE" policy activate \
    --file "$WORKDIR/policy-bundle.json" --step-up-stdin >/dev/null
}

echo "== init, serve, unlock, format v10"
init_out="$(printf '%s\n' "$PASSWORD" | "$REKEYD" init --state-dir "$STATE" --password-stdin)"
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
printf '%s\n' "$status" | rg -q '"format_version": 10' || {
  echo "expected format_version 10: $status" >&2
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
    "format_version": 3,
    "version": 2,
    "expires_at_ms": int(time.time() * 1000) + 600000,
    "approvers": [approver],
    "workload_identities": [],
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
        "approval": {
            "approver_ids": [approver["approver_id"]],
            "quorum": 1,
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

echo "== workload mint, execute, replay deny"
python3 "$SIGNER" workload-key --key-dir "$WORKDIR/workload-key" --kid "$KID" \
  >"$WORKDIR/workload-key.json"
python3 - "$WORKDIR/policy.json" "$action_id" "$action_ver" "$principal_id" \
  "$WORKDIR/workload-key.json" "$ISSUER" "$AUDIENCE" <<'PY'
import json, pathlib, sys, time, uuid
path, action_id, action_version, admin_principal, key_path, issuer, audience = sys.argv[1:]
key = json.loads(pathlib.Path(key_path).read_text())
resource = {"type": "fixed-http-action", "id": action_id}
workload_principal = str(uuid.uuid4())
pathlib.Path(path).write_text(json.dumps({
    "format_version": 3,
    "version": 3,
    "expires_at_ms": int(time.time() * 1000) + 600000,
    "approvers": [],
    "workload_identities": [{
        "principal_id": workload_principal,
        "issuer": issuer,
        "audiences": [audience],
        "max_token_age_ms": 900000,
        "profile": {"kind": "oidc", "subject": "service:archive"},
        "keys": [key],
    }],
    "bindings": [{
        "action_id": action_id,
        "version": int(action_version),
        "resource": resource,
        "parameter_schema_id": "archive-empty/v1",
        "parameter_schema": {"type": "null"},
    }],
    "rules": [
        {
            "id": str(uuid.uuid4()),
            "effect": "permit",
            "principal_id": admin_principal,
            "action_id": action_id,
            "version": int(action_version),
            "resource": resource,
            "parameters": {"kind": "any_validated"},
        },
        {
            "id": str(uuid.uuid4()),
            "effect": "permit",
            "principal_id": workload_principal,
            "action_id": action_id,
            "version": int(action_version),
            "resource": resource,
            "parameters": {"kind": "any_validated"},
        },
    ],
}))
PY
activate_snapshot
python3 "$SIGNER" workload-token --key-dir "$WORKDIR/workload-key" --kid "$KID" \
  --issuer "$ISSUER" --subject "service:archive" --audience "$AUDIENCE" \
  --jti "archive-jti-1" --now "$(date +%s)" --validity-seconds 600 \
  >"$WORKDIR/workload.jwt"
workload_session="$("$REKEY" --state-dir "$STATE" session create --action "$action_ref" \
  --ttl 10m --max-uses 5 --workload-token-stdin <"$WORKDIR/workload.jwt")"
workload_token="$(printf '%s\n' "$workload_session" | json_field capability_token)"
if [[ "${REKEY_ACCEPTANCE_SKIP_EXECUTE:-}" != "1" ]]; then
  "$REKEY" --state-dir "$STATE" execute "$action_ref" --capability "$workload_token" | assert_status
fi
expect_exit 4 "$REKEY" --state-dir "$STATE" session create --action "$action_ref" \
  --ttl 10m --max-uses 5 --workload-token-stdin <"$WORKDIR/workload.jwt"

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

echo "== Vault CLI register/rotate without claiming live Vault execute"
python3 - "$WORKDIR/vault-kv-1.json" "$WORKDIR/vault-kv-2.json" \
  "$WORKDIR/vault-dyn-1.json" "$WORKDIR/vault-dyn-2.json" \
  "$WORKDIR/vault-bad.json" "$VAULT_TOKEN_ONE" "$VAULT_TOKEN_TWO" <<'PY'
import json, pathlib, sys
kv1, kv2, dyn1, dyn2, bad, token_one, token_two = sys.argv[1:]
def kv(version, token):
    return {"credential_type":"vault-kv-v2-source-v1","origin":"https://example.com",
            "mount":"secret","path":"agents/archive","key":"token","version":version,
            "vault_token":token}
def dyn(token):
    return {"credential_type":"vault-dynamic-source-v1","origin":"https://example.com",
            "mount":"database","role":"agent-api-token","key":"token","vault_token":token}
pathlib.Path(kv1).write_text(json.dumps(kv(7, token_one)))
pathlib.Path(kv2).write_text(json.dumps(kv(8, token_two)))
pathlib.Path(dyn1).write_text(json.dumps(dyn(token_one)))
pathlib.Path(dyn2).write_text(json.dumps(dyn(token_two)))
bad_profile = kv(9, token_two)
bad_profile["origin"] = "http://example.com"
pathlib.Path(bad).write_text(json.dumps(bad_profile))
PY
expect_exit 2 pipe_secret "$PASSWORD" "$REKEY" --state-dir "$STATE" credential \
  add-vault-kv archive-bad --file "$WORKDIR/vault-bad.json" --password-stdin
kv_json="$(printf '%s\n' "$PASSWORD" | "$REKEY" --state-dir "$STATE" credential \
  add-vault-kv archive-kv --file "$WORKDIR/vault-kv-1.json" --password-stdin)"
kv_id="$(printf '%s\n' "$kv_json" | json_field id)"
[[ "$(printf '%s\n' "$kv_json" | json_field kind)" == "vault-kv-v2-source" ]]
[[ "$(printf '%s\n' "$kv_json" | json_field current_version)" == "1" ]]
rot_kv="$(printf '%s\n' "$PASSWORD" | "$REKEY" --state-dir "$STATE" credential \
  rotate-vault-kv "$kv_id" --file "$WORKDIR/vault-kv-2.json" --password-stdin)"
[[ "$(printf '%s\n' "$rot_kv" | json_field current_version)" == "2" ]]
dyn_json="$(printf '%s\n' "$PASSWORD" | "$REKEY" --state-dir "$STATE" credential \
  add-vault-dynamic archive-dyn --file "$WORKDIR/vault-dyn-1.json" --password-stdin)"
dyn_id="$(printf '%s\n' "$dyn_json" | json_field id)"
[[ "$(printf '%s\n' "$dyn_json" | json_field kind)" == "vault-dynamic-source" ]]
rot_dyn="$(printf '%s\n' "$PASSWORD" | "$REKEY" --state-dir "$STATE" credential \
  rotate-vault-dynamic "$dyn_id" --file "$WORKDIR/vault-dyn-2.json" --password-stdin)"
[[ "$(printf '%s\n' "$rot_dyn" | json_field current_version)" == "2" ]]
list="$("$REKEY" --state-dir "$STATE" credential list)"
printf '%s\n' "$list" | rg -q 'vault-kv-v2-source'
printf '%s\n' "$list" | rg -q 'vault-dynamic-source'
if printf '%s\n' "$list" | rg -F -- "$VAULT_TOKEN_ONE"; then
  echo "vault token leaked into credential list" >&2
  exit 1
fi

printf '%s\n' "$PASSWORD" | "$REKEY" --state-dir "$STATE" shutdown --password-stdin >/dev/null
SERVE_PID=""

if [[ "$(uname -s)" != Linux ]]; then
  echo "== macOS agent-run is UNSUPPORTED_PLATFORM and does not spawn"
  mkdir -p "$AGENT_RUN"
  printf '%s\n' "$PASSWORD" | "$REKEYD" init --state-dir "$WORKDIR/macos" --password-stdin >/dev/null
  "$REKEYD" serve --state-dir "$WORKDIR/macos" --idle-lock 15m --agent-runtime-dir "$AGENT_RUN" \
    >"$WORKDIR/macos.out" 2>"$WORKDIR/macos.err" &
  SERVE_PID=$!
  for _ in $(seq 1 200); do
    [[ -S "$WORKDIR/macos/runtime/admin.sock" && -S "$AGENT_RUN/agent.sock" ]] && break
    sleep 0.05
  done
  [[ -S "$AGENT_RUN/agent.sock" ]] || { echo "disjoint agent socket missing"; exit 1; }
  expect_exit 2 "$REKEY" --state-dir "$WORKDIR/macos" --agent-socket "$AGENT_RUN/agent.sock" \
    agent-run -- /bin/echo archive-agent-run-must-not-run
  printf '%s\n' "$CAPTURE_OUT" | rg -q 'UNSUPPORTED_PLATFORM|unsupported on this platform' || {
    echo "macOS agent-run did not report unsupported platform: $CAPTURE_OUT" >&2
    exit 1
  }
  printf '%s\n' "$CAPTURE_OUT" | rg -F archive-agent-run-must-not-run && {
    echo "macOS agent-run executed the child" >&2
    exit 1
  }
  printf '%s\n' "$PASSWORD" | "$REKEY" --state-dir "$WORKDIR/macos" shutdown --password-stdin >/dev/null
  SERVE_PID=""
fi

echo "release-archive-acceptance: PASS"
echo "release-archive-acceptance: proved=password-change,recovery-rotate,audit-list-export,policy-activate,approval-grant,workload-mint,vault-kv-register,vault-dynamic-register"
echo "release-archive-acceptance: limitation=vault-execute-still-fixture-only,not-live-vault"
