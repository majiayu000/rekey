#!/usr/bin/env bash
# P1.1 release-process acceptance: real CLI, broker runtime process, Admin and
# Agent UDS, SQLite audit, and a local CA/TLS upstream. The fixture transport is
# confined to a Cargo example; production rekeyd remains loopback-denying.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
REKEY="$ROOT/target/release/rekey"
REKEYD="$ROOT/target/release/rekeyd"
FIXTURE="$ROOT/target/release/examples/p1_policy_fixture"
PASSWORD="p1 acceptance horse battery staple"
SECRET="P1-LOCAL-TLS-CREDENTIAL-CANARY"

cargo build --release -p rekey-cli --bin rekey -p rekey-broker --bin rekeyd
cargo build --release -p rekey-broker --example p1_policy_fixture

WORKDIR="$(mktemp -d /tmp/rkp1.XXXXXX)"
STATE="$WORKDIR/s"
READY="$WORKDIR/port"
HITS="$WORKDIR/hits"
BROKER_PID=""
cleanup() {
  if [[ -n "$BROKER_PID" ]]; then
    kill "$BROKER_PID" 2>/dev/null || true
    wait "$BROKER_PID" 2>/dev/null || true
  fi
  rm -rf "$WORKDIR"
}
trap cleanup EXIT

json_field() {
  python3 -c 'import json,sys; print(json.load(sys.stdin)[sys.argv[1]])' "$1"
}

expect_denied() {
  set +e
  "$@" >"$WORKDIR/denied.out" 2>"$WORKDIR/denied.err"
  local rc=$?
  set -e
  [[ "$rc" -eq 4 ]] || {
    echo "expected policy denial exit 4, got $rc"
    cat "$WORKDIR/denied.err"
    exit 1
  }
}

activate_policy_file() {
  python3 "$ROOT/scripts/sign-test-policy.py" policy --key-dir "$WORKDIR/policy-key" \
    --snapshot "$WORKDIR/policy.json" --bundle "$WORKDIR/policy-bundle.json" \
    --trust "$WORKDIR/policy-trust.json"
  printf '%s\n' "$PASSWORD" | "$REKEY" --state-dir "$STATE" policy trust install \
    --file "$WORKDIR/policy-trust.json" --step-up-stdin >/dev/null
  printf '%s\n' "$PASSWORD" | "$REKEY" --state-dir "$STATE" policy activate \
    --file "$WORKDIR/policy-bundle.json" --step-up-stdin >/dev/null
}

printf '%s\n' "$PASSWORD" | "$REKEYD" init --state-dir "$STATE" --password-stdin >/dev/null
"$FIXTURE" "$STATE" "$READY" "$HITS" >"$WORKDIR/broker.out" 2>"$WORKDIR/broker.err" &
BROKER_PID=$!
for _ in $(seq 1 200); do
  [[ -f "$READY" && -S "$STATE/runtime/admin.sock" ]] && break
  sleep 0.025
done
[[ -f "$READY" && -S "$STATE/runtime/admin.sock" ]] || {
  echo "broker fixture did not start"
  cat "$WORKDIR/broker.err"
  exit 1
}
PORT="$(tr -d '\n' <"$READY")"

printf '%s\n' "$PASSWORD" | "$REKEY" --state-dir "$STATE" unlock --password-stdin >/dev/null
cred_json="$(printf '%s\n%s\n' "$PASSWORD" "$SECRET" | "$REKEY" --state-dir "$STATE" credential add p1-local-tls --stdin-secrets)"
cred_id="$(printf '%s\n' "$cred_json" | json_field id)"

python3 - "$WORKDIR/action.json" "$cred_id" "$PORT" <<'PY'
import json, pathlib, sys
pathlib.Path(sys.argv[1]).write_text(json.dumps({
    "name": "p1-local-tls",
    "credential_id": sys.argv[2],
    "origin": f"https://api.test.local:{sys.argv[3]}",
    "method": "POST",
    "exact_path": "/v1/policy",
    "auth_header": "authorization",
    "auth_prefix": "Bearer ",
    "timeout_ms": 10000,
    "request_max_bytes": 4096,
    "allowed_extra_headers": [],
    "response_max_bytes": 4096,
    "allowed_response_headers": ["content-type"],
}))
PY
action_json="$(printf '%s\n' "$PASSWORD" | "$REKEY" --state-dir "$STATE" action create --file "$WORKDIR/action.json" --password-stdin)"
action_id="$(printf '%s\n' "$action_json" | json_field id)"
action_version="$(printf '%s\n' "$action_json" | json_field version)"
action_ref="${action_id}@${action_version}"
session_json="$(printf '%s\n' "$PASSWORD" | "$REKEY" --state-dir "$STATE" session create --action "$action_ref" --ttl 10m --max-uses 20 --password-stdin)"
principal_id="$(printf '%s\n' "$session_json" | json_field principal_id)"
token="$(printf '%s\n' "$session_json" | json_field capability_token)"
printf '%s\n' '{"message":"allowed"}' >"$WORKDIR/allowed.json"

status="$($REKEY --state-dir "$STATE" policy status)"
printf '%s\n' "$status" | grep -q '"status": "unavailable"'
expect_denied "$REKEY" --state-dir "$STATE" execute "$action_ref" --capability "$token" --body-file "$WORKDIR/allowed.json" --content-type application/json
[[ "$(tr -d '\n' <"$HITS")" -eq 0 ]]

python3 - "$WORKDIR/policy.json" "$action_id" "$action_version" "$principal_id" 1 empty <<'PY'
import json, pathlib, sys, time, uuid
path, action, version, principal, policy_version, mode = sys.argv[1:]
resource = {"type": "fixed-http-action", "id": action}
snapshot = {
    "format_version": 2,
    "version": int(policy_version),
    "expires_at_ms": int(time.time() * 1000) + 600000,
    "approvers": [],
    "bindings": [{
        "action_id": action, "version": int(version), "resource": resource,
        "parameter_schema_id": "p1-message/v1",
        "parameter_schema": {"type": "object", "required": ["message"],
            "properties": {"message": {"type": "string"}}, "additionalProperties": False},
    }],
    "rules": [],
}
pathlib.Path(path).write_text(json.dumps(snapshot))
PY
activate_policy_file
expect_denied "$REKEY" --state-dir "$STATE" execute "$action_ref" --capability "$token" --body-file "$WORKDIR/allowed.json" --content-type application/json
[[ "$(tr -d '\n' <"$HITS")" -eq 0 ]]

python3 - "$WORKDIR/policy.json" "$action_id" "$action_version" "$principal_id" <<'PY'
import json, pathlib, sys, time, uuid
path, action, version, principal = sys.argv[1:]
resource = {"type": "fixed-http-action", "id": action}
binding = {"action_id": action, "version": int(version), "resource": resource,
    "parameter_schema_id": "p1-message/v1", "parameter_schema": {"type": "object",
    "required": ["message"], "properties": {"message": {"type": "string"}},
    "additionalProperties": False}}
rule = {"id": str(uuid.uuid4()), "effect": "permit", "principal_id": principal,
    "action_id": action, "version": int(version), "resource": resource,
    "parameters": {"kind": "any_validated"}}
pathlib.Path(path).write_text(json.dumps({"format_version": 2, "version": 2,
    "expires_at_ms": int(time.time() * 1000) + 600000, "approvers": [],
    "bindings": [binding], "rules": [rule]}))
PY
activate_policy_file
status="$($REKEY --state-dir "$STATE" policy status)"
printf '%s\n' "$status" | grep -q '"version": 2'
execute_out="$($REKEY --state-dir "$STATE" execute "$action_ref" --capability "$token" --body-file "$WORKDIR/allowed.json" --content-type application/json)"
printf '%s\n' "$execute_out" | grep -q '"ok":true'
[[ "$(tr -d '\n' <"$HITS")" -eq 1 ]]

parameter_hash="$(python3 - "$STATE/vault.sqlite3" <<'PY'
import pathlib, sqlite3, sys
db = sqlite3.connect(sys.argv[1])
row = db.execute("SELECT lower(hex(parameter_hash)) FROM audit_events WHERE event_type='execution.finished' ORDER BY created_at_ms DESC LIMIT 1").fetchone()
if not row or not row[0]: raise SystemExit("missing durable parameter hash")
header = db.execute("SELECT format_version FROM vault_header").fetchone()
if not header or header[0] != 6: raise SystemExit("durable format is not 6")
print(row[0])
PY
)"

python3 - "$WORKDIR/policy.json" "$action_id" "$action_version" "$principal_id" <<'PY'
import json, pathlib, sys, time, uuid
path, action, version, principal = sys.argv[1:]
resource = {"type": "fixed-http-action", "id": action}
binding = {"action_id": action, "version": int(version), "resource": resource,
    "parameter_schema_id": "p1-message/v1", "parameter_schema": {"type": "object",
    "required": ["message"], "properties": {"message": {"type": "string"}},
    "additionalProperties": False}}
rule = {"id": str(uuid.uuid4()), "effect": "permit", "principal_id": principal,
    "action_id": action, "version": int(version), "resource": resource,
    "parameters": {"kind": "any_validated"}}
pathlib.Path(path).write_text(json.dumps({"format_version": 2, "version": 3,
    "expires_at_ms": int(time.time() * 1000) + 5000, "approvers": [],
    "bindings": [binding], "rules": [rule]}))
PY
activate_policy_file
for _ in $(seq 1 60); do
  status="$($REKEY --state-dir "$STATE" policy status)"
  printf '%s\n' "$status" | grep -q '"status": "expired"' && break
  sleep 0.1
done
printf '%s\n' "$status" | grep -q '"status": "expired"'
expect_denied "$REKEY" --state-dir "$STATE" execute "$action_ref" --capability "$token" --body-file "$WORKDIR/allowed.json" --content-type application/json
[[ "$(tr -d '\n' <"$HITS")" -eq 1 ]]

python3 - "$WORKDIR/policy.json" "$action_id" "$action_version" "$principal_id" "$parameter_hash" <<'PY'
import json, pathlib, sys, time, uuid
path, action, version, principal, parameter_hash = sys.argv[1:]
resource = {"type": "fixed-http-action", "id": action}
binding = {"action_id": action, "version": int(version), "resource": resource,
    "parameter_schema_id": "p1-message/v1", "parameter_schema": {"type": "object",
    "required": ["message"], "properties": {"message": {"type": "string"}},
    "additionalProperties": False}}
def rule(effect, parameters): return {"id": str(uuid.uuid4()), "effect": effect,
    "principal_id": principal, "action_id": action, "version": int(version),
    "resource": resource, "parameters": parameters}
rules = [rule("permit", {"kind": "any_validated"}),
    rule("forbid", {"kind": "exact_hash", "sha256": parameter_hash})]
pathlib.Path(path).write_text(json.dumps({"format_version": 2, "version": 4,
    "expires_at_ms": int(time.time() * 1000) + 600000, "approvers": [],
    "bindings": [binding], "rules": rules}))
PY
activate_policy_file
expect_denied "$REKEY" --state-dir "$STATE" execute "$action_ref" --capability "$token" --body-file "$WORKDIR/allowed.json" --content-type application/json
printf '%s\n' '{"message":"one","message":"two"}' >"$WORKDIR/ambiguous.json"
expect_denied "$REKEY" --state-dir "$STATE" execute "$action_ref" --capability "$token" --body-file "$WORKDIR/ambiguous.json" --content-type application/json
[[ "$(tr -d '\n' <"$HITS")" -eq 1 ]]

python3 - "$STATE/vault.sqlite3" "$SECRET" <<'PY'
import pathlib, sqlite3, sys
db = sqlite3.connect(sys.argv[1])
row = db.execute("SELECT principal_id, policy_version, policy_digest, policy_rule_id, resource_type, resource_id, parameter_hash FROM audit_events WHERE event_type='execution.finished' ORDER BY created_at_ms DESC LIMIT 1").fetchone()
if not row or any(value is None for value in row): raise SystemExit("incomplete authorization audit evidence")
if sys.argv[2].encode() in pathlib.Path(sys.argv[1]).read_bytes(): raise SystemExit("credential leaked into sqlite")
PY

printf '%s\n' "$PASSWORD" | "$REKEY" --state-dir "$STATE" shutdown --password-stdin >/dev/null
wait "$BROKER_PID"
BROKER_PID=""
echo "P1 policy acceptance passed"
