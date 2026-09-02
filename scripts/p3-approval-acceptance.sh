#!/usr/bin/env bash
# P-03 release-process acceptance: signed persistent policy, restart reload,
# one- and two-person approvals, replay/tamper/expiry denial, and audit evidence.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
REKEY="$ROOT/target/release/rekey"
REKEYD="$ROOT/target/release/rekeyd"
FIXTURE="$ROOT/target/release/examples/p1_policy_fixture"
SIGNER="$ROOT/scripts/sign-test-policy.py"
PASSWORD="p3 acceptance horse battery staple"
SECRET="P3-APPROVAL-CREDENTIAL-CANARY"

command -v openssl >/dev/null || { echo "openssl is required"; exit 1; }
command -v python3 >/dev/null || { echo "python3 is required"; exit 1; }
command -v rg >/dev/null || { echo "ripgrep is required"; exit 1; }

cargo build --release -p rekey-cli --bin rekey -p rekey-broker --bin rekeyd
cargo build --release -p rekey-broker --example p1_policy_fixture

WORKDIR="$(mktemp -d /tmp/rkp3.XXXXXX)"
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

expect_exit() {
  local expected="$1"
  shift
  set +e
  "$@" >"$WORKDIR/rejected.out" 2>"$WORKDIR/rejected.err"
  local actual=$?
  set -e
  [[ "$actual" -eq "$expected" ]] || {
    echo "expected exit $expected, got $actual"
    cat "$WORKDIR/rejected.err"
    exit 1
  }
}

start_fixture() {
  rm -f "$READY" "$HITS"
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
}

stop_fixture() {
  printf '%s\n' "$PASSWORD" | "$REKEY" --state-dir "$STATE" shutdown --password-stdin >/dev/null
  wait "$BROKER_PID"
  BROKER_PID=""
}

write_action() {
  python3 - "$WORKDIR/action.json" "$1" "$PORT" <<'PY'
import json, pathlib, sys
pathlib.Path(sys.argv[1]).write_text(json.dumps({
    "name": "p3-approval",
    "credential_id": sys.argv[2],
    "origin": f"https://api.test.local:{sys.argv[3]}",
    "method": "POST",
    "exact_path": "/v1/approval",
    "auth_header": "authorization",
    "auth_prefix": "Bearer ",
    "timeout_ms": 10000,
    "request_max_bytes": 4096,
    "allowed_extra_headers": [],
    "response_max_bytes": 4096,
    "allowed_response_headers": ["content-type"],
}))
PY
}

write_policy() {
  python3 - "$WORKDIR/policy-snapshot.json" "$action_id" "$action_version" \
    "$principal_id" "$1" "$2" "$WORKDIR/approver-1.json" \
    "$WORKDIR/approver-2.json" <<'PY'
import json, pathlib, sys, time, uuid
path, action, action_version, principal, policy_version, quorum, first, second = sys.argv[1:]
approvers = [json.loads(pathlib.Path(first).read_text()), json.loads(pathlib.Path(second).read_text())]
resource = {"type": "fixed-http-action", "id": action}
snapshot = {
    "format_version": 2,
    "version": int(policy_version),
    "expires_at_ms": int(time.time() * 1000) + 600000,
    "approvers": approvers,
    "bindings": [{
        "action_id": action,
        "version": int(action_version),
        "resource": resource,
        "parameter_schema_id": "p3-message/v1",
        "parameter_schema": {
            "type": "object",
            "required": ["message"],
            "properties": {"message": {"type": "string"}},
            "additionalProperties": False,
        },
    }],
    "rules": [{
        "id": str(uuid.uuid4()),
        "effect": "require-approval",
        "principal_id": principal,
        "action_id": action,
        "version": int(action_version),
        "resource": resource,
        "parameters": {"kind": "any_validated"},
        "approval": {
            "approver_ids": [entry["approver_id"] for entry in approvers],
            "quorum": int(quorum),
            "mode": "one-time",
            "max_uses": 1,
        },
    }],
}
pathlib.Path(path).write_text(json.dumps(snapshot))
PY
}

activate_policy() {
  python3 "$SIGNER" policy --key-dir "$WORKDIR/policy-key" \
    --snapshot "$WORKDIR/policy-snapshot.json" --bundle "$WORKDIR/policy-bundle.json" \
    --trust "$WORKDIR/policy-trust.json"
  printf '%s\n' "$PASSWORD" | "$REKEY" --state-dir "$STATE" policy trust install \
    --file "$WORKDIR/policy-trust.json" --step-up-stdin >/dev/null
  printf '%s\n' "$PASSWORD" | "$REKEY" --state-dir "$STATE" policy activate \
    --file "$WORKDIR/policy-bundle.json" --step-up-stdin >/dev/null
}

create_session() {
  local session
  session="$(printf '%s\n' "$PASSWORD" | "$REKEY" --state-dir "$STATE" session create \
    --action "$action_ref" --ttl 10m --max-uses 40 --password-stdin)"
  principal_id="$(printf '%s\n' "$session" | json_field principal_id)"
  token="$(printf '%s\n' "$session" | json_field capability_token)"
}

prepare() {
  local output="$1"
  printf '%s\n' "$token" | "$REKEY" --state-dir "$STATE" approval prepare "$action_ref" \
    --capability - --body-file "$WORKDIR/request.json" --content-type application/json >"$output"
}

sign_grant() {
  python3 "$SIGNER" approval-sign --key-dir "$1" --challenge "$2" \
    --output "$3" --max-uses 1 --validity-ms "$4"
}

execute_with() {
  printf '%s\n' "$token" | "$REKEY" --state-dir "$STATE" execute "$action_ref" \
    --capability - --body-file "$WORKDIR/request.json" --content-type application/json "$@"
}

printf '%s\n' "$PASSWORD" | "$REKEYD" init --state-dir "$STATE" --password-stdin >/dev/null
python3 "$SIGNER" approval-identity --key-dir "$WORKDIR/approver-1-key" >"$WORKDIR/approver-1.json"
python3 "$SIGNER" approval-identity --key-dir "$WORKDIR/approver-2-key" >"$WORKDIR/approver-2.json"
printf '%s\n' '{"message":"approved"}' >"$WORKDIR/request.json"
printf '%s\n' '{"message":"changed"}' >"$WORKDIR/changed.json"

start_fixture
printf '%s\n' "$PASSWORD" | "$REKEY" --state-dir "$STATE" unlock --password-stdin >/dev/null
credential="$(printf '%s\n%s\n' "$PASSWORD" "$SECRET" | "$REKEY" --state-dir "$STATE" credential add p3-approval --stdin-secrets)"
credential_id="$(printf '%s\n' "$credential" | json_field id)"
write_action "$credential_id"
action="$(printf '%s\n' "$PASSWORD" | "$REKEY" --state-dir "$STATE" action create --file "$WORKDIR/action.json" --password-stdin)"
action_id="$(printf '%s\n' "$action" | json_field id)"
action_version="$(printf '%s\n' "$action" | json_field version)"
action_ref="${action_id}@${action_version}"
create_session
old_token="$token"
write_policy 1 1
activate_policy
"$REKEY" --state-dir "$STATE" policy status | rg -q '"status": "active"'
stop_fixture

start_fixture
status="$($REKEY --state-dir "$STATE" policy status)"
printf '%s\n' "$status" | rg -q '"status": "unavailable"'
printf '%s\n' "$PASSWORD" | "$REKEY" --state-dir "$STATE" unlock --password-stdin >/dev/null
status="$($REKEY --state-dir "$STATE" policy status)"
printf '%s\n' "$status" | rg -q '"status": "active"'
printf '%s\n' "$status" | rg -q '"version": 1'
expect_exit 4 bash -c 'printf "%s\n" "$1" | "$2" --state-dir "$3" approval prepare "$4" --capability - --body-file "$5" --content-type application/json' \
  _ "$old_token" "$REKEY" "$STATE" "$action_ref" "$WORKDIR/request.json"

write_action "$credential_id"
action="$(printf '%s\n' "$PASSWORD" | "$REKEY" --state-dir "$STATE" action update "$action_id" --file "$WORKDIR/action.json" --password-stdin)"
action_version="$(printf '%s\n' "$action" | json_field version)"
action_ref="${action_id}@${action_version}"
create_session
write_policy 2 1
activate_policy

prepare "$WORKDIR/challenge-1.json"
sign_grant "$WORKDIR/approver-1-key" "$WORKDIR/challenge-1.json" "$WORKDIR/grant-1.json" 60000
execute_with --approval "$WORKDIR/grant-1.json" | rg -q '"ok":true'
expect_exit 4 execute_with --approval "$WORKDIR/grant-1.json"

prepare "$WORKDIR/challenge-parameter.json"
sign_grant "$WORKDIR/approver-1-key" "$WORKDIR/challenge-parameter.json" "$WORKDIR/grant-parameter.json" 60000
expect_exit 4 bash -c 'printf "%s\n" "$1" | "$2" --state-dir "$3" execute "$4" --capability - --body-file "$5" --content-type application/json --approval "$6"' \
  _ "$token" "$REKEY" "$STATE" "$action_ref" "$WORKDIR/changed.json" "$WORKDIR/grant-parameter.json"
python3 - "$WORKDIR/grant-parameter.json" "$WORKDIR/grant-tampered.json" <<'PY'
import json, pathlib, sys
grant = json.loads(pathlib.Path(sys.argv[1]).read_text())
grant["expires_at_ms"] += 1
pathlib.Path(sys.argv[2]).write_text(json.dumps(grant))
PY
expect_exit 4 execute_with --approval "$WORKDIR/grant-tampered.json"

prepare "$WORKDIR/challenge-expired.json"
sign_grant "$WORKDIR/approver-1-key" "$WORKDIR/challenge-expired.json" "$WORKDIR/grant-expired.json" 200
sleep 0.4
expect_exit 4 execute_with --approval "$WORKDIR/grant-expired.json"

prepare "$WORKDIR/challenge-old-policy.json"
sign_grant "$WORKDIR/approver-1-key" "$WORKDIR/challenge-old-policy.json" "$WORKDIR/grant-old-policy.json" 60000
write_policy 3 2
activate_policy
expect_exit 4 execute_with --approval "$WORKDIR/grant-old-policy.json"

prepare "$WORKDIR/challenge-2.json"
sign_grant "$WORKDIR/approver-1-key" "$WORKDIR/challenge-2.json" "$WORKDIR/grant-2a.json" 60000
sign_grant "$WORKDIR/approver-2-key" "$WORKDIR/challenge-2.json" "$WORKDIR/grant-2b.json" 60000
expect_exit 4 execute_with --approval "$WORKDIR/grant-2a.json"
execute_with --approval "$WORKDIR/grant-2a.json" --approval "$WORKDIR/grant-2b.json" | rg -q '"ok":true'
[[ "$(tr -d '\n' <"$HITS")" -eq 2 ]]

ln -s "$WORKDIR/grant-2a.json" "$WORKDIR/grant-link.json"
expect_exit 2 execute_with --approval "$WORKDIR/grant-link.json"
expect_exit 2 execute_with --approval "$WORKDIR/grant-2a.json" --approval "$WORKDIR/grant-2a.json"

"$REKEY" --state-dir "$STATE" audit list --limit 100 >"$WORKDIR/audit.json"
for event in approval.requested approval.accepted approval.rejected execution.started execution.finished; do
  rg -q "\"event_type\": \"$event\"" "$WORKDIR/audit.json"
done
"$REKEY" --state-dir "$STATE" audit export --output "$WORKDIR/audit.jsonl" >/dev/null
rg -q '"record_type":"rekey.audit.export.v2"' "$WORKDIR/audit.jsonl"
rg -q '"event_type":"approval.accepted"' "$WORKDIR/audit.jsonl"

approval_signature="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["signature"])' "$WORKDIR/grant-2a.json")"
approval_id="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["approval_id"])' "$WORKDIR/grant-2a.json")"
rg -q "$approval_id" "$WORKDIR/audit.json"
rg -q "$approval_id" "$WORKDIR/audit.jsonl"
if rg -aF "$token" "$STATE" "$WORKDIR/broker.out" "$WORKDIR/broker.err" "$WORKDIR/audit.json" "$WORKDIR/audit.jsonl"; then
  echo "capability token leaked"
  exit 1
fi
if rg -aF "$approval_signature" "$STATE" "$WORKDIR/broker.out" "$WORKDIR/broker.err" "$WORKDIR/audit.json" "$WORKDIR/audit.jsonl"; then
  echo "approval signature leaked"
  exit 1
fi
if rg -aF "$SECRET" "$STATE" "$WORKDIR/broker.out" "$WORKDIR/broker.err" "$WORKDIR/audit.json" "$WORKDIR/audit.jsonl"; then
  echo "credential leaked"
  exit 1
fi

stop_fixture
echo "P3 approval acceptance passed"
