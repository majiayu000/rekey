#!/usr/bin/env bash
# P-07A local black-box acceptance: release CLI/daemon, real dual UDS + SQLite,
# local CA/TLS Vault KV v2 resolution followed by a fixed HTTPS action.
set -euo pipefail

command -v rg >/dev/null || {
  echo "p7-vault-kv-source requires ripgrep (rg)" >&2
  exit 1
}

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
REKEY="$ROOT/target/release/rekey"
REKEYD="$ROOT/target/release/rekeyd"
FIXTURE="$ROOT/target/release/examples/p2_github_app_fixture"
PASSWORD="p7 vault source acceptance password"
SOURCE_ONE="P7-VAULT-SOURCE-TOKEN-ONE-CANARY"
SOURCE_TWO="P7-VAULT-SOURCE-TOKEN-TWO-CANARY"
RESOLVED_ONE="P7-RESOLVED-VALUE-ONE-CANARY"
RESOLVED_TWO="P7-RESOLVED-VALUE-TWO-CANARY"

cargo build --release -p rekey-cli --bin rekey -p rekey-broker --bin rekeyd
cargo build --release -p rekey-broker --example p2_github_app_fixture

WORKDIR="$(mktemp -d /tmp/rkp7vault.XXXXXX)"
STATE="$WORKDIR/state"
READY="$WORKDIR/ready"
MODE="$WORKDIR/mode"
TRACE="$WORKDIR/trace"
PROFILE_ONE="$WORKDIR/profile-one.json"
PROFILE_TWO="$WORKDIR/profile-two.json"
INVALID_PROFILE="$WORKDIR/profile-invalid.json"
ACTION_FILE="$WORKDIR/action.json"
REQUEST_BODY="$WORKDIR/request.json"
BROKER_PID=""

cleanup() {
  if [[ -n "$BROKER_PID" ]]; then
    kill "$BROKER_PID" 2>/dev/null || true
    wait "$BROKER_PID" 2>/dev/null || true
  fi
  rm -rf "$WORKDIR"
}
failure() {
  local rc=$?
  [[ ! -f "$WORKDIR/broker.err" ]] || cat "$WORKDIR/broker.err" >&2
  [[ ! -f "$TRACE" ]] || tail -80 "$TRACE" >&2
  echo "P7 Vault KV source acceptance failed at line $1 (exit $rc)" >&2
  exit "$rc"
}
trap cleanup EXIT
trap 'failure "$LINENO"' ERR

json_field() {
  python3 -c 'import json,sys; print(json.load(sys.stdin)[sys.argv[1]])' "$1"
}

credential_version() {
  "$REKEY" --state-dir "$STATE" credential list | python3 -c \
    'import json,sys; wanted=sys.argv[1]; print(next(c["current_version"] for c in json.load(sys.stdin)["credentials"] if c["id"] == wanted))' "$1"
}

python3 - "$PROFILE_ONE" "$PROFILE_TWO" "$INVALID_PROFILE" "$SOURCE_ONE" "$SOURCE_TWO" <<'PY'
import json, pathlib, sys
one, two, invalid, source_one, source_two = sys.argv[1:]
def profile(version, token):
    return {"credential_type":"vault-kv-v2-source-v1","origin":"https://vault.test.local",
            "mount":"secret","path":"agents/github","key":"token","version":version,
            "vault_token":token}
pathlib.Path(one).write_text(json.dumps(profile(7, source_one)))
pathlib.Path(two).write_text(json.dumps(profile(8, source_two)))
bad=profile(9, source_two); bad["origin"]="http://vault.test.local"
pathlib.Path(invalid).write_text(json.dumps(bad))
PY

printf '%s' '{"operation":"bounded"}' >"$REQUEST_BODY"
printf '%s\n' "$PASSWORD" | "$REKEYD" init --state-dir "$STATE" --password-stdin >/dev/null
printf '%s\n' p7-v1 >"$MODE"
"$FIXTURE" "$STATE" "$READY" "$MODE" "$TRACE" "$PROFILE_ONE" "$PROFILE_ONE" \
  >"$WORKDIR/broker.out" 2>"$WORKDIR/broker.err" &
BROKER_PID=$!
for _ in $(seq 1 400); do
  [[ -f "$READY" && -S "$STATE/runtime/admin.sock" ]] && break
  sleep 0.025
done
[[ -f "$READY" && -S "$STATE/runtime/admin.sock" ]]
printf '%s\n' "$PASSWORD" | "$REKEY" --state-dir "$STATE" unlock --password-stdin >/dev/null

CREDENTIAL_JSON="$(printf '%s\n' "$PASSWORD" | "$REKEY" --state-dir "$STATE" credential \
  add-vault-kv p7-vault --file "$PROFILE_ONE" --password-stdin)"
CREDENTIAL_ID="$(printf '%s\n' "$CREDENTIAL_JSON" | json_field id)"
[[ "$(printf '%s\n' "$CREDENTIAL_JSON" | json_field current_version)" == "1" ]]

python3 - "$ACTION_FILE" "$CREDENTIAL_ID" <<'PY'
import json, pathlib, sys
path, credential = sys.argv[1:]
pathlib.Path(path).write_text(json.dumps({
  "name":"p7-source-action","credential_id":credential,"origin":"https://api.test.local",
  "method":"POST","exact_path":"/v1/things","auth_header":"authorization",
  "auth_prefix":"Bearer ","timeout_ms":5000,"request_max_bytes":1024,
  "allowed_extra_headers":[],"response_max_bytes":4096,
  "allowed_response_headers":["content-type"]}))
PY
ACTION_JSON="$(printf '%s\n' "$PASSWORD" | "$REKEY" --state-dir "$STATE" action create \
  --file "$ACTION_FILE" --password-stdin)"
ACTION_ID="$(printf '%s\n' "$ACTION_JSON" | json_field id)"
ACTION_REF="$ACTION_ID@1"
SESSION_JSON="$(printf '%s\n' "$PASSWORD" | "$REKEY" --state-dir "$STATE" session create \
  --action "$ACTION_REF" --ttl 10m --max-uses 10 --password-stdin)"
PRINCIPAL_ID="$(printf '%s\n' "$SESSION_JSON" | json_field principal_id)"
CAPABILITY="$(printf '%s\n' "$SESSION_JSON" | json_field capability_token)"

python3 - "$WORKDIR/policy-snapshot.json" "$ACTION_ID" "$PRINCIPAL_ID" <<'PY'
import json, pathlib, sys, time, uuid
path, action, principal = sys.argv[1:]
binding={"action_id":action,"version":1,"resource":{"type":"p7-vault-action","id":action},
         "parameter_schema_id":"p7-vault/v1","parameter_schema":{"type":"object","additionalProperties":False,
         "required":["operation"],"properties":{"operation":{"const":"bounded"}}}}
rule={"id":str(uuid.uuid4()),"effect":"permit","principal_id":principal,"action_id":action,
      "version":1,"resource":binding["resource"],"parameters":{"kind":"any_validated"}}
pathlib.Path(path).write_text(json.dumps({"format_version":3,"version":1,
  "expires_at_ms":int(time.time()*1000)+600000,"approvers":[],"workload_identities":[],
  "bindings":[binding],"rules":[rule]}))
PY
python3 "$ROOT/scripts/sign-test-policy.py" policy --key-dir "$WORKDIR/policy-key" \
  --snapshot "$WORKDIR/policy-snapshot.json" --bundle "$WORKDIR/policy.json" \
  --trust "$WORKDIR/policy-trust.json"
printf '%s\n' "$PASSWORD" | "$REKEY" --state-dir "$STATE" policy trust install \
  --file "$WORKDIR/policy-trust.json" --step-up-stdin >/dev/null
printf '%s\n' "$PASSWORD" | "$REKEY" --state-dir "$STATE" policy activate \
  --file "$WORKDIR/policy.json" --step-up-stdin >/dev/null

"$REKEY" --state-dir "$STATE" execute "$ACTION_REF" --capability "$CAPABILITY" \
  --body-file "$REQUEST_BODY" --content-type application/json >"$WORKDIR/v1.out"
grep -q '"result":"p7-ok"' "$WORKDIR/v1.out"
[[ "$(grep -c '^p7.source.ok$' "$TRACE")" == "1" ]]
[[ "$(grep -c '^p7.action.ok$' "$TRACE")" == "1" ]]

printf '%s\n' p7-wrong-version >"$MODE"
WRONG_RC=0
"$REKEY" --state-dir "$STATE" execute "$ACTION_REF" --capability "$CAPABILITY" \
  --body-file "$REQUEST_BODY" --content-type application/json >/dev/null 2>"$WORKDIR/wrong.err" || WRONG_RC=$?
[[ "$WRONG_RC" == "6" && "$(grep -c '^p7.action.ok$' "$TRACE")" == "1" ]]

printf '%s\n' p7-reflect-source-token >"$MODE"
REFLECT_RC=0
"$REKEY" --state-dir "$STATE" execute "$ACTION_REF" --capability "$CAPABILITY" \
  --body-file "$REQUEST_BODY" --content-type application/json >/dev/null 2>"$WORKDIR/reflect.err" || REFLECT_RC=$?
[[ "$REFLECT_RC" == "8" && "$(grep -c '^p7.action.ok$' "$TRACE")" == "1" ]]

INVALID_RC=0
printf '%s\n' "$PASSWORD" | "$REKEY" --state-dir "$STATE" credential rotate-vault-kv \
  "$CREDENTIAL_ID" --file "$INVALID_PROFILE" --password-stdin >/dev/null 2>"$WORKDIR/invalid.err" || INVALID_RC=$?
[[ "$INVALID_RC" == "2" && "$(credential_version "$CREDENTIAL_ID")" == "1" ]]

ROTATED_JSON="$(printf '%s\n' "$PASSWORD" | "$REKEY" --state-dir "$STATE" credential \
  rotate-vault-kv "$CREDENTIAL_ID" --file "$PROFILE_TWO" --password-stdin)"
[[ "$(printf '%s\n' "$ROTATED_JSON" | json_field current_version)" == "2" ]]
printf '%s\n' p7-v2 >"$MODE"
"$REKEY" --state-dir "$STATE" execute "$ACTION_REF" --capability "$CAPABILITY" \
  --body-file "$REQUEST_BODY" --content-type application/json >"$WORKDIR/v2.out"
grep -q '"result":"p7-ok"' "$WORKDIR/v2.out"
[[ "$(grep -c '^p7.action.ok$' "$TRACE")" == "2" ]]

"$REKEY" --state-dir "$STATE" audit export --output "$WORKDIR/audit.jsonl" >/dev/null
python3 - "$WORKDIR/audit.jsonl" <<'PY'
import json, pathlib, sys
rows=[json.loads(line) for line in pathlib.Path(sys.argv[1]).read_text().splitlines()]
events=[row["event_type"] for row in rows if "event_type" in row]
assert events.count("execution.started") == 4
assert events.count("execution.finished") == 2
assert events.count("execution.blocked") == 2
PY

printf '%s\n' "$PASSWORD" | "$REKEY" --state-dir "$STATE" shutdown --password-stdin >/dev/null
wait "$BROKER_PID"
BROKER_PID=""

READY="$WORKDIR/restarted-ready"
"$FIXTURE" "$STATE" "$READY" "$MODE" "$TRACE" "$PROFILE_ONE" "$PROFILE_ONE" \
  >"$WORKDIR/restarted-broker.out" 2>"$WORKDIR/restarted-broker.err" &
BROKER_PID=$!
for _ in $(seq 1 400); do
  [[ -f "$READY" && -S "$STATE/runtime/admin.sock" ]] && break
  sleep 0.025
done
[[ -f "$READY" && -S "$STATE/runtime/admin.sock" ]]
printf '%s\n' "$PASSWORD" | "$REKEY" --state-dir "$STATE" unlock --password-stdin >/dev/null

RESTARTED_SESSION="$(printf '%s\n' "$PASSWORD" | "$REKEY" --state-dir "$STATE" session create \
  --action "$ACTION_REF" --ttl 10m --max-uses 2 --password-stdin)"
RESTARTED_PRINCIPAL="$(printf '%s\n' "$RESTARTED_SESSION" | json_field principal_id)"
RESTARTED_CAPABILITY="$(printf '%s\n' "$RESTARTED_SESSION" | json_field capability_token)"
python3 - "$WORKDIR/policy-snapshot.json" "$RESTARTED_PRINCIPAL" 2 <<'PY'
import json, pathlib, sys, time, uuid
path=pathlib.Path(sys.argv[1]); policy=json.loads(path.read_text())
policy["version"]=int(sys.argv[3]); policy["expires_at_ms"]=int(time.time()*1000)+600000
policy["rules"][0]["id"]=str(uuid.uuid4()); policy["rules"][0]["principal_id"]=sys.argv[2]
path.write_text(json.dumps(policy))
PY
python3 "$ROOT/scripts/sign-test-policy.py" policy --key-dir "$WORKDIR/policy-key" \
  --snapshot "$WORKDIR/policy-snapshot.json" --bundle "$WORKDIR/policy.json" \
  --trust "$WORKDIR/policy-trust.json"
printf '%s\n' "$PASSWORD" | "$REKEY" --state-dir "$STATE" policy activate \
  --file "$WORKDIR/policy.json" --step-up-stdin >/dev/null
"$REKEY" --state-dir "$STATE" execute "$ACTION_REF" --capability "$RESTARTED_CAPABILITY" \
  --body-file "$REQUEST_BODY" --content-type application/json >"$WORKDIR/restarted.out"
grep -q '"result":"p7-ok"' "$WORKDIR/restarted.out"
[[ "$(grep -c '^p7.action.ok$' "$TRACE")" == "3" ]]

BACKUP="$WORKDIR/p7-vault.backup"
BACKUP_JSON="$(printf '%s\n' "$PASSWORD" | "$REKEY" --state-dir "$STATE" backup \
  --output "$BACKUP" --password-stdin)"
BACKUP_SHA256="$(printf '%s\n' "$BACKUP_JSON" | json_field sha256_hex)"
printf '%s\n' "$PASSWORD" | "$REKEY" --state-dir "$STATE" shutdown --password-stdin >/dev/null
wait "$BROKER_PID"
BROKER_PID=""

RESTORED_STATE="$WORKDIR/restored-state"
printf '%s\n' "$PASSWORD" | "$REKEY" --state-dir "$RESTORED_STATE" restore \
  --input "$BACKUP" --sha256 "$BACKUP_SHA256" --password-stdin >/dev/null
STATE="$RESTORED_STATE"
READY="$WORKDIR/restored-ready"
RESTORED_TRACE="$WORKDIR/restored-trace"
"$FIXTURE" "$STATE" "$READY" "$MODE" "$RESTORED_TRACE" "$PROFILE_ONE" "$PROFILE_ONE" \
  >"$WORKDIR/restored-broker.out" 2>"$WORKDIR/restored-broker.err" &
BROKER_PID=$!
for _ in $(seq 1 400); do
  [[ -f "$READY" && -S "$STATE/runtime/admin.sock" ]] && break
  sleep 0.025
done
[[ -f "$READY" && -S "$STATE/runtime/admin.sock" ]]
printf '%s\n' "$PASSWORD" | "$REKEY" --state-dir "$STATE" unlock --password-stdin >/dev/null
"$REKEY" --state-dir "$STATE" credential list | python3 -c '
import json,sys
wanted=sys.argv[1]
credential=next(c for c in json.load(sys.stdin)["credentials"] if c["id"] == wanted)
assert credential["kind"] == "vault-kv-v2-source"
assert credential["current_version"] == 2
' "$CREDENTIAL_ID"

RESTORED_SESSION="$(printf '%s\n' "$PASSWORD" | "$REKEY" --state-dir "$STATE" session create \
  --action "$ACTION_REF" --ttl 10m --max-uses 2 --password-stdin)"
RESTORED_PRINCIPAL="$(printf '%s\n' "$RESTORED_SESSION" | json_field principal_id)"
RESTORED_CAPABILITY="$(printf '%s\n' "$RESTORED_SESSION" | json_field capability_token)"
python3 - "$WORKDIR/policy-snapshot.json" "$RESTORED_PRINCIPAL" 3 <<'PY'
import json, pathlib, sys, time, uuid
path=pathlib.Path(sys.argv[1]); policy=json.loads(path.read_text())
policy["version"]=int(sys.argv[3]); policy["expires_at_ms"]=int(time.time()*1000)+600000
policy["rules"][0]["id"]=str(uuid.uuid4()); policy["rules"][0]["principal_id"]=sys.argv[2]
path.write_text(json.dumps(policy))
PY
python3 "$ROOT/scripts/sign-test-policy.py" policy --key-dir "$WORKDIR/policy-key" \
  --snapshot "$WORKDIR/policy-snapshot.json" --bundle "$WORKDIR/policy.json" \
  --trust "$WORKDIR/policy-trust.json"
printf '%s\n' "$PASSWORD" | "$REKEY" --state-dir "$STATE" policy activate \
  --file "$WORKDIR/policy.json" --step-up-stdin >/dev/null
"$REKEY" --state-dir "$STATE" execute "$ACTION_REF" --capability "$RESTORED_CAPABILITY" \
  --body-file "$REQUEST_BODY" --content-type application/json >"$WORKDIR/restored.out"
grep -q '"result":"p7-ok"' "$WORKDIR/restored.out"
[[ "$(grep -c '^p7.action.ok$' "$RESTORED_TRACE")" == "1" ]]

"$REKEY" --state-dir "$STATE" audit export --output "$WORKDIR/restored-audit.jsonl" >/dev/null
python3 - "$WORKDIR/restored-audit.jsonl" <<'PY'
import json, pathlib, sys
rows=[json.loads(line) for line in pathlib.Path(sys.argv[1]).read_text().splitlines()]
events=[row["event_type"] for row in rows if "event_type" in row]
assert events.count("execution.started") == 6
assert events.count("execution.finished") == 4
assert events.count("execution.blocked") == 2
PY

rm "$PROFILE_ONE" "$PROFILE_TWO" "$INVALID_PROFILE" "$ACTION_FILE" "$REQUEST_BODY" \
  "$WORKDIR/policy-snapshot.json" "$WORKDIR/policy.json" "$WORKDIR/policy-trust.json"
for canary in "$SOURCE_ONE" "$SOURCE_TWO" "$RESOLVED_ONE" "$RESOLVED_TWO" \
  "$CAPABILITY" "$RESTARTED_CAPABILITY" "$RESTORED_CAPABILITY"; do
  if rg -a -F --glob '!trace' --glob '!restored-trace' -- "$canary" "$STATE" "$WORKDIR" >/dev/null; then
    echo "P7 source secret canary leaked: $canary" >&2
    exit 1
  fi
done

printf '%s\n' "$PASSWORD" | "$REKEY" --state-dir "$STATE" shutdown --password-stdin >/dev/null
wait "$BROKER_PID"
BROKER_PID=""
echo "P7 Vault KV source local acceptance passed"
