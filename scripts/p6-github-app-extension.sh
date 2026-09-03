#!/usr/bin/env bash
# P6 local black-box acceptance: release CLI/daemon, real dual UDS + SQLite,
# local CA/TLS GitHub exchange/list/write/revoke, typed rotation and webhook apply.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
REKEY="$ROOT/target/release/rekey"
REKEYD="$ROOT/target/release/rekeyd"
FIXTURE="$ROOT/target/release/examples/p2_github_app_fixture"
PASSWORD="p6 github extension acceptance password"
WEBHOOK_SECRET="P6-WEBHOOK-SECRET-CANARY-0123456789"
TOKEN_CANARY="P2-INSTALLATION-TOKEN-CANARY"
ISSUE_BODY_CANARY="P6 issue body canary"

cargo build --release -p rekey-cli --bin rekey -p rekey-broker --bin rekeyd
cargo build --release -p rekey-broker --example p2_github_app_fixture

WORKDIR="$(mktemp -d /tmp/rkp6github.XXXXXX)"
STATE="$WORKDIR/state"
READY="$WORKDIR/ready"
MODE="$WORKDIR/mode"
TRACE="$WORKDIR/trace"
KEY_ONE="$WORKDIR/key-one.pem"
KEY_ONE_DER="$WORKDIR/key-one.der"
KEY_ONE_PUBLIC="$WORKDIR/key-one-public.der"
KEY_TWO="$WORKDIR/key-two.pem"
KEY_TWO_DER="$WORKDIR/key-two.der"
KEY_TWO_PUBLIC="$WORKDIR/key-two-public.der"
PROFILE="$WORKDIR/profile.json"
KEY_ROTATION_PROFILE="$WORKDIR/key-rotation-profile.json"
ROTATED_PROFILE="$WORKDIR/rotated-profile.json"
INVALID_PROFILE="$WORKDIR/invalid-profile.json"
PAYLOAD_ADD="$WORKDIR/webhook-add.json"
PAYLOAD_REMOVE="$WORKDIR/webhook-remove.json"
ISSUE_BODY="$WORKDIR/issue.json"
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
  echo "P6 GitHub extension acceptance failed at line $1 (exit $rc)" >&2
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

openssl genrsa -traditional -out "$KEY_ONE" 2048 >/dev/null 2>&1
openssl rsa -in "$KEY_ONE" -traditional -outform DER -out "$KEY_ONE_DER" >/dev/null 2>&1
openssl rsa -in "$KEY_ONE" -RSAPublicKey_out -outform DER -out "$KEY_ONE_PUBLIC" >/dev/null 2>&1
openssl genrsa -traditional -out "$KEY_TWO" 2048 >/dev/null 2>&1
openssl rsa -in "$KEY_TWO" -traditional -outform DER -out "$KEY_TWO_DER" >/dev/null 2>&1
openssl rsa -in "$KEY_TWO" -RSAPublicKey_out -outform DER -out "$KEY_TWO_PUBLIC" >/dev/null 2>&1
KEY_TWO_BASE64_CANARY="$(python3 -c 'import base64,pathlib,sys; data=pathlib.Path(sys.argv[1]).read_bytes(); print(base64.b64encode(data[300:324]).decode())' "$KEY_TWO_DER")"

python3 - "$PROFILE" "$KEY_ROTATION_PROFILE" "$ROTATED_PROFILE" "$INVALID_PROFILE" \
  "$KEY_ONE_DER" "$KEY_TWO_DER" "$WEBHOOK_SECRET" <<'PY'
import base64, json, pathlib, sys
profile, key_rotation, rotated, invalid, key_one, key_two, webhook = sys.argv[1:]
def payload(key, repositories):
    return {
        "credential_type": "github-app-installation-v2",
        "client_id": "Iv1.8a61f9b3a7aba766",
        "app_id": 424242,
        "installation_id": 818180,
        "repositories": repositories,
        "permissions": {"metadata": "read", "issues": "write"},
        "webhook_secret": webhook,
        "private_key_pkcs1_der_base64": base64.b64encode(pathlib.Path(key).read_bytes()).decode(),
    }
both = [
    {"id": 818181, "owner": "p6-owner", "name": "alpha"},
    {"id": 818182, "owner": "p6-owner", "name": "beta"},
]
pathlib.Path(profile).write_text(json.dumps(payload(key_one, both)))
pathlib.Path(key_rotation).write_text(json.dumps(payload(key_two, both[:1])))
pathlib.Path(rotated).write_text(json.dumps(payload(key_one, both[:1])))
bad = payload(key_one, both)
bad["repositories"].append({"id": 818181, "owner": "other", "name": "duplicate"})
pathlib.Path(invalid).write_text(json.dumps(bad))
PY

printf '%s\n' "$PASSWORD" | "$REKEYD" init --state-dir "$STATE" --password-stdin >/dev/null
printf '%s\n' p6-list >"$MODE"
"$FIXTURE" "$STATE" "$READY" "$MODE" "$TRACE" "$KEY_ONE_PUBLIC" "$KEY_TWO_PUBLIC" \
  >"$WORKDIR/broker.out" 2>"$WORKDIR/broker.err" &
BROKER_PID=$!
for _ in $(seq 1 400); do
  [[ -f "$READY" && -S "$STATE/runtime/admin.sock" ]] && break
  sleep 0.025
done
[[ -f "$READY" && -S "$STATE/runtime/admin.sock" ]]
printf '%s\n' "$PASSWORD" | "$REKEY" --state-dir "$STATE" unlock --password-stdin >/dev/null

CREDENTIAL_JSON="$(printf '%s\n' "$PASSWORD" | "$REKEY" --state-dir "$STATE" credential \
  add-github-app p6-github --file "$PROFILE" --password-stdin)"
CREDENTIAL_ID="$(printf '%s\n' "$CREDENTIAL_JSON" | json_field id)"
[[ "$(printf '%s\n' "$CREDENTIAL_JSON" | json_field current_version)" == "1" ]]

python3 - "$WORKDIR/list-action.json" "$WORKDIR/issue-action.json" "$CREDENTIAL_ID" <<'PY'
import json, pathlib, sys
list_path, issue_path, credential = sys.argv[1:]
base = {
    "credential_id": credential,
    "origin": "https://api.github.com",
    "auth_header": "authorization",
    "auth_prefix": "Bearer ",
    "timeout_ms": 5000,
    "allowed_extra_headers": [],
    "response_max_bytes": 262144,
    "allowed_response_headers": ["content-type"],
}
pathlib.Path(list_path).write_text(json.dumps(base | {
    "name":"p6-list", "method":"GET", "exact_path":"/installation/repositories",
    "request_max_bytes":1,
}))
pathlib.Path(issue_path).write_text(json.dumps(base | {
    "name":"p6-create-issue", "method":"POST", "exact_path":"/repos/p6-owner/beta/issues",
    "request_max_bytes":33792,
}))
PY
LIST_JSON="$(printf '%s\n' "$PASSWORD" | "$REKEY" --state-dir "$STATE" action create \
  --file "$WORKDIR/list-action.json" --password-stdin)"
ISSUE_JSON="$(printf '%s\n' "$PASSWORD" | "$REKEY" --state-dir "$STATE" action create \
  --file "$WORKDIR/issue-action.json" --password-stdin)"
LIST_ID="$(printf '%s\n' "$LIST_JSON" | json_field id)"
ISSUE_ID="$(printf '%s\n' "$ISSUE_JSON" | json_field id)"
LIST_REF="$LIST_ID@1"
ISSUE_REF="$ISSUE_ID@1"

SESSION_JSON="$(printf '%s\n' "$PASSWORD" | "$REKEY" --state-dir "$STATE" session create \
  --action "$LIST_REF" --action "$ISSUE_REF" --ttl 10m --max-uses 20 --password-stdin)"
PRINCIPAL_ID="$(printf '%s\n' "$SESSION_JSON" | json_field principal_id)"
CAPABILITY="$(printf '%s\n' "$SESSION_JSON" | json_field capability_token)"

python3 - "$WORKDIR/policy-snapshot.json" "$LIST_ID" "$ISSUE_ID" "$PRINCIPAL_ID" <<'PY'
import json, pathlib, sys, time, uuid
path, list_id, issue_id, principal = sys.argv[1:]
bindings = [
  {"action_id":list_id,"version":1,"resource":{"type":"github-repositories","id":list_id},
   "parameter_schema_id":"github-list/v1","parameter_schema":{"type":"null"}},
  {"action_id":issue_id,"version":1,"resource":{"type":"github-issue","id":issue_id},
   "parameter_schema_id":"github-issue/v1","parameter_schema":{"type":"object","additionalProperties":False,
    "required":["title"],"properties":{"title":{"type":"string"},"body":{"type":"string"}}}},
]
rules = [{"id":str(uuid.uuid4()),"effect":"permit","principal_id":principal,
          "action_id":b["action_id"],"version":1,"resource":b["resource"],
          "parameters":{"kind":"any_validated"}} for b in bindings]
pathlib.Path(path).write_text(json.dumps({"format_version":3,"version":1,
  "expires_at_ms":int(time.time()*1000)+600000,"approvers":[],"workload_identities":[],
  "bindings":bindings,"rules":rules}))
PY
python3 "$ROOT/scripts/sign-test-policy.py" policy --key-dir "$WORKDIR/policy-key" \
  --snapshot "$WORKDIR/policy-snapshot.json" --bundle "$WORKDIR/policy.json" \
  --trust "$WORKDIR/policy-trust.json"
printf '%s\n' "$PASSWORD" | "$REKEY" --state-dir "$STATE" policy trust install \
  --file "$WORKDIR/policy-trust.json" --step-up-stdin >/dev/null
printf '%s\n' "$PASSWORD" | "$REKEY" --state-dir "$STATE" policy activate \
  --file "$WORKDIR/policy.json" --step-up-stdin >/dev/null

"$REKEY" --state-dir "$STATE" execute "$LIST_REF" --capability "$CAPABILITY" \
  >"$WORKDIR/list.out"
python3 - "$WORKDIR/list.out" <<'PY'
import json, sys
text=open(sys.argv[1]).read()
decoder=json.JSONDecoder()
values=[]
offset=0
while offset < len(text):
  while offset < len(text) and text[offset].isspace(): offset += 1
  if offset < len(text):
    value, offset = decoder.raw_decode(text, offset)
    values.append(value)
value=values[1]
assert value == {"total_count":2,"repositories":[
  {"id":818181,"owner":"p6-owner","name":"alpha"},
  {"id":818182,"owner":"p6-owner","name":"beta"}]}
PY

printf '%s' '{"title":"P6 issue","body":"P6 issue body canary"}' >"$ISSUE_BODY"
printf '%s\n' p6-issue >"$MODE"
"$REKEY" --state-dir "$STATE" execute "$ISSUE_REF" --capability "$CAPABILITY" \
  --body-file "$ISSUE_BODY" --content-type application/json >"$WORKDIR/issue.out"
grep -q 'https://github.com/p6-owner/beta/issues/7' "$WORKDIR/issue.out"
[[ "$(grep -c '^issue.ok$' "$TRACE")" == "1" ]]

ROTATED_JSON="$(printf '%s\n' "$PASSWORD" | "$REKEY" --state-dir "$STATE" credential \
  rotate-github-app "$CREDENTIAL_ID" --file "$KEY_ROTATION_PROFILE" --password-stdin)"
[[ "$(printf '%s\n' "$ROTATED_JSON" | json_field current_version)" == "2" ]]
printf '%s\n' p6-key-two-list >"$MODE"
KEY_TWO_RESOURCE_BEFORE="$(grep -c '^resource.ok$' "$TRACE")"
"$REKEY" --state-dir "$STATE" execute "$LIST_REF" --capability "$CAPABILITY" \
  >"$WORKDIR/key-two-list.out"
grep -q '"total_count":1' "$WORKDIR/key-two-list.out"
[[ "$(grep -c '^resource.ok$' "$TRACE")" == "$((KEY_TWO_RESOURCE_BEFORE + 1))" ]]
TRACE_BEFORE="$(wc -l <"$TRACE")"
DENIED_RC=0
"$REKEY" --state-dir "$STATE" execute "$ISSUE_REF" --capability "$CAPABILITY" \
  --body-file "$ISSUE_BODY" --content-type application/json >/dev/null 2>"$WORKDIR/removed.err" || DENIED_RC=$?
[[ "$DENIED_RC" == "4" && "$(wc -l <"$TRACE")" == "$TRACE_BEFORE" ]]

printf '%s\n' "$PASSWORD" | "$REKEY" --state-dir "$STATE" credential rotate-github-app \
  "$CREDENTIAL_ID" --file "$ROTATED_PROFILE" --password-stdin >/dev/null
[[ "$(credential_version "$CREDENTIAL_ID")" == "3" ]]
printf '%s\n' p6-rotated-list >"$MODE"
"$REKEY" --state-dir "$STATE" execute "$LIST_REF" --capability "$CAPABILITY" \
  >"$WORKDIR/rotated-list.out"
grep -q '"total_count":1' "$WORKDIR/rotated-list.out"

python3 - "$PAYLOAD_ADD" "$PAYLOAD_REMOVE" "$WEBHOOK_SECRET" <<'PY'
import hashlib, hmac, json, pathlib, sys
add, remove, secret = sys.argv[1:]
def write(path, action, added, removed):
    raw=json.dumps({"action":action,"installation":{"id":818180},
                    "repositories_added":added,"repositories_removed":removed},
                   separators=(",", ":")).encode()
    pathlib.Path(path).write_bytes(raw)
repo={"id":818182,"full_name":"p6-owner/beta"}
write(add,"added",[repo],[])
write(remove,"removed",[],[repo])
PY
ADD_SIGNATURE="$(python3 -c 'import hashlib,hmac,pathlib,sys; print("sha256="+hmac.new(sys.argv[2].encode(),pathlib.Path(sys.argv[1]).read_bytes(),hashlib.sha256).hexdigest())' "$PAYLOAD_ADD" "$WEBHOOK_SECRET")"
REMOVE_SIGNATURE="$(python3 -c 'import hashlib,hmac,pathlib,sys; print("sha256="+hmac.new(sys.argv[2].encode(),pathlib.Path(sys.argv[1]).read_bytes(),hashlib.sha256).hexdigest())' "$PAYLOAD_REMOVE" "$WEBHOOK_SECRET")"
printf '%s\n' "$PASSWORD" | "$REKEY" --state-dir "$STATE" credential apply-github-webhook \
  "$CREDENTIAL_ID" --expected-version 3 --event installation_repositories \
  --delivery 11111111-1111-4111-8111-111111111111 --signature "$ADD_SIGNATURE" \
  --file "$PAYLOAD_ADD" --password-stdin >/dev/null
[[ "$(credential_version "$CREDENTIAL_ID")" == "4" ]]
REPLAY_RC=0
printf '%s\n' "$PASSWORD" | "$REKEY" --state-dir "$STATE" credential apply-github-webhook \
  "$CREDENTIAL_ID" --expected-version 3 --event installation_repositories \
  --delivery 11111111-1111-4111-8111-111111111111 --signature "$ADD_SIGNATURE" \
  --file "$PAYLOAD_ADD" --password-stdin >/dev/null 2>"$WORKDIR/replay.err" || REPLAY_RC=$?
[[ "$REPLAY_RC" == "2" && "$(credential_version "$CREDENTIAL_ID")" == "4" ]]
printf '%s\n' p6-webhook-list >"$MODE"
"$REKEY" --state-dir "$STATE" execute "$LIST_REF" --capability "$CAPABILITY" \
  >"$WORKDIR/webhook-list.out"
grep -q '"total_count":2' "$WORKDIR/webhook-list.out"

printf '%s\n' "$PASSWORD" | "$REKEY" --state-dir "$STATE" credential apply-github-webhook \
  "$CREDENTIAL_ID" --expected-version 4 --event installation_repositories \
  --delivery 22222222-2222-4222-8222-222222222222 --signature "$REMOVE_SIGNATURE" \
  --file "$PAYLOAD_REMOVE" --password-stdin >/dev/null
[[ "$(credential_version "$CREDENTIAL_ID")" == "5" ]]
INVALID_RC=0
printf '%s\n' "$PASSWORD" | "$REKEY" --state-dir "$STATE" credential rotate-github-app \
  "$CREDENTIAL_ID" --file "$INVALID_PROFILE" --password-stdin >/dev/null 2>"$WORKDIR/invalid.err" || INVALID_RC=$?
[[ "$INVALID_RC" == "2" && "$(credential_version "$CREDENTIAL_ID")" == "5" ]]

"$REKEY" --state-dir "$STATE" audit export --output "$WORKDIR/audit.jsonl" >/dev/null
rm "$KEY_ONE" "$KEY_ONE_DER" "$KEY_TWO" "$KEY_TWO_DER" "$KEY_TWO_PUBLIC" "$PROFILE" \
  "$KEY_ROTATION_PROFILE" "$ROTATED_PROFILE" "$INVALID_PROFILE" "$PAYLOAD_ADD" \
  "$PAYLOAD_REMOVE" "$ISSUE_BODY"
for canary in "$KEY_TWO_BASE64_CANARY" "$WEBHOOK_SECRET" "$TOKEN_CANARY" "$ISSUE_BODY_CANARY" "$CAPABILITY" \
  "$ADD_SIGNATURE" "$REMOVE_SIGNATURE"; do
  if rg -a -F --glob '!trace' -- "$canary" "$STATE" "$WORKDIR" >/dev/null; then
    echo "P6 secret/canary escaped: $canary" >&2
    exit 1
  fi
done
while IFS= read -r jwt_canary; do
  if rg -a -F --glob '!trace' -- "$jwt_canary" "$STATE" "$WORKDIR" >/dev/null; then
    echo "P6 JWT canary escaped" >&2
    exit 1
  fi
done < <(sed -n 's/^jwt\.canary=//p' "$TRACE" | sort -u)

printf '%s\n' "$PASSWORD" | "$REKEY" --state-dir "$STATE" shutdown --password-stdin >/dev/null
wait "$BROKER_PID"
BROKER_PID=""
echo "P6 GitHub App extension local acceptance passed"
