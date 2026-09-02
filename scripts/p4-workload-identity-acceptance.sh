#!/usr/bin/env bash
# P-04 release-process acceptance: four offline workload JWT profiles, real
# fixed-Action execution, replay/tamper/expiry denial, rotation, and canaries.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
REKEY="$ROOT/target/release/rekey"
REKEYD="$ROOT/target/release/rekeyd"
FIXTURE="$ROOT/target/release/examples/p1_policy_fixture"
SIGNER="$ROOT/scripts/sign-test-policy.py"
PASSWORD="p4 acceptance horse battery staple"
SECRET="P4-WORKLOAD-CREDENTIAL-CANARY"
ISSUER="https://issuer.example"
AUDIENCE="rekey://p4-acceptance"
KID="p4-workload-key"

command -v openssl >/dev/null || { echo "openssl is required"; exit 1; }
command -v python3 >/dev/null || { echo "python3 is required"; exit 1; }
command -v rg >/dev/null || { echo "ripgrep is required"; exit 1; }

cargo build --release -p rekey-cli --bin rekey -p rekey-broker --bin rekeyd
cargo build --release -p rekey-broker --example p1_policy_fixture

WORKDIR="$(mktemp -d /tmp/rkp4.XXXXXX)"
STATE="$WORKDIR/state"
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

write_action() {
  python3 - "$WORKDIR/action.json" "$1" "$2" <<'PY'
import json, pathlib, sys
pathlib.Path(sys.argv[1]).write_text(json.dumps({
    "name": "p4-workload",
    "credential_id": sys.argv[2],
    "origin": f"https://api.test.local:{sys.argv[3]}",
    "method": "POST",
    "exact_path": "/v1/workload",
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
    "$1" "$WORKDIR/workload-key.json" <<'PY'
import json, pathlib, sys, time, uuid
path, action, action_version, policy_version, key_path = sys.argv[1:]
key = json.loads(pathlib.Path(key_path).read_text())
subjects = [
    ("oidc", {"kind": "oidc", "subject": "service:build"}),
    ("spiffe", {"kind": "spiffe-jwt-svid", "spiffe_id": "spiffe://issuer.example/workload/api"}),
    ("kubernetes", {"kind": "kubernetes-service-account", "namespace": "prod", "service_account": "api"}),
    ("ci", {"kind": "ci-cloud", "subject": "repo:owner/name:ref:refs/heads/main"}),
]
resource = {"type": "fixed-http-action", "id": action}
identities = []
rules = []
for _, profile in subjects:
    principal = str(uuid.uuid4())
    identities.append({
        "principal_id": principal,
        "issuer": "https://issuer.example",
        "audiences": ["rekey://p4-acceptance"],
        "max_token_age_ms": 900000,
        "profile": profile,
        "keys": [key],
    })
    rules.append({
        "id": str(uuid.uuid4()),
        "effect": "permit",
        "principal_id": principal,
        "action_id": action,
        "version": int(action_version),
        "resource": resource,
        "parameters": {"kind": "any_validated"},
    })
snapshot = {
    "format_version": 3,
    "version": int(policy_version),
    "expires_at_ms": int(time.time() * 1000) + 600000,
    "approvers": [],
    "workload_identities": identities,
    "bindings": [{
        "action_id": action,
        "version": int(action_version),
        "resource": resource,
        "parameter_schema_id": "p4-message/v1",
        "parameter_schema": {
            "type": "object",
            "required": ["message"],
            "properties": {"message": {"type": "string"}},
            "additionalProperties": False,
        },
    }],
    "rules": rules,
}
pathlib.Path(path).write_text(json.dumps(snapshot))
PY
}

sign_and_activate_policy() {
  python3 "$SIGNER" policy --key-dir "$WORKDIR/policy-key" \
    --snapshot "$WORKDIR/policy-snapshot.json" --bundle "$WORKDIR/policy-bundle.json" \
    --trust "$WORKDIR/policy-trust.json"
  printf '%s\n' "$PASSWORD" | "$REKEY" --state-dir "$STATE" policy trust install \
    --file "$WORKDIR/policy-trust.json" --step-up-stdin >/dev/null
  printf '%s\n' "$PASSWORD" | "$REKEY" --state-dir "$STATE" policy activate \
    --file "$WORKDIR/policy-bundle.json" --step-up-stdin >/dev/null
}

write_token() {
  local subject="$1"
  local jti="$2"
  local validity="$3"
  local destination="$4"
  python3 "$SIGNER" workload-token --key-dir "$WORKDIR/workload-key" --kid "$KID" \
    --issuer "$ISSUER" --subject "$subject" --audience "$AUDIENCE" --jti "$jti" \
    --now "$(date +%s)" --validity-seconds "$validity" >"$destination"
}

mint() {
  "$REKEY" --state-dir "$STATE" session create --action "$action_ref" \
    --ttl 10m --max-uses 5 --workload-token-stdin <"$1"
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
credential="$(printf '%s\n%s\n' "$PASSWORD" "$SECRET" | "$REKEY" --state-dir "$STATE" \
  credential add p4-workload --stdin-secrets)"
credential_id="$(printf '%s\n' "$credential" | json_field id)"
write_action "$credential_id" "$PORT"
action="$(printf '%s\n' "$PASSWORD" | "$REKEY" --state-dir "$STATE" action create \
  --file "$WORKDIR/action.json" --password-stdin)"
action_id="$(printf '%s\n' "$action" | json_field id)"
action_version="$(printf '%s\n' "$action" | json_field version)"
action_ref="${action_id}@${action_version}"
python3 "$SIGNER" workload-key --key-dir "$WORKDIR/workload-key" --kid "$KID" \
  >"$WORKDIR/workload-key.json"
write_policy 1
sign_and_activate_policy

subjects=(
  "service:build"
  "spiffe://issuer.example/workload/api"
  "system:serviceaccount:prod:api"
  "repo:owner/name:ref:refs/heads/main"
)
first_capability=""
for index in "${!subjects[@]}"; do
  token_path="$WORKDIR/token-$index.jwt"
  write_token "${subjects[$index]}" "p4-jti-$index" 600 "$token_path"
  created="$(mint "$token_path")"
  if [[ "$index" -eq 0 ]]; then
    first_capability="$(printf '%s\n' "$created" | json_field capability_token)"
  fi
done

printf '%s\n' '{"message":"workload"}' >"$WORKDIR/request.json"
printf '%s\n' "$first_capability" | "$REKEY" --state-dir "$STATE" execute "$action_ref" \
  --capability - --body-file "$WORKDIR/request.json" --content-type application/json \
  | rg -q '"ok":true'
[[ "$(tr -d '\n' <"$HITS")" -ge 1 ]]

expect_exit 4 mint "$WORKDIR/token-0.jwt"
cp "$WORKDIR/token-1.jwt" "$WORKDIR/tampered.jwt"
python3 - "$WORKDIR/tampered.jwt" <<'PY'
import pathlib, sys
path = pathlib.Path(sys.argv[1])
token = bytearray(path.read_bytes())
token[-2] = ord("A") if token[-2] != ord("A") else ord("B")
path.write_bytes(token)
PY
expect_exit 4 mint "$WORKDIR/tampered.jwt"
write_token "service:build" "p4-expired" 1 "$WORKDIR/expired.jwt"
sleep 2
expect_exit 4 mint "$WORKDIR/expired.jwt"

write_policy 2
sign_and_activate_policy
# Positional parameters are expanded by the nested bash process.
# shellcheck disable=SC2016
expect_exit 4 bash -c 'printf "%s\n" "$1" | "$2" --state-dir "$3" execute "$4" --capability - --body-file "$5" --content-type application/json' \
  _ "$first_capability" "$REKEY" "$STATE" "$action_ref" "$WORKDIR/request.json"

"$REKEY" --state-dir "$STATE" audit list --limit 100 >"$WORKDIR/audit.json"
"$REKEY" --state-dir "$STATE" audit export --output "$WORKDIR/audit.jsonl" >/dev/null
rg -q 'workload-attested' "$WORKDIR/audit.json"
token_canary="$(tr -d '\n' <"$WORKDIR/token-0.jwt")"
signature_canary="${token_canary##*.}"
for canary in "$SECRET" "p4-jti-0" "$first_capability" "$token_canary" "$signature_canary"; do
  if rg -aF -- "$canary" "$STATE" "$WORKDIR/broker.out" "$WORKDIR/broker.err" \
    "$WORKDIR/audit.json" "$WORKDIR/audit.jsonl"; then
    echo "sensitive workload material leaked: $canary"
    exit 1
  fi
done
if rg -aF "service:build" "$WORKDIR/broker.out" "$WORKDIR/broker.err" \
  "$WORKDIR/audit.json" "$WORKDIR/audit.jsonl"; then
  echo "external workload subject leaked outside signed policy state"
  exit 1
fi

printf '%s\n' "$PASSWORD" | "$REKEY" --state-dir "$STATE" shutdown --password-stdin >/dev/null
wait "$BROKER_PID"
BROKER_PID=""
echo "P-04 workload identity acceptance passed"
