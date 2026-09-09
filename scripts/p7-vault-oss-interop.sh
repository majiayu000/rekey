#!/usr/bin/env bash
# P-07 Layer A: closed KV v2 and one-shot dynamic-lease profiles against a
# pinned HashiCorp Vault OSS binary. Screening stays production-strict; the
# fixture injects the Vault listen address after that screen. Unmodified
# rekeyd is never pointed at 127.0.0.1.
#
# Dynamic engine: Vault database secrets engine + ephemeral PostgreSQL.
# macOS is skip-by-OS. Ubuntu must install and run the pinned Vault binary.
set -euo pipefail

if [[ "$(uname -s)" != Linux ]]; then
  echo "p7-vault-oss-interop: skip-by-OS ($(uname -s)); Ubuntu CI must run this script" >&2
  exit 0
fi

command -v rg >/dev/null || {
  echo "p7-vault-oss-interop requires ripgrep (rg)" >&2
  exit 1
}
command -v docker >/dev/null || {
  echo "p7-vault-oss-interop requires docker for ephemeral PostgreSQL" >&2
  exit 1
}
command -v openssl >/dev/null || {
  echo "p7-vault-oss-interop requires openssl" >&2
  exit 1
}
command -v unzip >/dev/null || {
  echo "p7-vault-oss-interop requires unzip" >&2
  exit 1
}

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
REKEY="$ROOT/target/release/rekey"
REKEYD="$ROOT/target/release/rekeyd"
FIXTURE="$ROOT/target/release/examples/p7_vault_oss_fixture"
VAULT_VERSION="1.20.3"
PASSWORD="p7oss vault interop acceptance password"
RESOLVED_ONE="P7OSS-RESOLVED-VALUE-ONE-CANARY"
RESOLVED_TWO="P7OSS-RESOLVED-VALUE-TWO-CANARY"
SOURCE_CANARY="P7OSS-VAULT-SOURCE-TOKEN-CANARY"
PG_PASSWORD="p7oss-postgres-bootstrap"

cargo build --release -p rekey-cli --bin rekey -p rekey-broker --bin rekeyd
cargo build --release -p rekey-broker --example p7_vault_oss_fixture

WORKDIR="$(mktemp -d /tmp/rkp7oss.XXXXXX)"
STATE="$WORKDIR/state"
READY="$WORKDIR/ready"
TRACE="$WORKDIR/trace"
EXPECTED="$WORKDIR/expected-bearer"
PROFILE_KV_ONE="$WORKDIR/profile-kv-one.json"
PROFILE_KV_TWO="$WORKDIR/profile-kv-two.json"
PROFILE_KV_MISSING="$WORKDIR/profile-kv-missing.json"
PROFILE_KV_BAD_VERSION="$WORKDIR/profile-kv-bad-version.json"
PROFILE_KV_BAD_TOKEN="$WORKDIR/profile-kv-bad-token.json"
PROFILE_DYN="$WORKDIR/profile-dyn.json"
PROFILE_DYN_BAD="$WORKDIR/profile-dyn-bad.json"
ACTION_FILE="$WORKDIR/action.json"
REQUEST_BODY="$WORKDIR/request.json"
CA_PEM="$WORKDIR/ca.pem"
CA_DER="$WORKDIR/ca.der"
VAULT_BIN="$WORKDIR/vault"
BROKER_PID=""
VAULT_PID=""
PG_CONTAINER=""

cleanup() {
  if [[ -n "$BROKER_PID" ]]; then
    kill "$BROKER_PID" 2>/dev/null || true
    wait "$BROKER_PID" 2>/dev/null || true
  fi
  if [[ -n "$VAULT_PID" ]]; then
    kill "$VAULT_PID" 2>/dev/null || true
    wait "$VAULT_PID" 2>/dev/null || true
  fi
  if [[ -n "$PG_CONTAINER" ]]; then
    docker rm -f "$PG_CONTAINER" >/dev/null 2>&1 || true
  fi
  rm -rf "$WORKDIR"
}
failure() {
  local rc=$?
  [[ ! -f "$WORKDIR/broker.err" ]] || cat "$WORKDIR/broker.err" >&2
  [[ ! -f "$WORKDIR/vault.log" ]] || tail -80 "$WORKDIR/vault.log" >&2
  [[ ! -f "$TRACE" ]] || tail -80 "$TRACE" >&2
  echo "P7 Vault OSS interop failed at line $1 (exit $rc)" >&2
  exit "$rc"
}
trap cleanup EXIT
trap 'failure "$LINENO"' ERR

json_field() {
  python3 -c 'import json,sys; print(json.load(sys.stdin)[sys.argv[1]])' "$1"
}

install_vault() {
  local goarch
  case "$(uname -m)" in
    x86_64) goarch=amd64 ;;
    aarch64 | arm64) goarch=arm64 ;;
    *)
      echo "unsupported architecture: $(uname -m)" >&2
      exit 1
      ;;
  esac
  local base="https://releases.hashicorp.com/vault/${VAULT_VERSION}"
  local zip_name="vault_${VAULT_VERSION}_linux_${goarch}.zip"
  curl -fsSL -o "$WORKDIR/$zip_name" "$base/$zip_name"
  curl -fsSL -o "$WORKDIR/SHA256SUMS" "$base/vault_${VAULT_VERSION}_SHA256SUMS"
  (
    cd "$WORKDIR"
    grep " $zip_name\$" SHA256SUMS | sha256sum -c -
  )
  unzip -qo "$WORKDIR/$zip_name" -d "$WORKDIR"
  chmod 0755 "$VAULT_BIN"
  [[ "$("$VAULT_BIN" version | awk '{print $2}')" == "v${VAULT_VERSION}" ]]
}

make_tls() {
  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$WORKDIR/ca.key" >/dev/null 2>&1
  openssl req -new -x509 -key "$WORKDIR/ca.key" -out "$CA_PEM" -days 1 -subj "/CN=rekey-vault-oss-ca" >/dev/null
  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$WORKDIR/leaf.key" >/dev/null 2>&1
  openssl req -new -key "$WORKDIR/leaf.key" -out "$WORKDIR/leaf.csr" -subj "/CN=vault.test.local" >/dev/null
  printf '%s\n' \
    '[v3]' \
    'subjectAltName=DNS:vault.test.local,IP:127.0.0.1' \
    >"$WORKDIR/san.cnf"
  openssl x509 -req -in "$WORKDIR/leaf.csr" -CA "$CA_PEM" -CAkey "$WORKDIR/ca.key" \
    -CAcreateserial -out "$WORKDIR/leaf.pem" -days 1 -extfile "$WORKDIR/san.cnf" \
    -extensions v3 >/dev/null 2>&1
  openssl x509 -in "$CA_PEM" -outform DER -out "$CA_DER" >/dev/null
}

free_port() {
  python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()'
}

start_vault() {
  local port=$1
  cat >"$WORKDIR/vault.hcl" <<EOF
disable_mlock = true
storage "inmem" {}
listener "tcp" {
  address       = "127.0.0.1:${port}"
  tls_cert_file = "${WORKDIR}/leaf.pem"
  tls_key_file  = "${WORKDIR}/leaf.key"
}
EOF
  "$VAULT_BIN" server -config "$WORKDIR/vault.hcl" >"$WORKDIR/vault.log" 2>&1 &
  VAULT_PID=$!
  export VAULT_ADDR="https://127.0.0.1:${port}"
  export VAULT_CACERT="$CA_PEM"
  export VAULT_TLS_SERVER_NAME="vault.test.local"
  for _ in $(seq 1 150); do
    status_rc=0
    "$VAULT_BIN" status >/dev/null 2>&1 || status_rc=$?
    if [[ "$status_rc" -eq 0 || "$status_rc" -eq 2 ]]; then
      return 0
    fi
    sleep 0.1
  done
  echo "vault did not become reachable" >&2
  exit 1
}

init_vault() {
  local init
  init="$("$VAULT_BIN" operator init -key-shares=1 -key-threshold=1 -format=json)"
  local unseal
  unseal="$(printf '%s\n' "$init" | python3 -c 'import json,sys; print(json.load(sys.stdin)["unseal_keys_b64"][0])')"
  printf '%s\n' "$init" | python3 -c 'import json,sys; print(json.load(sys.stdin)["root_token"])' >"$WORKDIR/root-token"
  chmod 0600 "$WORKDIR/root-token"
  "$VAULT_BIN" operator unseal "$unseal" >/dev/null
  export VAULT_TOKEN
  VAULT_TOKEN="$(cat "$WORKDIR/root-token")"
}

setup_kv() {
  "$VAULT_BIN" secrets enable -path=secret kv-v2 >/dev/null
  local i
  for i in $(seq 1 6); do
    "$VAULT_BIN" kv put secret/agents/github token="placeholder-${i}" >/dev/null
  done
  "$VAULT_BIN" kv put secret/agents/github token="$RESOLVED_ONE" >/dev/null
  "$VAULT_BIN" kv put secret/agents/github token="$RESOLVED_TWO" >/dev/null
  "$VAULT_BIN" kv put secret/agents/missing other="not-the-token" >/dev/null
}

start_postgres() {
  local port=$1
  PG_CONTAINER="rekey-p7oss-pg-$$"
  docker run -d --name "$PG_CONTAINER" \
    -e POSTGRES_USER=vault \
    -e POSTGRES_PASSWORD="$PG_PASSWORD" \
    -e POSTGRES_DB=postgres \
    -p "127.0.0.1:${port}:5432" \
    postgres:16-alpine >/dev/null
  for _ in $(seq 1 60); do
    if docker exec "$PG_CONTAINER" pg_isready -U vault >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.5
  done
  echo "postgres did not become ready" >&2
  exit 1
}

setup_database_engine() {
  local pg_port=$1
  "$VAULT_BIN" secrets enable database >/dev/null
  "$VAULT_BIN" write database/config/rekey \
    plugin_name=postgresql-database-plugin \
    allowed_roles=agent-api-token \
    connection_url="postgresql://{{username}}:{{password}}@127.0.0.1:${pg_port}/postgres?sslmode=disable" \
    username="vault" \
    password="$PG_PASSWORD" >/dev/null
  "$VAULT_BIN" write database/roles/agent-api-token \
    db_name=rekey \
    creation_statements="CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}';" \
    default_ttl=60 \
    max_ttl=60 >/dev/null
}

start_fixture() {
  local ready=$1
  : >"$TRACE"
  printf '%s\n' "$2" >"$EXPECTED"
  "$FIXTURE" "$STATE" "$ready" "$TRACE" "127.0.0.1:${VAULT_PORT}" "$CA_DER" "$EXPECTED" \
    >"$WORKDIR/broker.out" 2>"$WORKDIR/broker.err" &
  BROKER_PID=$!
  for _ in $(seq 1 400); do
    [[ -f "$ready" && -S "$STATE/runtime/admin.sock" ]] && break
    sleep 0.025
  done
  [[ -f "$ready" && -S "$STATE/runtime/admin.sock" ]]
  printf '%s\n' "$PASSWORD" | "$REKEY" --state-dir "$STATE" unlock --password-stdin >/dev/null
}

stop_fixture() {
  if [[ -n "$BROKER_PID" ]]; then
    printf '%s\n' "$PASSWORD" | "$REKEY" --state-dir "$STATE" shutdown --password-stdin >/dev/null || true
    wait "$BROKER_PID" 2>/dev/null || true
    BROKER_PID=""
  fi
}

activate_policy() {
  local principal=$1
  local version=$2
  python3 - "$WORKDIR/policy-snapshot.json" "$ACTION_ID" "$principal" "$version" <<'PY'
import json, pathlib, sys, time, uuid
path, action, principal, version = sys.argv[1:]
binding={"action_id":action,"version":1,"resource":{"type":"p7oss-vault-action","id":action},
         "parameter_schema_id":"p7oss-vault/v1","parameter_schema":{"type":"object","additionalProperties":False,
         "required":["operation"],"properties":{"operation":{"const":"bounded"}}}}
rule={"id":str(uuid.uuid4()),"effect":"permit","principal_id":principal,"action_id":action,
      "version":1,"resource":binding["resource"],"parameters":{"kind":"any_validated"}}
pathlib.Path(path).write_text(json.dumps({"format_version":3,"version":int(version),
  "expires_at_ms":int(time.time()*1000)+600000,"approvers":[],"workload_identities":[],
  "bindings":[binding],"rules":[rule]}))
PY
  python3 "$ROOT/scripts/sign-test-policy.py" policy --key-dir "$WORKDIR/policy-key" \
    --snapshot "$WORKDIR/policy-snapshot.json" --bundle "$WORKDIR/policy.json" \
    --trust "$WORKDIR/policy-trust.json"
  if [[ "$version" == "1" ]]; then
    printf '%s\n' "$PASSWORD" | "$REKEY" --state-dir "$STATE" policy trust install \
      --file "$WORKDIR/policy-trust.json" --step-up-stdin >/dev/null
  fi
  printf '%s\n' "$PASSWORD" | "$REKEY" --state-dir "$STATE" policy activate \
    --file "$WORKDIR/policy.json" --step-up-stdin >/dev/null
}

leases_empty() {
  if "$VAULT_BIN" list -format=json sys/leases/lookup/database/creds/agent-api-token \
    >"$WORKDIR/leases.json" 2>"$WORKDIR/leases.err"; then
    echo "expected no outstanding database leases" >&2
    cat "$WORKDIR/leases.json" >&2
    exit 1
  fi
}

ROOT_TOKEN=""
install_vault
make_tls
VAULT_PORT="$(free_port)"
PG_PORT="$(free_port)"
start_vault "$VAULT_PORT"
init_vault
ROOT_TOKEN="$(cat "$WORKDIR/root-token")"
setup_kv
start_postgres "$PG_PORT"
setup_database_engine "$PG_PORT"

python3 - "$PROFILE_KV_ONE" "$PROFILE_KV_TWO" "$PROFILE_KV_MISSING" \
  "$PROFILE_KV_BAD_VERSION" "$PROFILE_KV_BAD_TOKEN" "$ROOT_TOKEN" \
  "$RESOLVED_ONE" "$RESOLVED_TWO" <<'PY'
import json, pathlib, sys
one, two, missing, bad_ver, bad_token, token, resolved_one, resolved_two = sys.argv[1:]
def kv(version, key="token", path="agents/github", vault_token=None):
    return {"credential_type":"vault-kv-v2-source-v1","origin":"https://vault.test.local",
            "mount":"secret","path":path,"key":key,"version":int(version),
            "vault_token":vault_token or token}
pathlib.Path(one).write_text(json.dumps(kv(7)))
pathlib.Path(two).write_text(json.dumps(kv(8)))
pathlib.Path(missing).write_text(json.dumps(kv(1, path="agents/missing")))
pathlib.Path(bad_ver).write_text(json.dumps(kv(99)))
pathlib.Path(bad_token).write_text(json.dumps(kv(7, vault_token="hvs.invalid-oss-token")))
PY
python3 - "$PROFILE_DYN" "$PROFILE_DYN_BAD" "$ROOT_TOKEN" <<'PY'
import json, pathlib, sys
one, bad, token = sys.argv[1:]
def dyn(vault_token):
    return {"credential_type":"vault-dynamic-source-v1","origin":"https://vault.test.local",
            "mount":"database","role":"agent-api-token","key":"password","vault_token":vault_token}
pathlib.Path(one).write_text(json.dumps(dyn(token)))
pathlib.Path(bad).write_text(json.dumps(dyn("hvs.invalid-oss-token")))
PY
printf '%s' '{"operation":"bounded"}' >"$REQUEST_BODY"

printf '%s\n' "$PASSWORD" | "$REKEYD" init --state-dir "$STATE" --password-stdin >/dev/null
start_fixture "$READY" "$RESOLVED_ONE"

CREDENTIAL_JSON="$(printf '%s\n' "$PASSWORD" | "$REKEY" --state-dir "$STATE" credential \
  add-vault-kv p7oss-kv --file "$PROFILE_KV_ONE" --password-stdin)"
CREDENTIAL_ID="$(printf '%s\n' "$CREDENTIAL_JSON" | json_field id)"

python3 - "$ACTION_FILE" "$CREDENTIAL_ID" <<'PY'
import json, pathlib, sys
path, credential = sys.argv[1:]
pathlib.Path(path).write_text(json.dumps({
  "name":"p7oss-source-action","credential_id":credential,"origin":"https://api.test.local",
  "method":"POST","exact_path":"/v1/things","auth_header":"authorization",
  "auth_prefix":"Bearer ","timeout_ms":8000,"request_max_bytes":1024,
  "allowed_extra_headers":[],"response_max_bytes":4096,
  "allowed_response_headers":["content-type"]}))
PY
ACTION_JSON="$(printf '%s\n' "$PASSWORD" | "$REKEY" --state-dir "$STATE" action create \
  --file "$ACTION_FILE" --password-stdin)"
ACTION_ID="$(printf '%s\n' "$ACTION_JSON" | json_field id)"
ACTION_REF="$ACTION_ID@1"
SESSION_JSON="$(printf '%s\n' "$PASSWORD" | "$REKEY" --state-dir "$STATE" session create \
  --action "$ACTION_REF" --ttl 10m --max-uses 20 --password-stdin)"
PRINCIPAL_ID="$(printf '%s\n' "$SESSION_JSON" | json_field principal_id)"
CAPABILITY="$(printf '%s\n' "$SESSION_JSON" | json_field capability_token)"
activate_policy "$PRINCIPAL_ID" 1

"$REKEY" --state-dir "$STATE" execute "$ACTION_REF" --capability "$CAPABILITY" \
  --body-file "$REQUEST_BODY" --content-type application/json >"$WORKDIR/kv-v1.out"
grep -q '"result":"p7oss-ok"' "$WORKDIR/kv-v1.out"
[[ "$(grep -c '^p7oss.action.ok$' "$TRACE")" == "1" ]]

printf '%s\n' "$PASSWORD" | "$REKEY" --state-dir "$STATE" credential rotate-vault-kv \
  "$CREDENTIAL_ID" --file "$PROFILE_KV_BAD_VERSION" --password-stdin >/dev/null
WRONG_RC=0
"$REKEY" --state-dir "$STATE" execute "$ACTION_REF" --capability "$CAPABILITY" \
  --body-file "$REQUEST_BODY" --content-type application/json >/dev/null 2>"$WORKDIR/wrong.err" || WRONG_RC=$?
[[ "$WRONG_RC" != "0" && "$(grep -c '^p7oss.action.ok$' "$TRACE")" == "1" ]]

printf '%s\n' "$PASSWORD" | "$REKEY" --state-dir "$STATE" credential rotate-vault-kv \
  "$CREDENTIAL_ID" --file "$PROFILE_KV_MISSING" --password-stdin >/dev/null
MISSING_RC=0
"$REKEY" --state-dir "$STATE" execute "$ACTION_REF" --capability "$CAPABILITY" \
  --body-file "$REQUEST_BODY" --content-type application/json >/dev/null 2>"$WORKDIR/missing.err" || MISSING_RC=$?
[[ "$MISSING_RC" != "0" && "$(grep -c '^p7oss.action.ok$' "$TRACE")" == "1" ]]

printf '%s\n' "$PASSWORD" | "$REKEY" --state-dir "$STATE" credential rotate-vault-kv \
  "$CREDENTIAL_ID" --file "$PROFILE_KV_BAD_TOKEN" --password-stdin >/dev/null
BAD_RC=0
"$REKEY" --state-dir "$STATE" execute "$ACTION_REF" --capability "$CAPABILITY" \
  --body-file "$REQUEST_BODY" --content-type application/json >/dev/null 2>"$WORKDIR/bad-token.err" || BAD_RC=$?
[[ "$BAD_RC" != "0" && "$(grep -c '^p7oss.action.ok$' "$TRACE")" == "1" ]]

printf '%s\n' "$PASSWORD" | "$REKEY" --state-dir "$STATE" credential rotate-vault-kv \
  "$CREDENTIAL_ID" --file "$PROFILE_KV_TWO" --password-stdin >/dev/null
printf '%s\n' "$RESOLVED_TWO" >"$EXPECTED"
"$REKEY" --state-dir "$STATE" execute "$ACTION_REF" --capability "$CAPABILITY" \
  --body-file "$REQUEST_BODY" --content-type application/json >"$WORKDIR/kv-v2.out"
grep -q '"result":"p7oss-ok"' "$WORKDIR/kv-v2.out"
[[ "$(grep -c '^p7oss.action.ok$' "$TRACE")" == "2" ]]

rg -F "$ROOT_TOKEN" "$WORKDIR/kv-v1.out" "$WORKDIR/kv-v2.out" && {
  echo "vault token reached agent output" >&2
  exit 1
}
rg -F "$RESOLVED_ONE" "$WORKDIR/kv-v1.out" "$WORKDIR/kv-v2.out" && {
  echo "resolved KV value reached agent output" >&2
  exit 1
}

stop_fixture
READY="$WORKDIR/dyn-ready"
start_fixture "$READY" "*"

DYN_JSON="$(printf '%s\n' "$PASSWORD" | "$REKEY" --state-dir "$STATE" credential \
  add-vault-dynamic p7oss-dyn --file "$PROFILE_DYN" --password-stdin)"
DYN_ID="$(printf '%s\n' "$DYN_JSON" | json_field id)"
python3 - "$ACTION_FILE" "$DYN_ID" <<'PY'
import json, pathlib, sys
path, credential = sys.argv[1:]
pathlib.Path(path).write_text(json.dumps({
  "name":"p7oss-dyn-action","credential_id":credential,"origin":"https://api.test.local",
  "method":"POST","exact_path":"/v1/things","auth_header":"authorization",
  "auth_prefix":"Bearer ","timeout_ms":8000,"request_max_bytes":1024,
  "allowed_extra_headers":[],"response_max_bytes":4096,
  "allowed_response_headers":["content-type"]}))
PY
DYN_ACTION_JSON="$(printf '%s\n' "$PASSWORD" | "$REKEY" --state-dir "$STATE" action create \
  --file "$ACTION_FILE" --password-stdin)"
DYN_ACTION_ID="$(printf '%s\n' "$DYN_ACTION_JSON" | json_field id)"
ACTION_ID="$DYN_ACTION_ID"
ACTION_REF="$DYN_ACTION_ID@1"
SESSION_JSON="$(printf '%s\n' "$PASSWORD" | "$REKEY" --state-dir "$STATE" session create \
  --action "$ACTION_REF" --ttl 10m --max-uses 10 --password-stdin)"
PRINCIPAL_ID="$(printf '%s\n' "$SESSION_JSON" | json_field principal_id)"
CAPABILITY="$(printf '%s\n' "$SESSION_JSON" | json_field capability_token)"
activate_policy "$PRINCIPAL_ID" 2

"$REKEY" --state-dir "$STATE" execute "$ACTION_REF" --capability "$CAPABILITY" \
  --body-file "$REQUEST_BODY" --content-type application/json >"$WORKDIR/dyn-ok.out"
grep -q '"result":"p7oss-ok"' "$WORKDIR/dyn-ok.out"
leases_empty

printf '%s\n' "wrong-expected-bearer" >"$EXPECTED"
printf '%s\n' "$PASSWORD" | "$REKEY" --state-dir "$STATE" credential rotate-vault-dynamic \
  "$DYN_ID" --file "$PROFILE_DYN" --password-stdin >/dev/null
FAIL_RC=0
"$REKEY" --state-dir "$STATE" execute "$ACTION_REF" --capability "$CAPABILITY" \
  --body-file "$REQUEST_BODY" --content-type application/json >/dev/null 2>"$WORKDIR/dyn-fail.err" || FAIL_RC=$?
[[ "$FAIL_RC" != "0" ]]
leases_empty

BAD_DYN_RC=0
printf '%s\n' "$PASSWORD" | "$REKEY" --state-dir "$STATE" credential rotate-vault-dynamic \
  "$DYN_ID" --file "$PROFILE_DYN_BAD" --password-stdin >/dev/null
printf '%s\n' "*" >"$EXPECTED"
"$REKEY" --state-dir "$STATE" execute "$ACTION_REF" --capability "$CAPABILITY" \
  --body-file "$REQUEST_BODY" --content-type application/json >/dev/null 2>"$WORKDIR/dyn-bad.err" || BAD_DYN_RC=$?
[[ "$BAD_DYN_RC" != "0" ]]
leases_empty

"$REKEY" --state-dir "$STATE" audit export --output "$WORKDIR/audit.jsonl" >/dev/null
python3 - "$WORKDIR/audit.jsonl" "$ROOT_TOKEN" "$RESOLVED_ONE" "$RESOLVED_TWO" "$SOURCE_CANARY" <<'PY'
import json, pathlib, sys
path, *needles = sys.argv[1:]
text = pathlib.Path(path).read_text()
for needle in needles:
    assert needle not in text, needle
rows=[json.loads(line) for line in text.splitlines() if line.strip()]
events=[row["event_type"] for row in rows if "event_type" in row]
assert "execution.started" in events
assert "execution.finished" in events
assert "execution.blocked" in events
PY

rg -F "$ROOT_TOKEN" "$WORKDIR/dyn-ok.out" "$WORKDIR/broker.out" "$WORKDIR/broker.err" && {
  echo "vault token reached logs or agent output" >&2
  exit 1
}

printf '%s\n' "$PASSWORD" | "$REKEY" --state-dir "$STATE" shutdown --password-stdin >/dev/null
BROKER_PID=""
echo "p7-vault-oss-interop: PASS"
echo "p7-vault-oss-interop: vault=${VAULT_VERSION} engine=database+postgres"
echo "p7-vault-oss-interop: limitation=local-ca-fixture,not-field-validated,not-private-network"
