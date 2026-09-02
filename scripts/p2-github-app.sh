#!/usr/bin/env bash
# P2.1 local black-box acceptance: release CLI/daemon bootstrap, real broker
# dual UDS + SQLite, and a local CA/TLS GitHub App exchange/resource/revoke chain.
set -euo pipefail

command -v rg >/dev/null || {
  echo "p2-github-app requires ripgrep (rg)" >&2
  exit 1
}

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
REKEY="$ROOT/target/release/rekey"
REKEYD="$ROOT/target/release/rekeyd"
FIXTURE="$ROOT/target/release/examples/p2_github_app_fixture"
PASSWORD="p2 github app acceptance password"
TOKEN_CANARY="P2-INSTALLATION-TOKEN-CANARY"
STATELESS_TOKEN_CANARY="P2-STATELESS-INSTALLATION-TOKEN-CANARY"

cargo build --release -p rekey-cli --bin rekey -p rekey-broker --bin rekeyd
cargo build --release -p rekey-broker --example p2_github_app_fixture

WORKDIR="$(mktemp -d /tmp/rkp2github.XXXXXX)"
STATE="$WORKDIR/state"
READY="$WORKDIR/ready"
MODE="$WORKDIR/mode"
TRACE="$WORKDIR/trace"
PROFILE="$WORKDIR/github-app.json"
INVALID_PROFILE="$WORKDIR/github-app-invalid.json"
LATE_INVALID_KEY_PROFILE="$WORKDIR/github-app-late-invalid-key.json"
PRIVATE_KEY="$WORKDIR/github-app-key.pem"
PRIVATE_KEY_DER="$WORKDIR/github-app-key.der"
PUBLIC_KEY_DER="$WORKDIR/github-app-public.der"
BROKER_PID=""
DISCONNECT_PID=""
cleanup() {
  if [[ -n "$DISCONNECT_PID" ]]; then
    kill "$DISCONNECT_PID" 2>/dev/null || true
    wait "$DISCONNECT_PID" 2>/dev/null || true
  fi
  if [[ -n "$BROKER_PID" ]]; then
    kill "$BROKER_PID" 2>/dev/null || true
    wait "$BROKER_PID" 2>/dev/null || true
  fi
  rm -rf "$WORKDIR"
}
failure() {
  local rc=$?
  [[ ! -f "$WORKDIR/success.err" ]] || cat "$WORKDIR/success.err" >&2
  [[ ! -f "$WORKDIR/disconnected-agent.err" ]] || cat "$WORKDIR/disconnected-agent.err" >&2
  [[ ! -f "$WORKDIR/broker.err" ]] || cat "$WORKDIR/broker.err" >&2
  [[ ! -f "$TRACE" ]] || tail -80 "$TRACE" >&2
  echo "P2 GitHub acceptance failed at line $1 (exit $rc)" >&2
  exit "$rc"
}
trap cleanup EXIT
trap 'failure "$LINENO"' ERR

json_field() {
  python3 -c 'import json,sys; print(json.load(sys.stdin)[sys.argv[1]])' "$1"
}

pid_running() {
  local pid="$1" state
  kill -0 "$pid" 2>/dev/null || return 1
  state="$(ps -o stat= -p "$pid" 2>/dev/null || true)"
  [[ -n "$state" && "$state" != Z* ]]
}

wait_pid_bounded() {
  local pid="$1" seconds="$2" ticks
  ticks=$((seconds * 40))
  for _ in $(seq 1 "$ticks"); do
    pid_running "$pid" || return 0
    sleep 0.025
  done
  return 1
}

trace_count() {
  grep -c "^$1$" "$TRACE" 2>/dev/null || true
}

fixed_string_scan() {
  local needle="$1" rc
  shift
  if rg -a -F --glob '!trace' --glob '!restored-trace' -- "$needle" "$@" >/dev/null; then
    return 0
  else
    rc=$?
    return "$rc"
  fi
}

assert_secret_absent() {
  local label="$1" needle="$2" rc=0
  fixed_string_scan "$needle" "$STATE" "$WORKDIR" || rc=$?
  case "$rc" in
    0)
      echo "$label leaked into Agent-visible or durable output" >&2
      return 1
      ;;
    1) return 0 ;;
    *)
      echo "$label scan failed with rg exit $rc" >&2
      return "$rc"
      ;;
  esac
}

unique_jwt_canaries() {
  awk '
    /^jwt\.canary=/ {
      canary = substr($0, length("jwt.canary=") + 1)
      if (!seen[canary]++) print canary
    }
  ' "$1"
}

assert_all_jwt_canaries_absent() {
  local trace="$1" label="$2" canaries canary producer_rc=0
  [[ -f "$trace" ]] || {
    echo "$label trace is missing: $trace" >&2
    return 1
  }
  canaries="$(unique_jwt_canaries "$trace")" || producer_rc=$?
  if [[ "$producer_rc" -ne 0 ]]; then
    echo "$label producer failed with exit $producer_rc" >&2
    return "$producer_rc"
  fi
  [[ -n "$canaries" ]] || {
    echo "$label trace contains no JWT canaries" >&2
    return 1
  }
  while IFS= read -r canary; do
    [[ "$canary" =~ ^[A-Za-z0-9_-]{32}$ ]] || {
      echo "$label has malformed JWT canary" >&2
      return 1
    }
    assert_secret_absent "$label" "$canary"
  done <<<"$canaries"
}

assert_raw_private_key_absent() {
  local restored_trace="${RESTORED_TRACE:-}"
  python3 - "$PRIVATE_KEY_RAW_CANARY_HEX" "$STATE" "$WORKDIR" \
    "$TRACE" "$restored_trace" "$PROFILE" "$INVALID_PROFILE" \
    "$LATE_INVALID_KEY_PROFILE" "$PRIVATE_KEY" "$PRIVATE_KEY_DER" <<'PY'
import pathlib, sys

needle = bytes.fromhex(sys.argv[1])
roots = [pathlib.Path(value) for value in sys.argv[2:4]]
excluded = {pathlib.Path(value).resolve() for value in sys.argv[4:] if value}
seen = set()
for root in roots:
    for path in [root, *root.rglob("*")]:
        try:
            resolved = path.resolve()
            if resolved in seen or resolved in excluded or not path.is_file():
                continue
            seen.add(resolved)
            data = path.read_bytes()
        except OSError as error:
            raise SystemExit(f"raw private-key scan failed for {path}: {error}")
        if needle in data:
            raise SystemExit(f"raw private-key canary leaked into {path}")
PY
}

expect_failure() {
  local mode="$1"
  local expected="$2"
  printf '%s\n' "$mode" >"$MODE"
  set +e
  "$REKEY" --state-dir "$STATE" execute "$ACTION_REF" --capability "$CAPABILITY" \
    >"$WORKDIR/$mode.out" 2>"$WORKDIR/$mode.err"
  local rc=$?
  set -e
  [[ "$rc" -eq "$expected" ]] || {
    echo "$mode: expected exit $expected, got $rc"
    cat "$WORKDIR/$mode.err"
    exit 1
  }
  [[ ! -s "$WORKDIR/$mode.out" ]] || {
    echo "$mode: Agent received response bytes on a failed execution"
    exit 1
  }
}

RG_SELFTEST="$WORKDIR/rg-leading-hyphen-self-test"
printf '%s\n' '-jwt-canary' >"$RG_SELFTEST"
RG_SELFTEST_RC=0
fixed_string_scan '-jwt-canary' "$RG_SELFTEST" || RG_SELFTEST_RC=$?
[[ "$RG_SELFTEST_RC" -eq 0 ]] || {
  echo "hyphen-leading fixed-string scan self-test failed with exit $RG_SELFTEST_RC" >&2
  exit 1
}
rm "$RG_SELFTEST"

JWT_PRODUCER_SELFTEST_INPUT="$WORKDIR/missing-jwt-producer-input"
JWT_PRODUCER_SELFTEST_OUTPUT=""
JWT_PRODUCER_SELFTEST_RC=0
JWT_PRODUCER_SELFTEST_OUTPUT="$(
  unique_jwt_canaries "$JWT_PRODUCER_SELFTEST_INPUT" 2>/dev/null
)" || JWT_PRODUCER_SELFTEST_RC=$?
[[ "$JWT_PRODUCER_SELFTEST_RC" -ne 0 && -z "$JWT_PRODUCER_SELFTEST_OUTPUT" ]] || {
  echo "JWT canary producer failure self-test did not propagate a nonzero exit" >&2
  exit 1
}

printf '%s\n' "$PASSWORD" | "$REKEYD" init --state-dir "$STATE" --password-stdin >/dev/null
openssl genrsa -traditional -out "$PRIVATE_KEY" 2048 >/dev/null 2>&1
openssl rsa -in "$PRIVATE_KEY" -RSAPublicKey_out -outform DER -out "$PUBLIC_KEY_DER" \
  >/dev/null 2>&1
openssl rsa -in "$PRIVATE_KEY" -traditional -outform DER -out "$PRIVATE_KEY_DER" \
  >/dev/null 2>&1
python3 - "$PROFILE" "$PRIVATE_KEY_DER" <<'PY'
import base64, json, pathlib, sys
pathlib.Path(sys.argv[1]).write_text(json.dumps({
    "credential_type": "github-app-installation-v1",
    "client_id": "Iv1.8a61f9b3a7aba766",
    "app_id": 424242,
    "installation_id": 515151,
    "repository_id": 616161,
    "private_key_pkcs1_der_base64": base64.b64encode(pathlib.Path(sys.argv[2]).read_bytes()).decode()
}))
PY
python3 - "$PROFILE" "$INVALID_PROFILE" "$LATE_INVALID_KEY_PROFILE" <<'PY'
import json, pathlib, sys
profile = json.load(open(sys.argv[1]))
profile["unexpected"] = "must-be-rejected"
pathlib.Path(sys.argv[2]).write_text(json.dumps(profile))
profile.pop("unexpected")
encoded = profile["private_key_pkcs1_der_base64"]
position = len(encoded.rstrip("=")) - 1
profile["private_key_pkcs1_der_base64"] = encoded[:position] + "!" + encoded[position + 1:]
large_profile = json.dumps(profile)
target_size = 60 * 1024
if len(large_profile) >= target_size:
    raise SystemExit("fixture profile unexpectedly exceeds large-profile target")
pathlib.Path(sys.argv[3]).write_text(large_profile + " " * (target_size - len(large_profile)))
PY
PRIVATE_KEY_CANARIES="$(python3 - "$PRIVATE_KEY_DER" "$PUBLIC_KEY_DER" <<'PY'
import base64, pathlib, sys

private = pathlib.Path(sys.argv[1]).read_bytes()
public = pathlib.Path(sys.argv[2]).read_bytes()
window_size = 24
first = ((len(private) // 2) + 2) // 3 * 3
for start in range(first, len(private) - window_size + 1, 3):
    window = private[start:start + window_size]
    if window not in public:
        encoded = base64.b64encode(window).decode()
        if encoded not in base64.b64encode(private).decode():
            raise SystemExit("aligned private window missing from base64 profile")
        print(f"{window.hex()}:{encoded}")
        break
else:
    raise SystemExit("no private-only PKCS#1 DER window found")
PY
)"
PRIVATE_KEY_RAW_CANARY_HEX="${PRIVATE_KEY_CANARIES%%:*}"
PRIVATE_KEY_BASE64_CANARY="${PRIVATE_KEY_CANARIES#*:}"
[[ "$PRIVATE_KEY_RAW_CANARY_HEX" =~ ^[0-9a-f]{48}$ ]]
[[ ${#PRIVATE_KEY_BASE64_CANARY} -eq 32 ]]
rm "$PRIVATE_KEY" "$PRIVATE_KEY_DER"
printf '%s\n' success >"$MODE"
"$FIXTURE" "$STATE" "$READY" "$MODE" "$TRACE" "$PUBLIC_KEY_DER" \
  >"$WORKDIR/broker.out" 2>"$WORKDIR/broker.err" &
BROKER_PID=$!
for _ in $(seq 1 400); do
  [[ -f "$READY" && -S "$STATE/runtime/admin.sock" ]] && break
  sleep 0.025
done
[[ -f "$READY" && -S "$STATE/runtime/admin.sock" ]] || {
  echo "P2 GitHub fixture did not start"
  cat "$WORKDIR/broker.err"
  exit 1
}
printf '%s\n' "$PASSWORD" | "$REKEY" --state-dir "$STATE" unlock --password-stdin >/dev/null
WRONG_PROOF_RC=0
printf '%s\n' "definitely-wrong-password" | "$REKEY" --state-dir "$STATE" credential \
  add-github-app wrong-proof --file "$LATE_INVALID_KEY_PROFILE" --password-stdin \
  >"$WORKDIR/wrong-proof.out" 2>"$WORKDIR/wrong-proof.err" || WRONG_PROOF_RC=$?
[[ "$WRONG_PROOF_RC" -eq 3 && ! -s "$WORKDIR/wrong-proof.out" ]] || {
  echo "wrong step-up proof did not fail before GitHub RSA validation"
  exit 1
}
LATE_INVALID_RC=0
printf '%s\n' "$PASSWORD" | "$REKEY" --state-dir "$STATE" credential \
  add-github-app late-invalid-key --file "$LATE_INVALID_KEY_PROFILE" --password-stdin \
  >"$WORKDIR/late-invalid.out" 2>"$WORKDIR/late-invalid.err" || LATE_INVALID_RC=$?
[[ "$LATE_INVALID_RC" -eq 2 && ! -s "$WORKDIR/late-invalid.out" ]] || {
  echo "late-invalid base64 was not rejected after valid step-up"
  exit 1
}
INVALID_ADD_RC=0
printf '%s\n' "$PASSWORD" | "$REKEY" --state-dir "$STATE" credential \
  add-github-app invalid-github --file "$INVALID_PROFILE" --password-stdin \
  >"$WORKDIR/invalid-add.out" 2>"$WORKDIR/invalid-add.err" || INVALID_ADD_RC=$?
[[ "$INVALID_ADD_RC" -eq 2 && ! -s "$WORKDIR/invalid-add.out" ]] || {
  echo "invalid GitHub profile was not rejected before storage"
  exit 1
}
CREDENTIAL_JSON="$(printf '%s\n' "$PASSWORD" | "$REKEY" --state-dir "$STATE" credential \
  add-github-app p2-github --file "$PROFILE" --password-stdin)"
CREDENTIAL_ID="$(printf '%s\n' "$CREDENTIAL_JSON" | json_field id)"
[[ "$(printf '%s\n' "$CREDENTIAL_JSON" | json_field kind)" == "github-app-installation" ]]
ROTATE_RC=0
printf '%s\n%s\n' "$PASSWORD" "opaque-overwrite" | "$REKEY" --state-dir "$STATE" credential \
  rotate "$CREDENTIAL_ID" --stdin-secrets >"$WORKDIR/rotate.out" 2>"$WORKDIR/rotate.err" || ROTATE_RC=$?
[[ "$ROTATE_RC" -eq 2 && ! -s "$WORKDIR/rotate.out" ]] || {
  echo "generic rotate did not reject GitHub App credential"
  exit 1
}
rm "$PROFILE" "$INVALID_PROFILE" "$LATE_INVALID_KEY_PROFILE"

python3 - "$WORKDIR/action.json" "$CREDENTIAL_ID" <<'PY'
import json, pathlib, sys
pathlib.Path(sys.argv[1]).write_text(json.dumps({
    "name": "github-installation-repositories",
    "credential_id": sys.argv[2],
    "origin": "https://api.github.com",
    "method": "GET",
    "exact_path": "/installation/repositories",
    "auth_header": "authorization",
    "auth_prefix": "Bearer ",
    "timeout_ms": 5000,
    "request_max_bytes": 1,
    "allowed_extra_headers": [],
    "response_max_bytes": 262144,
    "allowed_response_headers": ["content-type"]
}))
PY
ACTION_JSON="$(printf '%s\n' "$PASSWORD" | "$REKEY" --state-dir "$STATE" action create \
  --file "$WORKDIR/action.json" --password-stdin)"
ACTION_ID="$(printf '%s\n' "$ACTION_JSON" | json_field id)"
ACTION_VERSION="$(printf '%s\n' "$ACTION_JSON" | json_field version)"
ACTION_REF="$ACTION_ID@$ACTION_VERSION"
SESSION_JSON="$(printf '%s\n' "$PASSWORD" | "$REKEY" --state-dir "$STATE" session create \
  --action "$ACTION_REF" --ttl 10m --max-uses 20 --password-stdin)"
PRINCIPAL_ID="$(printf '%s\n' "$SESSION_JSON" | json_field principal_id)"
CAPABILITY="$(printf '%s\n' "$SESSION_JSON" | json_field capability_token)"

python3 - "$WORKDIR/policy-snapshot.json" "$ACTION_ID" "$ACTION_VERSION" "$PRINCIPAL_ID" <<'PY'
import json, pathlib, sys, time, uuid
path, action, version, principal = sys.argv[1:]
resource = {"type": "github-installation-repositories", "id": action}
binding = {"action_id": action, "version": int(version), "resource": resource,
    "parameter_schema_id": "github-installation-repositories/v1",
    "parameter_schema": {"type": "null"}}
rule = {"id": str(uuid.uuid4()), "effect": "permit", "principal_id": principal,
    "action_id": action, "version": int(version), "resource": resource,
    "parameters": {"kind": "any_validated"}}
pathlib.Path(path).write_text(json.dumps({"format_version": 3, "version": 1,
    "expires_at_ms": int(time.time() * 1000) + 600000,
    "approvers": [], "workload_identities": [], "bindings": [binding], "rules": [rule]}))
PY
python3 "$ROOT/scripts/sign-test-policy.py" policy --key-dir "$WORKDIR/policy-key" \
  --snapshot "$WORKDIR/policy-snapshot.json" --bundle "$WORKDIR/policy.json" \
  --trust "$WORKDIR/policy-trust.json"
printf '%s\n' "$PASSWORD" | "$REKEY" --state-dir "$STATE" policy trust install \
  --file "$WORKDIR/policy-trust.json" --step-up-stdin >/dev/null
printf '%s\n' "$PASSWORD" | "$REKEY" --state-dir "$STATE" policy activate \
  --file "$WORKDIR/policy.json" --step-up-stdin >/dev/null

printf '%s\n' success >"$MODE"
"$REKEY" --state-dir "$STATE" execute "$ACTION_REF" --capability "$CAPABILITY" \
  >"$WORKDIR/success.out" 2>"$WORKDIR/success.err"
grep -q '"id":616161' "$WORKDIR/success.out"

printf '%s\n' stateless-token >"$MODE"
"$REKEY" --state-dir "$STATE" execute "$ACTION_REF" --capability "$CAPABILITY" \
  >"$WORKDIR/stateless-token.out" 2>"$WORKDIR/stateless-token.err"
grep -q '"id":616161' "$WORKDIR/stateless-token.out"

printf '%s\n' provider-extra >"$MODE"
"$REKEY" --state-dir "$STATE" execute "$ACTION_REF" --capability "$CAPABILITY" \
  >"$WORKDIR/provider-extra.out" 2>"$WORKDIR/provider-extra.err"
grep -q '"id":616161' "$WORKDIR/provider-extra.out"
if rg -q 'debug_hex|50322d494e5354414c4c4154494f4e2d544f4b454e2d43414e415259' \
  "$WORKDIR/provider-extra.out"; then
  echo "provider-controlled extra field escaped the typed connector" >&2
  exit 1
fi

expect_failure bad-scope 6
expect_failure malformed-scope 6
expect_failure exchange-error 6
expect_failure exchange-status-token 6
expect_failure trailing-token 6
expect_failure duplicate-token 6
expect_failure resource-error 6
expect_failure wrong-repository 6
expect_failure revoke-error 6
printf '%s\n' reflect-token >"$MODE"
"$REKEY" --state-dir "$STATE" execute "$ACTION_REF" --capability "$CAPABILITY" \
  >"$WORKDIR/reflect-token.out" 2>"$WORKDIR/reflect-token.err"
grep -q '"id":616161' "$WORKDIR/reflect-token.out"
if rg -q "$TOKEN_CANARY" "$WORKDIR/reflect-token.out"; then
  echo "typed connector leaked a provider-controlled secret field" >&2
  exit 1
fi
DEADLINE_STARTED="$(python3 -c 'import time; print(time.monotonic())')"
expect_failure deadline-resource 6
DEADLINE_ELAPSED="$(python3 - "$DEADLINE_STARTED" <<'PY'
import sys, time
print(time.monotonic() - float(sys.argv[1]))
PY
)"
python3 - "$DEADLINE_ELAPSED" <<'PY'
import sys
if float(sys.argv[1]) >= 5.5:
    raise SystemExit("GitHub effect exceeded total deadline bound")
PY

# Cancellation after exchange must keep the in-flight permit until the
# resource finishes and the remote token is revoked.
printf '%s\n' slow-resource >"$MODE"
RESOURCE_BEFORE="$(grep -c '^resource.ok$' "$TRACE" || true)"
REVOKE_BEFORE="$(grep -c '^revoke.ok$' "$TRACE" || true)"
"$REKEY" --state-dir "$STATE" execute "$ACTION_REF" --capability "$CAPABILITY" \
  >"$WORKDIR/slow-resource.out" 2>"$WORKDIR/slow-resource.err" &
SLOW_PID=$!
for _ in $(seq 1 200); do
  [[ "$(grep -c '^resource.ok$' "$TRACE" || true)" -ge "$((RESOURCE_BEFORE + 1))" ]] && break
  sleep 0.01
done
[[ "$(grep -c '^resource.ok$' "$TRACE" || true)" -ge "$((RESOURCE_BEFORE + 1))" ]]
if ! "$REKEY" --state-dir "$STATE" lock >"$WORKDIR/lock.out" 2>"$WORKDIR/lock.err"; then
  echo "lock did not wait for the cancellation-shielded GitHub effect" >&2
  cat "$WORKDIR/lock.err" >&2
  exit 1
fi
wait "$SLOW_PID"
grep -q '"id":616161' "$WORKDIR/slow-resource.out"
[[ "$(grep -c '^revoke.ok$' "$TRACE" || true)" -eq "$((REVOKE_BEFORE + 1))" ]] || {
  echo "lock returned before the installation token was revoked" >&2
  exit 1
}

# Restart from the completed Locked state so the signal/disconnect scenario begins in a fresh runtime
# while preserving the same vault, audit log, action, and typed credential.
"$REKEY" --state-dir "$STATE" shutdown >/dev/null
wait_pid_bounded "$BROKER_PID" 6
wait "$BROKER_PID"
BROKER_PID=""
READY="$WORKDIR/pre-signal-restart-ready"
printf '%s\n' success >"$MODE"
"$FIXTURE" "$STATE" "$READY" "$MODE" "$TRACE" "$PUBLIC_KEY_DER" \
  >"$WORKDIR/pre-signal-restart-broker.out" 2>"$WORKDIR/pre-signal-restart-broker.err" &
BROKER_PID=$!
for _ in $(seq 1 400); do
  [[ -f "$READY" && -S "$STATE/runtime/admin.sock" ]] && break
  sleep 0.025
done
[[ -f "$READY" && -S "$STATE/runtime/admin.sock" ]] || {
  echo "P2 GitHub fixture did not restart before signal scenario"
  cat "$WORKDIR/pre-signal-restart-broker.err"
  exit 1
}

# The combined supervisor/connector gate: after the resource request proves a
# token exists, disconnect the Agent and signal the real BrokerRuntime. The
# supervisor must retain ownership through revoke, terminal audit, and stop.
printf '%s\n' "$PASSWORD" | "$REKEY" --state-dir "$STATE" unlock --password-stdin >/dev/null
SIGNAL_SESSION_JSON="$(printf '%s\n' "$PASSWORD" | "$REKEY" --state-dir "$STATE" session create \
  --action "$ACTION_REF" --ttl 10m --max-uses 2 --password-stdin)"
SIGNAL_PRINCIPAL_ID="$(printf '%s\n' "$SIGNAL_SESSION_JSON" | json_field principal_id)"
SIGNAL_CAPABILITY="$(printf '%s\n' "$SIGNAL_SESSION_JSON" | json_field capability_token)"
python3 - "$WORKDIR/policy-snapshot.json" "$SIGNAL_PRINCIPAL_ID" <<'PY'
import json, pathlib, sys, time, uuid
path = pathlib.Path(sys.argv[1])
policy = json.loads(path.read_text())
policy["version"] = 2
policy["expires_at_ms"] = int(time.time() * 1000) + 600000
policy["rules"][0]["id"] = str(uuid.uuid4())
policy["rules"][0]["principal_id"] = sys.argv[2]
path.write_text(json.dumps(policy))
PY
python3 "$ROOT/scripts/sign-test-policy.py" policy --key-dir "$WORKDIR/policy-key" \
  --snapshot "$WORKDIR/policy-snapshot.json" --bundle "$WORKDIR/policy.json" \
  --trust "$WORKDIR/policy-trust.json"
printf '%s\n' "$PASSWORD" | "$REKEY" --state-dir "$STATE" policy activate \
  --file "$WORKDIR/policy.json" --step-up-stdin >/dev/null

printf '%s\n' slow-resource >"$MODE"
SIGNAL_RESOURCE_BEFORE="$(trace_count resource.ok)"
SIGNAL_REVOKE_BEFORE="$(trace_count revoke.ok)"
"$REKEY" --state-dir "$STATE" execute "$ACTION_REF" --capability "$SIGNAL_CAPABILITY" \
  >"$WORKDIR/disconnected-agent.out" 2>"$WORKDIR/disconnected-agent.err" &
DISCONNECT_PID=$!
SIGNAL_RESOURCE_TARGET=$((SIGNAL_RESOURCE_BEFORE + 1))
for _ in $(seq 1 200); do
  [[ "$(trace_count resource.ok)" -eq "$SIGNAL_RESOURCE_TARGET" ]] && break
  sleep 0.01
done
[[ "$(trace_count resource.ok)" -eq "$SIGNAL_RESOURCE_TARGET" ]] || {
  echo "signal scenario did not observe exactly one new resource request"
  cat "$WORKDIR/disconnected-agent.err" >&2 || true
  tail -80 "$TRACE" >&2 || true
  exit 1
}
pid_running "$DISCONNECT_PID"
pid_running "$BROKER_PID"
SIGNAL_STOP_STARTED="$(python3 -c 'import time; print(time.monotonic())')"
kill -TERM "$DISCONNECT_PID"
kill -TERM "$BROKER_PID"
wait_pid_bounded "$DISCONNECT_PID" 2 || {
  echo "Agent CLI did not disconnect within two seconds"
  exit 1
}
DISCONNECT_RC=0
wait "$DISCONNECT_PID" || DISCONNECT_RC=$?
DISCONNECT_PID=""
[[ "$DISCONNECT_RC" -ne 0 && ! -s "$WORKDIR/disconnected-agent.out" ]] || {
  echo "disconnected Agent unexpectedly received a successful response"
  exit 1
}
wait_pid_bounded "$BROKER_PID" 6 || {
  echo "SIGTERM stop exceeded the absolute deadline"
  exit 1
}
BROKER_RC=0
wait "$BROKER_PID" || BROKER_RC=$?
BROKER_PID=""
[[ "$BROKER_RC" -eq 0 ]] || {
  echo "SIGTERM stop returned $BROKER_RC"
  exit 1
}
SIGNAL_STOP_ELAPSED="$(python3 - "$SIGNAL_STOP_STARTED" <<'PY'
import sys, time
print(time.monotonic() - float(sys.argv[1]))
PY
)"
python3 - "$SIGNAL_STOP_ELAPSED" <<'PY'
import sys
if float(sys.argv[1]) >= 6.0:
    raise SystemExit("SIGTERM stop exceeded the six-second absolute test bound")
PY
[[ "$(trace_count revoke.ok)" -eq "$((SIGNAL_REVOKE_BEFORE + 1))" ]] || {
  echo "signal scenario did not revoke exactly one installation token"
  exit 1
}
python3 - "$STATE/vault.sqlite3" <<'PY'
import sqlite3, sys
db = sqlite3.connect(sys.argv[1])
row = db.execute("""
    SELECT request_id FROM audit_events
    WHERE event_type='execution.started'
    ORDER BY sequence DESC LIMIT 1
""").fetchone()
if row is None or row[0] is None:
    raise SystemExit("signal scenario has no request_id")
chain = db.execute("""
    SELECT event_type FROM audit_events
    WHERE request_id=?
      AND event_type IN ('execution.started', 'connector.github.authorized',
                         'connector.github.token_revoked', 'execution.finished',
                         'execution.blocked', 'execution.indeterminate')
    ORDER BY sequence
""", (row[0],)).fetchall()
types = [item[0] for item in chain]
expected = ['execution.started', 'connector.github.authorized',
            'connector.github.token_revoked', 'execution.finished']
if types != expected:
    raise SystemExit(f"signal scenario audit chain is not exact: {types}")
PY

python3 - "$STATE/vault.sqlite3" "$PRIVATE_KEY_BASE64_CANARY" \
  "$PRIVATE_KEY_RAW_CANARY_HEX" "$TOKEN_CANARY" "$STATELESS_TOKEN_CANARY" <<'PY'
import pathlib, re, sqlite3, sys
db_path, key_base64_canary, key_raw_canary_hex, token_canary, stateless_token_canary = sys.argv[1:]
db = sqlite3.connect(db_path)
def scalar(sql): return db.execute(sql).fetchone()[0]
if scalar("SELECT count(*) FROM audit_events WHERE event_type='execution.started'") != 16:
    raise SystemExit("expected sixteen started audits")
if scalar("SELECT count(*) FROM audit_events WHERE event_type IN ('execution.finished','execution.blocked','execution.indeterminate')") != 16:
    raise SystemExit("expected sixteen terminal audits")
if scalar("SELECT count(*) FROM audit_events WHERE event_type='execution.finished'") != 6:
    raise SystemExit("expected six successful executions")
if scalar("SELECT count(*) FROM audit_events WHERE event_type='connector.github.authorized'") != 16:
    raise SystemExit("missing connector authorization commitments")
if scalar("SELECT count(*) FROM audit_events WHERE event_type='connector.github.token_revoked'") != 15:
    raise SystemExit("unexpected revoke audit count")
if scalar("SELECT count(*) FROM audit_events WHERE event_type='connector.github.token_revoked' AND outcome='failure'") != 1:
    raise SystemExit("missing revoke failure audit")
reasons = [row[0] for row in db.execute("SELECT reason_code FROM audit_events")]
if any("binding-sha256=" in value and len(value.rsplit("binding-sha256=",1)[1]) != 64 for value in reasons):
    raise SystemExit("invalid connector binding commitment")
binding_re = re.compile(r"binding-sha256=([0-9a-f]{64})")
rows = db.execute("""
    SELECT sequence, hex(request_id), event_type, outcome, reason_code
    FROM audit_events
    WHERE request_id IS NOT NULL
      AND event_type IN ('execution.started', 'connector.github.authorized',
                         'connector.github.token_revoked', 'execution.finished', 'execution.blocked',
                         'execution.indeterminate')
    ORDER BY sequence
""").fetchall()
chains = {}
for row in rows:
    chains.setdefault(row[1], []).append(row)
if len(chains) != 16:
    raise SystemExit(f"expected sixteen non-vacuous request audit chains, got {len(chains)}")
without_revoke = 0
for request_id, chain in chains.items():
    types = [row[2] for row in chain]
    if types[0] != 'execution.started' or types[-1] not in ('execution.finished', 'execution.blocked', 'execution.indeterminate'):
        raise SystemExit(f"bad terminal ordering for {request_id}: {types}")
    if types.count('execution.started') != 1 or types.count('connector.github.authorized') != 1:
        raise SystemExit(f"missing or duplicate start/authorized for {request_id}: {types}")
    if sum(t in ('execution.finished', 'execution.blocked', 'execution.indeterminate') for t in types) != 1:
        raise SystemExit(f"missing or duplicate terminal for {request_id}: {types}")
    authorized = next(row for row in chain if row[2] == 'connector.github.authorized')
    match = binding_re.fullmatch(authorized[4])
    if not match or not (chain[0][0] < authorized[0] < chain[-1][0]):
        raise SystemExit(f"invalid authorized binding/order for {request_id}")
    revoke_rows = [row for row in chain if row[2] == 'connector.github.token_revoked']
    if not revoke_rows:
        without_revoke += 1
        continue
    if len(revoke_rows) != 1:
        raise SystemExit(f"duplicate revoke audit for {request_id}")
    revoke = revoke_rows[0]
    revoke_match = re.fullmatch(
        r"(?:success|github-token-revoke-rejected);binding-sha256=([0-9a-f]{64})",
        revoke[4],
    )
    if not revoke_match or revoke_match.group(1) != match.group(1):
        raise SystemExit(f"revoke binding mismatch for {request_id}")
    if not (authorized[0] < revoke[0] < chain[-1][0]):
        raise SystemExit(f"bad revoke ordering for {request_id}")
if without_revoke != 1:
    raise SystemExit(f"expected exactly one exchange-without-token chain, got {without_revoke}")
raw = pathlib.Path(db_path).read_bytes()
if (key_base64_canary.encode() in raw
        or bytes.fromhex(key_raw_canary_hex) in raw
        or token_canary.encode() in raw
        or stateless_token_canary.encode() in raw):
    raise SystemExit("connector secret leaked into SQLite")
PY

[[ "$(grep -c '^exchange.ok$' "$TRACE")" -eq 15 ]]
[[ "$(grep -c '^exchange.error$' "$TRACE")" -eq 1 ]]
RESOURCE_OK_COUNT="$(grep -c '^resource.ok$' "$TRACE")"
[[ "$RESOURCE_OK_COUNT" -eq 9 ]] || {
  echo "expected nine resource.ok traces, got $RESOURCE_OK_COUNT"
  cat "$TRACE"
  exit 1
}
[[ "$(grep -c '^resource.error$' "$TRACE")" -eq 1 ]]
[[ "$(grep -c '^revoke.ok$' "$TRACE")" -eq 14 ]]
[[ "$(grep -c '^revoke.error$' "$TRACE")" -eq 1 ]]

assert_secret_absent "base64 private-key canary" "$PRIVATE_KEY_BASE64_CANARY"
assert_secret_absent "installation token canary" "$TOKEN_CANARY"
assert_secret_absent "stateless installation token canary" "$STATELESS_TOKEN_CANARY"
assert_all_jwt_canaries_absent "$TRACE" "GitHub JWT canary"
assert_raw_private_key_absent

READY="$WORKDIR/restarted-ready"
printf '%s\n' success >"$MODE"
"$FIXTURE" "$STATE" "$READY" "$MODE" "$TRACE" "$PUBLIC_KEY_DER" \
  >"$WORKDIR/restarted-broker.out" 2>"$WORKDIR/restarted-broker.err" &
BROKER_PID=$!
for _ in $(seq 1 400); do
  [[ -f "$READY" && -S "$STATE/runtime/admin.sock" ]] && break
  sleep 0.025
done
[[ -f "$READY" && -S "$STATE/runtime/admin.sock" ]] || {
  echo "P2 GitHub fixture did not restart after SIGTERM"
  cat "$WORKDIR/restarted-broker.err"
  exit 1
}

printf '%s\n' "$PASSWORD" | "$REKEY" --state-dir "$STATE" unlock --password-stdin >/dev/null
BACKUP="$WORKDIR/github-app.backup"
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
printf '%s\n' success >"$MODE"
"$FIXTURE" "$STATE" "$READY" "$MODE" "$RESTORED_TRACE" "$PUBLIC_KEY_DER" \
  >"$WORKDIR/restored-broker.out" 2>"$WORKDIR/restored-broker.err" &
BROKER_PID=$!
for _ in $(seq 1 400); do
  [[ -f "$READY" && -S "$STATE/runtime/admin.sock" ]] && break
  sleep 0.025
done
[[ -f "$READY" && -S "$STATE/runtime/admin.sock" ]] || {
  echo "restored P2 GitHub fixture did not start"
  cat "$WORKDIR/restored-broker.err"
  exit 1
}
printf '%s\n' "$PASSWORD" | "$REKEY" --state-dir "$STATE" unlock --password-stdin >/dev/null
RESTORED_CREDENTIALS="$("$REKEY" --state-dir "$STATE" credential list)"
printf '%s\n' "$RESTORED_CREDENTIALS" | python3 -c '
import json, sys
credentials = json.load(sys.stdin)["credentials"]
matches = [item for item in credentials if item["id"] == sys.argv[1]]
if len(matches) != 1 or matches[0]["kind"] != "github-app-installation":
    raise SystemExit("restored GitHub credential lost its typed kind")
' "$CREDENTIAL_ID"
RESTORED_SESSION="$(printf '%s\n' "$PASSWORD" | "$REKEY" --state-dir "$STATE" session create \
  --action "$ACTION_REF" --ttl 10m --max-uses 2 --password-stdin)"
RESTORED_PRINCIPAL="$(printf '%s\n' "$RESTORED_SESSION" | json_field principal_id)"
RESTORED_CAPABILITY="$(printf '%s\n' "$RESTORED_SESSION" | json_field capability_token)"
python3 - "$WORKDIR/policy-snapshot.json" "$RESTORED_PRINCIPAL" <<'PY'
import json, pathlib, sys, time, uuid
path = pathlib.Path(sys.argv[1])
policy = json.loads(path.read_text())
policy["version"] = 3
policy["expires_at_ms"] = int(time.time() * 1000) + 600000
policy["rules"][0]["id"] = str(uuid.uuid4())
policy["rules"][0]["principal_id"] = sys.argv[2]
path.write_text(json.dumps(policy))
PY
python3 "$ROOT/scripts/sign-test-policy.py" policy --key-dir "$WORKDIR/policy-key" \
  --snapshot "$WORKDIR/policy-snapshot.json" --bundle "$WORKDIR/policy.json" \
  --trust "$WORKDIR/policy-trust.json"
printf '%s\n' "$PASSWORD" | "$REKEY" --state-dir "$STATE" policy activate \
  --file "$WORKDIR/policy.json" --step-up-stdin >/dev/null
"$REKEY" --state-dir "$STATE" execute "$ACTION_REF" --capability "$RESTORED_CAPABILITY" \
  >"$WORKDIR/restored-success.out" 2>"$WORKDIR/restored-success.err"
grep -q '"id":616161' "$WORKDIR/restored-success.out"
python3 - "$STATE/vault.sqlite3" <<'PY'
import re, sqlite3, sys
db = sqlite3.connect(sys.argv[1])
if db.execute("SELECT count(*) FROM audit_events WHERE event_type='execution.started'").fetchone()[0] != 17:
    raise SystemExit("restored execution did not append the seventeenth start")
request_id = db.execute("SELECT request_id FROM audit_events WHERE event_type='execution.started' ORDER BY sequence DESC LIMIT 1").fetchone()[0]
chain = db.execute("SELECT event_type, reason_code FROM audit_events WHERE request_id=? ORDER BY sequence", (request_id,)).fetchall()
if [row[0] for row in chain] != ['execution.started', 'connector.github.authorized', 'connector.github.token_revoked', 'execution.finished']:
    raise SystemExit(f"restored execution audit chain invalid: {chain}")
if not re.fullmatch(r"binding-sha256=[0-9a-f]{64}", chain[1][1]):
    raise SystemExit("restored authorized binding invalid")
if not re.fullmatch(r"success;binding-sha256=[0-9a-f]{64}", chain[2][1]):
    raise SystemExit("restored revoke binding invalid")
PY
assert_secret_absent "base64 private-key canary after restore" "$PRIVATE_KEY_BASE64_CANARY"
assert_secret_absent "installation token canary after restore" "$TOKEN_CANARY"
assert_secret_absent "stateless installation token canary after restore" "$STATELESS_TOKEN_CANARY"
assert_all_jwt_canaries_absent "$TRACE" "GitHub JWT canary after restore"
assert_all_jwt_canaries_absent "$RESTORED_TRACE" "restored GitHub JWT canary"
assert_raw_private_key_absent
printf '%s\n' "$PASSWORD" | "$REKEY" --state-dir "$STATE" shutdown --password-stdin >/dev/null
wait "$BROKER_PID"
BROKER_PID=""
echo "P2 GitHub App local acceptance passed"
