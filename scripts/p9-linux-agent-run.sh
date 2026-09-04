#!/usr/bin/env bash
# P-09 Linux agent-run black-box: real rekey/rekeyd, disjoint agent.sock,
# system bubblewrap. Proves deny-by-default IP egress for one launched argv.
# Does not replace scripts/p1-linux-g2.sh or upgrade default G1.
set -euo pipefail

if [[ "$(uname -s)" != Linux ]]; then
  echo "p9-linux-agent-run is Linux-only" >&2
  exit 1
fi

command -v rg >/dev/null || {
  echo "p9-linux-agent-run requires ripgrep (rg)" >&2
  exit 1
}
[[ -x /usr/bin/bwrap || -x /bin/bwrap ]] || {
  echo "p9-linux-agent-run requires bubblewrap (/usr/bin/bwrap or /bin/bwrap)" >&2
  exit 1
}

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN_DIR="${BIN_DIR:-$ROOT/target/release}"
REKEY="${BIN_DIR}/rekey"
REKEYD="${BIN_DIR}/rekeyd"
PYTHON="$(command -v python3)"
PASSWORD="${REKEY_P9_PASSWORD:-p09 agent-run acceptance password}"
SECRET="p09-credential-canary-secret"
ORIGIN="${REKEY_ACCEPTANCE_ORIGIN:-https://1.1.1.1}"
EXACT_PATH="${REKEY_ACCEPTANCE_PATH:-/cdn-cgi/trace}"
PARENT_CANARY="p09-parent-env-canary-secret"

if [[ ! -x "$REKEY" || ! -x "$REKEYD" ]]; then
  echo "building release binaries…"
  cargo build --release -p rekey-cli -p rekey-broker
fi

WORKDIR="$(mktemp -d /tmp/rkp9.XXXXXX)"
STATE="$WORKDIR/s"
AGENT_RUN="$WORKDIR/a"
AGENT_SOCK="$AGENT_RUN/agent.sock"
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
  echo "P-09 Linux agent-run acceptance failed at line $1 (exit $rc)" >&2
  exit "$rc"
}
trap cleanup EXIT
trap 'failure "$LINENO"' ERR

json_field() {
  python3 -c 'import json,sys; print(json.load(sys.stdin)[sys.argv[1]])' "$1"
}

echo "== overlap default G1 socket is rejected"
printf '%s\n' "$PASSWORD" | "$REKEYD" init --state-dir "$STATE" --password-stdin >/dev/null
set +e
overlap_out="$("$REKEY" --state-dir "$STATE" agent-run -- "$PYTHON" -c 'print(1)' 2>&1)"
overlap_rc=$?
set -e
[[ "$overlap_rc" -eq 2 ]] || {
  echo "expected overlapping agent-run exit 2, got $overlap_rc: $overlap_out"
  exit 1
}
printf '%s\n' "$overlap_out" | rg -q 'disjoint|INVALID_INPUT|invalid launch plan' \
  || { echo "overlap error did not mention launch plan: $overlap_out"; exit 1; }

echo "== serve with disjoint Agent endpoint"
mkdir -p "$AGENT_RUN"
"$REKEYD" serve --state-dir "$STATE" --idle-lock 15m --agent-runtime-dir "$AGENT_RUN" \
  >"$WORKDIR/broker.out" 2>"$WORKDIR/broker.err" &
SERVE_PID=$!
for _ in $(seq 1 200); do
  [[ -S "$STATE/runtime/admin.sock" && -S "$AGENT_SOCK" ]] && break
  sleep 0.05
done
[[ -S "$STATE/runtime/admin.sock" && -S "$AGENT_SOCK" ]] || {
  echo "broker did not start disjoint sockets"
  exit 1
}

echo "== unlock, credential, action, session, policy"
printf '%s\n' "$PASSWORD" | "$REKEY" --state-dir "$STATE" unlock --password-stdin >/dev/null
cred_json="$(printf '%s\n%s\n' "$PASSWORD" "$SECRET" | "$REKEY" --state-dir "$STATE" \
  credential add p09-canary --stdin-secrets)"
cred_id="$(printf '%s\n' "$cred_json" | json_field id)"
cat >"$WORKDIR/action.json" <<EOF
{
  "name": "p09-trace",
  "credential_id": "$cred_id",
  "origin": "$ORIGIN",
  "method": "GET",
  "exact_path": "$EXACT_PATH",
  "auth_header": "authorization",
  "auth_prefix": "Bearer ",
  "timeout_ms": 30000,
  "request_max_bytes": 1024,
  "allowed_extra_headers": [],
  "response_max_bytes": 262144,
  "allowed_response_headers": ["content-type"]
}
EOF
action_json="$(printf '%s\n' "$PASSWORD" | "$REKEY" --state-dir "$STATE" action create \
  --file "$WORKDIR/action.json" --password-stdin)"
action_id="$(printf '%s\n' "$action_json" | json_field id)"
action_ver="$(printf '%s\n' "$action_json" | json_field version)"
action_ref="$action_id@$action_ver"
session_json="$(printf '%s\n' "$PASSWORD" | "$REKEY" --state-dir "$STATE" session create \
  --action "$action_ref" --ttl 10m --max-uses 5 --password-stdin)"
token="$(printf '%s\n' "$session_json" | json_field capability_token)"
principal_id="$(printf '%s\n' "$session_json" | json_field principal_id)"
python3 - "$WORKDIR/policy.json" "$action_id" "$action_ver" "$principal_id" <<'PY'
import json, pathlib, sys, time, uuid
path, action_id, action_version, principal_id = sys.argv[1:]
resource = {"type": "fixed-http-action", "id": action_id}
pathlib.Path(path).write_text(json.dumps({
    "format_version": 3,
    "version": 1,
    "expires_at_ms": int(time.time() * 1000) + 600000,
    "approvers": [],
    "workload_identities": [],
    "bindings": [{
        "action_id": action_id,
        "version": int(action_version),
        "resource": resource,
        "parameter_schema_id": "p09-empty/v1",
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
  --snapshot "$WORKDIR/policy.json" --bundle "$WORKDIR/policy-bundle.json" \
  --trust "$WORKDIR/policy-trust.json"
printf '%s\n' "$PASSWORD" | "$REKEY" --state-dir "$STATE" policy trust install \
  --file "$WORKDIR/policy-trust.json" --step-up-stdin >/dev/null
printf '%s\n' "$PASSWORD" | "$REKEY" --state-dir "$STATE" policy activate \
  --file "$WORKDIR/policy-bundle.json" --step-up-stdin >/dev/null

echo "== child cannot use public TCP"
set +e
tcp_out="$(REKEY_PASSWORD="$PARENT_CANARY" "$REKEY" --state-dir "$STATE" \
  --agent-socket "$AGENT_SOCK" agent-run -- "$PYTHON" -c \
  'import socket; s=socket.socket(); s.settimeout(2); s.connect(("1.1.1.1", 443))' 2>&1)"
tcp_rc=$?
set -e
[[ "$tcp_rc" -ne 0 ]] || {
  echo "sandboxed child connected to 1.1.1.1:443: $tcp_out"
  exit 1
}

echo "== child cannot read vault files or inherit parent env"
hide_out="$(REKEY_PASSWORD="$PARENT_CANARY" "$REKEY" --state-dir "$STATE" \
  --agent-socket "$AGENT_SOCK" agent-run -- "$PYTHON" -c \
  'import os, pathlib, sys
state=pathlib.Path(sys.argv[1])
secret=sys.argv[2]
canary=sys.argv[3]
if (state / "vault.sqlite3").exists() or (state / "runtime" / "admin.sock").exists():
    raise SystemExit("state visible")
env="".join(f"{k}={v}" for k,v in os.environ.items())
if "REKEY_PASSWORD" in os.environ or canary in env or secret in env:
    raise SystemExit("parent secret in child env")
print("hidden-ok")
' "$STATE" "$SECRET" "$PARENT_CANARY")"
[[ "$hide_out" == *hidden-ok* ]] || {
  echo "state/env hide failed: $hide_out"
  exit 1
}
printf '%s\n' "$hide_out" | rg -F "$SECRET" && { echo "secret reached child output"; exit 1; }
printf '%s\n' "$hide_out" | rg -F "$PARENT_CANARY" && { echo "parent canary reached child output"; exit 1; }

echo "== child can still use the Agent Unix socket"
unix_out="$("$REKEY" --state-dir "$STATE" --agent-socket "$AGENT_SOCK" agent-run -- \
  "$PYTHON" -c \
  'import socket,sys
s=socket.socket(socket.AF_UNIX)
s.settimeout(3)
s.connect(sys.argv[1])
print("unix-ok")
' "$AGENT_SOCK")"
[[ "$unix_out" == *unix-ok* ]] || {
  echo "unix connect failed: $unix_out"
  exit 1
}

echo "== capability-authorized execute through the sandbox"
exec_out="$("$REKEY" --state-dir "$STATE" --agent-socket "$AGENT_SOCK" agent-run -- \
  "$REKEY" --state-dir "$STATE" --agent-socket "$AGENT_SOCK" \
  execute "$action_ref" --capability "$token")"
printf '%s\n' "$exec_out" | python3 -c 'import json,sys; v,_=json.JSONDecoder().raw_decode(sys.stdin.read().lstrip());
assert v["upstream_status"]==200, v'
printf '%s\n' "$exec_out" | rg -F "$SECRET" && { echo "secret reached execute output"; exit 1; }
rg -F "$SECRET" "$WORKDIR/broker.out" "$WORKDIR/broker.err" && {
  echo "secret reached broker logs"
  exit 1
}

printf '%s\n' "$PASSWORD" | "$REKEY" --state-dir "$STATE" shutdown --password-stdin >/dev/null
SERVE_PID=""

echo "p9-linux-agent-run: PASS"
echo "p9-linux-agent-run: profile=linux-netns-v1 bwrap=$(command -v bwrap || true)"
echo "p9-linux-agent-run: proved=overlap-reject,public-tcp-denied,state-hidden,parent-env-dropped,unix-agent-socket,approved-execute"
echo "p9-linux-agent-run: limitation=not-general-G2,not-macos,not-kernel-or-host-root"
