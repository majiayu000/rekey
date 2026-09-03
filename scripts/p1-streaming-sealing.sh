#!/usr/bin/env bash
# P1 bounded-response sealing gate: release CLI, independent BrokerRuntime,
# dual UDS, SQLite audit, and a local CA/TLS HTTP/1.1 chunked upstream.
set -euo pipefail
umask 077

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN_DIR="${BIN_DIR:-$ROOT/target/release}"
REKEY="$BIN_DIR/rekey"
REKEYD="$BIN_DIR/rekeyd"
FIXTURE="$BIN_DIR/examples/p1_policy_fixture"
PASSWORD="p1 sealing acceptance horse battery staple"
SECRET='P1-CHUNK+/=%-CREDENTIAL-CANARY'

cargo build --release -p rekey-cli --bin rekey -p rekey-broker --bin rekeyd
cargo build --release -p rekey-broker --example p1_policy_fixture

WORKDIR="$(mktemp -d /tmp/rkseal.XXXXXX)"
STATE="$WORKDIR/state"
READY="$WORKDIR/port"
HITS="$WORKDIR/hits"
BROKER_PID=""
ACTIVE_PROXY_PID=""
cleanup() {
  if [[ -n "$ACTIVE_PROXY_PID" ]]; then
    kill "$ACTIVE_PROXY_PID" 2>/dev/null || true
    wait "$ACTIVE_PROXY_PID" 2>/dev/null || true
  fi
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

write_mode() {
  printf '{"mode":"%s"}\n' "$1" >"$WORKDIR/$1.json"
}

start_agent_capture() {
  local mode="$1"
  PROXY_SOCKET="$WORKDIR/$mode-agent.sock"
  PROXY_READY="$WORKDIR/$mode-agent.ready"
  CAPTURE_PATH="$WORKDIR/$mode-agent.response"
  python3 - "$PROXY_SOCKET" "$STATE/runtime/agent.sock" "$CAPTURE_PATH" "$PROXY_READY" <<'PY' &
import os, socket, struct, sys, threading

listen_path, upstream_path, capture_path, ready_path = sys.argv[1:]

def recv_exact(stream, size):
    chunks = []
    remaining = size
    while remaining:
        chunk = stream.recv(remaining)
        if not chunk:
            raise EOFError(f"truncated request with {remaining} bytes remaining")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)

listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
listener.bind(listen_path)
os.chmod(listen_path, 0o600)
listener.listen(1)
pathlib_ready = open(ready_path, "xb")
pathlib_ready.close()
client, _ = listener.accept()
upstream = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
upstream.connect(upstream_path)
client.settimeout(30)
upstream.settimeout(30)
relay_errors = []

def relay_one_request():
    try:
        header = recv_exact(client, 36)
        _, _, _, _, _, _, _, metadata_len, body_len = struct.unpack(
            ">4sHBBHH16sII", header
        )
        upstream.sendall(header)
        remaining = metadata_len + body_len
        while remaining:
            chunk = client.recv(min(65536, remaining))
            if not chunk:
                raise EOFError(f"truncated request payload with {remaining} bytes remaining")
            upstream.sendall(chunk)
            remaining -= len(chunk)
        upstream.shutdown(socket.SHUT_WR)
    except BaseException as error:
        relay_errors.append(error)
        try:
            upstream.shutdown(socket.SHUT_WR)
        except OSError:
            pass

request_thread = threading.Thread(target=relay_one_request)
request_thread.start()
captured = bytearray()
while True:
    chunk = upstream.recv(65536)
    if not chunk:
        break
    captured.extend(chunk)
    client.sendall(chunk)
request_thread.join()
with open(capture_path, "xb") as capture:
    capture.write(captured)
if relay_errors:
    raise relay_errors[0]
client.close()
upstream.close()
listener.close()
PY
  ACTIVE_PROXY_PID=$!
  for _ in $(seq 1 200); do
    if [[ -S "$PROXY_SOCKET" && -f "$PROXY_READY" ]]; then
      return
    fi
    if ! kill -0 "$ACTIVE_PROXY_PID" 2>/dev/null; then
      wait "$ACTIVE_PROXY_PID"
    fi
    sleep 0.025
  done
  echo "$mode: Agent capture proxy did not start" >&2
  exit 1
}

validate_agent_error_capture() {
  local mode="$1"
  local expected_code="$2"
  python3 - "$CAPTURE_PATH" "$mode" "$expected_code" <<'PY'
import json, pathlib, struct, sys

path, mode, expected_code = pathlib.Path(sys.argv[1]), sys.argv[2], sys.argv[3]
captured = path.read_bytes()
if len(captured) < 36:
    raise SystemExit(f"{mode}: truncated RKIP response header ({len(captured)} bytes)")
magic, version, channel, flags, message_type, reserved, _, metadata_len, body_len = (
    struct.unpack(">4sHBBHH16sII", captured[:36])
)
if (magic, version, channel, flags, message_type, reserved) != (
    b"RKIP", 1, 2, 0, 101, 0
):
    raise SystemExit(
        f"{mode}: expected one Agent ERROR frame, got "
        f"{(magic, version, channel, flags, message_type, reserved)}"
    )
if body_len != 0:
    raise SystemExit(f"{mode}: ERROR frame exposed {body_len} body bytes")
expected_len = 36 + metadata_len
if len(captured) != expected_len:
    raise SystemExit(
        f"{mode}: expected exactly {expected_len} response bytes, got {len(captured)}"
    )
try:
    metadata = json.loads(captured[36:].decode("utf-8"))
except (UnicodeDecodeError, json.JSONDecodeError) as error:
    raise SystemExit(f"{mode}: invalid ERROR metadata: {error}") from error
if metadata.get("code") != expected_code:
    raise SystemExit(
        f"{mode}: expected metadata code {expected_code}, got {metadata.get('code')}"
    )
PY
}

expect_failure() {
  local mode="$1"
  local expected_rc="$2"
  local expected_code="$3"
  write_mode "$mode"
  start_agent_capture "$mode"
  set +e
  "$REKEY" --state-dir "$STATE" --agent-socket "$PROXY_SOCKET" execute "$ACTION_REF" \
    --capability "$CAPABILITY" --body-file "$WORKDIR/$mode.json" \
    --content-type application/json \
    >"$WORKDIR/$mode.out" 2>"$WORKDIR/$mode.err"
  local rc=$?
  set -e
  wait "$ACTIVE_PROXY_PID"
  ACTIVE_PROXY_PID=""
  validate_agent_error_capture "$mode" "$expected_code"
  [[ "$rc" -eq "$expected_rc" ]] || {
    echo "$mode: expected exit $expected_rc, got $rc" >&2
    sed -n '1,20p' "$WORKDIR/$mode.err" >&2
    exit 1
  }
  [[ ! -s "$WORKDIR/$mode.out" ]] || {
    echo "$mode: failure returned an Agent response body" >&2
    exit 1
  }
  grep -q "$expected_code" "$WORKDIR/$mode.err" || {
    echo "$mode: missing $expected_code" >&2
    exit 1
  }
}

printf '%s\n' "$PASSWORD" | "$REKEYD" init --state-dir "$STATE" --password-stdin >/dev/null
"$FIXTURE" "$STATE" "$READY" "$HITS" >"$WORKDIR/broker.out" 2>"$WORKDIR/broker.err" &
BROKER_PID=$!
for _ in $(seq 1 300); do
  if [[ -f "$READY" && -S "$STATE/runtime/admin.sock" && -S "$STATE/runtime/agent.sock" ]] \
    && "$REKEY" --state-dir "$STATE" status >/dev/null 2>&1; then
    break
  fi
  sleep 0.025
done
[[ -f "$READY" && -S "$STATE/runtime/admin.sock" && -S "$STATE/runtime/agent.sock" ]] || {
  echo "sealing fixture did not start" >&2
  sed -n '1,40p' "$WORKDIR/broker.err" >&2
  exit 1
}
PORT="$(tr -d '\n' <"$READY")"

printf '%s\n' "$PASSWORD" | "$REKEY" --state-dir "$STATE" unlock --password-stdin >/dev/null
CREDENTIAL_JSON="$(printf '%s\n%s\n' "$PASSWORD" "$SECRET" | \
  "$REKEY" --state-dir "$STATE" credential add p1-sealing --stdin-secrets)"
CREDENTIAL_ID="$(printf '%s\n' "$CREDENTIAL_JSON" | json_field id)"

python3 - "$WORKDIR/action.json" "$CREDENTIAL_ID" "$PORT" <<'PY'
import json, pathlib, sys
pathlib.Path(sys.argv[1]).write_text(json.dumps({
    "name": "p1-chunk-boundary-sealing",
    "credential_id": sys.argv[2],
    "origin": f"https://api.test.local:{sys.argv[3]}",
    "method": "POST",
    "exact_path": "/v1/sealing",
    "auth_header": "authorization",
    "auth_prefix": "Bearer ",
    "timeout_ms": 10000,
    "request_max_bytes": 1024,
    "allowed_extra_headers": [],
    "response_max_bytes": 1024,
    "allowed_response_headers": ["content-type"],
}))
PY
ACTION_JSON="$(printf '%s\n' "$PASSWORD" | \
  "$REKEY" --state-dir "$STATE" action create --file "$WORKDIR/action.json" --password-stdin)"
ACTION_ID="$(printf '%s\n' "$ACTION_JSON" | json_field id)"
ACTION_VERSION="$(printf '%s\n' "$ACTION_JSON" | json_field version)"
ACTION_REF="$ACTION_ID@$ACTION_VERSION"
SESSION_JSON="$(printf '%s\n' "$PASSWORD" | \
  "$REKEY" --state-dir "$STATE" session create --action "$ACTION_REF" \
  --ttl 10m --max-uses 20 --password-stdin)"
PRINCIPAL_ID="$(printf '%s\n' "$SESSION_JSON" | json_field principal_id)"
CAPABILITY="$(printf '%s\n' "$SESSION_JSON" | json_field capability_token)"

python3 - "$WORKDIR/policy.json" "$ACTION_ID" "$ACTION_VERSION" "$PRINCIPAL_ID" <<'PY'
import json, pathlib, sys, time, uuid
path, action, version, principal = sys.argv[1:]
resource = {"type": "fixed-http-action", "id": action}
binding = {
    "action_id": action,
    "version": int(version),
    "resource": resource,
    "parameter_schema_id": "p1-sealing-mode/v1",
    "parameter_schema": {
        "type": "object",
        "required": ["mode"],
        "properties": {"mode": {"type": "string"}},
        "additionalProperties": False,
    },
}
rule = {
    "id": str(uuid.uuid4()),
    "effect": "permit",
    "principal_id": principal,
    "action_id": action,
    "version": int(version),
    "resource": resource,
    "parameters": {"kind": "any_validated"},
}
pathlib.Path(path).write_text(json.dumps({
    "format_version": 3,
    "version": 1,
    "expires_at_ms": int(time.time() * 1000) + 600000,
    "approvers": [],
    "workload_identities": [],
    "bindings": [binding],
    "rules": [rule],
}))
PY
python3 "$ROOT/scripts/sign-test-policy.py" policy --key-dir "$WORKDIR/policy-key" \
  --snapshot "$WORKDIR/policy.json" --bundle "$WORKDIR/policy-bundle.json" \
  --trust "$WORKDIR/policy-trust.json"
printf '%s\n' "$PASSWORD" | "$REKEY" --state-dir "$STATE" policy trust install \
  --file "$WORKDIR/policy-trust.json" --step-up-stdin >/dev/null
printf '%s\n' "$PASSWORD" | "$REKEY" --state-dir "$STATE" policy activate \
  --file "$WORKDIR/policy-bundle.json" --step-up-stdin >/dev/null

for mode in raw base64 base64url percent percent-all percent-selective; do
  expect_failure "$mode" 8 RESPONSE_SECURITY_VIOLATION
done

write_mode clean
"$REKEY" --state-dir "$STATE" execute "$ACTION_REF" \
  --capability "$CAPABILITY" --body-file "$WORKDIR/clean.json" \
  --content-type application/json \
  >"$WORKDIR/clean.out" 2>"$WORKDIR/clean.err"
grep -q '"upstream_status": 200' "$WORKDIR/clean.out"
grep -q '{"ok":true}' "$WORKDIR/clean.out"

expect_failure oversize 6 RESPONSE_TOO_LARGE
expect_failure midstream 6 UPSTREAM_FAILED
[[ "$(tr -d '\n' <"$HITS")" -eq 9 ]] || {
  echo "expected nine real TLS upstream requests" >&2
  exit 1
}

printf '%s\n' "$PASSWORD" | "$REKEY" --state-dir "$STATE" shutdown --password-stdin >/dev/null
wait "$BROKER_PID"
BROKER_PID=""

python3 - "$STATE/vault.sqlite3" <<'PY'
import collections, sqlite3, sys
db = sqlite3.connect(sys.argv[1])
rows = db.execute("""
    SELECT hex(request_id), event_type, reason_code
    FROM audit_events
    WHERE event_type LIKE 'execution.%'
    ORDER BY sequence
""").fetchall()
by_request = collections.defaultdict(list)
for request_id, event_type, reason in rows:
    by_request[request_id].append((event_type, reason))
if len(by_request) != 9:
    raise SystemExit(f"expected 9 audited executions, got {len(by_request)}")
for request_id, events in by_request.items():
    started = sum(event == "execution.started" for event, _ in events)
    terminal = sum(event in ("execution.finished", "execution.blocked", "execution.indeterminate") for event, _ in events)
    if started != 1 or terminal != 1:
        raise SystemExit(f"orphan or duplicate terminal for {request_id}: {events}")
blocked = collections.Counter(
    reason for _, event, reason in rows if event == "execution.blocked"
)
if blocked:
    raise SystemExit(f"unexpected blocked audit reasons: {blocked}")
indeterminate = collections.Counter(
    reason for _, event, reason in rows if event == "execution.indeterminate"
)
if indeterminate != collections.Counter({
    "reflected-secret": 6,
    "response-too-large": 1,
    "upstream-transport": 1,
}):
    raise SystemExit(f"unexpected indeterminate audit reasons: {indeterminate}")
if sum(event == "execution.finished" for _, event, _ in rows) != 1:
    raise SystemExit("clean request did not have exactly one finished terminal")
PY

python3 - "$WORKDIR" "$STATE/vault.sqlite3" "$SECRET" <<'PY'
import base64, pathlib, sys
workdir, database, secret = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2]), sys.argv[3].encode()
safe = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.~"
percent = b"".join(bytes([value]) if value in safe else f"%{value:02x}".encode() for value in secret)
needles = {
    secret,
    base64.b64encode(secret),
    base64.urlsafe_b64encode(secret).rstrip(b"="),
    percent,
    b"partial-agent-body",
}
paths = [database, workdir / "broker.out", workdir / "broker.err"]
paths.extend(workdir.glob("*.out"))
paths.extend(workdir.glob("*.err"))
paths.extend(workdir.glob("*-agent.response"))
for path in paths:
    data = path.read_bytes()
    for needle in needles:
        if needle and needle in data:
            raise SystemExit(f"sealed response material leaked into {path.name}")
PY

echo "P1 chunk-boundary response sealing acceptance passed"
