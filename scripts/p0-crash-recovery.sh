#!/usr/bin/env bash
# Real-process crash recovery: kill rekeyd after execution.started commits,
# restart it, and prove startup appends exactly one abandoned terminal event.
set -euo pipefail
umask 077

command -v rg >/dev/null || {
  echo "p0-crash-recovery requires ripgrep (rg)" >&2
  exit 1
}

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN_DIR="${BIN_DIR:-$ROOT/target/release}"
REKEY="${BIN_DIR}/rekey"
REKEYD="${BIN_DIR}/rekeyd"
PASSWORD="crash recovery acceptance password"
SECRET="crash-recovery-credential-canary"

if [[ ! -x "$REKEY" || ! -x "$REKEYD" ]]; then
  cargo build --release -p rekey-cli -p rekey-broker
fi

WORKDIR="$(mktemp -d "/tmp/rkc.XXXXXX")"
STATE="$WORKDIR/s"
BROKER_PID=""
cleanup() {
  for pid in ${EXEC_PIDS:-}; do
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
  done
  if [[ -n "$BROKER_PID" ]]; then
    kill "$BROKER_PID" 2>/dev/null || true
    wait "$BROKER_PID" 2>/dev/null || true
  fi
  rm -rf "$WORKDIR"
}
trap cleanup EXIT

json_field() {
  python3 -c 'import json,sys; print(json.load(sys.stdin)['"$1"'])'
}

wait_for_socket() {
  for _ in $(seq 1 200); do
    if [[ -S "$STATE/runtime/admin.sock" ]] \
      && "$REKEY" --state-dir "$STATE" status >/dev/null 2>&1; then
      return
    fi
    sleep 0.02
  done
  echo "broker did not start"
  exit 1
}

printf '%s\n' "$PASSWORD" | "$REKEY" --state-dir "$STATE" init --password-stdin >/dev/null
"$REKEYD" serve --state-dir "$STATE" --idle-lock 15m >"$WORKDIR/serve-1.out" 2>"$WORKDIR/serve-1.jsonl" &
BROKER_PID=$!
wait_for_socket
printf '%s\n' "$PASSWORD" | "$REKEY" --state-dir "$STATE" unlock --password-stdin >/dev/null

cred_json="$(printf '%s\n%s\n' "$PASSWORD" "$SECRET" | "$REKEY" --state-dir "$STATE" credential add crash-credential --stdin-secrets)"
cred_id="$(printf '%s\n' "$cred_json" | json_field '"id"')"
action_file="$WORKDIR/action.json"
python3 - "$action_file" "$cred_id" <<'PY'
import json, pathlib, sys
pathlib.Path(sys.argv[1]).write_text(json.dumps({
    "name": "crash-recovery-action",
    "credential_id": sys.argv[2],
    "origin": "https://1.1.1.1",
    "method": "GET",
    "exact_path": "/cdn-cgi/trace",
    "auth_header": "authorization",
    "auth_prefix": "Bearer ",
    "timeout_ms": 15000,
    "request_max_bytes": 1024,
    "allowed_extra_headers": [],
    "response_max_bytes": 65536,
    "allowed_response_headers": ["content-type"]
}))
PY
action_json="$(printf '%s\n' "$PASSWORD" | "$REKEY" --state-dir "$STATE" action create --file "$action_file" --password-stdin)"
action_ref="$(printf '%s\n' "$action_json" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d["id"]+"@"+str(d["version"]))')"
session_json="$(printf '%s\n' "$PASSWORD" | "$REKEY" --state-dir "$STATE" session create --action "$action_ref" --ttl 10m --max-uses 20 --password-stdin)"
token="$(printf '%s\n' "$session_json" | json_field '"capability_token"')"
principal_id="$(printf '%s\n' "$session_json" | json_field '"principal_id"')"

python3 - "$WORKDIR/policy.json" "${action_ref%@*}" "${action_ref#*@}" "$principal_id" <<'PY'
import json, pathlib, sys, time, uuid
path, action_id, action_version, principal_id = sys.argv[1:]
resource = {"type": "fixed-http-action", "id": action_id}
pathlib.Path(path).write_text(json.dumps({
    "format_version": 1,
    "version": 1,
    "expires_at_ms": int(time.time() * 1000) + 600000,
    "bindings": [{
        "action_id": action_id,
        "version": int(action_version),
        "resource": resource,
        "parameter_schema_id": "p0-crash-empty/v1",
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
printf '%s\n' "$PASSWORD" | "$REKEY" --state-dir "$STATE" policy activate --file "$WORKDIR/policy.json" --password-stdin >/dev/null

# Reuse one attacker-controlled frame request_id for two real executions. The
# transport responses must echo it, while durable execution IDs stay distinct.
python3 - "$STATE/runtime/agent.sock" "$STATE/vault.sqlite3" "$token" "${action_ref%@*}" "${action_ref#*@}" <<'PY'
import json, socket, sqlite3, struct, sys, uuid

sock_path, db, token, action_id, action_version = sys.argv[1:]
frame_id = uuid.UUID("11111111-1111-4111-8111-111111111111").bytes
metadata = json.dumps({
    "capability_token": token,
    "action_id": action_id,
    "action_version": int(action_version),
    "content_type": None,
    "extra_headers": [],
}, separators=(",", ":")).encode()
header = struct.pack(">4sHBBHH16sII", b"RKIP", 1, 2, 0, 1, 0, frame_id, len(metadata), 0)

def recv_exact(stream, length):
    chunks = []
    remaining = length
    while remaining:
        chunk = stream.recv(remaining)
        if not chunk:
            raise SystemExit("broker closed duplicate-id test connection")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)

con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
baseline = con.execute("SELECT coalesce(max(sequence), 0) FROM audit_events").fetchone()[0]
con.close()

with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as stream:
    stream.connect(sock_path)
    for _ in range(2):
        stream.sendall(header + metadata)
        raw = recv_exact(stream, 36)
        magic, version, channel, flags, message_type, reserved, response_id, meta_len, body_len = struct.unpack(
            ">4sHBBHH16sII", raw
        )
        recv_exact(stream, meta_len + body_len)
        if (magic, version, channel, flags, message_type, reserved, response_id) != (
            b"RKIP", 1, 2, 0, 100, 0, frame_id
        ):
            raise SystemExit(
                "invalid response to duplicate frame-id execution: "
                f"{(magic, version, channel, flags, message_type, reserved, response_id.hex())}"
            )

con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
rows = con.execute("""
    SELECT hex(s.request_id),
           (SELECT count(*) FROM audit_events t
            WHERE t.request_id = s.request_id
              AND t.event_type IN ('execution.finished', 'execution.blocked', 'execution.indeterminate'))
    FROM audit_events s
    WHERE s.sequence > ? AND s.event_type = 'execution.started'
    ORDER BY s.sequence
""", (baseline,)).fetchall()
con.close()
if len(rows) != 2 or len({row[0] for row in rows}) != 2 or any(row[1] != 1 for row in rows):
    raise SystemExit(f"frame request_id contaminated audit pairing: {rows}")
PY

# Step the actual rekeyd process—not the CLI wrapper—in short run intervals.
# Inspecting the real WAL while rekeyd is stopped makes the committed-started
# boundary observable even when the public upstream returns very quickly.
python3 - "$STATE/vault.sqlite3" "$BROKER_PID" <<'PY' &
import os, signal, sqlite3, subprocess, sys, time
db, pid = sys.argv[1], int(sys.argv[2])

def wait_stopped():
    deadline = time.monotonic() + 1
    while time.monotonic() < deadline:
        try:
            state = subprocess.check_output(
                ["ps", "-o", "state=", "-p", str(pid)], text=True
            ).strip()
        except subprocess.CalledProcessError:
            raise SystemExit("rekeyd exited before its stopped state was observable")
        if state.startswith("T"):
            return
        time.sleep(0.001)
    raise SystemExit("rekeyd did not enter stopped state")

def unmatched_request():
    con = sqlite3.connect(f"file:{db}?mode=ro", uri=True, timeout=0.1)
    row = con.execute("""
        SELECT hex(s.request_id)
        FROM audit_events s
        WHERE s.event_type = 'execution.started'
          AND NOT EXISTS (
            SELECT 1 FROM audit_events t
            WHERE t.request_id = s.request_id
              AND t.event_type IN ('execution.finished', 'execution.blocked', 'execution.indeterminate')
          )
        ORDER BY s.sequence DESC LIMIT 1
    """).fetchone()
    con.close()
    return row

deadline = time.monotonic() + 15
stopped = False
try:
    while time.monotonic() < deadline:
        os.kill(pid, signal.SIGSTOP)
        stopped = True
        wait_stopped()
        if unmatched_request():
            os.kill(pid, signal.SIGKILL)
            stopped = False
            raise SystemExit(0)
        os.kill(pid, signal.SIGCONT)
        stopped = False
        time.sleep(0.001)
finally:
    if stopped:
        os.kill(pid, signal.SIGCONT)
raise SystemExit("did not observe an unmatched execution.started while stepping rekeyd")
PY
POLL_PID=$!

EXEC_PIDS=""
for n in $(seq 1 16); do
  "$REKEY" --state-dir "$STATE" execute "$action_ref" --capability "$token" >"$WORKDIR/execute-$n.out" 2>"$WORKDIR/execute-$n.err" &
  EXEC_PIDS="$EXEC_PIDS $!"
done
wait "$POLL_PID"
set +e
wait "$BROKER_PID"
set -e
BROKER_PID=""
for pid in $EXEC_PIDS; do
  wait "$pid" 2>/dev/null || true
done
EXEC_PIDS=""

python3 - "$STATE/vault.sqlite3" "$STATE/vault.sqlite3.killed-requests" <<'PY'
import pathlib, sqlite3, sys

con = sqlite3.connect(f"file:{sys.argv[1]}?mode=ro", uri=True)
rows = con.execute("""
    SELECT hex(s.request_id)
    FROM audit_events s
    WHERE s.event_type = 'execution.started'
      AND NOT EXISTS (
        SELECT 1 FROM audit_events t
        WHERE t.request_id = s.request_id
          AND t.event_type IN ('execution.finished', 'execution.blocked', 'execution.indeterminate')
      )
    ORDER BY s.sequence
""").fetchall()
con.close()
if not rows:
    raise SystemExit("SIGKILL left no durable unmatched execution.started row")
pathlib.Path(sys.argv[2]).write_text("".join(f"{row[0]}\n" for row in rows))
PY

"$REKEYD" serve --state-dir "$STATE" --idle-lock 15m >"$WORKDIR/serve-2.out" 2>"$WORKDIR/serve-2.jsonl" &
BROKER_PID=$!
wait_for_socket

python3 - "$STATE/vault.sqlite3" "$STATE/vault.sqlite3.killed-requests" <<'PY'
import pathlib, sqlite3, sys
request_ids = pathlib.Path(sys.argv[2]).read_text().splitlines()
con = sqlite3.connect(f"file:{sys.argv[1]}?mode=ro", uri=True)
for request_hex in request_ids:
    rows = con.execute("""
        SELECT event_type, reason_code, principal_id, policy_version, policy_digest,
               policy_rule_id, resource_type, resource_id, parameter_hash
        FROM audit_events
        WHERE hex(request_id) = ? ORDER BY sequence
    """, (request_hex,)).fetchall()
    started = [row for row in rows if row[0] == 'execution.started']
    terminal = [row for row in rows if row[0] in ('execution.finished', 'execution.blocked', 'execution.indeterminate')]
    if len(started) != 1 or len(terminal) != 1 or terminal[0][:2] != ('execution.indeterminate', 'abandoned-on-restart'):
        raise SystemExit(f"bad crash reconciliation for {request_hex}: {rows}")
    if any(value is None for value in started[0][2:]) or terminal[0][2:] != started[0][2:]:
        raise SystemExit(f"crash reconciliation lost authorization evidence for {request_hex}: {rows}")
unpaired = con.execute("""
    SELECT count(*) FROM audit_events s
    WHERE s.event_type = 'execution.started'
      AND (SELECT count(*) FROM audit_events t
           WHERE t.request_id = s.request_id
             AND t.event_type IN ('execution.finished', 'execution.blocked', 'execution.indeterminate')) != 1
""").fetchone()[0]
if unpaired:
    raise SystemExit(f"found {unpaired} started rows without exactly one terminal")
con.close()
PY

"$REKEY" --state-dir "$STATE" shutdown >/dev/null
wait "$BROKER_PID"
BROKER_PID=""

if rg -a -q "$SECRET" "$WORKDIR" "$STATE"; then
  echo "crash recovery artifacts leaked the credential"
  exit 1
fi

echo "P0 crash recovery acceptance passed"
