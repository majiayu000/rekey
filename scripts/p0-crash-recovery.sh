#!/usr/bin/env bash
# Real-process crash recovery: kill rekeyd after execution.started commits,
# restart it, and prove startup appends exactly one abandoned terminal event.
set -euo pipefail
umask 077

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
    [[ -S "$STATE/runtime/admin.sock" ]] && return
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

# Poll the real WAL database. The moment an unmatched started row is visible,
# SIGKILL the actual rekeyd process—not the CLI wrapper.
python3 - "$STATE/vault.sqlite3" "$BROKER_PID" <<'PY' &
import os, signal, sqlite3, sys, time
db, pid = sys.argv[1], int(sys.argv[2])
deadline = time.monotonic() + 10
while time.monotonic() < deadline:
    con = sqlite3.connect(f"file:{db}?mode=ro", uri=True, timeout=0.1)
    row = con.execute("""
        SELECT hex(s.request_id)
        FROM audit_events s
        WHERE s.event_type = 'execution.started'
          AND NOT EXISTS (
            SELECT 1 FROM audit_events t
            WHERE t.request_id = s.request_id
              AND t.event_type IN ('execution.finished', 'execution.blocked')
          )
        ORDER BY s.sequence DESC LIMIT 1
    """).fetchone()
    con.close()
    if row:
        pathlib = __import__('pathlib')
        pathlib.Path(sys.argv[1] + ".killed-request").write_text(row[0])
        os.kill(pid, signal.SIGKILL)
        raise SystemExit(0)
    time.sleep(0.002)
raise SystemExit("did not observe an unmatched execution.started")
PY
POLL_PID=$!

EXEC_PIDS=""
for n in 1 2 3 4; do
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

"$REKEYD" serve --state-dir "$STATE" --idle-lock 15m >"$WORKDIR/serve-2.out" 2>"$WORKDIR/serve-2.jsonl" &
BROKER_PID=$!
wait_for_socket

python3 - "$STATE/vault.sqlite3" "$STATE/vault.sqlite3.killed-request" <<'PY'
import pathlib, sqlite3, sys
request_hex = pathlib.Path(sys.argv[2]).read_text().strip()
con = sqlite3.connect(f"file:{sys.argv[1]}?mode=ro", uri=True)
rows = con.execute("""
    SELECT event_type, reason_code FROM audit_events
    WHERE hex(request_id) = ? ORDER BY sequence
""", (request_hex,)).fetchall()
started = [row for row in rows if row[0] == 'execution.started']
terminal = [row for row in rows if row[0] in ('execution.finished', 'execution.blocked')]
if len(started) != 1 or terminal != [('execution.blocked', 'abandoned-on-restart')]:
    raise SystemExit(f"bad crash reconciliation: {rows}")
unpaired = con.execute("""
    SELECT count(*) FROM audit_events s
    WHERE s.event_type = 'execution.started'
      AND (SELECT count(*) FROM audit_events t
           WHERE t.request_id = s.request_id
             AND t.event_type IN ('execution.finished', 'execution.blocked')) != 1
""").fetchone()[0]
if unpaired:
    raise SystemExit(f"found {unpaired} started rows without exactly one terminal")
PY

"$REKEY" --state-dir "$STATE" shutdown >/dev/null
wait "$BROKER_PID"
BROKER_PID=""

if rg -a -q "$SECRET" "$WORKDIR" "$STATE"; then
  echo "crash recovery artifacts leaked the credential"
  exit 1
fi

echo "P0 crash recovery acceptance passed"
