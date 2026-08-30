#!/usr/bin/env bash
# Real-process runtime fault acceptance. Forces the release broker into EMFILE
# while Agent UDS connections are arriving and proves it exits nonzero instead
# of leaving one channel silently dead inside a half-alive daemon.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN_DIR="${BIN_DIR:-$ROOT/target/release}"
REKEY="${BIN_DIR}/rekey"
PASSWORD="runtime fault acceptance password"

if [[ ! -x "$REKEY" || ! -x "${BIN_DIR}/rekeyd" ]]; then
  cargo build --release -p rekey-cli -p rekey-broker
fi

WORKDIR="$(mktemp -d "/tmp/rkf.XXXXXX")"
STATE="$WORKDIR/s"
cleanup() {
  if [[ -n "${SERVE_PID:-}" ]]; then
    kill "$SERVE_PID" 2>/dev/null || true
    wait "$SERVE_PID" 2>/dev/null || true
  fi
  if [[ "${REKEY_KEEP_WORKDIR:-}" == "1" ]]; then
    echo "kept runtime-fault artifacts at $WORKDIR"
  else
    rm -rf "$WORKDIR"
  fi
}
trap cleanup EXIT

printf '%s\n' "$PASSWORD" | "$REKEY" --state-dir "$STATE" init --password-stdin >/dev/null

(
  ulimit -n 64
  exec "$REKEY" --state-dir "$STATE" serve --idle-lock 15m
) >"$WORKDIR/stdout.log" 2>"$WORKDIR/stderr.jsonl" &
SERVE_PID=$!

for _ in $(seq 1 200); do
  [[ -S "$STATE/runtime/agent.sock" ]] && break
  sleep 0.02
done
[[ -S "$STATE/runtime/agent.sock" ]] || { echo "broker did not start"; exit 1; }

python3 - "$STATE/runtime/agent.sock" <<'PY'
import socket, sys, time
sockets = []
for _ in range(160):
    try:
        conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        conn.connect(sys.argv[1])
        sockets.append(conn)
    except OSError:
        break
time.sleep(1)
PY

for _ in $(seq 1 200); do
  ! kill -0 "$SERVE_PID" 2>/dev/null && break
  sleep 0.02
done
if kill -0 "$SERVE_PID" 2>/dev/null; then
  echo "broker stayed half-alive after listener fault"
  exit 1
fi

set +e
wait "$SERVE_PID"
serve_rc=$?
set -e
SERVE_PID=""
[[ "$serve_rc" -eq 5 ]] || { echo "expected runtime fault exit 5, got $serve_rc"; exit 1; }

python3 - "$WORKDIR/stderr.jsonl" <<'PY'
import json, pathlib, sys
events = []
for line in pathlib.Path(sys.argv[1]).read_text().splitlines():
    if line.strip():
        events.append(json.loads(line)["fields"]["event"])
required = {"runtime.starting", "runtime.listener_fault", "rekeyd.command_failed"}
missing = required.difference(events)
if missing:
    raise SystemExit(f"missing structured runtime events: {sorted(missing)}")
PY

if rg -a -q 'runtime fault acceptance password' "$WORKDIR"; then
  echo "runtime logs leaked password"
  exit 1
fi

echo "P0 runtime fault acceptance passed"
