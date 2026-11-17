#!/usr/bin/env bash
# Real-process crash recovery for the Connection model, release binaries only.
#  1. Two CALL frames reuse one Agent-chosen frame request_id: both responses
#     echo it, the runtime stays up and the durable execution IDs differ.
#  2. Tokenless CALLs commit execution.started; rekeyd is SIGKILLed while their
#     terminal audit insert is held. After restart, startup appends exactly one
#     execution.indeterminate(abandoned-on-restart) per unmatched started row,
#     keeping its signed authorization evidence; the vault restarts locked and
#     the signed Connection still governs the next CALL.
#  3. SIGKILL outside any execution (idle and with a pending approval) appends
#     no execution terminal and never revives the approval.
#
# The signed Connection targets https://localhost: after execution.started the
# production upstream screen refuses the loopback answer before any connect,
# so the effect phase is deterministic and needs no network. A temporary
# SQLite trigger delays only the terminal insert, as the archived Action gate
# did; it is dropped offline after SIGKILL and before restart because the vault
# refuses unknown schema objects at open. No test-only transport, screen bypass
# or secret in argv or the environment is used.
#
# Not covered: SIGKILL after a reachable upstream received the request. Release
# binaries refuse local fixtures by design, and a public upstream is neither
# deterministic nor available offline.
set -euo pipefail
umask 077

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN_DIR="${BIN_DIR:-$ROOT/target/release}"
# shellcheck source=scripts/p0-connection-lib.sh
source "$ROOT/scripts/p0-connection-lib.sh"
p0_require_binaries

random() { python3 -c 'import secrets; print(secrets.token_hex(16))'; }
PASSWORD="p0-crash-password-$(random)"
SECRET="p0-crash-canary-$(random)"

# macOS sockaddr_un is ~104 bytes; keep state-dir names tiny.
WORKDIR="$(mktemp -d "/tmp/rkc.XXXXXX")"
STATE="$WORKDIR/s"
KEY="$WORKDIR/signer.p8"
BROKER_PID=""
CALL_PIDS=""
cleanup() {
  for pid in $CALL_PIDS $BROKER_PID; do
    kill -CONT "$pid" 2>/dev/null || true
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
  done
  if [[ "${REKEY_KEEP_WORKDIR:-}" == "1" ]]; then
    echo "kept crash-recovery artifacts at $WORKDIR"
  else
    rm -rf "$WORKDIR"
  fi
}
trap cleanup EXIT

start_broker() {
  "$REKEYD" serve --state-dir "$STATE" --idle-lock 15m >/dev/null 2>"$WORKDIR/$1.jsonl" &
  BROKER_PID=$!
  p0_wait_for_broker "$STATE" "$BROKER_PID"
}

kill_broker() {
  kill -KILL "$BROKER_PID"
  wait "$BROKER_PID" 2>/dev/null || true
  BROKER_PID=""
}

audit() { p0_sql "$STATE/vault.sqlite3" "$1"; }
started_count() { audit "SELECT count(*) FROM audit_events WHERE event_type = 'execution.started'"; }
terminal_count() {
  audit "SELECT count(*) FROM audit_events
    WHERE event_type IN ('execution.finished', 'execution.blocked', 'execution.indeterminate')"
}
broker_state() { "$REKEY" --state-dir "$STATE" status --passive | p0_field state; }

echo "== vault, basic-mode software trust and a signed loopback Connection"
p0_proof | "$REKEY" --state-dir "$STATE" init --mode personal --password-stdin >/dev/null
p0_private_service_port "$STATE"
start_broker serve-1
p0_proof | "$REKEY" --state-dir "$STATE" unlock --password-stdin >/dev/null
cred_id="$(printf '%s\n%s\n' "$PASSWORD" "$SECRET" \
  | "$REKEY" --state-dir "$STATE" credential add crash-credential --stdin-secrets | p0_field id)"
p0_install_software_trust "$STATE" "$KEY"
p0_connection "$STATE" crash-local https://localhost "$cred_id" true "$WORKDIR/local.json"
python3 -c 'import json, sys; print(json.dumps([json.load(open(sys.argv[1]))]))' \
  "$WORKDIR/local.json" >"$WORKDIR/connections.json"
p0_activate_connections "$STATE" "$KEY" "$WORKDIR/connections.json"

echo "== a reused frame request_id is transport correlation only"
python3 - "$STATE/runtime/agent.sock" <<'PY'
import json, socket, struct, sys, uuid

frame_id = uuid.UUID("11111111-1111-4111-8111-111111111111").bytes
metadata = json.dumps({"connection": "crash-local", "method": "GET", "path": "/p0/allowed"},
                      separators=(",", ":")).encode()
header = struct.pack(">4sHBBHH16sII", b"RKIP", 1, 2, 0, 11, 0, frame_id, len(metadata), 0)

def recv_exact(stream, length):
    data = b""
    while len(data) < length:
        chunk = stream.recv(length - len(data))
        if not chunk:
            raise SystemExit("broker closed the reused-frame-id connection")
        data += chunk
    return data

with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as stream:
    stream.connect(sys.argv[1])
    for _ in range(2):
        stream.sendall(header + metadata)
        fields = struct.unpack(">4sHBBHH16sII", recv_exact(stream, 36))
        reply = json.loads(recv_exact(stream, fields[7]))
        recv_exact(stream, fields[8])
        if fields[:7] != (b"RKIP", 1, 2, 0, 101, 0, frame_id) or reply["code"] != "UPSTREAM_ADDRESS_BLOCKED":
            raise SystemExit(f"reused frame id changed the CALL outcome: {fields[4]} {reply.get('code')}")
PY
[[ "$(broker_state)" == "unlocked" ]] || p0_fail "a reused frame id faulted the runtime"
python3 - "$STATE/vault.sqlite3" <<'PY'
import sqlite3, sys
con = sqlite3.connect(f"file:{sys.argv[1]}?mode=ro", uri=True)
rows = con.execute("""
    SELECT hex(s.request_id),
           (SELECT count(*) FROM audit_events t WHERE t.request_id = s.request_id
              AND t.event_type IN ('execution.finished', 'execution.blocked', 'execution.indeterminate'))
    FROM audit_events s WHERE s.event_type = 'execution.started' ORDER BY s.sequence""").fetchall()
con.close()
frame = "11111111111141118111111111111111"
if len(rows) != 2 or len({row[0] for row in rows}) != 2 or any(row[0] == frame or row[1] != 1 for row in rows):
    raise SystemExit(f"frame request_id contaminated audit pairing: {rows}")
PY

echo "== SIGKILL while the terminal audit insert is held"
python3 - "$STATE/vault.sqlite3" <<'PY'
import sqlite3, sys
con = sqlite3.connect(sys.argv[1])
con.executescript("""
CREATE TRIGGER crash_hold_terminal
BEFORE INSERT ON audit_events
WHEN NEW.event_type IN ('execution.finished', 'execution.blocked', 'execution.indeterminate')
BEGIN
  SELECT sum(value) FROM (
    WITH RECURSIVE counter(value) AS (
      VALUES(0) UNION ALL SELECT value + 1 FROM counter WHERE value < 100000000
    )
    SELECT value FROM counter
  );
END;
""")
con.close()
PY
for n in 1 2 3 4; do
  "$REKEY" --state-dir "$STATE" http crash-local GET /p0/allowed \
    >"$WORKDIR/call-$n.out" 2>"$WORKDIR/call-$n.err" &
  CALL_PIDS="$CALL_PIDS $!"
done
# Once the WAL exposes a committed unmatched start, stop rekeyd, confirm the
# stopped state, and recheck the row before SIGKILL.
python3 - "$STATE/vault.sqlite3" "$BROKER_PID" <<'PY'
import os, signal, sqlite3, subprocess, sys, time
db, pid = sys.argv[1], int(sys.argv[2])

def wait_stopped():
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        try:
            state = subprocess.check_output(["ps", "-o", "state=", "-p", str(pid)], text=True).strip()
        except subprocess.CalledProcessError:
            raise SystemExit("rekeyd exited before its stopped state was observable")
        if state.startswith("T"):
            return
        time.sleep(0.001)
    raise SystemExit("rekeyd did not enter the stopped state")

def unmatched():
    con = sqlite3.connect(f"file:{db}?mode=ro", uri=True, timeout=0.1)
    row = con.execute("""
        SELECT 1 FROM audit_events s
        WHERE s.event_type = 'execution.started' AND NOT EXISTS (
          SELECT 1 FROM audit_events t WHERE t.request_id = s.request_id
            AND t.event_type IN ('execution.finished', 'execution.blocked', 'execution.indeterminate'))
        LIMIT 1""").fetchone()
    con.close()
    return row

deadline = time.monotonic() + 30
stopped = False
try:
    while time.monotonic() < deadline:
        if unmatched():
            os.kill(pid, signal.SIGSTOP)
            stopped = True
            wait_stopped()
            if unmatched():
                os.kill(pid, signal.SIGKILL)
                stopped = False
                raise SystemExit(0)
            os.kill(pid, signal.SIGCONT)
            stopped = False
        time.sleep(0.005)
finally:
    if stopped:
        os.kill(pid, signal.SIGCONT)
raise SystemExit("did not preserve an unmatched execution.started before its terminal audit")
PY
wait "$BROKER_PID" 2>/dev/null || true
BROKER_PID=""
for pid in $CALL_PIDS; do
  wait "$pid" 2>/dev/null || true
done
CALL_PIDS=""

python3 - "$STATE/vault.sqlite3" "$WORKDIR/killed-requests" <<'PY'
import pathlib, sqlite3, sys
con = sqlite3.connect(sys.argv[1])
rows = con.execute("""
    SELECT hex(s.request_id) FROM audit_events s
    WHERE s.event_type = 'execution.started' AND NOT EXISTS (
      SELECT 1 FROM audit_events t WHERE t.request_id = s.request_id
        AND t.event_type IN ('execution.finished', 'execution.blocked', 'execution.indeterminate'))
    ORDER BY s.sequence""").fetchall()
con.execute("DROP TRIGGER crash_hold_terminal")
con.commit()
con.close()
if not rows:
    raise SystemExit("SIGKILL left no durable unmatched execution.started row")
pathlib.Path(sys.argv[2]).write_text("".join(f"{row[0]}\n" for row in rows))
PY

echo "== restart appends exactly one abandoned terminal per unmatched start"
start_broker serve-2
python3 - "$STATE/vault.sqlite3" "$WORKDIR/killed-requests" <<'PY'
import pathlib, sqlite3, sys
con = sqlite3.connect(f"file:{sys.argv[1]}?mode=ro", uri=True)
for request_hex in pathlib.Path(sys.argv[2]).read_text().splitlines():
    rows = con.execute("""
        SELECT event_type, reason_code, principal_id, policy_version, policy_digest,
               policy_rule_id, resource_type, resource_id, parameter_hash
        FROM audit_events WHERE hex(request_id) = ? ORDER BY sequence""", (request_hex,)).fetchall()
    started = [row for row in rows if row[0] == "execution.started"]
    terminal = [row for row in rows if row[0] in ("execution.finished", "execution.blocked",
                                                  "execution.indeterminate")]
    if len(started) != 1 or len(terminal) != 1 \
            or terminal[0][:2] != ("execution.indeterminate", "abandoned-on-restart"):
        raise SystemExit(f"bad crash reconciliation for {request_hex}: {rows}")
    if any(value is None for value in started[0][2:]) or terminal[0][2:] != started[0][2:] \
            or started[0][6:8] != ("connection", "crash-local"):
        raise SystemExit(f"crash reconciliation lost authorization evidence for {request_hex}")
con.close()
PY
p0_assert_audit_pairing "$STATE/vault.sqlite3"

echo "== the restarted vault is locked and the signed Connection still governs CALLs"
[[ "$(broker_state)" == "locked" ]] || p0_fail "restart did not come up locked"
p0_proof | "$REKEY" --state-dir "$STATE" unlock --password-stdin >/dev/null
before="$(started_count)"
p0_expect_exit 6 "$REKEY" --state-dir "$STATE" http crash-local GET /p0/allowed
[[ "$(started_count)" == "$((before + 1))" ]] || p0_fail "restarted broker did not admit the CALL"
p0_assert_audit_pairing "$STATE/vault.sqlite3"

echo "== SIGKILL of an idle unlocked broker appends no execution terminal"
before="$(terminal_count)"
kill_broker
start_broker serve-3
[[ "$(broker_state)" == "locked" && "$(terminal_count)" == "$before" ]] \
  || p0_fail "idle crash changed execution audit or did not restart locked"

echo "== SIGKILL with a pending approval never revives it"
p0_proof | "$REKEY" --state-dir "$STATE" unlock --password-stdin >/dev/null
p0_expect_exit 4 "$REKEY" --state-dir "$STATE" http crash-local GET /p0/approve --no-wait
grep -q APPROVAL_REQUIRED "$WORKDIR/expect.err" || p0_fail "approve rule did not require approval"
approval_id="$(p0_field approval challenge_id <"$WORKDIR/expect.err")"
kill_broker
start_broker serve-4
p0_proof | "$REKEY" --state-dir "$STATE" unlock --password-stdin >/dev/null
before="$(started_count)"
p0_expect_exit 4 "$REKEY" --state-dir "$STATE" http crash-local GET /p0/approve --approval "$approval_id"
grep -q DENIED "$WORKDIR/expect.err" || p0_fail "a pre-crash approval was not refused"
[[ "$(started_count)" == "$before" ]] || p0_fail "a pre-crash approval admitted an execution"
p0_assert_audit_pairing "$STATE/vault.sqlite3"

p0_proof | "$REKEY" --state-dir "$STATE" shutdown --password-stdin >/dev/null
wait "$BROKER_PID" 2>/dev/null || true
BROKER_PID=""

echo "== disk and output secret canary"
printf '%s\n' "$PASSWORD" "$SECRET" | p0_assert_no_secret_on_disk "$WORKDIR"

echo "P0 crash recovery acceptance passed"
