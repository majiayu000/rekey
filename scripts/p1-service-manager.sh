#!/usr/bin/env bash
# Native manager acceptance using release CLI + BrokerRuntime fixture, dual UDS,
# SQLite, and local CA/TLS. Linux is accepted only with systemd as PID 1.
set -euo pipefail
umask 077

command -v rg >/dev/null || {
  echo "p1-service-manager requires ripgrep (rg)" >&2
  exit 1
}

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN_DIR="${BIN_DIR:-$ROOT/target/release}"
REKEY="$BIN_DIR/rekey"
REKEYD="$BIN_DIR/rekeyd"
FIXTURE="${REKEY_SERVICE_FIXTURE:-$ROOT/target/release/examples/p1_policy_fixture}"
GENERATOR="${REKEY_SERVICE_GENERATOR:-$ROOT/scripts/rekey-service-unit.py}"
MANAGED_DAEMON_SOURCE="${REKEY_SERVICE_MANAGED_DAEMON:-}"
ARTIFACT_DAEMON_MODE=0
if [[ -n "$MANAGED_DAEMON_SOURCE" ]]; then
  ARTIFACT_DAEMON_MODE=1
else
  MANAGED_DAEMON_SOURCE="$FIXTURE"
fi
PASSWORD="p1 service manager horse battery staple"
SECRET="P1-SERVICE-MANAGER-CANARY"
PLATFORM="$(uname -s)"

if [[ "$PLATFORM" == Linux && "$(ps -p 1 -o comm= | tr -d ' ')" != systemd ]]; then
  echo "systemd acceptance requires systemd as PID 1" >&2
  exit 77
fi
if [[ "$PLATFORM" != Darwin && "$PLATFORM" != Linux ]]; then
  echo "unsupported service manager platform: $PLATFORM" >&2
  exit 77
fi
if [[ "$PLATFORM" == Linux && "$(id -u)" -eq 0 ]]; then
  echo "systemd acceptance must exercise a non-root service account" >&2
  exit 77
fi

run_bounded() {
  local seconds="$1"
  shift
  python3 - "$seconds" "$@" <<'PY'
import subprocess, sys
try:
    result = subprocess.run(sys.argv[2:], timeout=float(sys.argv[1]))
except subprocess.TimeoutExpired:
    raise SystemExit(124)
raise SystemExit(result.returncode)
PY
}

run_root_bounded() {
  local seconds="$1"
  shift
  if [[ "$(id -u)" -eq 0 ]]; then
    run_bounded "$seconds" "$@"
  else
    run_bounded "$seconds" sudo -n "$@"
  fi
}

pid_running() {
  local pid="$1" state
  kill -0 "$pid" 2>/dev/null || return 1
  state="$(ps -o stat= -p "$pid" 2>/dev/null || true)"
  [[ -n "$state" && "$state" != Z* ]]
}

wait_pid_bounded() {
  local pid="$1" seconds="$2" ticks
  ticks=$((seconds * 20))
  for _ in $(seq 1 "$ticks"); do
    pid_running "$pid" || { wait "$pid" 2>/dev/null || true; return 0; }
    sleep 0.05
  done
  return 1
}

terminate_pid() {
  local pid="${1:-}"
  [[ -n "$pid" ]] || return 0
  kill -TERM "$pid" 2>/dev/null || true
  if ! wait_pid_bounded "$pid" 2; then
    kill -KILL "$pid" 2>/dev/null || true
    wait_pid_bounded "$pid" 2 || return 1
  fi
}

if [[ ! -x "$REKEY" || ! -x "$REKEYD" ]]; then
  if [[ "${REKEY_SERVICE_REQUIRE_BINARIES:-}" == "1" ]]; then
    echo "required release binaries are missing from BIN_DIR: $BIN_DIR" >&2
    exit 1
  fi
  cargo build --release -p rekey-cli --bin rekey -p rekey-broker --bin rekeyd
fi
if [[ "$ARTIFACT_DAEMON_MODE" -eq 0 ]]; then
  cargo build --release -p rekey-broker --example p1_policy_fixture
fi
[[ -x "$MANAGED_DAEMON_SOURCE" ]] || {
  echo "managed daemon is not executable: $MANAGED_DAEMON_SOURCE" >&2
  exit 1
}

WORKDIR="$(mktemp -d /tmp/rksvc.XXXXXX)"
STATE="$WORKDIR/state"
MANAGED_DAEMON="$WORKDIR/managed-rekeyd"
LABEL="com.openai.rekey.p1.$(id -u).$$"
UNIT="rekey-p1-$(id -u)-$$.service"
PLIST="$WORKDIR/$LABEL.plist"
UNIT_FILE="$WORKDIR/$UNIT"
SYSTEM_UNIT_PATH="/etc/systemd/system/$UNIT"
MANAGER_ACTIVE=0
UNIT_INSTALLED=0
MANAGER_PID=""
PARTIAL_PID=""
RACE_PID=""
EXEC_PID=""
ROUND=0
ROUND_OFFSET=0
INVOCATION_ID=""

manager_pid() {
  if [[ "$PLATFORM" == Darwin ]]; then
    run_bounded 5 launchctl print "gui/$(id -u)/$LABEL" |
      awk '$1 == "pid" && $2 == "=" {print $3; exit}'
  else
    run_root_bounded 5 systemctl show "$UNIT" --property MainPID --value
  fi
}

cleanup() {
  local rc=$?
  if [[ "$rc" -ne 0 ]]; then
    for log in "$WORKDIR"/round-*.log "$STATE"/rekeyd.stderr.log; do
      [[ -f "$log" ]] && { echo "--- $log" >&2; tail -80 "$log" >&2; }
    done
  fi
  terminate_pid "$RACE_PID" || true
  terminate_pid "$PARTIAL_PID" || true
  terminate_pid "$EXEC_PID" || true
  if [[ "$MANAGER_ACTIVE" -eq 1 ]]; then
    if [[ "$PLATFORM" == Darwin ]]; then
      run_bounded 5 launchctl bootout "gui/$(id -u)/$LABEL" >/dev/null 2>&1 || true
    else
      run_root_bounded 5 systemctl stop "$UNIT" >/dev/null 2>&1 || true
    fi
    terminate_pid "$MANAGER_PID" || true
  fi
  if [[ "$UNIT_INSTALLED" -eq 1 ]]; then
    run_root_bounded 5 rm -f "$SYSTEM_UNIT_PATH" || true
    run_root_bounded 10 systemctl daemon-reload >/dev/null 2>&1 || true
    run_root_bounded 5 systemctl reset-failed "$UNIT" >/dev/null 2>&1 || true
  fi
  rm -rf "$WORKDIR"
}
trap cleanup EXIT

# LaunchAgents may not execute a developer binary beneath a TCC-protected
# Desktop checkout. Exercise the exact release artifact from its install path.
install -m 0755 "$MANAGED_DAEMON_SOURCE" "$MANAGED_DAEMON"

# Generator contract: real non-root passwd entry, no UID-0 alias, escaped '$'.
GOLDEN_STATE="$WORKDIR/systemd\$state"
mkdir -p "$GOLDEN_STATE"
for bad_user in root "rekey-no-such-user-$$"; do
  if python3 "$GENERATOR" systemd --rekeyd "$MANAGED_DAEMON" --state-dir "$GOLDEN_STATE" \
    --run-as-user "$bad_user" >/dev/null 2>&1; then
    echo "generator accepted forbidden user: $bad_user" >&2
    exit 1
  fi
done
if python3 "$GENERATOR" systemd --rekeyd "$MANAGED_DAEMON" --state-dir "$GOLDEN_STATE" \
  >/dev/null 2>&1; then
  echo "generator accepted missing --run-as-user" >&2
  exit 1
fi
python3 "$GENERATOR" systemd --rekeyd "$MANAGED_DAEMON" --state-dir "$GOLDEN_STATE" \
  --run-as-user "$(id -un)" >"$WORKDIR/golden.service"
grep -Fq 'TimeoutStopSec=130s' "$WORKDIR/golden.service"
grep -Fq "systemd\$\$state" "$WORKDIR/golden.service"

json_field() {
  python3 -c 'import json,sys; print(json.load(sys.stdin)[sys.argv[1]])' "$1"
}

wait_for_socket() {
  for _ in $(seq 1 300); do
    if [[ -S "$STATE/runtime/admin.sock" && -S "$STATE/runtime/agent.sock" ]] &&
      "$REKEY" --state-dir "$STATE" status >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.05
  done
  echo "manager failed to expose real Admin and Agent UDS" >&2
  return 1
}

start_manager() {
  ROUND=$((ROUND + 1))
  if [[ "$PLATFORM" == Darwin ]]; then
    ROUND_OFFSET=0
    [[ ! -f "$STATE/rekeyd.stderr.log" ]] || ROUND_OFFSET="$(wc -c <"$STATE/rekeyd.stderr.log" | tr -d ' ')"
    run_bounded 10 launchctl bootstrap "gui/$(id -u)" "$PLIST"
  else
    run_root_bounded 10 systemctl start "$UNIT"
    INVOCATION_ID="$(run_root_bounded 5 systemctl show "$UNIT" --property InvocationID --value)"
    [[ -n "$INVOCATION_ID" ]]
  fi
  MANAGER_ACTIVE=1
  wait_for_socket
  MANAGER_PID="$(manager_pid)"
  [[ "$MANAGER_PID" =~ ^[1-9][0-9]*$ ]] && pid_running "$MANAGER_PID"
}

capture_log() {
  local output="$WORKDIR/round-$ROUND.log"
  if [[ "$PLATFORM" == Darwin ]]; then
    python3 - "$STATE/rekeyd.stderr.log" "$output" "$ROUND_OFFSET" <<'PY'
import pathlib, sys
data = pathlib.Path(sys.argv[1]).read_bytes()
offset = int(sys.argv[3])
if len(data) < offset:
    raise SystemExit("manager log truncated")
pathlib.Path(sys.argv[2]).write_bytes(data[offset:])
PY
  else
    run_root_bounded 10 journalctl _SYSTEMD_INVOCATION_ID="$INVOCATION_ID" --no-pager >"$output"
  fi
}

stop_manager() {
  local started="$SECONDS"
  if [[ "$PLATFORM" == Darwin ]]; then
    run_bounded 15 launchctl bootout "gui/$(id -u)/$LABEL"
  else
    run_root_bounded 15 systemctl stop "$UNIT"
  fi
  wait_pid_bounded "$MANAGER_PID" 15
  [[ $((SECONDS - started)) -le 15 ]]
  [[ ! -e "$STATE/runtime/admin.sock" && ! -e "$STATE/runtime/agent.sock" ]]
  capture_log
  MANAGER_ACTIVE=0
  MANAGER_PID=""
}

start_partial_frame() {
  python3 - "$STATE/runtime/agent.sock" "$WORKDIR/partial.ready" <<'PY' &
import pathlib, socket, sys
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect(sys.argv[1]); s.sendall(b"R"); pathlib.Path(sys.argv[2]).touch()
while s.recv(1024): pass
PY
  PARTIAL_PID=$!
  for _ in $(seq 1 100); do [[ -f "$WORKDIR/partial.ready" ]] && return; sleep 0.05; done
  return 1
}

start_unlock_race() {
  ( while [[ -S "$STATE/runtime/admin.sock" ]]; do
      printf '%s\n' "$PASSWORD" | "$REKEY" --state-dir "$STATE" unlock --password-stdin >/dev/null 2>&1 || true
    done ) &
  RACE_PID=$!
}

activate_policy() {
  local version="$1" principal="$2"
  python3 - "$WORKDIR/policy.json" "$ACTION_ID" "$ACTION_VERSION" "$principal" "$version" <<'PY'
import json, pathlib, sys, time, uuid
path, action, version, principal, policy_version = sys.argv[1:]
resource = {"type":"fixed-http-action", "id":action}
binding = {"action_id":action, "version":int(version), "resource":resource,
 "parameter_schema_id":"service-mode/v1", "parameter_schema":{"type":"object",
 "required":["mode"], "properties":{"mode":{"type":"string"}}, "additionalProperties":False}}
rule = {"id":str(uuid.uuid4()), "effect":"permit", "principal_id":principal,
 "action_id":action, "version":int(version), "resource":resource,
 "parameters":{"kind":"any_validated"}}
pathlib.Path(path).write_text(json.dumps({"format_version":3,"version":int(policy_version),
 "expires_at_ms":int(time.time()*1000)+600000,"approvers":[],"workload_identities":[],
 "bindings":[binding],"rules":[rule]}))
PY
  python3 "$ROOT/scripts/sign-test-policy.py" policy --key-dir "$WORKDIR/policy-key" \
    --snapshot "$WORKDIR/policy.json" --bundle "$WORKDIR/policy-bundle.json" \
    --trust "$WORKDIR/policy-trust.json"
  printf '%s\n' "$PASSWORD" | "$REKEY" --state-dir "$STATE" policy trust install \
    --file "$WORKDIR/policy-trust.json" --step-up-stdin >/dev/null
  printf '%s\n' "$PASSWORD" | "$REKEY" --state-dir "$STATE" policy activate \
    --file "$WORKDIR/policy-bundle.json" --step-up-stdin >/dev/null
}

printf '%s\n' "$PASSWORD" | "$REKEYD" init --state-dir "$STATE" --password-stdin >/dev/null
if [[ "$PLATFORM" == Darwin ]]; then
  python3 "$GENERATOR" launchd --rekeyd "$MANAGED_DAEMON" --state-dir "$STATE" --label "$LABEL" >"$PLIST"
  plutil -lint "$PLIST" >/dev/null
  if rg -n 'EnvironmentVariables|REKEY_PASSWORD|--password|--unlock' "$PLIST"; then exit 1; fi
else
  python3 "$GENERATOR" systemd --rekeyd "$MANAGED_DAEMON" --state-dir "$STATE" \
    --run-as-user "$(id -un)" >"$UNIT_FILE"
  systemd-analyze verify "$UNIT_FILE"
  if rg -n 'Environment=|REKEY_PASSWORD|--password|--unlock' "$UNIT_FILE"; then exit 1; fi
  run_root_bounded 5 install -m 0644 "$UNIT_FILE" "$SYSTEM_UNIT_PATH"
  UNIT_INSTALLED=1
  run_root_bounded 10 systemctl daemon-reload
fi

start_manager
[[ "$("$REKEY" --state-dir "$STATE" status | json_field state)" == locked ]]
if [[ "$ARTIFACT_DAEMON_MODE" -eq 1 ]]; then
  printf '%s\n' "$PASSWORD" | "$REKEY" --state-dir "$STATE" unlock --password-stdin >/dev/null
  stop_manager
  grep -q '"event":"runtime.signal_received"' "$WORKDIR/round-1.log"
  grep -q '"event":"runtime.stopped"' "$WORKDIR/round-1.log"

  start_manager
  [[ "$("$REKEY" --state-dir "$STATE" status | json_field state)" == locked ]]
  CRASHED_PID="$MANAGER_PID"
  kill -KILL "$CRASHED_PID"
  wait_pid_bounded "$CRASHED_PID" 5
  for _ in $(seq 1 400); do
    if [[ -S "$STATE/runtime/admin.sock" ]] && "$REKEY" --state-dir "$STATE" status >/dev/null 2>&1; then
      MANAGER_PID="$(manager_pid)"
      if [[ "$MANAGER_PID" =~ ^[1-9][0-9]*$ && "$MANAGER_PID" != "$CRASHED_PID" ]] && pid_running "$MANAGER_PID"; then
        break
      fi
    fi
    sleep 0.05
  done
  [[ "$MANAGER_PID" =~ ^[1-9][0-9]*$ && "$MANAGER_PID" != "$CRASHED_PID" ]] && pid_running "$MANAGER_PID"
  [[ "$("$REKEY" --state-dir "$STATE" status | json_field state)" == locked ]]
  printf '%s\n' "$PASSWORD" | "$REKEY" --state-dir "$STATE" unlock --password-stdin >/dev/null

  ADMIN_PID="$MANAGER_PID"
  printf '%s\n' "$PASSWORD" | "$REKEY" --state-dir "$STATE" shutdown --password-stdin >"$WORKDIR/admin-shutdown.out"
  grep -q '"shutdown": true' "$WORKDIR/admin-shutdown.out"
  wait_pid_bounded "$ADMIN_PID" 15
  if [[ "$PLATFORM" == Darwin ]]; then
    run_bounded 10 launchctl bootout "gui/$(id -u)/$LABEL" >/dev/null 2>&1
  else
    run_root_bounded 10 systemctl stop "$UNIT" >/dev/null 2>&1
  fi
  CURRENT_PID="$(manager_pid 2>/dev/null || true)"
  if [[ "$CURRENT_PID" =~ ^[1-9][0-9]*$ ]] && pid_running "$CURRENT_PID"; then
    echo "native manager still owns a live process after final unload" >&2
    exit 1
  fi
  MANAGER_ACTIVE=0
  MANAGER_PID=""
  echo "P1 release-daemon service-manager acceptance passed on $PLATFORM"
  exit 0
fi
PORT="$(tr -d '\n' <"$STATE/fixture.port")"
printf '%s\n' "$PASSWORD" | "$REKEY" --state-dir "$STATE" unlock --password-stdin >/dev/null
CRED_JSON="$(printf '%s\n%s\n' "$PASSWORD" "$SECRET" | "$REKEY" --state-dir "$STATE" credential add service --stdin-secrets)"
CRED_ID="$(printf '%s\n' "$CRED_JSON" | json_field id)"
python3 - "$WORKDIR/action.json" "$CRED_ID" "$PORT" <<'PY'
import json, pathlib, sys
pathlib.Path(sys.argv[1]).write_text(json.dumps({"name":"service-slow","credential_id":sys.argv[2],
 "origin":f"https://api.test.local:{sys.argv[3]}","method":"POST","exact_path":"/v1/sealing",
 "auth_header":"authorization","auth_prefix":"Bearer ","timeout_ms":10000,"request_max_bytes":1024,
 "allowed_extra_headers":[],"response_max_bytes":4096,"allowed_response_headers":["content-type"]}))
PY
ACTION_JSON="$(printf '%s\n' "$PASSWORD" | "$REKEY" --state-dir "$STATE" action create --file "$WORKDIR/action.json" --password-stdin)"
ACTION_ID="$(printf '%s\n' "$ACTION_JSON" | json_field id)"
ACTION_VERSION="$(printf '%s\n' "$ACTION_JSON" | json_field version)"
ACTION_REF="$ACTION_ID@$ACTION_VERSION"
SESSION_JSON="$(printf '%s\n' "$PASSWORD" | "$REKEY" --state-dir "$STATE" session create --action "$ACTION_REF" --ttl 10m --max-uses 4 --password-stdin)"
PRINCIPAL="$(printf '%s\n' "$SESSION_JSON" | json_field principal_id)"
TOKEN="$(printf '%s\n' "$SESSION_JSON" | json_field capability_token)"
activate_policy 1 "$PRINCIPAL"
printf '%s\n' '{"mode":"slow"}' >"$WORKDIR/slow.json"
"$REKEY" --state-dir "$STATE" execute "$ACTION_REF" --capability "$TOKEN" \
  --body-file "$WORKDIR/slow.json" --content-type application/json >"$WORKDIR/slow.out" 2>"$WORKDIR/slow.err" &
EXEC_PID=$!
for _ in $(seq 1 200); do
  [[ "$(sqlite3 "$STATE/vault.sqlite3" "SELECT count(*) FROM audit_events WHERE event_type='execution.started';")" -eq 1 ]] && break
  sleep 0.025
done
[[ "$(sqlite3 "$STATE/vault.sqlite3" "SELECT count(*) FROM audit_events WHERE event_type='execution.started';")" -eq 1 ]]
for _ in $(seq 1 200); do
  [[ -f "$STATE/fixture.hits" && "$(tr -d '\n' <"$STATE/fixture.hits")" -eq 1 ]] && break
  sleep 0.025
done
[[ "$(tr -d '\n' <"$STATE/fixture.hits")" -eq 1 ]]
kill -TERM "$EXEC_PID" 2>/dev/null || true
wait_pid_bounded "$EXEC_PID" 2
EXEC_PID=""
start_partial_frame
start_unlock_race
stop_manager
terminate_pid "$RACE_PID"; RACE_PID=""
wait_pid_bounded "$PARTIAL_PID" 2; PARTIAL_PID=""
grep -q '"event":"runtime.signal_received"' "$WORKDIR/round-1.log"
grep -q '"event":"runtime.stopped"' "$WORKDIR/round-1.log"
python3 - "$STATE/vault.sqlite3" <<'PY'
import sqlite3, sys
db=sqlite3.connect(sys.argv[1])
events=list(db.execute("SELECT event_type,reason_code FROM audit_events WHERE request_id=(SELECT request_id FROM audit_events WHERE event_type='execution.started' ORDER BY sequence LIMIT 1) ORDER BY sequence"))
if [row[0] for row in events] != ["execution.started","execution.finished"]: raise SystemExit(events)
locks=db.execute("SELECT sequence FROM audit_events WHERE event_type='vault.locked' AND reason_code='service-manager-signal'").fetchall()
if len(locks)!=1: raise SystemExit(f"signal locks: {locks}")
if db.execute("SELECT count(*) FROM audit_events WHERE event_type='vault.unlocked' AND sequence>?", locks[0]).fetchone()[0]:
    raise SystemExit("unlock raced after terminal signal lock")
PY

start_manager
[[ "$("$REKEY" --state-dir "$STATE" status | json_field state)" == locked ]]
printf '%s\n' "$PASSWORD" | "$REKEY" --state-dir "$STATE" unlock --password-stdin >/dev/null
set +e
"$REKEY" --state-dir "$STATE" execute "$ACTION_REF" --capability "$TOKEN" >"$WORKDIR/replay.out" 2>"$WORKDIR/replay.err"
REPLAY_RC=$?
set -e
[[ "$REPLAY_RC" -eq 4 ]] && grep -q INVALID_CAPABILITY "$WORKDIR/replay.err"

# Sticky terminal audit failure must make the manager invocation fail. Restart
# then reconciles the durable started row to exactly one blocked terminal.
SESSION_JSON="$(printf '%s\n' "$PASSWORD" | "$REKEY" --state-dir "$STATE" session create --action "$ACTION_REF" --ttl 10m --max-uses 2 --password-stdin)"
PRINCIPAL="$(printf '%s\n' "$SESSION_JSON" | json_field principal_id)"
TOKEN="$(printf '%s\n' "$SESSION_JSON" | json_field capability_token)"
activate_policy 2 "$PRINCIPAL"
sqlite3 "$STATE/vault.sqlite3" <<'SQL'
CREATE TRIGGER fail_execution_terminal BEFORE INSERT ON audit_events
WHEN NEW.event_type IN ('execution.finished','execution.blocked','execution.indeterminate')
BEGIN SELECT RAISE(ABORT, 'injected terminal audit failure'); END;
SQL
set +e
"$REKEY" --state-dir "$STATE" execute "$ACTION_REF" --capability "$TOKEN" \
  --body-file "$WORKDIR/slow.json" --content-type application/json >"$WORKDIR/sticky.out" 2>"$WORKDIR/sticky.err"
STICKY_RC=$?
set -e
[[ "$STICKY_RC" -ne 0 ]]
stop_manager
if grep -q '"event":"runtime.stopped"' "$WORKDIR/round-2.log"; then exit 1; fi
grep -q '"event":"rekeyd.command_failed"' "$WORKDIR/round-2.log"
sqlite3 "$STATE/vault.sqlite3" 'DROP TRIGGER fail_execution_terminal;'
start_manager
[[ "$("$REKEY" --state-dir "$STATE" status | json_field state)" == locked ]]
python3 - "$STATE/vault.sqlite3" <<'PY'
import sqlite3, sys
db=sqlite3.connect(sys.argv[1])
rows=db.execute("""SELECT request_id, group_concat(event_type, ',') FROM
 (SELECT request_id,event_type,sequence FROM audit_events WHERE event_type LIKE 'execution.%' ORDER BY sequence)
 GROUP BY request_id HAVING group_concat(event_type, ',')='execution.started,execution.indeterminate'""").fetchall()
if len(rows)!=1: raise SystemExit(f"reconcile rows: {rows}")
PY

ADMIN_PID="$MANAGER_PID"
"$REKEY" --state-dir "$STATE" shutdown >"$WORKDIR/admin-shutdown.out"
grep -q '"shutdown": true' "$WORKDIR/admin-shutdown.out"
wait_pid_bounded "$ADMIN_PID" 15
# KeepAlive may already have restarted it; unload the label/unit with bounded cleanup.
if [[ "$PLATFORM" == Darwin ]]; then
  run_bounded 10 launchctl bootout "gui/$(id -u)/$LABEL" >/dev/null 2>&1
else
  run_root_bounded 10 systemctl stop "$UNIT" >/dev/null 2>&1
fi
CURRENT_PID="$(manager_pid 2>/dev/null || true)"
if [[ "$CURRENT_PID" =~ ^[1-9][0-9]*$ ]] && pid_running "$CURRENT_PID"; then
  echo "native manager still owns a live process after final unload" >&2
  exit 1
fi
MANAGER_ACTIVE=0
MANAGER_PID=""

if rg -a -q "$SECRET|$PASSWORD" "$WORKDIR"; then
  echo "service-manager artifacts leaked an acceptance secret" >&2
  exit 1
fi
echo "P1 native service-manager acceptance passed on $PLATFORM"
