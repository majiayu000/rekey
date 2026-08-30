#!/usr/bin/env bash
# Real release-process durability gate: backup crash windows and audit faults,
# bounded-RSS backup/restore, and SIGKILL recovery through the restore marker.
set -euo pipefail
umask 077

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN_DIR="${BIN_DIR:-$ROOT/target/release}"
REKEY="$BIN_DIR/rekey"
REKEYD="$BIN_DIR/rekeyd"
PASSWORD="p0 durability acceptance password"
RSS_LIMIT_BYTES=$((192 * 1024 * 1024))
PADDING_BYTES=$((256 * 1024 * 1024))

if [[ ! -x "$REKEY" || ! -x "$REKEYD" ]]; then
  cargo build --release -p rekey-cli -p rekey-broker
fi

WORKDIR="$(mktemp -d "/tmp/rkd.XXXXXX")"
printf '%s\n' "$PASSWORD" >"$WORKDIR/password"
PIDS=""
cleanup() {
  for pid in $PIDS; do
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
  done
  rm -rf "$WORKDIR"
}
trap cleanup EXIT

wait_for_socket() {
  local state="$1"
  for _ in $(seq 1 200); do
    if [[ -S "$state/runtime/admin.sock" ]] && "$REKEY" --state-dir "$state" status >/dev/null 2>&1; then
      return
    fi
    sleep 0.02
  done
  echo "broker did not start: $state"
  exit 1
}

json_hash() {
  python3 -c 'import json,sys; print(json.load(sys.stdin)["sha256_hex"])'
}

max_rss() {
  awk '/maximum resident set size/ { print $1 }' "$1"
}

echo "== post-publish audit failure leaves an authorized artifact without receipt"
AUDIT_STATE="$WORKDIR/audit-state"
AUDIT_OUTPUT="$WORKDIR/unaudited.rkbackup"
printf '%s\n' "$PASSWORD" | "$REKEYD" init --state-dir "$AUDIT_STATE" --password-stdin >/dev/null
"$REKEYD" serve --state-dir "$AUDIT_STATE" --idle-lock 15m >/dev/null 2>"$WORKDIR/audit-serve.jsonl" &
AUDIT_PID=$!
PIDS="$PIDS $AUDIT_PID"
wait_for_socket "$AUDIT_STATE"
printf '%s\n' "$PASSWORD" | "$REKEY" --state-dir "$AUDIT_STATE" unlock --password-stdin >/dev/null
sqlite3 "$AUDIT_STATE/vault.sqlite3" <<'SQL'
CREATE TRIGGER fail_backup_created
BEFORE INSERT ON audit_events
WHEN NEW.event_type = 'backup.created'
BEGIN SELECT RAISE(ABORT, 'injected final backup audit failure'); END;
SQL
set +e
printf '%s\n' "$PASSWORD" | "$REKEY" --state-dir "$AUDIT_STATE" backup --output "$AUDIT_OUTPUT" --password-stdin >/dev/null 2>&1
AUDIT_RC=$?
set -e
[[ "$AUDIT_RC" -eq 5 ]] || { echo "expected backup exit 5, got $AUDIT_RC"; exit 1; }
[[ -e "$AUDIT_OUTPUT" ]] || { echo "authorized failed backup did not leave its artifact"; exit 1; }
[[ "$(sqlite3 "$AUDIT_OUTPUT" "PRAGMA quick_check;")" == "ok" ]] || { echo "authorized artifact is not a complete SQLite backup"; exit 1; }
[[ "$(sqlite3 "$AUDIT_STATE/vault.sqlite3" "SELECT count(*) FROM audit_events WHERE event_type='backup.release_authorized';")" -eq 1 ]]
[[ "$(sqlite3 "$AUDIT_STATE/vault.sqlite3" "SELECT count(*) FROM audit_events WHERE event_type='backup.created';")" -eq 0 ]]
rm -f "$AUDIT_OUTPUT"
kill "$AUDIT_PID" 2>/dev/null || true
wait "$AUDIT_PID" 2>/dev/null || true
PIDS="${PIDS/ $AUDIT_PID/}"

echo "== prepare large valid backup fixture"
STATE="$WORKDIR/state"
BACKUP="$WORKDIR/large.rkbackup"
printf '%s\n' "$PASSWORD" | "$REKEYD" init --state-dir "$STATE" --password-stdin >/dev/null
sqlite3 "$STATE/vault.sqlite3" "CREATE TABLE durability_padding(payload BLOB); INSERT INTO durability_padding VALUES(zeroblob($PADDING_BYTES)); DROP TABLE durability_padding; PRAGMA wal_checkpoint(TRUNCATE);" >/dev/null

echo "== backup SIGKILL before release audit exposes no external file"
PREAUDIT_OUTPUT="$WORKDIR/preaudit.rkbackup"
"$REKEYD" serve --state-dir "$STATE" --idle-lock 15m >/dev/null 2>"$WORKDIR/preaudit-serve.jsonl" &
PREAUDIT_BROKER_PID=$!
PIDS="$PIDS $PREAUDIT_BROKER_PID"
wait_for_socket "$STATE"
printf '%s\n' "$PASSWORD" | "$REKEY" --state-dir "$STATE" unlock --password-stdin >/dev/null
"$REKEY" --state-dir "$STATE" backup --output "$PREAUDIT_OUTPUT" --password-stdin <"$WORKDIR/password" >"$WORKDIR/preaudit.out" 2>"$WORKDIR/preaudit.err" &
PREAUDIT_CLI_PID=$!
PIDS="$PIDS $PREAUDIT_CLI_PID"
PREAUDIT_KILLED=0
for _ in $(seq 1 1000); do
  if [[ -f "$STATE/.backup-snapshot.sqlite3" ]] && [[ "$(stat -f %z "$STATE/.backup-snapshot.sqlite3")" -gt 1048576 ]]; then
    AUTHORIZED="$(sqlite3 "$STATE/vault.sqlite3" "SELECT count(*) FROM audit_events WHERE event_type='backup.release_authorized';")"
    if [[ "$AUTHORIZED" -eq 0 ]]; then
      kill -KILL "$PREAUDIT_BROKER_PID"
      PREAUDIT_KILLED=1
      break
    fi
  fi
  sleep 0.002
done
[[ "$PREAUDIT_KILLED" -eq 1 ]] || { echo "missed pre-audit backup crash window"; exit 1; }
wait "$PREAUDIT_BROKER_PID" 2>/dev/null || true
wait "$PREAUDIT_CLI_PID" 2>/dev/null || true
PIDS="${PIDS/ $PREAUDIT_BROKER_PID/}"
PIDS="${PIDS/ $PREAUDIT_CLI_PID/}"
[[ ! -e "$PREAUDIT_OUTPUT" ]] || { echo "pre-audit crash exposed external backup"; exit 1; }
[[ "$(sqlite3 "$STATE/vault.sqlite3" "SELECT count(*) FROM audit_events WHERE event_type='backup.release_authorized';")" -eq 0 ]]
[[ -f "$STATE/.backup-snapshot.sqlite3" ]] || { echo "pre-audit crash did not leave internal snapshot evidence"; exit 1; }

echo "== backup SIGKILL after authorization leaves audit but no success"
POSTAUTH_OUTPUT="$WORKDIR/postauth.rkbackup"
"$REKEYD" serve --state-dir "$STATE" --idle-lock 15m >/dev/null 2>"$WORKDIR/postauth-serve.jsonl" &
POSTAUTH_BROKER_PID=$!
PIDS="$PIDS $POSTAUTH_BROKER_PID"
wait_for_socket "$STATE"
printf '%s\n' "$PASSWORD" | "$REKEY" --state-dir "$STATE" unlock --password-stdin >/dev/null
python3 - "$STATE/vault.sqlite3" "$STATE/.backup-snapshot.sqlite3" "$POSTAUTH_OUTPUT" "$POSTAUTH_BROKER_PID" <<'PY' &
import os, pathlib, signal, sqlite3, sys, time
db = sys.argv[1]
snapshot = pathlib.Path(sys.argv[2])
output = pathlib.Path(sys.argv[3])
pid = int(sys.argv[4])
deadline = time.monotonic() + 30
locker = None
expected_size = None
while time.monotonic() < deadline:
    if locker is None:
        con = sqlite3.connect(f"file:{db}?mode=ro", uri=True, timeout=0.1)
        authorized, created = con.execute("""
            SELECT
              sum(event_type = 'backup.release_authorized'),
              sum(event_type = 'backup.created')
            FROM audit_events
        """).fetchone()
        con.close()
        if authorized and not created and snapshot.exists():
            expected_size = snapshot.stat().st_size
            candidate = sqlite3.connect(db, isolation_level=None, timeout=0.1)
            try:
                candidate.execute("BEGIN EXCLUSIVE")
            except sqlite3.OperationalError:
                candidate.close()
            else:
                created = candidate.execute(
                    "SELECT count(*) FROM audit_events WHERE event_type='backup.created'"
                ).fetchone()[0]
                if created:
                    candidate.rollback()
                    candidate.close()
                    raise SystemExit("backup.created committed before exclusive fault lock")
                locker = candidate
    elif (
        output.exists()
        and output.stat().st_size == expected_size
        and not snapshot.exists()
    ):
        artifact = sqlite3.connect(f"file:{output}?mode=ro", uri=True, timeout=0.1)
        artifact.execute("SELECT count(*) FROM vault_header").fetchone()
        artifact.close()
        os.kill(pid, signal.SIGKILL)
        time.sleep(0.2)
        locker.rollback()
        locker.close()
        raise SystemExit(0)
    time.sleep(0.001)
if locker is not None:
    locker.rollback()
    locker.close()
raise SystemExit("missed post-authorization backup crash window")
PY
POSTAUTH_WATCH_PID=$!
PIDS="$PIDS $POSTAUTH_WATCH_PID"
"$REKEY" --state-dir "$STATE" backup --output "$POSTAUTH_OUTPUT" --password-stdin <"$WORKDIR/password" >"$WORKDIR/postauth.out" 2>"$WORKDIR/postauth.err" &
POSTAUTH_CLI_PID=$!
PIDS="$PIDS $POSTAUTH_CLI_PID"
wait "$POSTAUTH_WATCH_PID"
wait "$POSTAUTH_BROKER_PID" 2>/dev/null || true
set +e
wait "$POSTAUTH_CLI_PID"
POSTAUTH_CLI_RC=$?
set -e
PIDS="${PIDS/ $POSTAUTH_WATCH_PID/}"
PIDS="${PIDS/ $POSTAUTH_BROKER_PID/}"
PIDS="${PIDS/ $POSTAUTH_CLI_PID/}"
[[ "$POSTAUTH_CLI_RC" -ne 0 ]] || { echo "post-authorization crash returned success"; exit 1; }
[[ -e "$POSTAUTH_OUTPUT" ]] || { echo "post-authorization window was not reached"; exit 1; }
[[ "$(sqlite3 "$POSTAUTH_OUTPUT" "PRAGMA quick_check;")" == "ok" ]] || { echo "post-authorization artifact is not a complete SQLite backup"; exit 1; }
[[ ! -s "$WORKDIR/postauth.out" ]] || { echo "post-authorization crash returned a receipt"; exit 1; }
[[ "$(sqlite3 "$STATE/vault.sqlite3" "SELECT count(*) FROM audit_events WHERE event_type='backup.release_authorized';")" -eq 1 ]]
[[ "$(sqlite3 "$STATE/vault.sqlite3" "SELECT count(*) FROM audit_events WHERE event_type='backup.created';")" -eq 0 ]]
rm -f "$POSTAUTH_OUTPUT"

echo "== successful streaming backup stays below bounded RSS"
/usr/bin/time -l -o "$WORKDIR/backup.time" "$REKEYD" serve --state-dir "$STATE" --idle-lock 15m >/dev/null 2>"$WORKDIR/large-serve.jsonl" &
SERVE_PID=$!
PIDS="$PIDS $SERVE_PID"
wait_for_socket "$STATE"
printf '%s\n' "$PASSWORD" | "$REKEY" --state-dir "$STATE" unlock --password-stdin >/dev/null
BACKUP_JSON="$(printf '%s\n' "$PASSWORD" | "$REKEY" --state-dir "$STATE" backup --output "$BACKUP" --password-stdin)"
HASH="$(printf '%s\n' "$BACKUP_JSON" | json_hash)"
printf '%s\n' "$PASSWORD" | "$REKEY" --state-dir "$STATE" shutdown --password-stdin >/dev/null
wait "$SERVE_PID"
PIDS="${PIDS/ $SERVE_PID/}"
BACKUP_RSS="$(max_rss "$WORKDIR/backup.time")"
[[ -n "$BACKUP_RSS" && "$BACKUP_RSS" -lt "$RSS_LIMIT_BYTES" ]] || {
  echo "backup RSS exceeded bound: ${BACKUP_RSS:-missing}"
  exit 1
}
[[ "$(stat -f %z "$BACKUP")" -gt "$PADDING_BYTES" ]] || { echo "backup fixture is not large"; exit 1; }

echo "== SIGKILL leaves a startup-blocking marker"
CRASH_TARGET="$WORKDIR/crash-target"
FIFO="$WORKDIR/slow-backup.fifo"
mkfifo "$FIFO"
python3 - "$BACKUP" "$FIFO" <<'PY' &
import pathlib, sys, time
source, fifo = map(pathlib.Path, sys.argv[1:])
try:
    with source.open("rb") as src, fifo.open("wb") as dst:
        while chunk := src.read(65536):
            dst.write(chunk)
            dst.flush()
            time.sleep(0.001)
except BrokenPipeError:
    pass
PY
WRITER_PID=$!
PIDS="$PIDS $WRITER_PID"
"$REKEYD" restore --input "$FIFO" --state-dir "$CRASH_TARGET" --sha256 "$HASH" --password-stdin <"$WORKDIR/password" >/dev/null 2>"$WORKDIR/crash-restore.err" &
RESTORE_PID=$!
PIDS="$PIDS $RESTORE_PID"
for _ in $(seq 1 500); do
  [[ -f "$CRASH_TARGET/.restore-incomplete" ]] && break
  sleep 0.01
done
[[ -f "$CRASH_TARGET/.restore-incomplete" ]] || { echo "restore marker was not persisted"; exit 1; }
kill -KILL "$RESTORE_PID"
wait "$RESTORE_PID" 2>/dev/null || true
PIDS="${PIDS/ $RESTORE_PID/}"
kill "$WRITER_PID" 2>/dev/null || true
wait "$WRITER_PID" 2>/dev/null || true
PIDS="${PIDS/ $WRITER_PID/}"
[[ -f "$CRASH_TARGET/.restore-incomplete" ]] || { echo "SIGKILL lost restore marker"; exit 1; }
set +e
"$REKEYD" serve --state-dir "$CRASH_TARGET" --idle-lock 15m >/dev/null 2>&1
SERVE_RC=$?
set -e
[[ "$SERVE_RC" -eq 5 ]] || { echo "incomplete restore served with exit $SERVE_RC"; exit 1; }

echo "== retry cleans interrupted state and streaming restore stays bounded"
/usr/bin/time -l -o "$WORKDIR/restore.time" "$REKEYD" restore --input "$BACKUP" --state-dir "$CRASH_TARGET" --sha256 "$HASH" --password-stdin <"$WORKDIR/password" >/dev/null
RESTORE_RSS="$(max_rss "$WORKDIR/restore.time")"
[[ -n "$RESTORE_RSS" && "$RESTORE_RSS" -lt "$RSS_LIMIT_BYTES" ]] || {
  echo "restore RSS exceeded bound: ${RESTORE_RSS:-missing}"
  exit 1
}
[[ ! -e "$CRASH_TARGET/.restore-incomplete" ]]
[[ ! -e "$CRASH_TARGET/.incoming-vault.sqlite3" ]]
"$REKEYD" serve --state-dir "$CRASH_TARGET" --idle-lock 15m >/dev/null 2>"$WORKDIR/restored-serve.jsonl" &
RESTORED_PID=$!
PIDS="$PIDS $RESTORED_PID"
wait_for_socket "$CRASH_TARGET"
printf '%s\n' "$PASSWORD" | "$REKEY" --state-dir "$CRASH_TARGET" unlock --password-stdin >/dev/null
printf '%s\n' "$PASSWORD" | "$REKEY" --state-dir "$CRASH_TARGET" shutdown --password-stdin >/dev/null
wait "$RESTORED_PID"
PIDS="${PIDS/ $RESTORED_PID/}"

echo "p0 durability acceptance: PASS (backup_rss=$BACKUP_RSS restore_rss=$RESTORE_RSS)"
