#!/usr/bin/env bash
# P0 clean-install acceptance for the Connection model. Release binaries only:
# no fixture transport, no injected CA and no bypass of the public-IP screen.
# Real processes prove init → serve → wrong/right unlock → credential add/list/
# rotate → basic-mode software trust through rekey-policy-sign → signed
# Connection activation → tokenless discovery, dry run, signed deny, default
# deny, allowed CALL and password-approved CALL → disable by re-signing →
# revoke → lock/unlock under an Agent connection flood → backup overlap
# refusal → backup → shutdown → restore with wrong/right proof → restored
# signed Connections → audit pairing and disk secret canary.
#
# Allowed CALLs target https://localhost. The production upstream screen
# refuses that loopback answer after execution.started commits, so each such
# CALL ends in exactly one execution.blocked(private-address) with no network.
# REKEY_ACCEPTANCE_PUBLIC_UPSTREAM=1 additionally calls the public literal-IP
# origin https://1.1.1.1/cdn-cgi/trace through the production HTTPS transport
# and requires execution.finished. It needs Internet access; off by default.
set -euo pipefail
umask 077

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN_DIR="${BIN_DIR:-$ROOT/target/release}"
# shellcheck source=scripts/p0-connection-lib.sh
source "$ROOT/scripts/p0-connection-lib.sh"
p0_require_binaries

random() { python3 -c 'import secrets; print(secrets.token_hex(16))'; }
PASSWORD="p0-acceptance-password-$(random)"
SECRET_V1="p0-acceptance-canary-v1-$(random)"
SECRET_V2="p0-acceptance-canary-v2-$(random)"

# macOS sockaddr_un is ~104 bytes; keep state-dir names tiny.
WORKDIR="$(mktemp -d "/tmp/rk.XXXXXX")"
STATE="$WORKDIR/s"
KEY="$WORKDIR/signer.p8"
SERVE_PID=""
FLOOD_PID=""
cleanup() {
  for pid in $FLOOD_PID $SERVE_PID; do
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
  done
  if [[ "${REKEY_KEEP_WORKDIR:-}" == "1" ]]; then
    echo "kept acceptance artifacts at $WORKDIR"
  else
    rm -rf "$WORKDIR"
  fi
}
trap cleanup EXIT

stop_broker() {
  p0_proof | "$REKEY" --state-dir "$1" shutdown --password-stdin >/dev/null
  wait "$SERVE_PID" 2>/dev/null || true
  SERVE_PID=""
}

audit() { p0_sql "$STATE/vault.sqlite3" "$1"; }

# The newest execution.started for a Connection, with its terminal rows.
last_execution() {
  audit "SELECT t.event_type, t.reason_code FROM audit_events t
    WHERE t.request_id = (SELECT s.request_id FROM audit_events s
      WHERE s.event_type = 'execution.started' AND s.resource_id = '$1'
      ORDER BY s.sequence DESC LIMIT 1)
      AND t.event_type IN ('execution.finished', 'execution.blocked', 'execution.indeterminate')"
}

echo "== init (personal) under umask 000"
p0_proof | (umask 000; exec "$REKEY" --state-dir "$STATE" init --mode personal --password-stdin) >/dev/null
p0_private_service_port "$STATE"

echo "== delegated exit codes (usage=2, storage/state=5)"
p0_expect_exit 2 "$REKEY" --state-dir "$STATE" serve --idle-lock 1s
p0_proof | p0_expect_exit 5 "$REKEY" --state-dir "$STATE" init --mode personal --password-stdin

echo "== serve (delegated to rekeyd) under umask 000"
(umask 000; exec "$REKEY" --state-dir "$STATE" serve --idle-lock 15m) >/dev/null 2>"$WORKDIR/serve-1.jsonl" &
SERVE_PID=$!
p0_wait_for_broker "$STATE" "$SERVE_PID"

echo "== wrong password, then unlock"
printf 'wrong-password\n' | p0_expect_exit 3 "$REKEY" --state-dir "$STATE" unlock --password-stdin
p0_proof | "$REKEY" --state-dir "$STATE" unlock --password-stdin >/dev/null

echo "== credential add, list and rotate"
cred_id="$(printf '%s\n%s\n' "$PASSWORD" "$SECRET_V1" \
  | "$REKEY" --state-dir "$STATE" credential add p0-acceptance --stdin-secrets | p0_field id)"
p0_output_has p0-acceptance "$REKEY" --state-dir "$STATE" credential list || p0_fail "credential list lacks the credential"
printf '%s\n%s\n' "$PASSWORD" "$SECRET_V2" \
  | "$REKEY" --state-dir "$STATE" credential rotate "$cred_id" --stdin-secrets >/dev/null

echo "== owner-only runtime and SQLite modes"
python3 - "$STATE" <<'PY'
import os, pathlib, stat, sys
root = pathlib.Path(sys.argv[1])
expected = {
    root: 0o700,
    root / "vault.sqlite3": 0o600,
    root / "vault.sqlite3-wal": 0o600,
    root / "vault.sqlite3-shm": 0o600,
    root / "broker.lock": 0o600,
    root / "runtime": 0o700,
    root / "runtime" / "admin.sock": 0o600,
    root / "runtime" / "agent.sock": 0o600,
}
for path, wanted in expected.items():
    if not path.exists():
        raise SystemExit(f"required runtime path missing: {path.name}")
    got = stat.S_IMODE(os.stat(path).st_mode)
    if got != wanted:
        raise SystemExit(f"wrong mode for {path.name}: {oct(got)} != {oct(wanted)}")
PY

echo "== basic-mode software trust through rekey-policy-sign"
p0_install_software_trust "$STATE" "$KEY"
[[ "$("$REKEY" --state-dir "$STATE" policy status | p0_field trust_installed)" == "true" ]] \
  || p0_fail "software trust was not installed"

echo "== sign and activate Connections"
p0_connection "$STATE" p0-local https://localhost "$cred_id" true "$WORKDIR/local.json"
p0_connection "$STATE" p0-public https://1.1.1.1 "$cred_id" true "$WORKDIR/public.json"
combine() { python3 -c 'import json, sys; print(json.dumps([json.load(open(p)) for p in sys.argv[1:]]))' "$@"; }
combine "$WORKDIR/local.json" "$WORKDIR/public.json" >"$WORKDIR/connections.json"
p0_activate_connections "$STATE" "$KEY" "$WORKDIR/connections.json"
"$REKEY" --state-dir "$STATE" policy status >"$WORKDIR/policy-status.json"
[[ "$(p0_field status <"$WORKDIR/policy-status.json")" == "active" ]] || p0_fail "policy is not active"

echo "== tokenless discovery and dry run"
"$REKEY" --state-dir "$STATE" list --json >"$WORKDIR/list.json"
python3 - "$WORKDIR/list.json" <<'PY'
import json, sys
names = {c["connection"]: c for c in json.load(open(sys.argv[1]))["connections"]}
if set(names) != {"p0-local", "p0-public"} or names["p0-local"]["origin"] != "https://localhost":
    raise SystemExit(f"unexpected discovery: {sorted(names)}")
PY
"$REKEY" --state-dir "$STATE" http p0-local GET /p0/allowed --dry-run >"$WORKDIR/dry-run.json"
"$REKEY" --state-dir "$STATE" http p0-public GET /cdn-cgi/trace --dry-run >"$WORKDIR/dry-run-public.json"
python3 - "$WORKDIR/dry-run.json" "$WORKDIR/dry-run-public.json" <<'PY'
import json, sys
for path, name in zip(sys.argv[1:], ("p0-local", "p0-public")):
    dry = json.load(open(path))
    if dry["effect"] != "allow" or dry["credential_placeholder"] != f"«rekey:{name}»":
        raise SystemExit(f"unexpected dry run: {dry}")
PY
[[ "$(audit "SELECT count(*) FROM audit_events WHERE event_type = 'execution.started'")" == "0" ]] \
  || p0_fail "dry run started an execution"

echo "== signed deny and default deny refuse before execution.started"
p0_expect_exit 4 "$REKEY" --state-dir "$STATE" http p0-local POST /p0/allowed --json '{}'
grep -q DENIED "$WORKDIR/expect.err" || p0_fail "write was not denied by the signed rule"
p0_expect_exit 4 "$REKEY" --state-dir "$STATE" http p0-local GET /p0/unlisted
grep -q DENIED "$WORKDIR/expect.err" || p0_fail "unlisted path was not denied"
[[ "$(audit "SELECT count(*) FROM audit_events WHERE event_type = 'execution.started'")" == "0" ]] \
  || p0_fail "denied CALL started an execution"
[[ "$(audit "SELECT count(*) FROM audit_events WHERE event_type = 'execution.blocked'
  AND reason_code = 'connection-rule-denied'")" == "2" ]] || p0_fail "denials were not audited"

echo "== allowed tokenless CALL: started, then the production screen refuses loopback"
p0_expect_exit 6 "$REKEY" --state-dir "$STATE" http p0-local GET /p0/allowed
grep -q UPSTREAM_ADDRESS_BLOCKED "$WORKDIR/expect.err" || p0_fail "loopback target was not refused"
[[ "$(last_execution p0-local)" == "execution.blocked|private-address" ]] \
  || p0_fail "allowed CALL lacks exactly one private-address terminal: $(last_execution p0-local)"

echo "== approve rule: password-approved local challenge, single use"
p0_expect_exit 4 "$REKEY" --state-dir "$STATE" http p0-local GET /p0/approve --no-wait
grep -q APPROVAL_REQUIRED "$WORKDIR/expect.err" || p0_fail "approve rule did not require approval"
approval_id="$(p0_field approval challenge_id <"$WORKDIR/expect.err")"
"$REKEY" --state-dir "$STATE" approval review "$approval_id" >"$WORKDIR/review.json"
review_sha="$(p0_field metadata review_sha256 <"$WORKDIR/review.json")"
p0_proof | "$REKEY" --state-dir "$STATE" approval approve "$approval_id" \
  --review-sha256 "$review_sha" --password --password-stdin >"$WORKDIR/approved.json"
[[ "$(p0_field state <"$WORKDIR/approved.json")" == "approved" ]] || p0_fail "approval was not recorded"
p0_expect_exit 6 "$REKEY" --state-dir "$STATE" http p0-local GET /p0/approve --approval "$approval_id"
[[ "$(last_execution p0-local)" == "execution.blocked|private-address" ]] \
  || p0_fail "approved CALL lacks exactly one terminal"
p0_expect_exit 4 "$REKEY" --state-dir "$STATE" http p0-local GET /p0/approve --approval "$approval_id"
grep -q DENIED "$WORKDIR/expect.err" || p0_fail "a consumed approval was accepted again"

if [[ "${REKEY_ACCEPTANCE_PUBLIC_UPSTREAM:-}" == "1" ]]; then
  echo "== public upstream through the production HTTPS transport"
  "$REKEY" --state-dir "$STATE" http p0-public GET /cdn-cgi/trace >"$WORKDIR/public-call.json"
  [[ "$(p0_field status <"$WORKDIR/public-call.json")" == "200" ]] || p0_fail "public CALL failed"
  [[ "$(last_execution p0-public)" == "execution.finished|finished" ]] \
    || p0_fail "public CALL lacks execution.finished: $(last_execution p0-public)"
else
  echo "== public upstream CALL skipped (REKEY_ACCEPTANCE_PUBLIC_UPSTREAM=1 needs Internet)"
fi

echo "== disable by re-signing; disabled Connection is refused and hidden"
p0_connection "$STATE" p0-local https://localhost "$cred_id" false "$WORKDIR/local.json"
combine "$WORKDIR/local.json" "$WORKDIR/public.json" >"$WORKDIR/connections.json"
p0_activate_connections "$STATE" "$KEY" "$WORKDIR/connections.json"
p0_expect_exit 4 "$REKEY" --state-dir "$STATE" http p0-local GET /p0/allowed
grep -q NOT_CONFIGURED "$WORKDIR/expect.err" || p0_fail "disabled Connection was not refused"
p0_output_has '"p0-local"' "$REKEY" --state-dir "$STATE" list --json && p0_fail "disabled Connection is discoverable"

echo "== credential revoke"
p0_proof | "$REKEY" --state-dir "$STATE" credential revoke "$cred_id" --password-stdin >/dev/null
p0_output_has '"revoked"' "$REKEY" --state-dir "$STATE" credential list || p0_fail "credential was not revoked"

echo "== explicit lock under an Agent connection flood, locked CALL, unlock"
flood_ready="$WORKDIR/agent-flood-ready"
python3 - "$STATE/runtime/agent.sock" "$flood_ready" <<'PY' &
import pathlib, signal, socket, sys
sockets = []
for _ in range(128):
    conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    conn.connect(sys.argv[1])
    sockets.append(conn)
pathlib.Path(sys.argv[2]).touch()
signal.pause()
PY
FLOOD_PID=$!
for _ in $(seq 1 100); do
  [[ -f "$flood_ready" ]] && break
  sleep 0.02
done
[[ -f "$flood_ready" ]] || p0_fail "agent connection flood did not start"
"$REKEY" --state-dir "$STATE" status >/dev/null
"$REKEY" --state-dir "$STATE" lock >/dev/null
kill "$FLOOD_PID" 2>/dev/null || true
wait "$FLOOD_PID" 2>/dev/null || true
FLOOD_PID=""
[[ "$("$REKEY" --state-dir "$STATE" status | p0_field state)" == "locked" ]] || p0_fail "broker did not lock"
p0_expect_exit 3 "$REKEY" --state-dir "$STATE" http p0-public GET /cdn-cgi/trace
grep -q LOCKED "$WORKDIR/expect.err" || p0_fail "locked CALL was not refused as LOCKED"
p0_proof | "$REKEY" --state-dir "$STATE" unlock --password-stdin >/dev/null

echo "== reject backup overlap with live state and a second broker"
ln -s "$STATE" "$WORKDIR/state-alias"
for protected_output in \
  "$STATE/vault.sqlite3" \
  "$STATE/broker.lock" \
  "$STATE/runtime/admin.sock" \
  "$WORKDIR/state-alias/vault.sqlite3"; do
  p0_proof | p0_expect_exit 5 "$REKEY" --state-dir "$STATE" backup --output "$protected_output" --password-stdin
done
p0_expect_exit 5 "$REKEYD" serve --state-dir "$STATE" --idle-lock 15m
p0_output_has p0-acceptance "$REKEY" --state-dir "$STATE" credential list || p0_fail "live state changed"

echo "== backup and shutdown"
backup="$WORKDIR/out.rkbackup"
hash="$(p0_proof | "$REKEY" --state-dir "$STATE" backup --output "$backup" --password-stdin | p0_field sha256_hex)"
stop_broker "$STATE"
p0_assert_audit_pairing "$STATE/vault.sqlite3"

echo "== restore: wrong proof refused, then restored signed Connections"
restored="$WORKDIR/r"
bad_restore="$WORKDIR/bad"
# Inspect with the valid proof first so the negative case exercises restore
# authentication itself, not inspect.
bad_context="$(p0_proof | "$REKEY" --state-dir "$bad_restore" restore --input "$backup" --sha256 "$hash" --inspect --password-stdin)"
printf 'wrong-password\n' | p0_expect_exit 3 "$REKEY" --state-dir "$bad_restore" restore --input "$backup" \
  --sha256 "$hash" --expected-context "$bad_context" --password-stdin
context="$(p0_proof | "$REKEY" --state-dir "$restored" restore --input "$backup" --sha256 "$hash" --inspect --password-stdin)"
p0_proof | "$REKEY" --state-dir "$restored" restore --input "$backup" --sha256 "$hash" \
  --expected-context "$context" --password-stdin >/dev/null
p0_private_service_port "$restored"
"$REKEYD" serve --state-dir "$restored" --idle-lock 15m >/dev/null 2>"$WORKDIR/serve-restored.jsonl" &
SERVE_PID=$!
p0_wait_for_broker "$restored" "$SERVE_PID"
p0_proof | "$REKEY" --state-dir "$restored" unlock --password-stdin >/dev/null
p0_output_has p0-acceptance "$REKEY" --state-dir "$restored" credential list || p0_fail "restored credential missing"
"$REKEY" --state-dir "$restored" connection list >"$WORKDIR/restored-connections.json"
python3 - "$WORKDIR/restored-connections.json" <<'PY'
import json, sys
listed = {c["name"]: c["enabled"] for c in json.load(open(sys.argv[1]))["connections"]}
if listed != {"p0-local": False, "p0-public": True}:
    raise SystemExit(f"restored signed Connections differ: {listed}")
PY
stop_broker "$restored"
p0_assert_audit_pairing "$restored/vault.sqlite3"

echo "== disk and output secret canary"
printf '%s\n' "$PASSWORD" "$SECRET_V1" "$SECRET_V2" | p0_assert_no_secret_on_disk "$WORKDIR"

echo "P0 acceptance passed"
