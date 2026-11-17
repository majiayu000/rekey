# shellcheck shell=bash
# Shared helpers for the release-binary P0 Connection-model gates. Source it
# after setting ROOT, BIN_DIR and PASSWORD; it is not executable on its own.
#
# Proofs and credential values reach child processes only through stdin pipes
# fed by the printf builtin: never argv, the environment, logs or JSON files.
# The basic-mode signer is a mode-0600 software P-256 key file used through
# rekey-policy-sign, not Secure Enclave. The loopback target exercises the
# production public-IP screen; nothing here weakens that screen.

REKEY="$BIN_DIR/rekey"
REKEYD="$BIN_DIR/rekeyd"
SIGNER="$BIN_DIR/rekey-policy-sign"

p0_fail() {
  echo "FAIL: $*" >&2
  exit 1
}

p0_require_binaries() {
  if [[ -x "$REKEY" && -x "$REKEYD" && -x "$SIGNER" ]]; then
    return
  fi
  if [[ "${REKEY_ACCEPTANCE_REQUIRE_BINARIES:-}" == "1" ]]; then
    p0_fail "required release binaries are missing from BIN_DIR: $BIN_DIR"
  fi
  echo "building release binaries…"
  cargo build --manifest-path "$ROOT/Cargo.toml" --release -p rekey-cli -p rekey-broker -p rekey-policy
}

# Print one field of the JSON document on stdin; list indexes are integers.
p0_field() {
  python3 -c '
import json, sys
value = json.load(sys.stdin)
for key in sys.argv[1:]:
    value = value[int(key)] if isinstance(value, list) else value[key]
print(value if isinstance(value, str) else json.dumps(value))' "$@"
}

p0_proof() {
  printf '%s\n' "$PASSWORD"
}

# The default local HTTP service port may belong to an installed Rekey; give
# each disposable vault its own free loopback port before it is served.
p0_private_service_port() {
  python3 - "$1/service.json" <<'PY'
import json, os, socket, sys
with socket.socket() as probe:
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
descriptor = os.open(sys.argv[1], os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(descriptor, "w") as handle:
    json.dump({"port": port}, handle)
PY
}

p0_wait_for_broker() {
  local state="$1" pid="$2"
  for _ in $(seq 1 400); do
    if [[ -S "$state/runtime/admin.sock" ]] \
      && "$REKEY" --state-dir "$state" status --passive >/dev/null 2>&1; then
      return
    fi
    kill -0 "$pid" 2>/dev/null || p0_fail "broker exited during startup: $state"
    sleep 0.05
  done
  p0_fail "broker did not start: $state"
}

# Run a command that must exit with an exact code. Its stdout and stderr are
# kept in $WORKDIR/expect.out and $WORKDIR/expect.err for the caller.
p0_expect_exit() {
  local expected="$1"
  shift
  set +e
  "$@" >"$WORKDIR/expect.out" 2>"$WORKDIR/expect.err"
  local actual=$?
  set -e
  [[ "$actual" -eq "$expected" ]] || {
    cat "$WORKDIR/expect.err" >&2
    p0_fail "expected exit $expected, got $actual: $(basename "$1") ${*:2:6}"
  }
}

# True when the command's complete stdout contains the fixed string. Reading
# a file, not a pipe, means SIGPIPE under pipefail cannot hide a match.
p0_output_has() {
  local needle="$1"
  shift
  "$@" >"$WORKDIR/output.txt" || p0_fail "command failed: $(basename "$1") ${*:2:6}"
  grep -qF -- "$needle" "$WORKDIR/output.txt"
}

# Generate the basic-mode software key, then install its trust root with the
# vault password as step-up proof.
p0_install_software_trust() {
  local state="$1" key="$2"
  "$SIGNER" software-key generate --key-file "$key" >/dev/null
  local signer_id
  signer_id="$(python3 -c 'import uuid; print(uuid.uuid4())')"
  "$SIGNER" software-key trust --key-file "$key" --signer-id "$signer_id" \
    | p0_field trust >"$WORKDIR/trust.json"
  p0_proof | "$REKEY" --state-dir "$state" policy trust install \
    --file "$WORKDIR/trust.json" --step-up-stdin >/dev/null
}

# Write one Connection built from the daemon's generic-bearer preset, with
# explicit signed rules: allow GET /p0/allowed and GET /cdn-cgi/trace (the
# opt-in public origin), approve GET /p0/approve and deny every write.
# Anything else falls through to default deny.
p0_connection() {
  local state="$1" name="$2" origin="$3" credential="$4" enabled="$5" output="$6"
  "$REKEY" --state-dir "$state" connection preset generic-bearer --origin "$origin" \
    | python3 -c '
import json, sys, uuid
name, credential, enabled = sys.argv[1], sys.argv[2], sys.argv[3] == "true"
preset = json.load(sys.stdin)
rule = lambda methods, path, effect: {"id": str(uuid.uuid4()), "methods": methods,
                                      "path": path, "effect": effect}
preset.update(name=name, preset=preset.pop("name"), credential_id=credential, enabled=enabled,
              grade="T0", bindings={}, caller_overrides={}, llm=None, oauth=None,
              limits={"requests_per_hour": 600, "max_request_bytes": 1048576,
                      "max_response_bytes": 4194304},
              rules=[rule(["GET"], "/p0/allowed", "allow"),
                     rule(["GET"], "/p0/approve", "approve"),
                     rule(["GET"], "/cdn-cgi/trace", "allow"),
                     rule("write", "/**", "deny")])
print(json.dumps(preset))' "$name" "$credential" "$enabled" >"$output"
}

# Sign a complete Connection array (JSON file) with the software key through
# rekey-policy-sign and activate it. The daemon issues the signing envelope.
p0_activate_connections() {
  local state="$1" key="$2" connections="$3"
  local expected expires draft=(--connections-stdin)
  expected="$("$REKEY" --state-dir "$state" connection list | p0_field policy_sha256)"
  expires=$(( ($(date +%s) + 3600) * 1000 ))
  draft+=(--expires-at-ms "$expires")
  if [[ "$expected" != "null" ]]; then
    draft+=(--expected-policy-sha256 "$expected")
  fi
  "$REKEY" --state-dir "$state" policy draft "${draft[@]}" <"$connections" >"$WORKDIR/draft.json"
  python3 - "$WORKDIR/draft.json" "$WORKDIR/sign-bytes" <<'PY'
import json, pathlib, sys
draft = json.loads(pathlib.Path(sys.argv[1]).read_text())
pathlib.Path(sys.argv[2]).write_bytes(draft["sign_bytes"].encode())
PY
  "$SIGNER" software-key sign --key-file "$key" <"$WORKDIR/sign-bytes" >"$WORKDIR/signature"
  python3 - "$WORKDIR/sign-bytes" "$WORKDIR/signature" "$WORKDIR/bundle.json" <<'PY'
import json, pathlib, sys
prefix = b"RKPOLICY\x00\x01"
envelope = pathlib.Path(sys.argv[1]).read_bytes()
if not envelope.startswith(prefix):
    raise SystemExit("daemon returned an invalid signing envelope")
bundle = json.loads(envelope[len(prefix):])
bundle["signature"] = pathlib.Path(sys.argv[2]).read_text().strip()
pathlib.Path(sys.argv[3]).write_text(json.dumps(bundle, separators=(",", ":")))
PY
  local vault trust
  vault="$(p0_field metadata vault_id <"$WORKDIR/draft.json")"
  trust="$(p0_field metadata trust_sha256 <"$WORKDIR/draft.json")"
  p0_proof | "$REKEY" --state-dir "$state" policy activate --file "$WORKDIR/bundle.json" \
    --expected-vault-id "$vault" --expected-trust-sha256 "$trust" --step-up-stdin >/dev/null
}

# SQL over a read-only connection; prints one row per line, '|' separated.
p0_sql() {
  python3 - "$1" "$2" <<'PY'
import sqlite3, sys
con = sqlite3.connect(f"file:{sys.argv[1]}?mode=ro", uri=True, timeout=5)
for row in con.execute(sys.argv[2]):
    print("|".join("" if value is None else str(value) for value in row))
con.close()
PY
}

# Every execution.started row must have exactly one terminal row.
p0_assert_audit_pairing() {
  local unpaired
  unpaired="$(p0_sql "$1" "SELECT count(*) FROM audit_events s
    WHERE s.event_type = 'execution.started'
      AND (SELECT count(*) FROM audit_events t WHERE t.request_id = s.request_id
           AND t.event_type IN ('execution.finished', 'execution.blocked', 'execution.indeterminate')) != 1")"
  [[ "$unpaired" == "0" ]] || p0_fail "$unpaired execution.started rows lack exactly one terminal"
}

# No synthetic secret (one per stdin line) may appear in any file below the
# given roots: vault state, runtime logs and every captured CLI output.
p0_assert_no_secret_on_disk() {
  python3 -c '
import pathlib, sys
needles = [line for line in sys.stdin.buffer.read().splitlines() if line]
for root in sys.argv[1:]:
    for path in pathlib.Path(root).rglob("*"):
        if path.is_file() and not path.is_symlink():
            data = path.read_bytes()
            if any(needle in data for needle in needles):
                raise SystemExit(f"plaintext secret found in {path}")' "$@"
}
