#!/usr/bin/env bash
# Opt-in field dogfood: create one GitHub issue through rekey's fixed Action.
# Requires a revocable fine-grained token with Issues: Write on one repo.
# The token is entered directly into rekey's hidden TTY prompt. It is never
# accepted through env, argv, a shell variable, or a file.
#
#   scripts/dogfood-github.sh --repo owner/name
#
# Creates a throwaway vault under $TMPDIR and removes it on exit.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN_DIR="${BIN_DIR:-$ROOT/target/release}"
REKEY="${BIN_DIR}/rekey"
REKEYD="${BIN_DIR}/rekeyd"

if [[ "$#" -ne 2 || "$1" != "--repo" ]]; then
  echo "usage: $0 --repo owner/name" >&2
  exit 2
fi
REPO="$2"
if [[ ! "$REPO" =~ ^[A-Za-z0-9][A-Za-z0-9-]*/[A-Za-z0-9._-]+$ ]]; then
  echo "invalid repository; expected owner/name" >&2
  exit 2
fi
if [[ ! -t 0 ]]; then
  echo "dogfood requires a trusted interactive TTY for credential entry" >&2
  exit 2
fi
PASSWORD="$(python3 -c 'import secrets; print(secrets.token_urlsafe(24))')"

if [[ ! -x "$REKEY" || ! -x "$REKEYD" ]]; then
  cargo build --release -p rekey-cli -p rekey-broker
fi

WORKDIR="$(mktemp -d "/tmp/rk.XXXXXX")"
STATE="$WORKDIR/s"
cleanup() {
  if [[ -n "${SERVE_PID:-}" ]]; then
    kill "$SERVE_PID" 2>/dev/null || true
    wait "$SERVE_PID" 2>/dev/null || true
  fi
  rm -rf "$WORKDIR"
}
trap cleanup EXIT

json_field() {
  python3 -c 'import json,sys; print(json.load(sys.stdin)['"$1"'])'
}

json_first_field() {
  python3 -c 'import json,sys; value,_=json.JSONDecoder().raw_decode(sys.stdin.read().lstrip()); print(value['"$1"'])'
}

printf '%s\n' "$PASSWORD" | "$REKEYD" init --state-dir "$STATE" --password-stdin >/dev/null
"$REKEYD" serve --state-dir "$STATE" --idle-lock 15m >/dev/null 2>&1 &
SERVE_PID=$!
for _ in $(seq 1 100); do
  [[ -S "$STATE/runtime/admin.sock" ]] && break
  sleep 0.05
done

printf '%s\n' "$PASSWORD" | "$REKEY" --state-dir "$STATE" unlock --password-stdin >/dev/null
echo "== credential add (trusted TTY)"
echo "Temporary vault password for the first prompt: $PASSWORD"
echo "For the second prompt, enter the dedicated fine-grained GitHub token."
cred_json="$("$REKEY" --state-dir "$STATE" credential add github-dogfood)"
cred_id="$(printf '%s\n' "$cred_json" | json_field '"id"')"

action_file="$WORKDIR/action.json"
cat >"$action_file" <<EOF
{
  "name": "github-create-issue",
  "credential_id": "$cred_id",
  "origin": "https://api.github.com",
  "method": "POST",
  "exact_path": "/repos/${REPO}/issues",
  "auth_header": "authorization",
  "auth_prefix": "Bearer ",
  "timeout_ms": 30000,
  "request_max_bytes": 65536,
  "allowed_extra_headers": ["accept", "user-agent", "x-github-api-version"],
  "response_max_bytes": 262144,
  "allowed_response_headers": ["content-type"]
}
EOF
action_json="$(printf '%s\n' "$PASSWORD" | "$REKEY" --state-dir "$STATE" action create --file "$action_file" --password-stdin)"
action_ref="$(printf '%s\n' "$action_json" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d["id"]+"@"+str(d["version"]))')"
session_json="$(printf '%s\n' "$PASSWORD" | "$REKEY" --state-dir "$STATE" session create --action "$action_ref" --ttl 10m --max-uses 3 --password-stdin)"
cap="$(printf '%s\n' "$session_json" | json_field '"capability_token"')"

body="$WORKDIR/issue.json"
cat >"$body" <<EOF
{"title":"rekey dogfood $(date -u +%Y-%m-%dT%H:%M:%SZ)","body":"Created via rekey fixed HTTPS Action. Safe to close."}
EOF

execute_json="$(printf '%s\n' "$cap" | "$REKEY" --state-dir "$STATE" execute "$action_ref" --capability - \
  --content-type application/json \
  --header "accept: application/vnd.github+json" \
  --header "user-agent: rekey-dogfood/0.1" \
  --header "x-github-api-version: 2022-11-28" \
  --body-file "$body")"
printf '%s\n' "$execute_json"
upstream_status="$(printf '%s\n' "$execute_json" | json_first_field '"upstream_status"')"
if [[ "$upstream_status" != "201" ]]; then
  echo "dogfood expected GitHub status 201, got $upstream_status" >&2
  exit 1
fi

printf '%s\n' "$PASSWORD" | "$REKEY" --state-dir "$STATE" shutdown --password-stdin >/dev/null
echo "dogfood execute finished for $REPO"
