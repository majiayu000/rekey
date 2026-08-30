#!/usr/bin/env bash
# Linux namespace G2 reference attack harness. Runs only disposable Docker
# resources and proves the documented container boundary, not kernel/daemon safety.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
RUN_ID="rekey-g2-$$"
IMAGE="$RUN_ID:local"
BROKER="$RUN_ID-broker"
AGENT="$RUN_ID-agent"
NETWORK="$RUN_ID-internal"
STATE_VOLUME="$RUN_ID-state"
AGENT_VOLUME="$RUN_ID-agent-runtime"
BUILD_DIR="$(mktemp -d "${TMPDIR:-/tmp}/rekey-g2.XXXXXX")"

cleanup() {
  docker rm -f "$AGENT" "$BROKER" >/dev/null 2>&1 || true
  docker network rm "$NETWORK" >/dev/null 2>&1 || true
  docker volume rm "$STATE_VOLUME" "$AGENT_VOLUME" >/dev/null 2>&1 || true
  docker image rm "$IMAGE" >/dev/null 2>&1 || true
  rm -rf "$BUILD_DIR"
}
trap cleanup EXIT

fail() {
  echo "linux-g2: $*" >&2
  exit 1
}

command -v docker >/dev/null || fail "docker is required"
command -v curl >/dev/null || fail "curl is required for authoritative DNS lookup"
command -v python3 >/dev/null || fail "python3 is required"
docker info >/dev/null 2>&1 || fail "docker daemon is unavailable"
[[ "$(docker info --format '{{.OSType}}')" == "linux" ]] || fail "docker daemon is not Linux"

# This host uses a TUN fake-DNS range that Rekey correctly rejects. Resolve a
# real public endpoint through DNS-over-HTTPS, then pin it in the Broker's
# container hosts file so the production transport still performs its normal
# public-IP screening and direct TLS/SNI validation without a proxy fallback.
EXAMPLE_IP="$(curl --silent --show-error --max-time 10 \
  -H 'accept: application/dns-json' \
  'https://cloudflare-dns.com/dns-query?name=example.com&type=A' \
  | python3 -c '
import ipaddress, json, sys
answers = json.load(sys.stdin).get("Answer", [])
addresses = [a["data"] for a in answers if a.get("type") == 1]
if not addresses or not ipaddress.ip_address(addresses[0]).is_global:
    raise SystemExit("no public example.com A record")
print(addresses[0])
')" || fail "cannot resolve a real public example.com address"

tar -C "$ROOT" --exclude=.git --exclude=target -cf - . | tar -C "$BUILD_DIR" -xf -
cat >"$BUILD_DIR/g2_probe.rs" <<'RUST'
use std::ffi::c_void;
use std::net::{TcpStream, ToSocketAddrs};
use std::path::Path;
use std::time::Duration;

unsafe extern "C" {
    fn ptrace(request: i32, pid: i32, addr: *mut c_void, data: *mut c_void) -> i64;
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("connect") => {
            let target = args.get(2).expect("connect target");
            let connected = target
                .to_socket_addrs()
                .ok()
                .into_iter()
                .flatten()
                .any(|addr| TcpStream::connect_timeout(&addr, Duration::from_secs(3)).is_ok());
            std::process::exit(if connected { 0 } else { 1 });
        }
        Some("ptrace") => {
            let pid: i32 = args.get(2).expect("pid").parse().expect("numeric pid");
            if Path::new(&format!("/proc/{pid}")).exists() {
                eprintln!("Broker PID is visible in the Agent namespace");
                std::process::exit(2);
            }
            let result = unsafe {
                ptrace(16, pid, std::ptr::null_mut(), std::ptr::null_mut())
            };
            if result == 0 {
                unsafe {
                    ptrace(17, pid, std::ptr::null_mut(), std::ptr::null_mut());
                }
                eprintln!("ptrace unexpectedly succeeded");
                std::process::exit(2);
            }
        }
        _ => panic!("usage: g2-probe connect HOST:PORT | ptrace PID"),
    }
}
RUST
cat >"$BUILD_DIR/Dockerfile" <<'DOCKERFILE'
FROM rust:1.95-slim-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --release -p rekey-cli -p rekey-broker
RUN rustc -O /src/g2_probe.rs -o /src/target/release/g2-probe

FROM rust:1.95-slim-bookworm
COPY --from=build /src/target/release/rekey /usr/local/bin/rekey
COPY --from=build /src/target/release/rekeyd /usr/local/bin/rekeyd
COPY --from=build /src/target/release/g2-probe /usr/local/bin/g2-probe
DOCKERFILE
docker build --pull=false --quiet --tag "$IMAGE" "$BUILD_DIR" >/dev/null

docker network create --internal "$NETWORK" >/dev/null
docker volume create "$STATE_VOLUME" >/dev/null
docker volume create "$AGENT_VOLUME" >/dev/null
docker run --rm \
  --volume "$STATE_VOLUME:/state" \
  --volume "$AGENT_VOLUME:/run/rekey-agent" \
  "$IMAGE" sh -ceu '
    chown 10001:10001 /state
    chmod 0700 /state
    chown 10001:20000 /run/rekey-agent
    chmod 0770 /run/rekey-agent
  '

PASSWORD="$(python3 -c 'import secrets; print(secrets.token_urlsafe(24))')"
CANARY="$(python3 -c 'import secrets; print("rk_g2_" + secrets.token_urlsafe(24))')"
printf '%s\n' "$PASSWORD" | docker run --rm -i \
  --user 10001:10001 \
  --volume "$STATE_VOLUME:/state" \
  "$IMAGE" rekeyd init --state-dir /state --password-stdin >/dev/null

docker run -d --name "$BROKER" \
  --user 10001:10001 \
  --group-add 20000 \
  --volume "$STATE_VOLUME:/state" \
  --volume "$AGENT_VOLUME:/run/rekey-agent" \
  --add-host "example.com:$EXAMPLE_IP" \
  "$IMAGE" rekeyd serve \
    --state-dir /state \
    --idle-lock 15m \
    --agent-runtime-dir /run/rekey-agent \
    --agent-uid 0 \
    --agent-gid 20000 >/dev/null

for _ in $(seq 1 200); do
  docker exec "$BROKER" test -S /state/runtime/admin.sock \
    && docker exec "$BROKER" test -S /run/rekey-agent/agent.sock \
    && break
  sleep 0.05
done
docker exec "$BROKER" test -S /state/runtime/admin.sock || fail "admin socket missing"
docker exec "$BROKER" test -S /run/rekey-agent/agent.sock || fail "agent socket missing"
[[ "$(docker exec "$BROKER" stat -c '%a:%u:%g' /state/runtime/admin.sock)" == "600:10001:10001" ]] \
  || fail "admin socket ownership or mode is insecure"
[[ "$(docker exec "$BROKER" stat -c '%a:%u:%g' /run/rekey-agent/agent.sock)" == "660:10001:20000" ]] \
  || fail "agent socket ownership or mode is insecure"

printf '%s\n' "$PASSWORD" | docker exec -i "$BROKER" \
  rekey --state-dir /state unlock --password-stdin >/dev/null
CREDENTIAL_JSON="$(printf '%s\n%s\n' "$PASSWORD" "$CANARY" | docker exec -i "$BROKER" \
  rekey --state-dir /state credential add g2-canary --stdin-secrets)"
CREDENTIAL_ID="$(printf '%s' "$CREDENTIAL_JSON" | python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])')"

cat <<EOF | docker exec -i "$BROKER" sh -c 'cat >/tmp/action.json'
{
  "name": "g2-example-get",
  "credential_id": "$CREDENTIAL_ID",
  "origin": "https://example.com",
  "method": "GET",
  "exact_path": "/",
  "auth_header": "authorization",
  "auth_prefix": "Bearer ",
  "timeout_ms": 30000,
  "request_max_bytes": 1024,
  "allowed_extra_headers": [],
  "response_max_bytes": 262144,
  "allowed_response_headers": ["content-type"]
}
EOF
ACTION_JSON="$(printf '%s\n' "$PASSWORD" | docker exec -i "$BROKER" \
  rekey --state-dir /state action create --file /tmp/action.json --password-stdin)"
ACTION_REF="$(printf '%s' "$ACTION_JSON" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d["id"]+"@"+str(d["version"]))')"
SESSION_JSON="$(printf '%s\n' "$PASSWORD" | docker exec -i "$BROKER" \
  rekey --state-dir /state session create --action "$ACTION_REF" --ttl 10m --max-uses 3 --password-stdin)"
CAPABILITY="$(printf '%s' "$SESSION_JSON" | python3 -c 'import json,sys; print(json.load(sys.stdin)["capability_token"])')"

docker run -d --name "$AGENT" \
  --user 0:0 \
  --group-add 20000 \
  --read-only \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --network "$NETWORK" \
  --add-host "example.com:$EXAMPLE_IP" \
  --volume "$AGENT_VOLUME:/run/rekey-agent:ro" \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,mode=1777 \
  "$IMAGE" sleep infinity >/dev/null

INSPECT="$(docker inspect "$AGENT" --format '{{json .HostConfig}}')"
printf '%s' "$INSPECT" | python3 -c '
import json,sys
h=json.load(sys.stdin)
assert h["Privileged"] is False
assert h["ReadonlyRootfs"] is True
assert "ALL" in (h["CapDrop"] or [])
assert "no-new-privileges" in (h["SecurityOpt"] or [])
assert h["PidMode"] == ""
' || fail "agent container isolation invariant failed"
[[ "$(docker network inspect "$NETWORK" --format '{{.Internal}}')" == "true" ]] \
  || fail "agent network is not internal"

docker exec "$AGENT" test ! -e /state || fail "state directory is visible to Agent"
docker exec "$AGENT" test ! -S /run/rekey-agent/admin.sock || fail "admin socket is visible to Agent"
docker exec "$AGENT" test ! -S /var/run/docker.sock || fail "Docker socket is visible to Agent"
if docker exec "$AGENT" g2-probe connect example.com:443 >/dev/null 2>&1; then
  fail "Agent has direct egress"
fi

BROKER_HOST_PID="$(docker inspect "$BROKER" --format '{{.State.Pid}}')"
docker exec "$AGENT" g2-probe ptrace "$BROKER_HOST_PID" \
  || fail "Broker process is visible or ptraceable from Agent"

if printf '%s\n' "$CAPABILITY" | docker run --rm -i \
  --user 12345:20000 \
  --group-add 20000 \
  --read-only \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --network "$NETWORK" \
  --volume "$AGENT_VOLUME:/run/rekey-agent:ro" \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,mode=1777 \
  "$IMAGE" rekey --state-dir /tmp/unused --agent-socket /run/rekey-agent/agent.sock \
    execute "$ACTION_REF" --capability - >/dev/null 2>&1; then
  fail "unlisted Agent UID reached the data plane"
fi

EXECUTE_OUTPUT="$(printf '%s\n' "$CAPABILITY" | docker exec -i "$AGENT" \
  rekey --state-dir /tmp/unused --agent-socket /run/rekey-agent/agent.sock \
    execute "$ACTION_REF" --capability -)"
STATUS="$(printf '%s' "$EXECUTE_OUTPUT" | python3 -c '
import json,sys
value,_=json.JSONDecoder().raw_decode(sys.stdin.read().lstrip())
print(value["upstream_status"])
')"
[[ "$STATUS" == "200" ]] || fail "approved execute returned upstream status $STATUS"
printf '%s' "$EXECUTE_OUTPUT" | grep -Fq "$CANARY" && fail "secret reached Agent output"
docker logs "$BROKER" 2>&1 | grep -Fq "$CANARY" && fail "secret reached Broker logs"

printf '%s\n' "$PASSWORD" | docker exec -i "$BROKER" \
  rekey --state-dir /state shutdown --password-stdin >/dev/null

echo "linux-g2: PASS"
echo "linux-g2: kernel=$(docker version --format '{{.Server.KernelVersion}}') arch=$(docker version --format '{{.Server.Arch}}')"
echo "linux-g2: public-endpoint=example.com/$EXAMPLE_IP (DoH-pinned; direct TLS)"
echo "linux-g2: proved=uid,pid,ptrace,state,admin,docker-socket,direct-egress,approved-execute"
echo "linux-g2: limitation=does-not-cover-kernel,docker-daemon,vm-host,container-runtime-compromise"
