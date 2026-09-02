#!/usr/bin/env bash
# Linux namespace G2 reference attack harness. Runs only disposable Docker
# resources and proves the documented container boundary, not kernel/daemon safety.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
RUN_ID="rekey-g2-$$"
IMAGE="$RUN_ID:local"
BROKER="$RUN_ID-broker"
AGENT="$RUN_ID-agent"
FAKE_BROKER="$RUN_ID-fake-broker"
DNS_TARGET="$RUN_ID-dns-target"
NETWORK="$RUN_ID-internal"
STATE_VOLUME="$RUN_ID-state"
AGENT_VOLUME="$RUN_ID-agent-runtime"
FAKE_VOLUME="$RUN_ID-fake-runtime"
BUILD_DIR="$(mktemp -d "${TMPDIR:-/tmp}/rekey-g2.XXXXXX")"

cleanup() {
  docker rm -f "$AGENT" "$BROKER" "$FAKE_BROKER" "$DNS_TARGET" >/dev/null 2>&1 || true
  docker network rm "$NETWORK" >/dev/null 2>&1 || true
  docker volume rm "$STATE_VOLUME" "$AGENT_VOLUME" "$FAKE_VOLUME" >/dev/null 2>&1 || true
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
command -v openssl >/dev/null || fail "openssl is required"
docker info >/dev/null 2>&1 || fail "docker daemon is unavailable"
[[ "$(docker info --format '{{.OSType}}')" == "linux" ]] || fail "docker daemon is not Linux"
DOCKER_ENGINE_VERSION="$(docker version --format '{{.Server.Version}}')" \
  || fail "cannot read Docker Engine version"
DOCKER_ENGINE_MAJOR="${DOCKER_ENGINE_VERSION%%.*}"
[[ "$DOCKER_ENGINE_MAJOR" =~ ^[0-9]+$ ]] \
  || fail "unrecognized Docker Engine version: $DOCKER_ENGINE_VERSION"
(( DOCKER_ENGINE_MAJOR >= 26 )) \
  || fail "Docker Engine >=26 is required; older/backported builds are not accepted by this gate (found $DOCKER_ENGINE_VERSION)"

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
use std::ffi::{CString, c_char, c_void};
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::os::unix::net::{UnixListener, UnixStream};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::time::Duration;

unsafe extern "C" {
    fn ptrace(request: i32, pid: i32, addr: *mut c_void, data: *mut c_void) -> i64;
    fn chown(path: *const c_char, owner: u32, group: u32) -> i32;
    fn chmod(path: *const c_char, mode: u32) -> i32;
    fn setgid(gid: u32) -> i32;
    fn setuid(uid: u32) -> i32;
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
        Some("resolve") => {
            let host = args.get(2).expect("DNS hostname");
            let resolved = (host.as_str(), 443)
                .to_socket_addrs()
                .ok()
                .is_some_and(|mut addresses| addresses.next().is_some());
            std::process::exit(if resolved { 0 } else { 1 });
        }
        Some("replace-socket") => {
            let path = args.get(2).expect("Agent socket path");
            if std::fs::remove_file(path).is_err() {
                std::process::exit(1);
            }
            let _listener = UnixListener::bind(path).expect("replace Agent socket");
        }
        Some("fake-broker") => {
            let path = Path::new(args.get(2).expect("fake socket path"));
            let parent = path.parent().expect("fake runtime parent");
            std::fs::create_dir_all(parent).expect("create fake runtime");
            let parent_c = CString::new(parent.as_os_str().as_bytes()).expect("parent CString");
            assert_eq!(unsafe { chown(parent_c.as_ptr(), 10001, 20000) }, 0);
            assert_eq!(unsafe { chmod(parent_c.as_ptr(), 0o750) }, 0);
            let listener = UnixListener::bind(path).expect("bind fake Broker");
            let path_c = CString::new(path.as_os_str().as_bytes()).expect("path CString");
            assert_eq!(unsafe { chown(path_c.as_ptr(), 10001, 20000) }, 0);
            assert_eq!(unsafe { chmod(path_c.as_ptr(), 0o660) }, 0);
            assert_eq!(unsafe { setgid(12345) }, 0);
            assert_eq!(unsafe { setuid(12345) }, 0);
            let _stream = listener.accept().expect("accept attacked CLI").0;
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
        Some("agent-status") => {
            let path = args.get(2).expect("agent socket path");
            let expectation = args.get(3).expect("allowed or denied");
            let mut stream = UnixStream::connect(path).expect("connect Agent socket");
            stream
                .set_read_timeout(Some(Duration::from_secs(3)))
                .expect("set read timeout");
            let mut frame = Vec::with_capacity(38);
            frame.extend_from_slice(b"RKIP");
            frame.extend_from_slice(&1u16.to_be_bytes());
            frame.extend_from_slice(&[2, 0]);
            frame.extend_from_slice(&2u16.to_be_bytes());
            frame.extend_from_slice(&0u16.to_be_bytes());
            frame.extend_from_slice(&[0x11; 16]);
            frame.extend_from_slice(&2u32.to_be_bytes());
            frame.extend_from_slice(&0u32.to_be_bytes());
            frame.extend_from_slice(b"{}");
            if let Err(error) = stream.write_all(&frame) {
                if expectation == "denied" {
                    return;
                }
                panic!("write Agent status frame: {error}");
            }
            let mut response = [0u8; 36];
            let received = stream.read_exact(&mut response).is_ok();
            match expectation.as_str() {
                "allowed" if received && &response[..4] == b"RKIP" => {}
                "denied" if !received => {}
                _ => panic!(
                    "Agent peer-UID expectation failed: {expectation}, received={received}"
                ),
            }
        }
        _ => panic!(
            "usage: g2-probe connect HOST:PORT | resolve HOST | ptrace PID | agent-status SOCKET allowed|denied | replace-socket SOCKET | fake-broker SOCKET"
        ),
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
docker volume create "$FAKE_VOLUME" >/dev/null
docker run --rm \
  --volume "$STATE_VOLUME:/state" \
  --volume "$AGENT_VOLUME:/run/rekey-agent" \
  "$IMAGE" sh -ceu '
    chown 10001:10001 /state
    chmod 0700 /state
    chown 10001:20000 /run/rekey-agent
    chmod 0750 /run/rekey-agent
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
[[ "$(docker exec "$BROKER" stat -c '%a:%u:%g' /run/rekey-agent)" == "750:10001:20000" ]] \
  || fail "agent runtime directory ownership or mode permits endpoint replacement"

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
PRINCIPAL_ID="$(printf '%s' "$SESSION_JSON" | python3 -c 'import json,sys; print(json.load(sys.stdin)["principal_id"])')"
ACTION_ID="${ACTION_REF%@*}"
ACTION_VERSION="${ACTION_REF#*@}"
POLICY_RULE_ID="$(python3 -c 'import uuid; print(uuid.uuid4())')"
POLICY_EXPIRES_MS="$(python3 -c 'import time; print(int(time.time() * 1000) + 600000)')"
cat >"$BUILD_DIR/policy-snapshot.json" <<EOF
{
  "format_version": 2,
  "version": 1,
  "expires_at_ms": $POLICY_EXPIRES_MS,
  "approvers": [],
  "bindings": [{
    "action_id": "$ACTION_ID",
    "version": $ACTION_VERSION,
    "resource": {"type": "fixed-http-action", "id": "$ACTION_ID"},
    "parameter_schema_id": "g2-empty/v1",
    "parameter_schema": {"type": "null"}
  }],
  "rules": [{
    "id": "$POLICY_RULE_ID",
    "effect": "permit",
    "principal_id": "$PRINCIPAL_ID",
    "action_id": "$ACTION_ID",
    "version": $ACTION_VERSION,
    "resource": {"type": "fixed-http-action", "id": "$ACTION_ID"},
    "parameters": {"kind": "any_validated"}
  }]
}
EOF
python3 "$ROOT/scripts/sign-test-policy.py" policy --key-dir "$BUILD_DIR/policy-key" \
  --snapshot "$BUILD_DIR/policy-snapshot.json" --bundle "$BUILD_DIR/policy.json" \
  --trust "$BUILD_DIR/policy-trust.json"
docker cp "$BUILD_DIR/policy.json" "$BROKER:/tmp/policy.json"
docker cp "$BUILD_DIR/policy-trust.json" "$BROKER:/tmp/policy-trust.json"
printf '%s\n' "$PASSWORD" | docker exec -i "$BROKER" \
  rekey --state-dir /state policy trust install --file /tmp/policy-trust.json \
  --step-up-stdin >/dev/null
printf '%s\n' "$PASSWORD" | docker exec -i "$BROKER" \
  rekey --state-dir /state policy activate --file /tmp/policy.json --step-up-stdin >/dev/null

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

docker run -d --name "$DNS_TARGET" \
  --read-only \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --network "$NETWORK" \
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
# Positive control: Docker's embedded resolver can still resolve peers on the
# internal network. The negative assertion below proves only that public-name
# resolution is blocked; without authoritative telemetry it does not prove
# that no external DNS query packet was emitted.
docker exec "$AGENT" g2-probe resolve "$DNS_TARGET" >/dev/null 2>&1 \
  || fail "internal-network DNS positive control failed"
if docker exec "$AGENT" g2-probe resolve www.cloudflare.com >/dev/null 2>&1; then
  fail "external DNS resolution succeeded from an internal network"
fi

# The read-only reference mount is defense in depth, not the endpoint's only
# replacement barrier. A distinct UID with the shared group and a writable
# mount must still be unable to unlink and impersonate the Broker socket.
if docker run --rm \
  --user 12345:20000 \
  --group-add 20000 \
  --read-only \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --network "$NETWORK" \
  --volume "$AGENT_VOLUME:/run/rekey-agent:rw" \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,mode=1777 \
  "$IMAGE" g2-probe replace-socket /run/rekey-agent/agent.sock >/dev/null 2>&1; then
  fail "shared Agent group replaced the Broker socket through a writable mount"
fi
docker exec "$BROKER" test -S /run/rekey-agent/agent.sock \
  || fail "replacement attack removed the Broker socket"

# Metadata alone is not Broker authentication. This listener makes its path
# look Broker-owned, then drops to a foreign UID before the real release CLI
# connects. The CLI must reject the SO_PEERCRED mismatch before sending the
# capability or any RKIP frame.
docker run -d --name "$FAKE_BROKER" \
  --volume "$FAKE_VOLUME:/run/rekey-fake" \
  "$IMAGE" g2-probe fake-broker /run/rekey-fake/agent.sock >/dev/null
for _ in $(seq 1 200); do
  docker exec "$FAKE_BROKER" test -S /run/rekey-fake/agent.sock && break
  sleep 0.05
done
docker exec "$FAKE_BROKER" test -S /run/rekey-fake/agent.sock \
  || fail "foreign-UID fake Broker socket missing"
set +e
FAKE_OUTPUT="$(printf '%s\n' "$CAPABILITY" | docker run --rm -i \
  --user 0:0 \
  --group-add 20000 \
  --read-only \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --network "$NETWORK" \
  --volume "$FAKE_VOLUME:/run/rekey-fake:ro" \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,mode=1777 \
  "$IMAGE" rekey --state-dir /tmp/unused \
    --agent-socket /run/rekey-fake/agent.sock execute "$ACTION_REF" --capability - 2>&1)"
FAKE_STATUS=$?
set -e
[[ "$FAKE_STATUS" == "7" ]] \
  || fail "foreign-UID fake Broker returned exit $FAKE_STATUS instead of IPC_UNAVAILABLE: $FAKE_OUTPUT"
printf '%s' "$FAKE_OUTPUT" | grep -Fq 'connected peer is not the Broker' \
  || fail "foreign-UID fake Broker did not fail on peer mismatch: $FAKE_OUTPUT"

BROKER_HOST_PID="$(docker inspect "$BROKER" --format '{{.State.Pid}}')"
docker exec "$AGENT" g2-probe ptrace "$BROKER_HOST_PID" \
  || fail "Broker process is visible or ptraceable from Agent"

docker exec "$AGENT" g2-probe agent-status /run/rekey-agent/agent.sock allowed \
  || fail "allowlisted Agent UID could not reach the data plane"
docker run --rm \
  --user 12345:20000 \
  --group-add 20000 \
  --read-only \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --network "$NETWORK" \
  --volume "$AGENT_VOLUME:/run/rekey-agent:ro" \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,mode=1777 \
  "$IMAGE" g2-probe agent-status /run/rekey-agent/agent.sock denied \
  || fail "unlisted Agent UID reached the data plane"

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
echo "linux-g2: engine=$DOCKER_ENGINE_VERSION kernel=$(docker version --format '{{.Server.KernelVersion}}') arch=$(docker version --format '{{.Server.Arch}}')"
echo "linux-g2: public-endpoint=example.com/$EXAMPLE_IP (DoH-pinned; direct TLS)"
echo "linux-g2: proved=uid,pid,ptrace,state,admin,docker-socket,socket-replacement,direct-egress,internal-dns-positive,external-dns-resolution-blocked,broker-peer-mismatch,approved-execute"
echo "linux-g2: limitation=does-not-cover-kernel,docker-daemon,vm-host,container-runtime-compromise"
