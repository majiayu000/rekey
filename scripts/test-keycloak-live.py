#!/usr/bin/env python3
"""Real Keycloak 26.7.3 + BrokerRuntime acceptance via a test-only local TLS transport.

Build rekey, rekeyd and --example oau02_keycloak_fixture first. Docker image must
already exist locally. Output contains only a non-secret receipt; all generated
secrets and the uniquely named container are removed in finally.
"""
import argparse
import base64
import datetime
import http.client
import http.server
import json
import os
from pathlib import Path
import secrets
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

IMAGE = "quay.io/keycloak/keycloak:26.7.3"
ROOT = Path(__file__).resolve().parent.parent


def command(args, data=None, timeout=45, expected=0):
    result = subprocess.run(list(map(str, args)), input=data, capture_output=True,
                            text=True, timeout=timeout, check=False)
    if result.returncode != expected:
        raise RuntimeError("command returned unexpected status")
    return result


def claims(token):
    part = token.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bin-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True, help="new receipt directory")
    args = parser.parse_args()
    os.umask(0o077)
    args.output.mkdir(parents=True, exist_ok=False)
    binaries = args.bin_dir.resolve()
    suffix = uuid.uuid4().hex[:12]
    container = "rekey-oau02-live-" + suffix
    realm_name = "rekey-oau02-live-" + suffix
    secret_values = [secrets.token_urlsafe(36) for _ in range(3)]
    requester_secret, target_secret, proof = secret_values
    receipt = {"scope": "real Keycloak Standard V2 + real BrokerRuntime/UDS + injected local TLS transport; not public production-screening acceptance",
               "image": IMAGE, "container": container, "realm": realm_name,
               "started_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
               "steps": [], "pass": False}
    created = False
    broker = None
    server = None
    server_thread = None
    stage = "setup"
    transcript = []
    temporary = tempfile.TemporaryDirectory(prefix="rkoau.", dir="/tmp")
    work = Path(temporary.name)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    provider_events = []
    resources = []
    revocations = []
    fixture_errors = []
    issued_tokens = []
    reflect = False

    def record(name, **fields):
        receipt["steps"].append({"step": name, **fields})
        print(name + ": passed", flush=True)

    try:
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            provider_port = reservation.getsockname()[1]
        provider_origin = f"http://127.0.0.1:{provider_port}"
        provider_base = f"{provider_origin}/realms/{realm_name}/protocol/openid-connect"

        def post(endpoint, values, target=False):
            form = {"client_id": "rekey-target" if target else "rekey-requester",
                    "client_secret": target_secret if target else requester_secret, **values}
            request = urllib.request.Request(provider_base + "/" + endpoint,
                data=urllib.parse.urlencode(form).encode(),
                headers={"Content-Type": "application/x-www-form-urlencoded"})
            try:
                response = opener.open(request, timeout=10)
            except urllib.error.HTTPError as error:
                response = error
            with response:
                raw = response.read(65537)
                if len(raw) > 65536:
                    raise RuntimeError("provider response oversized")
                return response.status, json.loads(raw) if raw else {}

        realm = {"realm": realm_name, "enabled": True, "sslRequired": "none",
            "accessTokenLifespan": 30, "revokeRefreshToken": True,
            "defaultDefaultClientScopes": [], "defaultOptionalClientScopes": [],
            "clients": [
              {"clientId": "rekey-requester", "protocol": "openid-connect",
               "publicClient": False, "secret": requester_secret,
               "defaultClientScopes": [], "optionalClientScopes": [], "fullScopeAllowed": False,
               "standardFlowEnabled": False, "directAccessGrantsEnabled": False,
               "serviceAccountsEnabled": True,
               "attributes": {"standard.token.exchange.enabled": "true", "access.token.lifespan": "30"},
               "protocolMappers": [{"name": "fixed-target", "protocol": "openid-connect",
                 "protocolMapper": "oidc-audience-mapper", "config": {
                   "included.client.audience": "rekey-target", "access.token.claim": "true", "id.token.claim": "false"}}]},
              {"clientId": "rekey-target", "protocol": "openid-connect", "publicClient": False,
               "secret": target_secret, "defaultClientScopes": [], "optionalClientScopes": [],
               "fullScopeAllowed": False, "standardFlowEnabled": False, "directAccessGrantsEnabled": False}]}
        realm_file = work / "realm.json"
        realm_file.write_text(json.dumps(realm))
        image = json.loads(command(["docker", "image", "inspect", IMAGE]).stdout)[0]
        receipt["image_id"] = image["Id"]
        receipt["image_digests"] = image.get("RepoDigests", [])
        command(["docker", "create", "--name", container, "--user", "0", "--log-driver", "none",
            "-p", f"127.0.0.1:{provider_port}:{provider_port}", "--mount",
            f"type=bind,src={realm_file},dst=/opt/keycloak/data/import/{realm_name}-realm.json,readonly",
            IMAGE, "start-dev", "--http-port", provider_port, "--import-realm",
            "--features=token-exchange-standard:v2", "--features-disabled=token-exchange", "--log-level=error"])
        created = True
        command(["docker", "start", container])
        stage = "provider-readiness"
        deadline = time.monotonic() + 120
        while True:
            try:
                with opener.open(f"{provider_origin}/realms/{realm_name}/.well-known/openid-configuration", timeout=2) as response:
                    discovery = json.load(response)
                assert discovery["issuer"] == f"{provider_origin}/realms/{realm_name}"
                break
            except (OSError, urllib.error.URLError):
                if time.monotonic() >= deadline:
                    raise RuntimeError("Keycloak readiness timed out")
                time.sleep(1)
        record(stage)

        # No provider token exchange logic in this fixture: forward the Broker's
        # exact request to real Keycloak. The resource validates by introspection.
        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *_args):
                pass

            def answer(self, status, body, content_type="application/json"):
                self.send_response(status)
                self.send_header("content-type", content_type)
                self.send_header("content-length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):
                try:
                    if self.path != "/fixed":
                        self.answer(404, b"{}")
                        return
                    authorization = self.headers.get("authorization", "")
                    assert authorization.startswith("Bearer ")
                    token = authorization[7:]
                    status, detail = post("token/introspect", {"token": token}, target=True)
                    aud = detail.get("aud")
                    audience = [aud] if isinstance(aud, str) else aud
                    valid = status == 200 and detail.get("active") is True and audience == ["rekey-target"]
                    resources.append({"token": token, "valid": valid, "audience": audience})
                    provider_events.append("resource")
                    self.answer(200 if valid else 401, token.encode() if reflect else b'{"ok":true}')
                except Exception as error:
                    fixture_errors.append(type(error).__name__)
                    self.answer(500, b"{}")

            def do_POST(self):
                try:
                    length = int(self.headers.get("content-length", "0"))
                    assert 0 <= length <= 65536
                    body = self.rfile.read(length)
                    assert self.path.startswith(f"/realms/{realm_name}/protocol/openid-connect/")
                    connection = http.client.HTTPConnection("127.0.0.1", provider_port, timeout=10)
                    try:
                        connection.request("POST", self.path, body, {
                            "authorization": self.headers.get("authorization", ""),
                            "content-type": self.headers.get("content-type", ""),
                        })
                        response = connection.getresponse()
                        raw = response.read(65537)
                        assert len(raw) <= 65536
                        status = response.status
                    finally:
                        connection.close()
                    if self.path.endswith("/token"):
                        provider_events.append("exchange")
                        detail = json.loads(raw)
                        if status == 200:
                            token = detail["access_token"]
                            issued_tokens.append(token)
                            secret_values.append(token)
                        else:
                            receipt["last_exchange_http_status"] = status
                    elif self.path.endswith("/revoke"):
                        token = urllib.parse.parse_qs(body.decode())["token"][0]
                        provider_events.append("revoke")
                        check_status, detail = post("token/introspect", {"token": token}, target=True)
                        remaining = claims(token)["exp"] - time.time()
                        revocations.append({"token": token, "revoke_status": status,
                            "introspection_status": check_status, "active": detail.get("active"),
                            "remaining_ttl_seconds": remaining})
                    self.answer(status, raw)
                except Exception as error:
                    fixture_errors.append(type(error).__name__)
                    self.answer(500, b"{}")

        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        server.daemon_threads = True
        tls_port = server.server_port
        tls_origin = f"https://oau02.test:{tls_port}"
        cert = work / "tls.pem"
        key = work / "tls-key.pem"
        ca_der = work / "tls.der"
        ca = work / "ca.pem"
        ca_key = work / "ca-key.pem"
        csr = work / "tls.csr"
        extensions = work / "tls.ext"
        extensions.write_text("subjectAltName=DNS:oau02.test\nbasicConstraints=critical,CA:FALSE\nextendedKeyUsage=serverAuth\n")
        command(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                 "-keyout", ca_key, "-out", ca, "-subj", "/CN=rekey-oau02-test-ca",
                 "-addext", "basicConstraints=critical,CA:TRUE"])
        command(["openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes", "-keyout", key,
                 "-out", csr, "-subj", "/CN=oau02.test"])
        command(["openssl", "x509", "-req", "-in", csr, "-CA", ca, "-CAkey", ca_key,
                 "-CAcreateserial", "-days", "1", "-extfile", extensions, "-out", cert])
        command(["openssl", "x509", "-in", ca, "-outform", "DER", "-out", ca_der])
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)
        server.socket = context.wrap_socket(server.socket, server_side=True)
        server_thread = threading.Thread(target=server.serve_forever, daemon=True)
        server_thread.start()
        state = work / "state"
        base = [binaries / "rekey", "--state-dir", state]

        def cli(arguments, data=None):
            result = command(base + arguments, data)
            transcript.extend([result.stdout, result.stderr])
            return json.loads(result.stdout)

        command([binaries / "rekeyd", "init", "--state-dir", state, "--password-stdin"], proof + "\n")
        log_file = work / "broker.log"
        with log_file.open("w") as log:
            broker = subprocess.Popen(list(map(str, [binaries / "examples/oau02_keycloak_fixture", state, ca_der, tls_port])), stdout=log, stderr=log)
        deadline = time.monotonic() + 15
        while not (state / "runtime/admin.sock").exists():
            assert broker.poll() is None and time.monotonic() < deadline
            time.sleep(0.05)
        cli(["unlock", "--password-stdin"], proof + "\n")

        def subject():
            status, result = post("token", {"grant_type": "client_credentials"})
            assert status == 200
            token = result["access_token"]
            secret_values.append(token)
            return token

        def profile(token):
            path = work / (uuid.uuid4().hex + "-profile.json")
            path.write_text(json.dumps({"credential_type": "keycloak-token-exchange-v1",
                "origin": tls_origin, "realm": realm_name, "client_id": "rekey-requester",
                "client_secret": requester_secret, "subject_token": token, "audience": "rekey-target",
                "target_origin": tls_origin, "target_path": "/fixed"}))
            assert path.stat().st_mode & 0o777 == 0o600
            return path

        stage = "admin-profile-add"
        credential = cli(["credential", "add-keycloak", "keycloak-live", "--file", profile(subject()), "--password-stdin"], proof + "\n")
        record(stage, kind=credential["kind"], version=credential["current_version"])
        definition = work / "action.json"
        definition.write_text(json.dumps({"name": "keycloak-live", "credential_id": credential["id"],
            "origin": tls_origin, "method": "GET", "exact_path": "/fixed", "auth_header": "authorization",
            "auth_prefix": "Bearer ", "timeout_ms": 15000, "request_max_bytes": 1024,
            "allowed_extra_headers": [], "response_max_bytes": 65536, "allowed_response_headers": ["content-type"]}))
        action = cli(["action", "create", "--file", definition, "--password-stdin"], proof + "\n")
        reference = f'{action["id"]}@{action["version"]}'
        session = cli(["session", "create", "--action", reference, "--ttl", "10m", "--max-uses", "5", "--password-stdin"], proof + "\n")
        secret_values.append(session["capability_token"])
        # Capability is expected only in this one operator session-creation response;
        # scan Agent-facing output and logs separately below.
        transcript.pop(-2)
        resource = {"type": "fixed-http-action", "id": action["id"]}
        draft = work / "policy.json"
        draft.write_text(json.dumps({"format_version": 3, "version": 1, "expires_at_ms": int(time.time()*1000)+600000,
            "approvers": [], "workload_identities": [], "bindings": [{"action_id": action["id"], "version": 1,
                "resource": resource, "parameter_schema_id": "keycloak-live/v1", "parameter_schema": {"type": "null"}}],
            "rules": [{"id": str(uuid.uuid4()), "effect": "permit", "principal_id": session["principal_id"],
                "action_id": action["id"], "version": 1, "resource": resource, "parameters": {"kind": "any_validated"}}]}))
        command([sys.executable, ROOT / "scripts/sign-test-policy.py", "policy", "--key-dir", work / "signer",
                 "--snapshot", draft, "--trust", work / "trust.json", "--bundle", work / "bundle.json"])
        cli(["policy", "trust", "install", "--file", work / "trust.json", "--step-up-stdin"], proof + "\n")
        cli(["policy", "activate", "--file", work / "bundle.json", "--step-up-stdin"], proof + "\n")

        def rotate(token):
            value = cli(["credential", "rotate-keycloak", credential["id"], "--file", profile(token), "--password-stdin"], proof + "\n")
            return value["current_version"]

        def execute():
            result = subprocess.run(list(map(str, base + ["execute", reference, "--capability", "-"])),
                input=session["capability_token"]+"\n", text=True, capture_output=True, timeout=30)
            transcript.extend([result.stdout, result.stderr])
            return result

        def verified_revoke(index):
            revoked = revocations[index]
            assert revoked["token"] == resources[index]["token"] == issued_tokens[index]
            assert revoked["revoke_status"] == 200 and revoked["introspection_status"] == 200
            assert revoked["active"] is False and revoked["remaining_ttl_seconds"] > 0
            return {key: value for key, value in revoked.items() if key != "token"}

        stage = "broker-success-revoked-before-expiry"
        assert rotate(subject()) == 2
        result = execute()
        assert result.returncode == 0
        metadata, _ = json.JSONDecoder().raw_decode(result.stdout.lstrip())
        assert metadata["upstream_status"] == 200
        assert provider_events == ["exchange", "resource", "revoke"]
        assert len(resources) == 1 and resources[0]["valid"] and resources[0]["audience"] == ["rekey-target"]
        record(stage, resource_status=200, exact_audience="rekey-target", credential_version=2, **verified_revoke(0))

        stage = "same-subject-after-issued-revoke"
        previous_events = list(provider_events)
        previous_resources = len(resources)
        same_subject = execute()
        if same_subject.returncode == 0:
            assert provider_events == previous_events + ["exchange", "resource", "revoke"]
            assert len(resources) == previous_resources + 1 and resources[previous_resources]["valid"]
            same_metadata, _ = json.JSONDecoder().raw_decode(same_subject.stdout.lstrip())
            assert same_metadata["upstream_status"] == 200
            record(stage, reusable=True, resource_status=200, **verified_revoke(previous_resources))
        else:
            assert provider_events == previous_events + ["exchange"]
            assert len(resources) == previous_resources and receipt["last_exchange_http_status"] == 400
            record(stage, reusable=False, provider_status=400,
                   consequence="operator must rotate a fresh subject before another successful exchange; not merely after expiry")

        stage = "reflected-token-denied-and-revoked"
        previous_events = list(provider_events)
        reflection_index = len(resources)
        assert rotate(subject()) == 3
        reflect = True
        result = execute()
        assert result.returncode != 0 and "RESPONSE_SECURITY_VIOLATION" in result.stderr
        assert provider_events == previous_events + ["exchange", "resource", "revoke"]
        assert len(resources) == reflection_index + 1 and resources[reflection_index]["valid"]
        record(stage, agent_result="RESPONSE_SECURITY_VIOLATION", credential_version=3, **verified_revoke(reflection_index))

        stage = "expired-subject-denied-without-resource"
        previous_events = list(provider_events)
        previous_resources = len(resources)
        previous_revocations = len(revocations)
        expired = subject()
        assert rotate(expired) == 4
        wait_seconds = max(0, claims(expired)["exp"] + 2 - time.time())
        print(f"Waiting {wait_seconds:.1f}s for dedicated subject expiry", flush=True)
        time.sleep(wait_seconds)
        result = execute()
        assert result.returncode != 0
        assert provider_events == previous_events + ["exchange"]
        assert len(resources) == previous_resources and len(revocations) == previous_revocations
        assert receipt["last_exchange_http_status"] == 400
        record(stage, provider_status=400, resource_requests_added=0, issued_tokens_added=0)
        assert not fixture_errors
        audit = cli(["audit", "list", "--limit", "100"])
        receipt["audit"] = audit
        # JSON audit is an intended secret-free artifact; scan it before persistence.
        transcript.append(log_file.read_text())
        encoded = json.dumps(receipt)
        assert all(value not in encoded and all(value not in text for text in transcript) for value in secret_values)
        receipt["secret_scan_passed"] = True
        receipt["pass"] = True
    except Exception as error:
        receipt["failure"] = {"stage": stage, "class": type(error).__name__}
        print(f"Live acceptance failed at {stage} ({type(error).__name__})", flush=True)
    finally:
        if broker is not None:
            broker.terminate()
            try:
                broker.wait(timeout=15)
            except subprocess.TimeoutExpired:
                broker.kill()
                broker.wait(timeout=10)
        if server is not None:
            if server_thread is not None and server_thread.is_alive():
                server.shutdown()
            server.server_close()
        if server_thread is not None:
            server_thread.join(timeout=5)
        removed = not created
        if created:
            removed = subprocess.run(["docker", "rm", "-f", "-v", container], capture_output=True).returncode == 0
        absent = subprocess.run(["docker", "ps", "-a", "--filter", "name=^/"+container+"$", "--format", "{{.Names}}"], capture_output=True)
        temporary.cleanup()
        receipt["cleanup"] = {"owned_container_removed": removed,
            "owned_container_absent": absent.returncode == 0 and not absent.stdout.strip(),
            "temporary_secret_directory_removed": not work.exists(), "broker_stopped": broker is None or broker.poll() is not None}
        receipt["finished_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        if not all(receipt["cleanup"].values()):
            receipt["pass"] = False
        encoded = json.dumps(receipt, indent=2)
        if any(value in encoded for value in secret_values):
            encoded = json.dumps({"pass": False, "failure": "receipt secret scan failed", "cleanup": receipt["cleanup"]})
            receipt["pass"] = False
        (args.output / "receipt.json").write_text(encoded + "\n")
        print("Cleanup: " + json.dumps(receipt["cleanup"]), flush=True)
    return 0 if receipt["pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
