#!/usr/bin/env bash
# Exercise the 0.4 signed Connection contract using packaged binaries only.
# Software team signing is a portable fixture, not hardware/personal acceptance.
set -euo pipefail
umask 077
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN_DIR="${BIN_DIR:?BIN_DIR must point at unpacked archive binaries}"
python3 - "$ROOT" "$BIN_DIR" <<'PY'
import json
import os
from pathlib import Path
import queue
import socket
import subprocess
import sys
import tempfile
import threading
import time
import uuid

root, binaries = map(Path, sys.argv[1:])
# Deliberately synthetic fixtures; no user credentials are accepted here.
password = b"archive fixture horse battery staple\n"
secret = b"archive-synthetic-credential-canary"
origin = os.environ.get("REKEY_ACCEPTANCE_ORIGIN", "https://api.github.com")
path = os.environ.get("REKEY_ACCEPTANCE_PATH", "/meta")
for name in ("rekey", "rekeyd", "rekey-mcp", "rekey-policy-sign", "rekey-approval-sign"):
    if not os.access(binaries / name, os.X_OK):
        raise SystemExit("required archive executable is missing: " + name)
for name in ("rekey-policy-sign", "rekey-approval-sign"):
    subprocess.run([binaries / name, "--help"], check=True, stdout=subprocess.DEVNULL)

with tempfile.TemporaryDirectory(prefix="rkarch-") as directory:
    work = Path(directory).resolve()
    state = work / "state"
    base = [str(binaries / "rekey"), "--state-dir", str(state)]
    daemon = None
    mcp = None
    diagnostics = work / "broker.err"

    def run(args, data=None, ok=True):
        result = subprocess.run(base + args, input=data, capture_output=True, timeout=150)
        # Even synthetic canaries must not appear in public output.
        assert secret not in result.stdout + result.stderr, "credential appeared in public output"
        if ok and result.returncode:
            sys.stderr.buffer.write(result.stderr)
            raise RuntimeError("packaged CLI failed: " + args[0])
        return result

    def public(args, data=None):
        return json.loads(run(args, data).stdout)

    try:
        # Recovery output is deliberately discarded; this disposable fixture
        # never substitutes for a human's recovery acknowledgement.
        run(["init", "--mode", "team", "--password-stdin"], password)
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            port = listener.getsockname()[1]
        (state / "service.json").write_text(json.dumps({"port": port}))
        with diagnostics.open("wb") as error:
            daemon = subprocess.Popen([binaries / "rekeyd", "serve", "--state-dir", state,
                                       "--idle-lock", "15m"], stdout=subprocess.DEVNULL, stderr=error)
        deadline = time.monotonic() + 30
        while not (state / "runtime/admin.sock").exists() and time.monotonic() < deadline:
            if daemon.poll() is not None:
                raise RuntimeError("packaged daemon exited before readiness")
            time.sleep(.1)
        assert (state / "runtime/admin.sock").exists(), "packaged daemon did not become ready"
        run(["unlock", "--password-stdin"], password)
        assert public(["status"])["format_version"] == 26
        credential = public(["credential", "add", "archive-canary", "--kind", "opaque-token",
                             "--stdin-secrets"], password + secret + b"\n")
        preset = public(["connection", "preset", "generic-header", "--origin", origin,
                         "--header", "x-rekey-archive-fixture", "--prefix", ""])
        connection = dict(preset)
        connection["preset"] = connection.pop("name")
        connection.update(name="archive", credential_id=credential["id"], enabled=True, grade="T0",
                          bindings={}, caller_overrides={}, llm=None, oauth=None,
                          limits={"requests_per_hour": 600, "max_request_bytes": 1048576,
                                  "max_response_bytes": 4194304})
        # The arbitrary-origin Preset starts with approval. The fixture signs
        # a narrow read grant; writes retain explicit approval.
        connection["rules"] = [
            {"id": str(uuid.uuid4()), "methods": ["GET"], "path": path, "effect": "allow"},
            {"id": str(uuid.uuid4()), "methods": "write", "path": "/**", "effect": "approve"},
        ]
        snapshot = dict(format_version=7, version=1, expires_at_ms=int(time.time()*1000)+600000,
                        approvers=[], workload_identities=[], profiles=[], connections=[connection],
                        ssh_keys=[], derived_credentials=[], bindings=[], rules=[])
        (work / "policy.json").write_text(json.dumps(snapshot))
        subprocess.run([sys.executable, root / "scripts/sign-test-policy.py", "policy",
                        "--key-dir", work / "signer", "--snapshot", work / "policy.json",
                        "--bundle", work / "bundle.json", "--trust", work / "trust.json"], check=True)
        run(["policy", "trust", "install", "--file", str(work / "trust.json"),
             "--step-up-stdin"], password)
        target = public(["policy", "status"])
        run(["policy", "activate", "--file", str(work / "bundle.json"),
             "--expected-vault-id", target["vault_id"], "--expected-trust-sha256", target["trust_sha256"],
             "--step-up-stdin"], password)
        inventory = public(["list", "--json"])
        assert inventory["connections"][0]["connection"] == "archive"
        preview = public(["http", "archive", "GET", path, "--dry-run"])
        assert preview["effect"] == "allow"
        response = public(["http", "archive", "GET", path])
        assert response["status"] == 200
        write = run(["http", "archive", "POST", path, "--no-wait", "--json", "{}"], ok=False)
        assert write.returncode != 0 and b"APPROVAL_REQUIRED" in write.stderr
        assert b'"next"' in write.stderr
        clean = public(["scan", "--stdin"], b"ordinary source text")
        assert clean == []
        leaked = run(["scan", "--stdin"], secret + b"\n", ok=False)
        assert leaked.returncode != 0 and json.loads(leaked.stdout)
        assert b"LEAK_DETECTED" in leaked.stderr
        project = work / "project"
        project.mkdir()
        # Configuration writes still require a human TTY confirmation. The
        # archive gate exercises the non-mutating preview; PTY/idempotence
        # behavior is covered by the workspace connect contract suite.
        connected = run(["connect", "claude-code", "--project", str(project), "--print"])
        assert b"rekey" in connected.stdout and not list(project.iterdir())

        mcp = subprocess.Popen([binaries / "rekey-mcp", "--agent-socket", state / "runtime/agent.sock"],
                               stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        messages = queue.Queue()
        def read_responses():
            for line in mcp.stdout:
                messages.put(line)
        threading.Thread(target=read_responses, daemon=True).start()
        def request(identifier, method, params=None):
            message = dict(jsonrpc="2.0", id=identifier, method=method)
            if params is not None:
                message["params"] = params
            mcp.stdin.write(json.dumps(message).encode() + b"\n")
            mcp.stdin.flush()
            line = messages.get(timeout=45)
            assert secret not in line and b"capability_token" not in line
            value = json.loads(line)
            assert value["id"] == identifier and "error" not in value
            return value["result"]
        request(1, "initialize", dict(protocolVersion="2025-03-26", capabilities={},
                                     clientInfo=dict(name="archive-test", version="1")))
        mcp.stdin.write(b'{"jsonrpc":"2.0","method":"notifications/initialized"}\n')
        mcp.stdin.flush()
        names = {tool["name"] for tool in request(2, "tools/list")["tools"]}
        assert names == {"list_capabilities", "describe", "call", "http", "request_access",
                         "await_access", "await_approval", "cancel_approval", "await_unlock"}
        found = request(3, "tools/call", dict(name="list_capabilities", arguments={}))
        assert not found.get("isError", False) and "archive" in json.dumps(found)
        called = request(4, "tools/call", dict(name="http", arguments=dict(
            connection="archive", method="GET", path=path)))
        assert not called.get("isError", False)
        run(["lock"])
        locked = run(["list", "--json"], ok=False)
        assert locked.returncode != 0 and b"LOCKED" in locked.stderr
        run(["unlock", "--password-stdin"], password)
        run(["shutdown", "--password-stdin"], password)
        daemon.wait(timeout=15)
        assert daemon.returncode == 0
        print("release-archive-acceptance: PASS (vault26/policy7, signed Connections, CLI/MCP/read/write-approval/scan/connect-preview/lock)")
    finally:
        if mcp is not None:
            mcp.terminate()
            mcp.wait(timeout=10)
        if daemon is not None and daemon.poll() is None:
            daemon.terminate()
            try:
                daemon.wait(timeout=15)
            except subprocess.TimeoutExpired:
                daemon.kill()
                daemon.wait(timeout=10)
PY
