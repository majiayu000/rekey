#!/usr/bin/env python3
"""PTY + real Broker/TLS acceptance; build rekey, rekeyd and p1_policy_fixture first."""
import argparse
import importlib.util
import io
import json
import os
from pathlib import Path
import pty
import select
import signal
import sqlite3
import subprocess
import sys
import tempfile
import termios
import time
from unittest.mock import patch
import uuid

ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location("repair", ROOT / "scripts/operator-credential-repair.py")
APP = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(APP)


def terminal(command, responses, expected_exit=0):
    pid, fd = pty.fork()
    if pid == 0:
        os.execv(command[0], command)
    transcript = bytearray()
    answered = 0
    offset = 0
    deadline = time.monotonic() + 30
    try:
        while time.monotonic() < deadline:
            if select.select([fd], [], [], 0.1)[0]:
                try:
                    chunk = os.read(fd, 4096)
                except OSError as error:
                    if error.errno != 5:
                        raise
                    break
                if not chunk:
                    break
                transcript.extend(chunk)
            if answered < len(responses):
                prompt, response, hidden = responses[answered]
                found = transcript.find(prompt.encode(), offset)
                if found >= 0:
                    if hidden and termios.tcgetattr(fd)[3] & termios.ECHO:
                        continue
                    os.write(fd, (response + "\n").encode())
                    offset = found + len(prompt)
                    answered += 1
        else:
            raise AssertionError("trusted terminal timed out")
        _, status = os.waitpid(pid, 0)
        pid = None
        assert os.waitstatus_to_exitcode(status) == expected_exit, "unexpected terminal exit"
        assert answered == len(responses), "missing terminal prompt"
        return transcript.decode()
    finally:
        os.close(fd)
        if pid is not None:
            os.kill(pid, signal.SIGKILL)
            os.waitpid(pid, 0)


def metadata_boundaries():
    args = argparse.Namespace(rekey=Path("rekey"), state_dir=Path("state"), action="action@1")
    action = {"id": "action", "version": 1, "enabled": True, "credential_id": "credential",
              "name": "name\x1b[2J\nprovide\u202e", "origin": "https://example.test",
              "method": "POST", "exact_path": "/fixed"}
    credential = {"id": "credential", "kind": "opaque-token", "state": "active"}
    output = io.StringIO()
    with patch.object(APP, "cli_json", side_effect=[{"actions": [action]}, {"credentials": [credential]}]) as call:
        result = APP.repair(args, io.BytesIO(b"decline\n"), output)
        assert result["result"] == "declined" and call.call_count == 2
    assert "\x1b" not in output.getvalue() and "\u202e" not in output.getvalue()
    assert "\\u001b" in output.getvalue() and "\\u202e" in output.getvalue()
    for kind, state in [("github-app-installation", "active"), ("vault-kv-v2-source", "active"),
                        ("vault-dynamic-source", "active"), ("opaque-token", "revoked")]:
        entry = {**credential, "kind": kind, "state": state}
        with patch.object(APP, "cli_json", side_effect=[{"actions": [action]}, {"credentials": [entry]}]) as call:
            try:
                APP.repair(args, io.BytesIO(b"provide\n"), io.StringIO())
                raise AssertionError("unsupported credential accepted")
            except APP.RepairError:
                assert call.call_count == 2
    for metadata in [
        [{"actions": []}],
        [{"actions": [{**action, "enabled": False}]}],
        [{"actions": [action]}, {"credentials": []}],
    ]:
        with patch.object(APP, "cli_json", side_effect=metadata) as call:
            try:
                APP.repair(args, io.BytesIO(b"provide\n"), io.StringIO())
                raise AssertionError("missing or disabled registration accepted")
            except APP.RepairError:
                assert call.call_count == len(metadata)
    print("PASS: terminal metadata escaped; missing/disabled/GitHub/Vault/revoked registrations reject before rotation")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bin-dir", type=Path, required=True)
    binaries = parser.parse_args().bin_dir.resolve()
    metadata_boundaries()
    password = "repair-proof-canary"
    old = "repair-old-value-canary"
    replacement = "repair-new-value-canary"
    with tempfile.TemporaryDirectory(prefix="rkrp.", dir="/tmp") as directory:
        work = Path(directory)
        state = work / "state"
        base = [str(binaries / "rekey"), "--state-dir", str(state)]

        def run(command, secret=None):
            result = subprocess.run(command, input=secret, capture_output=True, text=True, timeout=30)
            assert result.returncode == 0, result.stderr
            return result.stdout

        def cli(*args, secret=None):
            return json.loads(run(base + list(args), secret))

        run(base + ["init", "--password-stdin"], password + "\n")
        with (work / "broker.log").open("w") as log:
            broker = subprocess.Popen([str(binaries / "examples/p1_policy_fixture"), "serve",
                                       "--state-dir", str(state)], stdout=log, stderr=log)
            try:
                deadline = time.monotonic() + 15
                while not (state / "runtime/admin.sock").exists():
                    assert broker.poll() is None and time.monotonic() < deadline
                    time.sleep(0.05)
                cli("unlock", "--password-stdin", secret=password + "\n")
                credential = cli("credential", "add", "repair-test", "--stdin-secrets", secret=password + "\n" + old + "\n")
                port = (state / "fixture.port").read_text().strip()
                definition = work / "action.json"
                definition.write_text(json.dumps({
                    "name": "repair-test", "credential_id": credential["id"],
                    "origin": f"https://api.test.local:{port}", "method": "POST", "exact_path": "/v1/policy",
                    "auth_header": "authorization", "auth_prefix": "Bearer ", "timeout_ms": 10000,
                    "request_max_bytes": 4096, "allowed_extra_headers": [], "response_max_bytes": 4096,
                    "allowed_response_headers": ["content-type"],
                }))
                action = cli("action", "create", "--file", str(definition), "--password-stdin", secret=password + "\n")
                reference = f'{action["id"]}@{action["version"]}'
                command = [sys.executable, str(ROOT / "scripts/operator-credential-repair.py"),
                           "--rekey", str(binaries / "rekey"), "--state-dir", str(state), "--action", reference]
                no_tty = subprocess.run(command, capture_output=True, text=True, timeout=10)
                assert no_tty.returncode == 2 and "interactive terminal" in no_tty.stderr

                def version():
                    return next(c for c in cli("credential", "list")["credentials"] if c["id"] == credential["id"])["current_version"]

                def executions():
                    with sqlite3.connect(f"file:{state / 'vault.sqlite3'}?mode=ro", uri=True) as db:
                        return db.execute("SELECT count(*) FROM audit_events WHERE event_type = 'execution.started'").fetchone()[0]

                prompt = "or decline to cancel: "
                cancelled = terminal(command, [(prompt, "decline", False)])
                assert '"result": "declined"' in cancelled and version() == 1 and executions() == 0
                provided = terminal(command, [(prompt, "provide", False),
                                             ("Vault password (step-up): ", password, True),
                                             ("New credential value: ", replacement, True)])
                assert '"result": "provided"' in provided and version() == 2 and executions() == 0
                assert int((state / "fixture.hits").read_text()) == 0
                for text in [cancelled, provided, no_tty.stdout, no_tty.stderr]:
                    assert all(secret not in text for secret in (password, old, replacement))
                # Only this explicit, separately authorized request may touch upstream.
                session = cli("session", "create", "--action", reference, "--ttl", "10m", "--max-uses", "2",
                              "--password-stdin", secret=password + "\n")
                resource = {"type": "fixed-http-action", "id": action["id"]}
                draft = work / "draft.json"
                draft.write_text(json.dumps({
                    "format_version": 3, "version": 1, "expires_at_ms": int(time.time() * 1000) + 600000,
                    "approvers": [], "workload_identities": [],
                    "bindings": [{"action_id": action["id"], "version": 1, "resource": resource,
                                  "parameter_schema_id": "repair/v1", "parameter_schema": {"type": "null"}}],
                    "rules": [{"id": str(uuid.uuid4()), "effect": "permit", "principal_id": session["principal_id"],
                               "action_id": action["id"], "version": 1, "resource": resource,
                               "parameters": {"kind": "any_validated"}}],
                }))
                run([sys.executable, str(ROOT / "scripts/sign-test-policy.py"), "policy", "--key-dir", str(work / "key"),
                     "--snapshot", str(draft), "--trust", str(work / "trust.json"), "--bundle", str(work / "policy.json")])
                cli("policy", "trust", "install", "--file", str(work / "trust.json"), "--step-up-stdin", secret=password + "\n")
                cli("policy", "activate", "--file", str(work / "policy.json"), "--step-up-stdin", secret=password + "\n")
                executed = run(base + ["execute", reference, "--capability", "-"], session["capability_token"] + "\n")
                metadata, _ = json.JSONDecoder().raw_decode(executed.lstrip())
                assert metadata["upstream_status"] == 200 and executions() == 1
                assert int((state / "fixture.hits").read_text()) == 1
                with sqlite3.connect(f"file:{state / 'vault.sqlite3'}?mode=ro", uri=True) as db:
                    assert db.execute("SELECT credential_version FROM audit_events WHERE event_type = 'execution.finished'").fetchone()[0] == 2
                cli("credential", "revoke", credential["id"], "--password-stdin", secret=password + "\n")
                revoked = terminal(command, [], expected_exit=2)
                assert "cannot restore revoked" in revoked and version() == 2 and executions() == 1
                for content in [cancelled, provided, revoked, executed, (work / "broker.log").read_text()]:
                    assert all(secret not in content for secret in (password, old, replacement, session["capability_token"]))
                print("PASS: real PTY decline unchanged; provide rotates to v2 with zero executions; explicit TLS request uses v2 and succeeds; revoked repair rejected; no secret output")
            finally:
                broker.terminate()
                broker.wait(timeout=15)


if __name__ == "__main__":
    main()
