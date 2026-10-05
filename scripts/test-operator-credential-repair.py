#!/usr/bin/env python3
"""PTY + real Broker/TLS acceptance; build rekey, rekeyd and p1_policy_fixture first."""
import argparse
import base64
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
    connection = {"enabled": True, "credential_id": "credential",
                  "name": "name\x1b[2J\nprovide\u202e", "origin": "https://example.test",
                  "preset": "generic-bearer", "grade": "T0"}
    args = argparse.Namespace(rekey=Path("rekey"), state_dir=Path("state"), connection=connection["name"])
    credential = {"id": "credential", "kind": "opaque-token", "state": "active"}
    output = io.StringIO()
    with patch.object(APP, "cli_json", side_effect=[{"connections": [connection]}, {"credentials": [credential]}]) as call:
        result = APP.repair(args, io.BytesIO(b"decline\n"), output)
        assert result["result"] == "declined" and call.call_count == 2
    assert "\x1b" not in output.getvalue() and "\u202e" not in output.getvalue()
    assert "\\u001b" in output.getvalue() and "\\u202e" in output.getvalue()
    assert "all Connections using this credential" in output.getvalue()
    for consent in [b"", b"decline\n", b"not-consent\n"]:
        with patch.object(APP, "cli_json", side_effect=[{"connections": [connection]}, {"credentials": [credential]}]) as call:
            if consent == b"not-consent\n":
                try:
                    APP.repair(args, io.BytesIO(consent), io.StringIO())
                    raise AssertionError("unexpected consent accepted")
                except APP.RepairError:
                    pass
            else:
                assert APP.repair(args, io.BytesIO(consent), io.StringIO())["result"] == "declined"
            assert call.call_count == 2, "decline or EOF changed a credential"
    for kind, state in [("github-app-installation", "active"), ("oauth-grant", "active"),
                        ("aws-static", "active"), ("vault-kv-v2-source", "active"),
                        ("vault-dynamic-source", "active"), ("opaque-token", "revoked")]:
        entry = {**credential, "kind": kind, "state": state}
        with patch.object(APP, "cli_json", side_effect=[{"connections": [connection]}, {"credentials": [entry]}]) as call:
            try:
                APP.repair(args, io.BytesIO(b"provide\n"), io.StringIO())
                raise AssertionError("unsupported credential accepted")
            except APP.RepairError:
                assert call.call_count == 2
    for metadata in [
        [{"connections": []}],
        [{"connections": [{**connection, "enabled": False}]}],
        [{"connections": [connection]}, {"credentials": []}],
    ]:
        with patch.object(APP, "cli_json", side_effect=metadata) as call:
            try:
                APP.repair(args, io.BytesIO(b"provide\n"), io.StringIO())
                raise AssertionError("missing or disabled registration accepted")
            except APP.RepairError:
                assert call.call_count == len(metadata)
    print("PASS: terminal metadata escaped; missing/disabled/GitHub/Vault/revoked registrations reject before rotation")


def owner_cli_path_boundary():
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        record = root / "argv.jsonl"
        binary = root / "fixture $cli% path"
        binary.write_text("#!/usr/bin/env python3\nimport json,sys\n"
                          f"with open({str(record)!r}, 'a') as f:f.write(json.dumps(sys.argv[1:])+'\\n')\n"
                          "if sys.argv[-2:]==['connection','list']:r={'connections':[{'enabled':True,'credential_id':'credential','name':'fixture','origin':'https://example.test','preset':'generic-bearer','grade':'T0'}]}\n"
                          "elif sys.argv[-2:]==['credential','list']:r={'credentials':[{'id':'credential','kind':'opaque-token','state':'active'}]}\n"
                          "else:r={'current_version':2}\nprint(json.dumps(r))\n")
        binary.chmod(0o700)
        args = argparse.Namespace(rekey=binary, state_dir=root / "state $path%", connection="fixture")
        with tempfile.TemporaryFile() as consent, tempfile.TemporaryFile(mode="w+", encoding="utf-8") as output:
            consent.write(b"provide\n")
            consent.seek(0)
            result = APP.repair(args, consent, output)
            output.seek(0)
            displayed = output.read()
        assert result["result"] == "provided" and result["credential_version"] == 2
        prefix = ["--state-dir", str(args.state_dir.resolve())]
        calls = [json.loads(line) for line in record.read_text().splitlines()]
        assert calls == [prefix + ["connection", "list"], prefix + ["credential", "list"],
                         prefix + ["credential", "rotate", "credential"]]
        assert '"connection": "fixture"' in displayed
        for obsolete in ["--action", "--admin-session-file"]:
            rejected = subprocess.run([sys.executable, str(ROOT / "scripts/operator-credential-repair.py"),
                                       "--rekey", str(binary), "--state-dir", str(args.state_dir),
                                       "--connection", "fixture", obsolete, "unused"], capture_output=True, text=True)
            assert rejected.returncode == 2 and "unrecognized arguments" in rejected.stderr
        assert len(record.read_text().splitlines()) == 3
    print("PASS: owner CLI receives literal paths; obsolete arguments reject without operations")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bin-dir", type=Path, required=True)
    binaries = parser.parse_args().bin_dir.resolve()
    metadata_boundaries()
    owner_cli_path_boundary()
    password = "repair-proof-canary"
    old = "repair-old-value-canary"
    replacement = "repair-new-value-canary"
    with tempfile.TemporaryDirectory(prefix="rkrp.", dir=Path("/tmp").resolve()) as directory:
        work = Path(directory)
        state = work / "state"
        base = [str(binaries / "rekey"), "--state-dir", str(state)]

        def run(command, secret=None):
            result = subprocess.run(command, input=secret, capture_output=True, text=True, timeout=30)
            assert result.returncode == 0, result.stderr
            return result.stdout

        def cli(*args, secret=None):
            if args[:2] == ("policy", "activate"):
                target = cli("policy", "status")
                args = (*args, "--expected-vault-id", target["vault_id"], "--expected-trust-sha256", target["trust_sha256"])
            return json.loads(run(base + list(args), secret))

        run(base + ["init", "--mode", "personal", "--password-stdin"], password + "\n")
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
                preset = cli("connection", "preset", "generic-bearer", "--origin", f"https://api.test.local:{port}")
                connection = {**preset, "preset": preset["name"], "name": "repair-test",
                              "credential_id": credential["id"], "enabled": True, "grade": "T0",
                              "bindings": {}, "caller_overrides": {}, "llm": None, "oauth": None,
                              "limits": {"requests_per_hour": 600, "max_request_bytes": 4096, "max_response_bytes": 4096}}
                for rule in connection["rules"]:
                    if rule["methods"] == "read":
                        rule["effect"] = "allow"
                        rule["path"] = "/v1/policy"
                # Software P256 signs the daemon's canonical draft; this fixture
                # does not claim hardware Presence or Touch ID acceptance.
                key = work / "policy-signing-key.pem"
                subprocess.run(["openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", str(key)],
                               check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
                key.chmod(0o600)
                public = subprocess.run(["openssl", "pkey", "-in", str(key), "-pubout", "-outform", "DER"],
                                        check=True, capture_output=True).stdout[-65:]
                assert len(public) == 65 and public[0] == 4
                trust = work / "trust.json"
                trust.write_text(json.dumps({"format_version": 1, "algorithm": "secure-enclave-p256",
                                             "signer_id": str(uuid.uuid4()), "public_key": public.hex()}))
                cli("policy", "trust", "install", "--file", str(trust), "--step-up-stdin", secret=password + "\n")
                draft = cli("policy", "draft", "--connections-stdin", "--expires-at-ms", str(int(time.time() * 1000) + 600000),
                            secret=json.dumps([connection]))
                sign_bytes = draft["sign_bytes"].encode()
                prefix = b"RKPOLICY\0\x01"
                assert sign_bytes.startswith(prefix)
                bundle = json.loads(sign_bytes[len(prefix):])
                signature = subprocess.run(["openssl", "dgst", "-sha256", "-sign", str(key)],
                                           input=sign_bytes, capture_output=True, check=True).stdout
                bundle["signature"] = base64.urlsafe_b64encode(signature).rstrip(b"=").decode()
                signed = work / "policy.json"
                signed.write_text(json.dumps(bundle))
                cli("policy", "activate", "--file", str(signed), "--step-up-stdin", secret=password + "\n")
                command = [sys.executable, str(ROOT / "scripts/operator-credential-repair.py"),
                           "--rekey", str(binaries / "rekey"), "--state-dir", str(state), "--connection", connection["name"]]
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
                executed = run(base + ["http", connection["name"], "GET", "/v1/policy", "--no-wait"])
                metadata, _ = json.JSONDecoder().raw_decode(executed.lstrip())
                assert metadata["status"] == 200 and executions() == 1
                assert int((state / "fixture.hits").read_text()) == 1
                with sqlite3.connect(f"file:{state / 'vault.sqlite3'}?mode=ro", uri=True) as db:
                    assert db.execute("SELECT credential_version FROM audit_events WHERE event_type = 'execution.finished'").fetchone()[0] == 2
                cli("credential", "revoke", credential["id"], "--password-stdin", secret=password + "\n")
                revoked = terminal(command, [], expected_exit=2)
                assert "cannot restore revoked" in revoked and version() == 2 and executions() == 1
                for content in [cancelled, provided, revoked, executed, (work / "broker.log").read_text()]:
                    assert all(secret not in content for secret in (password, old, replacement))
                print("PASS: signed Connection repair; real PTY decline unchanged; hidden provide rotates to v2 with zero executions; explicit TLS read uses v2; revoked repair rejected; no secret output")
            finally:
                broker.terminate()
                broker.wait(timeout=15)


if __name__ == "__main__":
    main()
