#!/usr/bin/env python3
"""Focused shell handoff tests, plus an opt-in real binary authorization test."""

import argparse
import contextlib
import importlib.util
import io
import json
import os
import pty
import select
import signal
from pathlib import Path
import subprocess
import sys
import tempfile
import termios
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location("quickstart", ROOT / "scripts/agent-quickstart.py")
APP = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(APP)
VAULT_SPEC = importlib.util.spec_from_file_location("vault_dogfood", ROOT / "scripts/dogfood-vault.py")
VAULT = importlib.util.module_from_spec(VAULT_SPEC)
VAULT_SPEC.loader.exec_module(VAULT)


def run_terminal(command, responses, expected_exit=0):
    """Exercise real /dev/tty prompts without putting proofs in argv or env."""
    pid, terminal = pty.fork()
    if pid == 0:
        os.execv(command[0], command)
    transcript = bytearray()
    position = 0
    answered = 0
    deadline = time.monotonic() + 30
    try:
        while time.monotonic() < deadline:
            readable, _, _ = select.select([terminal], [], [], 0.2)
            if readable:
                try:
                    chunk = os.read(terminal, 4096)
                except OSError as error:
                    if error.errno != 5:  # Linux PTY returns EIO after child exit.
                        raise
                    break
                if not chunk:
                    break
                transcript.extend(chunk)
                if answered < len(responses):
                    prompt, response = responses[answered]
                    offset = transcript.find(prompt.encode(), position)
                    if offset >= 0:
                        # rpassword writes the prompt before changing terminal
                        # attributes. Wait for actual hidden-input readiness.
                        while termios.tcgetattr(terminal)[3] & termios.ECHO:
                            if time.monotonic() >= deadline:
                                raise AssertionError("password prompt never disabled terminal echo")
                            time.sleep(0.005)
                        os.write(terminal, (response + "\n").encode())
                        position = offset + len(prompt)
                        answered += 1
        else:
            raise AssertionError("interactive onboarding timed out")
        _, status = os.waitpid(pid, 0)
        pid = None
        if os.waitstatus_to_exitcode(status) != expected_exit or answered != len(responses):
            raise AssertionError("interactive onboarding failed or omitted a required prompt")
        return transcript.decode()
    finally:
        os.close(terminal)
        if pid is not None:
            os.kill(pid, signal.SIGKILL)
            os.waitpid(pid, 0)


class HandoffTests(unittest.TestCase):
    def test_vault_dynamic_receipt_requires_revoke_before_finished(self):
        names = ["execution.started", "vault.lease.issued", "vault.lease.revoked", "execution.finished"]
        events = [{"sequence": i, "event_type": name, "outcome": "success"} for i, name in enumerate(names)]
        self.assertEqual(VAULT.verify_events(list(reversed(events)), True), names)
        with self.assertRaises(ValueError):
            VAULT.verify_events(events[:2] + events[3:], True)
        events[2]["sequence"] = 4
        with self.assertRaises(VAULT.QUICKSTART.InputError):
            VAULT.verify_events(events, True)
        events[2]["sequence"] = 2
        events[2]["outcome"] = "failure"
        with self.assertRaises(VAULT.QUICKSTART.InputError):
            VAULT.verify_events(events, True)

    def test_private_file_rejects_public_mode_symlink_and_existing_output(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "session.json"
            APP.write_new(path, {"capability_token": "CANARY"})
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(APP.read_private(path)["capability_token"], "CANARY")
            with self.assertRaises(FileExistsError):
                APP.write_new(path, {})
            alias = Path(directory) / "alias"
            alias.symlink_to(path)
            with self.assertRaises(OSError):
                APP.read_private(alias)
            path.chmod(0o644)
            with self.assertRaises(APP.InputError):
                APP.read_private(path)

    def test_execute_keeps_capability_off_argv_and_never_retries_http_error(self):
        with tempfile.TemporaryDirectory() as directory:
            handoff = Path(directory)
            APP.write_new(handoff / "session.json", {"capability_token": "CANARY"})
            APP.write_new(handoff / "agent.json", {
                "rekey": "/example/rekey", "agent_socket": "/example/agent.sock",
                "action": "fixed-action@1", "headers": [],
            })
            args = argparse.Namespace(handoff=handoff, body_file=None, approval=[])
            for status, expected in [(201, 0), (403, 1), (500, 1)]:
                payload = json.dumps({"upstream_status": status}).encode() + b"\n\xff\x00\r\nbody\r\n"
                result = subprocess.CompletedProcess([], 0, payload)
                output = io.TextIOWrapper(io.BytesIO(), encoding="utf-8")
                with patch.object(APP.subprocess, "run", return_value=result) as run:
                    with contextlib.redirect_stdout(output), contextlib.redirect_stderr(io.StringIO()):
                        self.assertEqual(APP.execute(args), expected)
                    run.assert_called_once()
                    self.assertNotIn("CANARY", str(run.call_args.args))
                    self.assertEqual(run.call_args.kwargs["input"], b"CANARY\n")
                    self.assertFalse(run.call_args.kwargs.get("text", False))
                    self.assertEqual(output.buffer.getvalue(), payload)


@unittest.skipUnless(os.environ.get("REKEY_QUICKSTART_REAL") == "1", "set REKEY_QUICKSTART_REAL=1 after building workspace")
class RealBrokerTests(unittest.TestCase):
    def test_prepare_signed_policy_and_revoke(self):
        rekey = ROOT / "target/debug/rekey"
        rekeyd = ROOT / "target/debug/rekeyd"
        password = "quickstart acceptance password"
        with tempfile.TemporaryDirectory(prefix="rkqs.", dir="/tmp") as directory:
            work = Path(directory)
            state = work / "state"
            base = [str(rekey), "--state-dir", str(state)]

            def run(args, secret=None):
                output = subprocess.run(args, input=secret, capture_output=True, text=True)
                self.assertEqual(output.returncode, 0, output.stderr)
                return json.loads(output.stdout)

            initialized = subprocess.run([str(rekeyd), "init", "--state-dir", str(state), "--password-stdin"],
                                         input=password + "\n", capture_output=True, text=True)
            self.assertEqual(initialized.returncode, 0, initialized.stderr)
            with (work / "broker.log").open("w") as log:
                broker = subprocess.Popen([str(rekeyd), "serve", "--state-dir", str(state)], stdout=log, stderr=log)
                try:
                    deadline = time.monotonic() + 10
                    while not (state / "runtime/admin.sock").exists():
                        self.assertIsNone(broker.poll())
                        self.assertLess(time.monotonic(), deadline)
                        time.sleep(0.05)
                    run(base + ["unlock", "--password-stdin"], password + "\n")
                    handoff = work / "handoff"
                    transcript = run_terminal(
                        [sys.executable, str(ROOT / "scripts/agent-quickstart.py"), "prepare",
                         "--rekey", str(rekey), "--state-dir", str(state),
                         "--output", str(handoff), "--repo", "example/dedicated-test"],
                        [("Vault password (step-up): ", password),
                         ("Credential value: ", "UPSTREAM-CANARY"),
                         ("Vault password (step-up): ", password),
                         ("Vault password (step-up): ", password)],
                    )
                    self.assertNotIn(password, transcript)
                    self.assertNotIn("UPSTREAM-CANARY", transcript)
                    session = APP.read_private(handoff / "session.json")
                    config = APP.read_private(handoff / "agent.json")
                    schema = work / "schema.json"
                    schema.write_text(json.dumps(APP.read_private(handoff / "policy-draft.json")["bindings"][0]["parameter_schema"]))
                    existing_handoff = work / "existing-handoff"
                    transcript += run_terminal(
                        [sys.executable, str(ROOT / "scripts/agent-quickstart.py"), "prepare",
                         "--rekey", str(rekey), "--state-dir", str(state),
                         "--output", str(existing_handoff), "--action", config["action"], "--schema", str(schema)],
                        [("Vault password (step-up): ", password)],
                    )
                    self.assertEqual(APP.read_private(existing_handoff / "agent.json")["action"], config["action"])
                    self.assertEqual(handoff.stat().st_mode & 0o777, 0o700)
                    body = work / "body.json"
                    body.write_text('{"title":"test"}')
                    command = [sys.executable, str(ROOT / "scripts/agent-quickstart.py"), "execute",
                               "--handoff", str(handoff), "--body-file", str(body)]
                    denied = subprocess.run(command, capture_output=True, text=True)
                    self.assertNotEqual(denied.returncode, 0)
                    self.assertIn("REQUEST_DENIED", denied.stderr)
                    subprocess.run([sys.executable, str(ROOT / "scripts/sign-test-policy.py"), "policy",
                                    "--key-dir", str(work / "signer"), "--snapshot", str(handoff / "policy-draft.json"),
                                    "--trust", str(work / "trust.json"), "--bundle", str(work / "bundle.json")], check=True)
                    for operation, filename in [(["policy", "trust", "install"], "trust.json"),
                                                (["policy", "activate"], "bundle.json")]:
                        run(base + operation + ["--file", str(work / filename), "--step-up-stdin"], password + "\n")
                    self.assertEqual(run(base + ["policy", "status"])["version"], 1)
                    rejected_handoff = work / "rejected-handoff"
                    refused = run_terminal(
                        [sys.executable, str(ROOT / "scripts/agent-quickstart.py"), "prepare",
                         "--rekey", str(rekey), "--state-dir", str(state),
                         "--output", str(rejected_handoff), "--repo", "example/dedicated-test"],
                        [], expected_exit=2,
                    )
                    self.assertIn("requires a fresh policy", refused)
                    self.assertFalse(rejected_handoff.exists())
                    action = APP.read_private(handoff / "registered-action.json")
                    transcript += run_terminal(
                        base + ["credential", "rotate", action["credential_id"]],
                        [("Vault password (step-up): ", password),
                         ("New credential value: ", "ROTATED-UPSTREAM-CANARY")],
                    )
                    credentials = run(base + ["credential", "list"])["credentials"]
                    self.assertEqual(next(c for c in credentials if c["id"] == action["credential_id"])["current_version"], 2)
                    self.assertNotIn(password, transcript)
                    self.assertNotIn("UPSTREAM-CANARY", transcript)
                    # A signed session still rejects invalid parameters before
                    # any public HTTP request can be made.
                    body.write_text('{"unexpected":"field"}')
                    invalid = subprocess.run(command, capture_output=True, text=True)
                    self.assertNotEqual(invalid.returncode, 0)
                    self.assertIn("REQUEST_DENIED", invalid.stderr)
                    run(base + ["session", "revoke", session["session_id"], "--password-stdin"], password + "\n")
                    revoked = subprocess.run(command, capture_output=True, text=True)
                    self.assertNotEqual(revoked.returncode, 0)
                    self.assertIn("INVALID_CAPABILITY", revoked.stderr)
                    for content in [denied.stdout, denied.stderr, revoked.stdout, revoked.stderr,
                                    invalid.stdout, invalid.stderr, transcript,
                                    (handoff / "policy-draft.json").read_text()]:
                        self.assertNotIn(session["capability_token"], content)
                        self.assertNotIn("UPSTREAM-CANARY", content)
                finally:
                    broker.terminate()
                    broker.wait(timeout=10)


if __name__ == "__main__":
    unittest.main()
