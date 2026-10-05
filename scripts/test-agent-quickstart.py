#!/usr/bin/env python3
"""Connection onboarding checks; opt in to real CLI/daemon and TTY confirmation."""

import argparse
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import pty
import select
import signal
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location("quickstart", ROOT / "scripts/agent-quickstart.py")
APP = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(APP)
VAULT_SPEC = importlib.util.spec_from_file_location("vault_dogfood", ROOT / "scripts/dogfood-vault.py")
VAULT = importlib.util.module_from_spec(VAULT_SPEC)
VAULT_SPEC.loader.exec_module(VAULT)


def completed(code=0, stdout="", stderr=""):
    return subprocess.CompletedProcess([], code, stdout, stderr)


def unavailable():
    return completed(5, stderr=json.dumps({"code": "IPC_UNAVAILABLE", "next": "Start Rekey"}) + "\n")


def run_terminal(command, responses, expected_exit):
    """Use a real terminal for connect confirmation; no proof is supplied here."""
    pid, terminal = pty.fork()
    if pid == 0:
        os.execv(command[0], command)
    transcript = bytearray()
    answered = 0
    position = 0
    deadline = time.monotonic() + 30
    try:
        while time.monotonic() < deadline:
            readable, _, _ = select.select([terminal], [], [], 0.2)
            if readable:
                try:
                    chunk = os.read(terminal, 4096)
                except OSError as error:
                    if error.errno != 5:
                        raise
                    break
                if not chunk:
                    break
                transcript.extend(chunk)
                if answered < len(responses):
                    prompt, response = responses[answered]
                    offset = transcript.find(prompt.encode(), position)
                    if offset >= 0:
                        os.write(terminal, (response + "\n").encode())
                        position = offset + len(prompt)
                        answered += 1
        else:
            raise AssertionError("interactive onboarding timed out")
        _, status = os.waitpid(pid, 0)
        pid = None
        if os.waitstatus_to_exitcode(status) != expected_exit or answered != len(responses):
            raise AssertionError("interactive onboarding exit={} expected={} confirmations={}/{}\n{}".format(
                os.waitstatus_to_exitcode(status), expected_exit, answered, len(responses), transcript.decode()))
        return transcript.decode()
    finally:
        os.close(terminal)
        if pid is not None:
            os.kill(pid, signal.SIGKILL)
            os.waitpid(pid, 0)


class OnboardingTests(unittest.TestCase):
    def args(self, work, **changes):
        args = argparse.Namespace(rekey=work / "rekey", state_dir=work / "state",
                                  project=work / "project with spaces", client="claude-code", print=False)
        for name, value in changes.items():
            setattr(args, name, value)
        return args

    def invoke(self, args):
        output, errors = io.StringIO(), io.StringIO()
        with patch.object(APP.sys.stdin, "isatty", return_value=True), contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
            code = APP.quickstart(args)
        return code, output.getvalue(), errors.getvalue()

    def test_print_never_runs_cli_or_creates_state(self):
        with tempfile.TemporaryDirectory() as directory:
            args = self.args(Path(directory), print=True)
            with patch.object(APP.subprocess, "run") as run, patch.object(APP.subprocess, "Popen") as spawn:
                code, output, _ = self.invoke(args)
            self.assertEqual(code, 0)
            run.assert_not_called()
            spawn.assert_not_called()
            self.assertFalse(args.state_dir.exists())
            for command in ["init --mode personal", "serve", "connect claude-code", "list --json"]:
                self.assertIn(command, output)
            self.assertIn("start the Agent normally", output)
            self.assertNotIn("capability", output)

    def test_nonterminal_refuses_before_any_action(self):
        with tempfile.TemporaryDirectory() as directory:
            args = self.args(Path(directory))
            with patch.object(APP.sys.stdin, "isatty", return_value=False), patch.object(APP.subprocess, "run") as run:
                with self.assertRaisesRegex(APP.InputError, "requires the operator's terminal"):
                    APP.quickstart(args)
            run.assert_not_called()

    def test_existing_daemon_runs_only_connect_and_discovery(self):
        with tempfile.TemporaryDirectory() as directory:
            args = self.args(Path(directory))
            with patch.object(APP.subprocess, "run", side_effect=[completed(stdout='{"unlocked":true}'), completed(), completed()]) as run, patch.object(APP, "start_daemon", return_value=0) as start:
                code, output, _ = self.invoke(args)
            base = [str(args.rekey), "--state-dir", str(args.state_dir)]
            self.assertEqual(code, 0)
            self.assertEqual([call.args[0] for call in run.call_args_list], [base + ["status", "--passive"], base + ["connect", "claude-code", "--project", str(args.project)], base + ["list", "--json"]])
            start.assert_not_called()
            for call in run.call_args_list:
                self.assertNotIn("input", call.kwargs)
                self.assertNotIn("env", call.kwargs)
            self.assertIn("approve Connections in Rekey.app", output)

    def test_fresh_vault_initializes_before_start_and_connect(self):
        with tempfile.TemporaryDirectory() as directory:
            args = self.args(Path(directory))
            events = []
            def run(command, **kwargs):
                events.append(command[-1] if command[-1] == "--passive" else command[3])
                return unavailable() if command[-1] == "--passive" else completed()
            with patch.object(APP.subprocess, "run", side_effect=run), patch.object(APP, "start_daemon", side_effect=lambda _: (events.append("serve") or 0)):
                code, _, _ = self.invoke(args)
            self.assertEqual(code, 0)
            self.assertEqual(events, ["--passive", "init", "serve", "connect", "list"])

    def test_existing_nonempty_state_is_never_initialized(self):
        with tempfile.TemporaryDirectory() as directory:
            args = self.args(Path(directory))
            args.state_dir.mkdir()
            marker = args.state_dir / "legacy.keep"
            marker.write_text("untouched")
            with patch.object(APP.subprocess, "run", side_effect=[unavailable(), completed(), completed()]) as run, patch.object(APP, "start_daemon", return_value=0) as start:
                self.assertEqual(self.invoke(args)[0], 0)
            self.assertFalse(any("init" in call.args[0] for call in run.call_args_list))
            start.assert_called_once()
            self.assertEqual(marker.read_text(), "untouched")

    def test_init_or_connect_failure_stops_without_replay(self):
        with tempfile.TemporaryDirectory() as directory:
            args = self.args(Path(directory))
            with patch.object(APP.subprocess, "run", side_effect=[unavailable(), completed(3)]) as run, patch.object(APP, "start_daemon", return_value=0) as start:
                self.assertEqual(self.invoke(args)[0], 3)
            self.assertEqual(run.call_count, 2)
            start.assert_not_called()
            with patch.object(APP.subprocess, "run", side_effect=[completed(stdout='{"unlocked":true}'), completed(2)]) as run:
                self.assertEqual(self.invoke(args)[0], 2)
            self.assertEqual(run.call_count, 2)

    def test_locked_discovery_keeps_error_exit_and_does_not_claim_authorization(self):
        with tempfile.TemporaryDirectory() as directory:
            args = self.args(Path(directory))
            with patch.object(APP.subprocess, "run", side_effect=[completed(stdout='{"unlocked":false}'), completed(), completed(3)]) as run:
                code, output, errors = self.invoke(args)
            self.assertEqual(code, 3)
            self.assertEqual(run.call_count, 3)
            self.assertIn("Discovery is pending", errors)
            self.assertNotIn("authorized", output)

    def test_status_error_preserves_diagnostic_and_never_starts_broker(self):
        with tempfile.TemporaryDirectory() as directory:
            args = self.args(Path(directory))
            for error in [json.dumps({"code": "STORAGE_INTEGRITY_FAILED", "next": "Inspect audit"}) + "\n", "non-json CLI diagnostic\n", "[]\n"]:
                with patch.object(APP.subprocess, "run", return_value=completed(5, stderr=error)) as run, patch.object(APP, "start_daemon", return_value=0) as start:
                    code, _, errors = self.invoke(args)
                self.assertEqual(code, 5)
                self.assertEqual(errors, error)
                run.assert_called_once()
                start.assert_not_called()

    def test_startup_uses_no_inherited_pipes_and_stops_only_its_own_failed_child(self):
        process = Mock()
        process.poll.side_effect = [None, None, None, 0]
        with patch.object(APP.subprocess, "Popen", return_value=process) as spawn, patch.object(APP, "status_once", return_value=(None, unavailable())), patch.object(APP.time, "monotonic", side_effect=[0, 16]), contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaisesRegex(APP.InputError, "broker did not start"):
                APP.start_daemon(["/synthetic/rekey"])
        process.terminate.assert_called_once()
        process.wait.assert_called_once_with(timeout=10)
        self.assertEqual(spawn.call_args.args[0], ["/synthetic/rekey", "serve"])
        self.assertEqual(spawn.call_args.kwargs["stdin"], subprocess.DEVNULL)
        self.assertEqual(spawn.call_args.kwargs["stdout"], subprocess.DEVNULL)
        self.assertTrue(spawn.call_args.kwargs["start_new_session"])

    def test_startup_integrity_error_is_not_retried_or_changed_to_unavailable(self):
        process = Mock()
        process.poll.return_value = None
        failure = completed(5, stderr=json.dumps({"code": "STORAGE_INTEGRITY_FAILED", "next": "Inspect audit"}))
        errors = io.StringIO()
        with patch.object(APP.subprocess, "Popen", return_value=process), patch.object(APP, "status_once", return_value=(None, failure)) as status, contextlib.redirect_stderr(errors):
            self.assertEqual(APP.start_daemon(["/synthetic/rekey"]), 5)
        status.assert_called_once()
        process.terminate.assert_called_once()
        self.assertEqual(errors.getvalue(), failure.stderr)

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


@unittest.skipUnless(os.environ.get("REKEY_QUICKSTART_REAL") == "1", "set REKEY_QUICKSTART_REAL=1 after building workspace")
class RealBrokerTests(unittest.TestCase):
    def test_real_connect_confirmation_and_locked_discovery(self):
        metadata = subprocess.run(["cargo", "metadata", "--format-version", "1", "--no-deps"], cwd=ROOT, check=True, capture_output=True, text=True)
        target = Path(json.loads(metadata.stdout)["target_directory"]) / "debug"
        rekey, rekeyd = target / "rekey", target / "rekeyd"
        proof = "QUICKSTART-SYNTHETIC-PROOF"
        with tempfile.TemporaryDirectory(prefix="rkqs.", dir=Path("/tmp").resolve()) as directory:
            work = Path(directory)
            state, project = work / "state", work / "project"
            project.mkdir()
            base = [str(rekey), "--state-dir", str(state)]
            initialized = subprocess.run(base + ["init", "--mode", "personal", "--password-stdin"], input=proof + "\n", capture_output=True, text=True)
            self.assertEqual(initialized.returncode, 0, initialized.stderr)
            with socket.socket() as reservation:
                reservation.bind(("127.0.0.1", 0))
                port = reservation.getsockname()[1]
            (state / "service.json").write_text(json.dumps({"port": port}))
            (state / "service.json").chmod(0o600)
            broker = subprocess.Popen([str(rekeyd), "serve", "--state-dir", str(state)], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            try:
                deadline = time.monotonic() + 10
                while not (state / "runtime/admin.sock").exists():
                    self.assertIsNone(broker.poll())
                    self.assertLess(time.monotonic(), deadline)
                    time.sleep(0.05)
                transcript = run_terminal([sys.executable, str(ROOT / "scripts/agent-quickstart.py"), "--rekey", str(rekey), "--state-dir", str(state), "--project", str(project)], [("Apply Rekey configuration and instructions? [y/N] ", "y")], expected_exit=3)
                self.assertIn("LOCKED", transcript)
                self.assertIn("Discovery is pending", transcript)
                self.assertNotIn(proof, transcript)
                config = json.loads((project / ".mcp.json").read_text())
                self.assertEqual(config["mcpServers"]["rekey"], {"command": "rekey-mcp", "args": ["--state-dir", str(state)]})
                self.assertIn("rekey:begin", (project / "CLAUDE.md").read_text())
                self.assertEqual((project / ".mcp.json").stat().st_mode & 0o777, 0o600)
                unlocked = subprocess.run(base + ["unlock", "--password-stdin"], input=proof + "\n", capture_output=True, text=True)
                self.assertEqual(unlocked.returncode, 0, unlocked.stderr)
                empty = subprocess.run(base + ["connection", "list"], capture_output=True, text=True)
                self.assertEqual(empty.returncode, 0, empty.stderr)
                self.assertEqual(json.loads(empty.stdout)["connections"], [])
                self.assertEqual(json.loads(empty.stdout)["derived_credentials"], [])
            finally:
                broker.terminate()
                broker.wait(timeout=10)


if __name__ == "__main__":
    unittest.main()
