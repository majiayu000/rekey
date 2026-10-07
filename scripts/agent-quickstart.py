#!/usr/bin/env python3
"""Start Rekey and connect an ordinary Agent; credentials are configured in the App."""

import argparse
import json
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tempfile
import time


class InputError(Exception):
    """Fixed operator guidance without credential values."""


def status_once(base):
    result = subprocess.run(base + ["status", "--passive"], capture_output=True, text=True)
    if result.returncode == 0:
        return json.loads(result.stdout), result
    return None, result


def ipc_unavailable(result):
    try:
        error = json.loads(result.stderr.splitlines()[-1])
    except (ValueError, IndexError):
        return False
    return isinstance(error, dict) and error.get("code") == "IPC_UNAVAILABLE"


def start_daemon(base):
    # An anonymous owner-only log avoids inherited output pipes keeping the
    # onboarding process alive. It is used only for a failed startup.
    with tempfile.TemporaryFile() as diagnostic:
        process = subprocess.Popen(base + ["serve"], stdin=subprocess.DEVNULL,
                                   stdout=subprocess.DEVNULL, stderr=diagnostic,
                                   start_new_session=True)
        ready = False
        try:
            deadline = time.monotonic() + 15
            while process.poll() is None and time.monotonic() < deadline:
                status, result = status_once(base)
                if status is not None:
                    ready = True
                    return 0
                if not ipc_unavailable(result):
                    sys.stderr.write(result.stderr)
                    return result.returncode
                time.sleep(0.1)
        finally:
            if not ready:
                if process.poll() is None:
                    process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=10)
        diagnostic.seek(0)
        sys.stderr.write(diagnostic.read(4096).decode("utf-8", errors="replace"))
        raise InputError("broker did not start; run rekey serve to inspect the reported error")


def quickstart(args):
    state = args.state_dir.expanduser().absolute()
    base = [str(args.rekey), "--state-dir", str(state)]
    connect = base + ["connect", args.client, "--project", str(args.project.absolute())]
    if args.print:
        for command in [base + ["init", "--mode", "personal"], base + ["serve"],
                        connect, base + ["list", "--json"]]:
            print(shlex.join(command))
        print("Configure credentials and signed Connections in Rekey.app; then start the Agent normally.")
        return 0
    if not sys.stdin.isatty():
        raise InputError("quickstart requires the operator's terminal for CLI prompts; use --print to preview")
    status, failed = status_once(base)
    if status is None:
        if not ipc_unavailable(failed):
            sys.stderr.write(failed.stderr)
            return failed.returncode
        if not state.exists() or not any(state.iterdir()):
            # Rekey owns the hidden proof prompt and recovery output. Python
            # never reads, stores, or forwards a provider credential or proof.
            initialized = subprocess.run(base + ["init", "--mode", "personal"])
            if initialized.returncode:
                return initialized.returncode
        started = start_daemon(base)
        if started:
            return started
    installed = subprocess.run(connect)
    if installed.returncode:
        return installed.returncode
    print("Connect completed. Add credentials and approve Connections in Rekey.app; start the Agent normally.")
    discovered = subprocess.run(base + ["list", "--json"])
    if discovered.returncode:
        print("Discovery is pending: follow the CLI next step in the App, then run rekey list again.", file=sys.stderr)
    return discovered.returncode


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rekey", default=shutil.which("rekey") or "rekey")
    parser.add_argument("--state-dir", type=Path, default=Path.home() / ".rekey")
    parser.add_argument("--project", type=Path, default=Path.cwd())
    parser.add_argument("--client", choices=["claude-code", "codex", "cursor"], default="claude-code")
    parser.add_argument("--print", action="store_true", help="print the CLI plan without starting or writing anything")
    args = parser.parse_args()
    try:
        return quickstart(args)
    except InputError as error:
        print(str(error), file=sys.stderr)
        return 2
    except (OSError, ValueError, TypeError):
        print("quickstart failed; inspect CLI diagnostics and file permissions", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
