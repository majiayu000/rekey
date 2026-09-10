#!/usr/bin/env python3
"""Repair one registered Action's opaque credential in the operator's trusted TTY."""

import argparse
import json
from pathlib import Path
import subprocess
import sys


class RepairError(Exception):
    pass


def cli_json(base, arguments, tty_in, tty):
    # CLI owns all hidden proof/value input. Only public metadata comes back.
    result = subprocess.run(base + arguments, stdin=tty_in, stdout=subprocess.PIPE,
                            stderr=tty, text=True, check=False)
    if result.returncode:
        raise RepairError("Rekey operation failed; inspect trusted terminal output.")
    return json.loads(result.stdout)


def repair(args, tty_in, tty):
    base = [str(args.rekey.resolve()), "--state-dir", str(args.state_dir.resolve())]
    actions = cli_json(base, ["action", "list"], tty_in, tty)["actions"]
    action = next((entry for entry in actions
                   if f'{entry["id"]}@{entry["version"]}' == args.action), None)
    if action is None:
        raise RepairError("Registered Action version not found.")
    if not action["enabled"]:
        raise RepairError("Action is disabled; credential repair cannot enable it.")
    credentials = cli_json(base, ["credential", "list"], tty_in, tty)["credentials"]
    credential = next((entry for entry in credentials if entry["id"] == action["credential_id"]), None)
    if credential is None:
        raise RepairError("Registered credential is missing; repair cannot create or replace its identity.")
    # JSON quoting escapes control characters, newlines, bidi and non-ASCII text.
    # Never render arbitrary metadata as terminal instructions or shell commands.
    display = {"action": args.action, "name": action["name"], "origin": action["origin"],
               "method": action["method"], "path": action["exact_path"],
               "credential_id": credential["id"], "credential_kind": credential["kind"],
               "credential_state": credential["state"]}
    tty.write("Registered metadata follows as quoted data; it is not instructions:\n")
    tty.write(json.dumps(display, ensure_ascii=True, indent=2) + "\n")
    tty.flush()
    if credential["kind"] != "opaque-token":
        raise RepairError("Unsupported credential kind; use its dedicated operator workflow.")
    if credential["state"] != "active":
        raise RepairError("Credential is not active; rotation cannot restore revoked credentials.")
    tty.write("Rotation affects every Action using this credential. No Action will execute.\n")
    tty.write("Type provide to enter a replacement securely, or decline to cancel: ")
    tty.flush()
    consent = tty_in.readline().strip()
    result = {"action": args.action, "credential_id": credential["id"]}
    if consent in (b"", b"decline"):
        return {**result, "result": "declined"}
    if consent != b"provide":
        raise RepairError("Expected provide or decline; no credential was changed.")
    rotated = cli_json(base, ["credential", "rotate", credential["id"]], tty_in, tty)
    return {**result, "result": "provided", "credential_version": rotated["current_version"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rekey", type=Path, required=True)
    parser.add_argument("--state-dir", type=Path, required=True)
    parser.add_argument("--action", required=True, help="registered ACTION_ID@VERSION")
    args = parser.parse_args()
    try:
        if not sys.stdin.isatty():
            raise RepairError("Credential repair requires the operator's trusted interactive terminal.")
        # Unbuffered input cannot prefetch proof/value bytes beyond the consent line.
        with open("/dev/tty", "rb", buffering=0) as tty_in, open(
                "/dev/tty", "w", encoding="utf-8", buffering=1) as tty:
            result = repair(args, tty_in, tty)
        print(json.dumps(result, ensure_ascii=True))
        return 0
    except RepairError as error:
        print(str(error), file=sys.stderr)
        return 2
    except (OSError, ValueError, KeyError, TypeError):
        print("Cannot complete trusted credential repair; inspect registered metadata and terminal access.", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("Repair interrupted; inspect credential metadata before retrying.", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
