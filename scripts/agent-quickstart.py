#!/usr/bin/env python3
"""Operator onboarding and explicit Agent shell entry, using only Rekey IPC CLI."""

import argparse
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import uuid


class InputError(Exception):
    """An operator-facing error containing only fixed, non-secret guidance."""


def write_new(path, value):
    with open(path, "x", encoding="utf-8", opener=lambda p, f: os.open(p, f, 0o600)) as out:
        json.dump(value, out, indent=2, ensure_ascii=True)
        out.write("\n")


def read_private(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "r", encoding="utf-8") as source:
        info = os.fstat(source.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise InputError("handoff file must be an owner-only regular file")
        content = source.read(65537)
        if len(content) > 65536:
            raise InputError("handoff file exceeds 64 KiB")
        return json.loads(content)


def cli_json(command):
    # Inherit the trusted operator TTY. Passwords and provider values are read
    # by rekey itself, never by this Python process.
    result = subprocess.run(command, stdout=subprocess.PIPE, check=False, text=True)
    if result.returncode:
        raise SystemExit(result.returncode)
    return json.loads(result.stdout)


def policy_draft(action, session, schema):
    resource = {"type": "fixed-http-action", "id": action["id"]}
    return {
        "format_version": 3, "version": 1,
        "expires_at_ms": session["expires_at_ms"],
        "approvers": [], "workload_identities": [],
        "bindings": [{
            "action_id": action["id"], "version": action["version"],
            "resource": resource, "parameter_schema_id": "agent-quickstart/v1",
            "parameter_schema": schema,
        }],
        "rules": [{
            "id": str(uuid.uuid4()), "effect": "permit",
            "principal_id": session["principal_id"], "action_id": action["id"],
            "version": action["version"], "resource": resource,
            "parameters": {"kind": "any_validated"},
        }],
    }


def require_private_regular_file(path, label):
    """Reject non-private profiles before claiming an exclusive handoff directory."""
    try:
        info = path.lstat()
    except OSError as error:
        raise InputError(f"{label} is not readable") from error
    if stat.S_ISLNK(info.st_mode):
        raise InputError(f"{label} must not be a symlink")
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise InputError(f"{label} must be an owner-only regular file")


def release_empty_handoff(path):
    """Drop an exclusive handoff that never received published files."""
    try:
        if path.is_dir() and not any(path.iterdir()):
            path.rmdir()
    except OSError:
        pass


def prepare(args):
    if not sys.stdin.isatty():
        raise InputError("prepare requires the operator's trusted interactive terminal")
    base = [str(args.rekey.resolve()), "--state-dir", str(args.state_dir.resolve())]
    status = cli_json(base + ["status"])
    if status["state"] != "unlocked":
        raise InputError("unlock the broker with rekey unlock before prepare")
    policy = cli_json(base + ["policy", "status"])
    if policy["bundle_persisted"] or policy["trust_installed"]:
        raise InputError("prepare requires a fresh policy; use a dedicated demo vault")
    existing_action = None
    if args.repo:
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9-]*/[A-Za-z0-9._-]+", args.repo):
            raise InputError("repository must be owner/name")
        schema = {"type": "object", "additionalProperties": False, "required": ["title"],
                  "properties": {"title": {"type": "string"}, "body": {"type": "string"}}}
        # Validate credential/profile inputs before the exclusive mkdir so a
        # corrected retry can reuse the same documented --output path.
        if args.credential is None:
            if args.github_app_profile is None:
                raise InputError(
                    "prepare --repo requires --credential (GitHub App id) "
                    "or --github-app-profile PATH"
                )
            require_private_regular_file(args.github_app_profile, "GitHub App profile")
    else:
        if args.schema is None:
            raise InputError("--action requires --schema (JSON Schema for the request body)")
        schema = json.loads(args.schema.read_text(encoding="utf-8"))
        actions = cli_json(base + ["action", "list"])["actions"]
        existing_action = next(
            (a for a in actions if f'{a["id"]}@{a["version"]}' == args.action), None
        )
        if existing_action is None:
            raise InputError("requested Action version does not exist")

    args.output.mkdir(mode=0o700)  # Exclusive: never overwrite a previous handoff.
    try:
        if args.repo:
            # /repos/{owner}/{repo}/issues is GitHub-App-reserved; OpaqueToken cannot bind it.
            credential = args.credential
            if credential is None:
                print(
                    "Enter the vault proof in rekey's hidden prompt for add-github-app.",
                    file=sys.stderr,
                )
                credential = cli_json(
                    base
                    + [
                        "credential",
                        "add-github-app",
                        "agent-quickstart",
                        "--file",
                        str(args.github_app_profile),
                    ]
                )["id"]
            definition = {
                "name": "github-create-issue", "credential_id": credential,
                "origin": "https://api.github.com", "method": "POST",
                "exact_path": f"/repos/{args.repo}/issues", "auth_header": "authorization",
                "auth_prefix": "Bearer ", "timeout_ms": 30000, "request_max_bytes": 65536,
                # GitHub App connector rejects nonempty extra_headers on execute.
                "allowed_extra_headers": [],
                "response_max_bytes": 262144, "allowed_response_headers": ["content-type"],
            }
            write_new(args.output / "action.json", definition)
            action = cli_json(base + ["action", "create", "--file", str(args.output / "action.json")])
        else:
            action = existing_action
        # Persist public IDs before the next mutation so partial setup is inspectable.
        write_new(args.output / "registered-action.json", action)
        action_ref = f'{action["id"]}@{action["version"]}'
        session = cli_json(base + ["session", "create", "--action", action_ref,
                                   "--ttl", "15m", "--max-uses", "10"])
        write_new(args.output / "session.json", session)
        write_new(args.output / "policy-draft.json", policy_draft(action, session, schema))
        write_new(args.output / "agent.json", {
            "rekey": str(args.rekey.resolve()),
            "agent_socket": str(args.state_dir.resolve() / "runtime" / "agent.sock"),
            "action": action_ref,
            # Empty for GitHub App prepare --repo; the closed connector forbids extra_headers.
            "headers": [],
        })
    except BaseException:
        release_empty_handoff(args.output)
        raise
    print(f"Prepared {action_ref}. Session expires in 15 minutes; maximum 10 uses.")
    print(f"Review and externally sign {args.output / 'policy-draft.json'}.")
    print("Install the signer trust with rekey policy trust install, then rekey policy activate.")
    print("Keep signing keys outside the Agent workspace. No action has been executed.")


def execute(args):
    config = read_private(args.handoff / "agent.json")
    session = read_private(args.handoff / "session.json")
    command = [config["rekey"], "--agent-socket", config["agent_socket"],
               "execute", config["action"], "--capability", "-"]
    if args.body_file:
        command += ["--body-file", str(args.body_file), "--content-type", "application/json"]
    for header in config["headers"]:
        command += ["--header", header]
    for approval in args.approval:
        command += ["--approval", str(approval)]
    result = subprocess.run(command, input=(session["capability_token"] + "\n").encode(),
                            stdout=subprocess.PIPE, check=False)
    if result.returncode:
        print("Ask the operator to inspect the reported error and audit trail. "
              "Do not request secrets in chat or retry a write automatically.", file=sys.stderr)
        return result.returncode
    # Only the leading metadata is JSON; the sealed body may contain arbitrary
    # bytes. Preserve those bytes (including CRLF) when forwarding CLI output.
    metadata, _ = json.JSONDecoder().raw_decode(
        result.stdout.decode("utf-8", errors="surrogateescape").lstrip())
    sys.stdout.buffer.write(result.stdout)
    if not 200 <= metadata["upstream_status"] < 300:
        sys.stderr.write("Upstream returned an HTTP error; ask the operator to inspect and repair access "
                         "in the trusted terminal. Do not request secrets in chat or retry a write automatically.\n")
        return 1
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    setup = commands.add_parser("prepare", help="operator terminal: prepare one Action and unsigned policy")
    setup.add_argument("--rekey", type=Path, required=True)
    setup.add_argument("--state-dir", type=Path, required=True)
    setup.add_argument("--output", type=Path, required=True)
    source = setup.add_mutually_exclusive_group(required=True)
    source.add_argument("--repo")
    source.add_argument("--action", help="existing ACTION_ID@VERSION")
    setup.add_argument("--credential", help="existing GitHub App credential ID for --repo")
    setup.add_argument(
        "--github-app-profile",
        type=Path,
        help="GitHub App profile JSON for prepare --repo when --credential is omitted",
    )
    setup.add_argument("--schema", type=Path)
    run = commands.add_parser("execute", help="Agent shell: execute the one prepared Action")
    run.add_argument("--handoff", type=Path, required=True)
    run.add_argument("--body-file", type=Path)
    run.add_argument("--approval", type=Path, action="append", default=[])
    args = parser.parse_args()
    try:
        if args.command == "prepare":
            prepare(args)
            return 0
        return execute(args)
    except InputError as error:
        print(str(error), file=sys.stderr)
        return 2
    except (OSError, ValueError, KeyError, TypeError) as error:
        # Do not print JSON contents or child argv in error paths.
        print(f"quickstart failed ({type(error).__name__}); check inputs, file permissions and broker status",
              file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
