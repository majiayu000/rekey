#!/usr/bin/env python3
"""Generate Rekey's minimal native service definition."""

import argparse
import os
import pathlib
import plistlib
import pwd
import re
import sys


STOP_HARD_CEILING_SECONDS = 130
LABEL_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,126}")
USER_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_-]{0,63}")


def installed_path(raw: str, *, executable: bool) -> pathlib.Path:
    path = pathlib.Path(raw)
    if not path.is_absolute():
        raise ValueError(f"path must be absolute: {raw}")
    resolved = path.resolve(strict=True)
    if any(ord(char) < 32 for char in str(resolved)):
        raise ValueError("paths containing control characters are unsupported")
    if executable and (not resolved.is_file() or not os.access(resolved, os.X_OK)):
        raise ValueError(f"rekeyd is not executable: {resolved}")
    if not executable and not resolved.is_dir():
        raise ValueError(f"state directory is not a directory: {resolved}")
    return resolved


def systemd_quote(value: pathlib.Path) -> str:
    escaped = (str(value).replace("$", "$$").replace("%", "%%")
               .replace("\\", "\\\\").replace('"', '\\"'))
    return f'"{escaped}"'


def launchd_definition(rekeyd: pathlib.Path, state: pathlib.Path, label: str) -> None:
    if LABEL_RE.fullmatch(label) is None:
        raise ValueError("invalid launchd label")
    plistlib.dump({
        "Label": label,
        "ProgramArguments": [str(rekeyd), "serve", "--state-dir", str(state)],
        "RunAtLoad": True,
        "KeepAlive": True,
        "ProcessType": "Background",
        "Umask": 0o077,
        "ExitTimeOut": STOP_HARD_CEILING_SECONDS,
        "StandardOutPath": str(state / "rekeyd.stdout.log"),
        "StandardErrorPath": str(state / "rekeyd.stderr.log"),
    }, sys.stdout.buffer, fmt=plistlib.FMT_XML, sort_keys=False)


def systemd_definition(rekeyd: pathlib.Path, state: pathlib.Path, user: str) -> None:
    if USER_RE.fullmatch(user) is None:
        raise ValueError("systemd user has an invalid name")
    try:
        account = pwd.getpwnam(user)
    except KeyError as error:
        raise ValueError("systemd user does not exist") from error
    if account.pw_uid == 0:
        raise ValueError("systemd service must run as a non-root user")
    sys.stdout.write("\n".join([
        "[Unit]",
        "Description=Rekey Credential Authority",
        "After=local-fs.target network-online.target",
        "Wants=network-online.target",
        "",
        "[Service]",
        "Type=simple",
        f"User={user}",
        f"ExecStart={systemd_quote(rekeyd)} serve --state-dir {systemd_quote(state)}",
        "Restart=on-failure",
        "RestartSec=5s",
        "KillSignal=SIGTERM",
        f"TimeoutStopSec={STOP_HARD_CEILING_SECONDS}s",
        "UMask=0077",
        "NoNewPrivileges=true",
        "",
        "[Install]",
        "WantedBy=multi-user.target",
        "",
    ]))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("platform", choices=("launchd", "systemd"))
    parser.add_argument("--rekeyd", required=True)
    parser.add_argument("--state-dir", required=True)
    parser.add_argument("--label")
    parser.add_argument("--run-as-user")
    args = parser.parse_args()
    try:
        rekeyd = installed_path(args.rekeyd, executable=True)
        state = installed_path(args.state_dir, executable=False)
        if args.platform == "launchd":
            if args.label is None or args.run_as_user is not None:
                raise ValueError("launchd requires --label and rejects --run-as-user")
            launchd_definition(rekeyd, state, args.label)
        else:
            if args.label is not None or args.run_as_user is None:
                raise ValueError("systemd requires --run-as-user and rejects --label")
            systemd_definition(rekeyd, state, args.run_as_user)
    except ValueError as error:
        parser.error(str(error))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
