#!/usr/bin/env python3
"""Generate Rekey's minimal native service definition."""

import argparse
import os
import pathlib
import plistlib
import pwd
import re
import sys
from typing import Optional


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


def launchd_definition(rekeyd: pathlib.Path, state: pathlib.Path, label: str, oidc_profile: pathlib.Path = None) -> None:
    if LABEL_RE.fullmatch(label) is None:
        raise ValueError("invalid launchd label")
    arguments = [str(rekeyd), "serve", "--state-dir", str(state)]
    if oidc_profile is not None:
        arguments += ["--oidc-admin-profile", str(oidc_profile)]
    plistlib.dump({
        "Label": label,
        "ProgramArguments": arguments,
        "RunAtLoad": True,
        "KeepAlive": True,
        "ProcessType": "Background",
        "Umask": 0o077,
        "ExitTimeOut": STOP_HARD_CEILING_SECONDS,
        "StandardOutPath": str(state / "rekeyd.stdout.log"),
        "StandardErrorPath": str(state / "rekeyd.stderr.log"),
    }, sys.stdout.buffer, fmt=plistlib.FMT_XML, sort_keys=False)


def validate_systemd_user(user: str) -> None:
    if USER_RE.fullmatch(user) is None:
        raise ValueError("systemd user has an invalid name")
    try:
        account = pwd.getpwnam(user)
    except KeyError as error:
        raise ValueError("systemd user does not exist") from error
    if account.pw_uid == 0:
        raise ValueError("systemd service must run as a non-root user")


def systemd_definition(rekeyd: pathlib.Path, state: pathlib.Path, user: Optional[str], oidc_profile: pathlib.Path = None) -> None:
    if user is not None:
        validate_systemd_user(user)
    profile_argument = "" if oidc_profile is None else " --oidc-admin-profile " + systemd_quote(oidc_profile)
    sys.stdout.write("\n".join([
        "[Unit]",
        "Description=Rekey Credential Authority",
        *([] if user is None else [
            "After=local-fs.target network-online.target",
            "Wants=network-online.target",
        ]),
        "",
        "[Service]",
        "Type=simple",
        *([] if user is None else [f"User={user}"]),
        f"ExecStart={systemd_quote(rekeyd)} serve --state-dir {systemd_quote(state)}{profile_argument}",
        "Restart=on-failure",
        "RestartSec=5s",
        "KillSignal=SIGTERM",
        f"TimeoutStopSec={STOP_HARD_CEILING_SECONDS}s",
        "UMask=0077",
        "NoNewPrivileges=true",
        "",
        "[Install]",
        "WantedBy=default.target" if user is None else "WantedBy=multi-user.target",
        "",
    ]))


def systemd_metrics_service(rekey: pathlib.Path, state: pathlib.Path, user: str) -> None:
    validate_systemd_user(user)
    sys.stdout.write("\n".join([
        "[Unit]",
        "Description=Publish Rekey local metrics",
        "After=local-fs.target",
        "",
        "[Service]",
        "Type=oneshot",
        f"User={user}",
        "SupplementaryGroups=rekey-metrics",
        f"ExecStart={systemd_quote(rekey)} --state-dir {systemd_quote(state)} metrics --prometheus --textfile-dir /var/lib/rekey-metrics",
        "TimeoutStartSec=10s",
        "TimeoutStartFailureMode=kill",
        "KillMode=control-group",
        "FinalKillSignal=SIGKILL",
        "SendSIGKILL=yes",
        "UMask=0077",
        "NoNewPrivileges=true",
        "",
    ]))


def systemd_metrics_timer() -> None:
    sys.stdout.write("\n".join([
        "[Unit]",
        "Description=Sample Rekey local metrics every 30 seconds",
        "",
        "[Timer]",
        "OnBootSec=30s",
        "OnUnitActiveSec=30s",
        "AccuracySec=1s",
        "RandomizedDelaySec=0",
        "Unit=rekey-metrics.service",
        "",
        "[Install]",
        "WantedBy=timers.target",
        "",
    ]))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("platform", choices=("launchd", "systemd-user", "systemd", "systemd-metrics-service", "systemd-metrics-timer"))
    parser.add_argument("--rekeyd")
    parser.add_argument("--rekey")
    parser.add_argument("--state-dir")
    parser.add_argument("--oidc-admin-profile", type=pathlib.Path)
    parser.add_argument("--label")
    parser.add_argument("--run-as-user")
    args = parser.parse_args()
    try:
        if args.platform == "systemd-metrics-timer":
            if any(value is not None for value in (args.rekeyd, args.rekey, args.state_dir, args.label, args.run_as_user, args.oidc_admin_profile)):
                raise ValueError("systemd-metrics-timer accepts no additional arguments")
            systemd_metrics_timer()
        elif args.platform == "systemd-metrics-service":
            if args.rekey is None or args.state_dir is None or args.run_as_user is None:
                raise ValueError("systemd-metrics-service requires --rekey, --state-dir and --run-as-user")
            if args.oidc_admin_profile is not None:
                raise ValueError("systemd-metrics-service rejects --oidc-admin-profile")
            if args.rekeyd is not None or args.label is not None:
                raise ValueError("systemd-metrics-service rejects --rekeyd and --label")
            rekey = installed_path(args.rekey, executable=True)
            state = installed_path(args.state_dir, executable=False)
            systemd_metrics_service(rekey, state, args.run_as_user)
        else:
            # Keep the old modes' required arguments and diagnostics.
            missing = [name for name, value in (("--rekeyd", args.rekeyd), ("--state-dir", args.state_dir)) if value is None]
            if missing:
                parser.error("the following arguments are required: " + ", ".join(missing))
            if args.rekey is not None:
                raise ValueError(f"{args.platform} rejects --rekey")
            if args.oidc_admin_profile is not None:
                if not args.oidc_admin_profile.is_absolute():
                    raise ValueError("OIDC profile path must be absolute")
                if any(ord(char) < 32 for char in str(args.oidc_admin_profile)):
                    raise ValueError("paths containing control characters are unsupported")
            rekeyd = installed_path(args.rekeyd, executable=True)
            state = installed_path(args.state_dir, executable=False)
            if args.platform == "launchd":
                if args.label is None or args.run_as_user is not None:
                    raise ValueError("launchd requires --label and rejects --run-as-user")
                launchd_definition(rekeyd, state, args.label, args.oidc_admin_profile)
            elif args.platform == "systemd-user":
                if args.label is not None or args.run_as_user is not None:
                    raise ValueError("systemd-user rejects --label and --run-as-user")
                systemd_definition(rekeyd, state, None, args.oidc_admin_profile)
            else:
                if args.label is not None or args.run_as_user is None:
                    raise ValueError("systemd requires --run-as-user and rejects --label")
                systemd_definition(rekeyd, state, args.run_as_user, args.oidc_admin_profile)
    except ValueError as error:
        parser.error(str(error))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
