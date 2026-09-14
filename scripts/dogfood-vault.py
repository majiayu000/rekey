#!/usr/bin/env python3
"""Opt-in Layer B: public HTTPS Vault through unmodified production rekeyd."""

import argparse
import datetime
import getpass
import importlib.util
import json
from pathlib import Path
import secrets
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location("quickstart", ROOT / "scripts/agent-quickstart.py")
QUICKSTART = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(QUICKSTART)


def run(command, stdin=None):
    result = subprocess.run(command, input=stdin, capture_output=True, text=True)
    if result.returncode:
        # Neither arbitrary provider error text nor a secret-bearing command
        # object is emitted. The operator can use the existing audit tooling.
        raise QUICKSTART.InputError(f"Rekey dogfood step failed (exit {result.returncode}); no public success evidence")
    return result.stdout


def verify_events(events, dynamic):
    ordered = sorted(events, key=lambda e: e["sequence"])
    names = [e["event_type"] for e in ordered]
    required = ["execution.started"]
    if dynamic:
        required += ["vault.lease.issued", "vault.lease.revoked"]
    required += ["execution.finished"]
    positions = [names.index(name) for name in required]
    if positions != sorted(positions):
        raise QUICKSTART.InputError("execution audit order is invalid")
    for name in required:
        if names.count(name) != 1 or ordered[names.index(name)]["outcome"] != "success":
            raise QUICKSTART.InputError("execution audit contains a failed or repeated event")
    return required


def dogfood(args):
    if not sys.stdin.isatty():
        raise QUICKSTART.InputError("dogfood requires a trusted interactive terminal")
    source = json.loads(args.source.read_text())
    if "vault_token" in source:
        raise QUICKSTART.InputError("source file must omit vault_token; enter it at the hidden prompt")
    kind = source["credential_type"]
    if kind not in ("vault-kv-v2-source-v1", "vault-dynamic-source-v1"):
        raise QUICKSTART.InputError("source must select one of the two closed Vault profiles")
    definition = json.loads(args.action.read_text())
    schema = json.loads(args.schema.read_text())
    if args.receipt.exists():
        raise QUICKSTART.InputError("receipt already exists; choose a new path")
    if not 200 <= args.expected_status < 300:
        raise QUICKSTART.InputError("expected status must be a successful HTTP status")
    # The production broker validates HTTPS, public IPs and the closed fields.
    # Do not duplicate its network screen or introduce local TLS exceptions.
    token = getpass.getpass("Disposable Vault token: ")
    if not token:
        raise QUICKSTART.InputError("Vault token is empty")
    password = secrets.token_urlsafe(32)
    with tempfile.TemporaryDirectory(prefix="rkvb.", dir="/tmp") as directory:
        work = Path(directory)
        state = work / "state"
        base = [str(args.bin_dir.resolve() / "rekey"), "--state-dir", str(state)]
        daemon = str(args.bin_dir.resolve() / "rekeyd")
        run([daemon, "init", "--state-dir", str(state), "--password-stdin"], password + "\n")
        with (work / "broker.log").open("w") as log:
            broker = subprocess.Popen([daemon, "serve", "--state-dir", str(state)], stdout=log, stderr=log)
            try:
                deadline = time.monotonic() + 10
                while not (state / "runtime/admin.sock").exists():
                    if broker.poll() is not None or time.monotonic() >= deadline:
                        raise QUICKSTART.InputError("broker did not become ready")
                    time.sleep(0.05)
                run(base + ["unlock", "--password-stdin"], password + "\n")
                source["vault_token"] = token
                QUICKSTART.write_new(work / "source.json", source)
                verb = "add-vault-dynamic" if kind == "vault-dynamic-source-v1" else "add-vault-kv"
                credential = json.loads(run(base + ["credential", verb, "layer-b", "--file", str(work / "source.json"),
                                                    "--password-stdin"], password + "\n"))
                (work / "source.json").unlink()
                definition["credential_id"] = credential["id"]
                QUICKSTART.write_new(work / "action.json", definition)
                action = json.loads(run(base + ["action", "create", "--file", str(work / "action.json"),
                                                "--password-stdin"], password + "\n"))
                ref = f'{action["id"]}@{action["version"]}'
                session = json.loads(run(base + ["session", "create", "--action", ref, "--ttl", "10m",
                                                 "--max-uses", "1", "--password-stdin"], password + "\n"))
                QUICKSTART.write_new(work / "draft.json", QUICKSTART.policy_draft(action, session, schema))
                run([sys.executable, str(ROOT / "scripts/sign-test-policy.py"), "policy", "--key-dir", str(work / "signer"),
                     "--snapshot", str(work / "draft.json"), "--trust", str(work / "trust.json"), "--bundle", str(work / "bundle.json")])
                for operation, file in [(["policy", "trust", "install"], "trust.json"),
                                        (["policy", "activate"], "bundle.json")]:
                    run(base + operation + ["--file", str(work / file), "--step-up-stdin"], password + "\n")
                command = base + ["execute", ref, "--capability", "-"]
                if args.body_file:
                    command += ["--body-file", str(args.body_file), "--content-type", "application/json"]
                for header in args.header:
                    command += ["--header", header]
                response = run(command, session["capability_token"] + "\n")
                metadata, _ = json.JSONDecoder().raw_decode(response.lstrip())
                if metadata["upstream_status"] != args.expected_status:
                    raise QUICKSTART.InputError("upstream status did not match; no success receipt written")
                if token in response:
                    raise QUICKSTART.InputError("Vault token reflected in Agent response")
                page = json.loads(run(base + ["audit", "list", "--action", action["id"], "--limit", "50"]))
                events = page["events"]
                if page["next_before_sequence"] is not None:
                    raise QUICKSTART.InputError("audit page incomplete; no success receipt written")
                required = verify_events(events, kind == "vault-dynamic-source-v1")
                receipt = {
                    "tested_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    "layer": "B", "source_kind": kind, "source_origin": source["origin"],
                    "source_mount": source["mount"], "action_origin": definition["origin"],
                    "source_selection": {key: source[key] for key in ("path", "version", "role", "key") if key in source},
                    "action_method": definition["method"], "action_path": definition["exact_path"],
                    "upstream_status": metadata["upstream_status"], "required_events": required,
                    "rekey_version": run([str(args.bin_dir.resolve() / "rekey"), "--version"]).strip(),
                    "limitation": "one public HTTPS source and fixed action; not general Vault support",
                }
                run(base + ["shutdown", "--password-stdin"], password + "\n")
                broker.wait(timeout=10)
                QUICKSTART.write_new(args.receipt, receipt)
                print(f"Layer B PASS; metadata-only receipt: {args.receipt}")
            finally:
                if broker.poll() is None:
                    broker.terminate()
                    broker.wait(timeout=10)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bin-dir", type=Path, default=ROOT / "target/release")
    parser.add_argument("--source", type=Path, required=True, help="public profile JSON without vault_token")
    parser.add_argument("--action", type=Path, required=True, help="fixed Action JSON; credential_id is replaced")
    parser.add_argument("--schema", type=Path, required=True)
    parser.add_argument("--body-file", type=Path)
    parser.add_argument("--header", action="append", default=[])
    parser.add_argument("--expected-status", type=int, required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    try:
        dogfood(parser.parse_args())
    except QUICKSTART.InputError as error:
        print(str(error), file=sys.stderr)
        return 1
    except (OSError, ValueError, KeyError, TypeError, subprocess.TimeoutExpired) as error:
        print(f"Layer B failed ({type(error).__name__}); no public success evidence", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
