#!/usr/bin/env python3
"""Real-process POL-08 acceptance. All keys/state are disposable test fixtures.

Build rekey-policy-sign, rekey and rekeyd first, then pass --bin-dir target/debug.
Requires OpenSSL with Ed25519 support; no network or provider credentials used.
"""
import argparse
import json
import pathlib
import subprocess
import tempfile
import time
import uuid


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bin-dir", type=pathlib.Path, required=True)
    args = parser.parse_args()
    binaries = args.bin_dir.resolve()
    with tempfile.TemporaryDirectory(prefix="rkpol-", dir="/tmp") as temporary:
        root = pathlib.Path(temporary)
        state = root / "state"
        proof = "disposable signer acceptance proof\n"

        def run(binary, *arguments, stdin=None, success=True):
            result = subprocess.run(
                [str(binaries / binary), *map(str, arguments)], input=stdin,
                capture_output=True, text=True, timeout=30, check=False,
            )
            assert (result.returncode == 0) == success, result.stderr
            return result.stdout

        def cli(*arguments, **kwargs):
            return run("rekey", "--state-dir", state, *arguments, **kwargs)

        cli("init", "--password-stdin", stdin=proof)
        with (root / "broker.log").open("w") as log:
            broker = subprocess.Popen(
                [str(binaries / "rekeyd"), "serve", "--state-dir", str(state)],
                stdout=log, stderr=log,
            )
            try:
                deadline = time.monotonic() + 15
                while not (state / "runtime" / "admin.sock").exists():
                    assert broker.poll() is None, "broker exited before opening socket"
                    assert time.monotonic() < deadline, "broker socket timeout"
                    time.sleep(0.05)
                cli("unlock", "--password-stdin", stdin=proof)
                initial = json.loads(cli("policy", "status"))
                assert not initial["trust_installed"] and not initial["bundle_persisted"]
                draft = root / "draft.json"
                draft.write_text(json.dumps({
                    "format_version": 3, "version": 1,
                    "expires_at_ms": int(time.time() * 1000) + 600000,
                    "approvers": [], "workload_identities": [], "bindings": [], "rules": [],
                }))
                key = root / "test-key.der"
                subprocess.run([
                    "openssl", "genpkey", "-algorithm", "ED25519", "-outform", "DER",
                    "-out", str(key),
                ], check=True, capture_output=True, timeout=30)
                key.chmod(0o600)
                review = json.loads(run("rekey-policy-sign", "review", draft))
                output = root / "signed"
                run("rekey-policy-sign", "sign", draft, "--reviewed-sha256", review["reviewed_sha256"],
                    "--signer-id", uuid.uuid4(), "--key-file", key, "--output", output)
                assert json.loads(cli("policy", "status")) == initial, "signer must not activate policy"
                cli("policy", "trust", "install", "--file", output / "trust.json", "--step-up-stdin", stdin=proof)
                trusted = json.loads(cli("policy", "status"))
                assert trusted["trust_installed"] and not trusted["bundle_persisted"]
                tampered = json.loads((output / "policy.json").read_text())
                tampered["snapshot"]["expires_at_ms"] += 1
                bad = root / "tampered.json"
                bad.write_text(json.dumps(tampered))
                cli("policy", "activate", "--file", bad, "--step-up-stdin", stdin=proof, success=False)
                assert not json.loads(cli("policy", "status"))["bundle_persisted"]
                cli("policy", "activate", "--file", output / "policy.json", "--step-up-stdin", stdin=proof)
                active = json.loads(cli("policy", "status"))
                assert active["bundle_persisted"] and active["trust_installed"]
                print("PASS: signer leaves Broker unchanged; real trust install succeeds; tampered activation fails; signed activation succeeds")
                print(json.dumps(active, sort_keys=True))
            finally:
                broker.terminate()
                broker.wait(timeout=15)


if __name__ == "__main__":
    main()
