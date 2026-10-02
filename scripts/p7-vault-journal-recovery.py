#!/usr/bin/env python3
"""Synthetic TLS provider in its own process; real CLI, UDS, SIGKILL and restart.

No real Vault or credentials. Artifacts contain evidence, never request secrets.
Use --artifacts for retained evidence; build the example and CLI first.
"""
import argparse
import json
import os
from pathlib import Path
import signal
import shutil
import tempfile
import sqlite3
import subprocess
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
PASSWORD = b"journal synthetic acceptance password\n"
TOKEN = "JOURNAL-SOURCE-TOKEN-ONE-CANARY"
VALUE = "JOURNAL-DYNAMIC-VALUE-CANARY"
LEASE = "database/creds/journal-role/JOURNAL-LEASE-ID-CANARY"


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def wait_for(predicate, message, seconds=20):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        if predicate():
            return
        time.sleep(0.025)
    raise RuntimeError(message)


def private_json(path, value):
    with path.open("x") as handle:
        os.chmod(path, 0o600)
        json.dump(value, handle)


class Scenario:
    def __init__(self, root, binaries):
        self.root, self.binaries = root, binaries
        root.mkdir(mode=0o700)
        self.state = root / "state"
        self.processes, self.logs = [], []
        self.recovery = None

    def cli(self, *args, proof=False, payload=None, check=True):
        if args[:2] == ("policy", "activate"):
            target = self.data("policy", "status")
            args = (*args, "--expected-vault-id", target["vault_id"], "--expected-trust-sha256", target["trust_sha256"])
        result = subprocess.run([str(self.binaries / "rekey"), "--state-dir", str(self.state), *args],
                                input=PASSWORD if proof else payload,
                                capture_output=True, timeout=40)
        if check:
            require(result.returncode == 0, f"CLI {' '.join(args[:2])} failed ({result.returncode})")
        return result

    def data(self, *args, **kwargs):
        return json.loads(self.cli(*args, **kwargs).stdout)

    def start(self, mode, gate="none"):
        index = len(self.logs)
        out = self.root / f"{mode}-{index}.out"
        err = self.root / f"{mode}-{index}.err"
        self.logs += [out, err]
        command = [str(self.binaries / "examples/p7_vault_journal_fixture"), mode, str(self.root)]
        if mode == "broker":
            command += [str(self.state), gate]
        with out.open("wb") as stdout, err.open("wb") as stderr:
            process = subprocess.Popen(command, stdout=stdout, stderr=stderr)
        self.processes.append(process)
        if mode == "provider":
            wait_for(lambda: (self.root / "provider-ready.json").exists(), "TLS provider not ready")
        else:
            wait_for(lambda: process.poll() is not None or self.cli("status", check=False).returncode == 0,
                     "Broker not ready")
            require(process.poll() is None, "Broker failed to start")
        return process

    def setup(self, gate="none"):
        result = self.cli("init", "--mode", "team", "--password-stdin", proof=True)
        self.recovery = result.stdout.strip().splitlines()[-1]  # Never persisted or printed.
        self.start("provider")
        self.broker = self.start("broker", gate)
        summary = self.data("unlock", "--password-stdin", proof=True)["lease_recovery"]
        require(summary["performed"] and summary["journal"]["pending"] == 0, "initial journal")
        private_json(self.root / "profile.json", {
            "credential_type": "vault-dynamic-source-v2", "origin": "https://vault.test.local",
            "mount": "database", "role": "journal-role", "key": "token", "renew_increment_seconds": 60,
            "vault_token": TOKEN})
        self.credential = self.data("credential", "add-vault-dynamic", "journal", "--file",
                                    str(self.root / "profile.json"), "--password-stdin", proof=True)["id"]
        private_json(self.root / "action.json", {
            "name": "journal-action", "credential_id": self.credential, "origin": "https://api.test.local",
            "method": "POST", "exact_path": "/v1/things", "auth_header": "authorization", "auth_prefix": "Bearer ",
            "timeout_ms": 30000, "request_max_bytes": 1024, "allowed_extra_headers": [],
            "response_max_bytes": 4096, "allowed_response_headers": ["content-type"]})
        self.action = self.data("action", "create", "--file", str(self.root / "action.json"),
                                "--password-stdin", proof=True)["id"]
        session = self.data("session", "create", "--action", self.action + "@1", "--ttl", "10m",
                            "--max-uses", "10", "--password-stdin", proof=True)
        self.capability = session["capability_token"]
        resource = {"type": "journal-action", "id": self.action}
        private_json(self.root / "snapshot.json", {"format_version": 3, "version": 1,
            "expires_at_ms": int(time.time() * 1000) + 600000, "approvers": [], "workload_identities": [],
            "bindings": [{"action_id": self.action, "version": 1, "resource": resource,
                          "parameter_schema_id": "journal/v1", "parameter_schema": {}}],
            "rules": [{"id": str(uuid.uuid4()), "effect": "permit", "principal_id": session["principal_id"],
                       "action_id": self.action, "version": 1, "resource": resource,
                       "parameters": {"kind": "any_validated"}}]})
        result = subprocess.run(["python3", str(ROOT / "scripts/sign-test-policy.py"), "policy", "--key-dir",
            str(self.root / "policy-key"), "--snapshot", str(self.root / "snapshot.json"),
            "--bundle", str(self.root / "policy.json"), "--trust", str(self.root / "trust.json")], capture_output=True)
        require(result.returncode == 0, "synthetic policy signing failed")
        self.cli("policy", "trust", "install", "--file", str(self.root / "trust.json"), "--step-up-stdin", proof=True)
        self.cli("policy", "activate", "--file", str(self.root / "policy.json"), "--step-up-stdin", proof=True)
        (self.root / "request.json").write_bytes(b'{"operation":"bounded"}')

    def execute(self, asynchronous=False):
        args = ["execute", self.action + "@1", "--capability", "-", "--body-file",
                str(self.root / "request.json"), "--content-type", "application/json"]
        if not asynchronous:
            return self.cli(*args, payload=self.capability.encode() + b"\n", check=False)
        process = subprocess.Popen([str(self.binaries / "rekey"), "--state-dir", str(self.state), *args],
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        process.stdin.write(self.capability.encode() + b"\n")
        process.stdin.close()
        self.processes.append(process)
        return process

    def ledger(self):
        return json.loads((self.root / "ledger.json").read_bytes())

    def journal(self):
        with sqlite3.connect(self.state / "vault.sqlite3") as db:
            return db.execute("SELECT phase,credential_version,cleanup_outcome FROM vault_lease_journal").fetchall()

    def check_secrets(self):
        paths = list(self.state.glob("vault.sqlite3*")) + self.logs
        for path in paths:
            data = path.read_bytes()
            for secret in (TOKEN, VALUE, LEASE):
                require(secret.encode() not in data, "secret canary in DB/WAL/process log")

    def cleanup(self):
        for process in reversed(self.processes):
            if process.poll() is None:
                process.kill()
            process.wait(timeout=10)
        self.check_secrets()


def crash_gate(s, gate):
    s.setup(gate)
    execution = s.execute(asynchronous=True)
    wait_for(lambda: (s.root / "gate-ready").exists(), "durable gate was not reached")
    before = s.ledger()
    require(before["acquired"] == 1 and before["business"] == (0 if gate == "issued_before_business" else 1),
            "wrong acquisition/business boundary")
    require(before["revoked"] == (1 if gate == "revoke_response_before_complete" else 0), "wrong revoke boundary")
    expected = "issued" if gate == "issued_before_business" else "cleanup_started"
    require(s.journal() == [(expected, 1, "none" if expected == "issued" else "unconfirmed")], "journal not durably persisted before SIGKILL")
    os.kill(s.broker.pid, signal.SIGKILL)
    s.broker.wait(timeout=10)
    execution.wait(timeout=10)
    s.check_secrets()
    require(s.processes[0].poll() is None, "provider did not survive Broker SIGKILL")
    s.broker = s.start("broker")
    status = s.data("status")["lease_journal"]
    require(not status["verified"] and status["pending"] == 1, "locked counts must be unverified")
    time.sleep(0.1)
    require(s.ledger() == before, "locked Broker performed provider IO")
    recovery = s.data("unlock", "--password-stdin", proof=True)["lease_recovery"]
    require(recovery["performed"] and recovery["journal"]["pending"] == 0 and
            recovery["journal"]["complete"] == 1 and recovery["leases"][0]["outcome"] == "complete",
            "unlock did not confirm exact cleanup")
    after = s.ledger()
    require(after["revoked"] == before["revoked"] + 1 and after["business"] == before["business"] and
            after["acquired"] == 1 and not after["active"] and after["exact_requests"], "business/acquire replay or wrong revoke")
    require(not s.data("unlock", "--password-stdin", proof=True)["lease_recovery"]["performed"], "Running unlock repeated recovery")
    require(s.ledger() == after, "Running unlock performed provider IO")
    return {"gate": gate, "before": before, "after": after, "recovery": recovery}


def maintenance(s):
    s.setup()
    (s.root / "provider-mode").write_text("reject")
    require(s.execute().returncode == 8, "rejected cleanup must stay indeterminate")
    require(s.journal()[0][0] == "cleanup_started", "pending cleanup missing")
    private_json(s.root / "profile-two.json", {"credential_type": "vault-dynamic-source-v2",
        "origin": "https://vault.test.local", "mount": "database", "role": "journal-role", "key": "token",
        "renew_increment_seconds": 60, "vault_token": "JOURNAL-NEW-CURRENT-TOKEN-CANARY"})
    require(s.data("credential", "rotate-vault-dynamic", s.credential, "--file", str(s.root / "profile-two.json"),
                   "--password-stdin", proof=True)["current_version"] == 2, "credential rotation")
    s.cli("credential", "revoke", s.credential, "--password-stdin", proof=True)
    s.cli("key", "rotate-dek", "--password-stdin", proof=True)
    backup = s.data("backup", "--output", str(s.root / "pending.backup"), "--password-stdin", proof=True)
    s.cli("lock")
    s.cli("key", "rotate-vrk", "--stdin-secrets", payload=PASSWORD + s.recovery + b"\n")
    (s.root / "provider-mode").write_text("")
    recovery = s.data("unlock", "--password-stdin", proof=True)["lease_recovery"]
    require(recovery["journal"]["pending"] == 0 and recovery["leases"][0]["credential_version"] == 1,
            "rotation/revocation historical cleanup")
    before = s.ledger()
    s.cli("shutdown", "--password-stdin", proof=True)
    s.broker.wait(timeout=10)
    s.state = s.root / "restored"
    s.cli("restore", "--input", str(s.root / "pending.backup"), "--sha256", backup["sha256_hex"],
          "--password-stdin", proof=True)
    s.broker = s.start("broker")
    require(not s.data("status")["lease_journal"]["verified"], "restored locked verification")
    recovery2 = s.data("unlock", "--password-stdin", proof=True)["lease_recovery"]
    require(recovery2["journal"]["complete"] == 1 and recovery2["journal"]["pending"] == 0,
            "old pending backup did not exact-clean")
    after = s.ledger()
    require(after["acquired"] == 1 and after["business"] == 1 and after["revoked"] == before["revoked"] + 1 and
            after["exact_requests"] and after["historical_token"], "current-profile fallback or backup business replay")
    return {"gate": "maintenance", "before": before, "after": after, "recovery": recovery, "restore": recovery2}


def unknown(s):
    s.setup()
    (s.root / "provider-mode").write_text("unknown")
    require(s.execute().returncode == 8, "unknown issuance error contract")
    before = s.ledger()
    s.cli("lock")
    require(not s.data("status")["lease_journal"]["verified"], "locked unknown summary")
    recovery = s.data("unlock", "--password-stdin", proof=True)["lease_recovery"]
    require(recovery["journal"]["unknown"] == 1 and not recovery["leases"], "unknown ID guessed")
    require(s.ledger() == before, "unknown recovery performed IO")
    require(s.execute().returncode != 0 and s.ledger() == before, "unknown source was reopened")
    return {"gate": "unknown", "before": before, "after": s.ledger(), "recovery": recovery}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--artifacts", type=Path, required=True)
    parser.add_argument("--binaries", type=Path, default=ROOT / "target/debug")
    args = parser.parse_args()
    args.artifacts.mkdir(mode=0o700, parents=True, exist_ok=True)
    results = []
    work = Path(tempfile.mkdtemp(prefix="rkjournal-"))
    cases = [(gate, lambda s, gate=gate: crash_gate(s, gate)) for gate in
             ("issued_before_business", "business_before_revoke", "revoke_response_before_complete")]
    cases += [("maintenance", maintenance), ("unknown", unknown)]
    for index, (name, function) in enumerate(cases):
        scenario = Scenario(work / str(index), args.binaries)
        try:
            results.append(function(scenario))
        finally:
            scenario.cleanup()
            destination = args.artifacts / name
            destination.mkdir(mode=0o700)
            for path in scenario.logs + list(scenario.state.glob("vault.sqlite3*")) + list(scenario.root.glob("ledger.json")):
                shutil.copy2(path, destination / path.name)
        print(f"PASS {name}", flush=True)
    shutil.rmtree(work)
    (args.artifacts / "evidence.json").write_text(json.dumps(results, indent=2))
    print(f"5/5 real-process TLS/CLI journal recovery scenarios passed; evidence: {args.artifacts}")


if __name__ == "__main__":
    main()
