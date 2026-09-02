#!/usr/bin/env python3
"""Create test-only Ed25519 policy and approval artifacts with OpenSSL."""

import argparse
import base64
import json
import os
import pathlib
import subprocess
import tempfile
import uuid


def canonical(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, allow_nan=False, separators=(",", ":"), sort_keys=True
    ).encode()


def ensure_identity(
    key_dir: pathlib.Path, key_name: str, id_name: str
) -> tuple[pathlib.Path, str, str]:
    key_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    key_path = key_dir / key_name
    id_path = key_dir / id_name
    if not key_path.exists():
        subprocess.run(
            ["openssl", "genpkey", "-algorithm", "ED25519", "-out", str(key_path)],
            check=True,
            stdout=subprocess.DEVNULL,
        )
        os.chmod(key_path, 0o600)
        id_path.write_text(str(uuid.uuid4()), encoding="ascii")
        os.chmod(id_path, 0o600)
    identity_id = id_path.read_text(encoding="ascii").strip()
    public_der = subprocess.run(
        ["openssl", "pkey", "-in", str(key_path), "-pubout", "-outform", "DER"],
        check=True,
        stdout=subprocess.PIPE,
    ).stdout
    if len(public_der) < 32:
        raise SystemExit("invalid Ed25519 public key output")
    return key_path, identity_id, public_der[-32:].hex()


def sign_bytes(key_path: pathlib.Path, message: bytes) -> str:
    with tempfile.TemporaryDirectory(dir=key_path.parent) as temp_dir:
        message_path = pathlib.Path(temp_dir) / "message"
        signature_path = pathlib.Path(temp_dir) / "signature"
        message_path.write_bytes(message)
        subprocess.run(
            [
                "openssl",
                "pkeyutl",
                "-sign",
                "-rawin",
                "-inkey",
                str(key_path),
                "-in",
                str(message_path),
                "-out",
                str(signature_path),
            ],
            check=True,
            stdout=subprocess.DEVNULL,
        )
        return base64.urlsafe_b64encode(signature_path.read_bytes()).rstrip(b"=").decode()


def sign_policy(args: argparse.Namespace) -> None:
    key_path, signer_id, public_key = ensure_identity(
        args.key_dir, "policy-signing-key.pem", "signer-id"
    )
    trust = {
        "algorithm": "ed25519",
        "format_version": 1,
        "public_key": public_key,
        "signer_id": signer_id,
    }
    args.trust.write_bytes(canonical(trust))

    snapshot = json.loads(args.snapshot.read_text(encoding="utf-8"))
    if snapshot.get("format_version") not in (2, 3):
        raise SystemExit("test policy snapshot must use format_version 2 or 3")
    unsigned = {"format_version": 1, "signer_id": signer_id, "snapshot": snapshot}
    bundle = dict(unsigned)
    bundle["signature"] = sign_bytes(key_path, b"RKPOLICY\0\x01" + canonical(unsigned))
    args.bundle.write_bytes(canonical(bundle))


def approval_identity(args: argparse.Namespace) -> None:
    _, approver_id, public_key = ensure_identity(
        args.key_dir, "approver-key.pem", "approver-id"
    )
    print(
        canonical(
            {
                "algorithm": "ed25519",
                "approver_id": approver_id,
                "public_key": public_key,
            }
        ).decode()
    )


def sign_approval(args: argparse.Namespace) -> None:
    key_path, approver_id, _ = ensure_identity(
        args.key_dir, "approver-key.pem", "approver-id"
    )
    challenge = json.loads(args.challenge.read_text(encoding="utf-8"))
    if challenge.get("record_type") != "rekey.approval.challenge.v1":
        raise SystemExit("invalid approval challenge")
    expires_at_ms = min(
        challenge["max_expires_at_ms"], challenge["created_at_ms"] + args.validity_ms
    )
    unsigned = {
        "format_version": 1,
        "approval_id": str(uuid.uuid4()),
        "approval_request_id": challenge["approval_request_id"],
        "approver_id": approver_id,
        "tenant_id": challenge["tenant_id"],
        "principal_id": challenge["principal_id"],
        "session_id": challenge["session_id"],
        "action_id": challenge["action_id"],
        "action_version": challenge["action_version"],
        "resource": challenge["resource"],
        "schema_id": challenge["schema_id"],
        "parameter_sha256": challenge["parameter_sha256"],
        "policy_version": challenge["policy_version"],
        "policy_sha256": challenge["policy_sha256"],
        "policy_rule_id": challenge["policy_rule_id"],
        "mode": challenge["mode"],
        "not_before_ms": challenge["created_at_ms"],
        "expires_at_ms": expires_at_ms,
        "max_uses": args.max_uses,
    }
    if expires_at_ms <= unsigned["not_before_ms"]:
        raise SystemExit("approval validity window is already empty")
    grant = dict(unsigned)
    grant["signature"] = sign_bytes(
        key_path, b"RKAPPROVAL\0\x01" + canonical(unsigned)
    )
    args.output.write_bytes(canonical(grant))


def workload_key(args: argparse.Namespace) -> None:
    _, _, public_key = ensure_identity(
        args.key_dir, "workload-key.pem", "workload-key-id"
    )
    raw = bytes.fromhex(public_key)
    print(
        canonical(
            {
                "algorithm": "ed25519",
                "kid": args.kid,
                "x": base64.urlsafe_b64encode(raw).rstrip(b"=").decode(),
            }
        ).decode()
    )


def sign_workload_token(args: argparse.Namespace) -> None:
    key_path, _, _ = ensure_identity(
        args.key_dir, "workload-key.pem", "workload-key-id"
    )
    header = {"alg": "EdDSA", "kid": args.kid, "typ": "JWT"}
    claims = {
        "iss": args.issuer,
        "sub": args.subject,
        "aud": [args.audience],
        "jti": args.jti,
        "iat": args.now,
        "nbf": args.now,
        "exp": args.now + args.validity_seconds,
    }
    encoded_header = base64.urlsafe_b64encode(canonical(header)).rstrip(b"=")
    encoded_claims = base64.urlsafe_b64encode(canonical(claims)).rstrip(b"=")
    signing_input = encoded_header + b"." + encoded_claims
    signature = sign_bytes(key_path, signing_input).encode()
    print((signing_input + b"." + signature).decode())


def main() -> None:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    policy = subparsers.add_parser("policy")
    policy.add_argument("--key-dir", required=True, type=pathlib.Path)
    policy.add_argument("--snapshot", required=True, type=pathlib.Path)
    policy.add_argument("--bundle", required=True, type=pathlib.Path)
    policy.add_argument("--trust", required=True, type=pathlib.Path)
    policy.set_defaults(func=sign_policy)
    identity = subparsers.add_parser("approval-identity")
    identity.add_argument("--key-dir", required=True, type=pathlib.Path)
    identity.set_defaults(func=approval_identity)
    approval = subparsers.add_parser("approval-sign")
    approval.add_argument("--key-dir", required=True, type=pathlib.Path)
    approval.add_argument("--challenge", required=True, type=pathlib.Path)
    approval.add_argument("--output", required=True, type=pathlib.Path)
    approval.add_argument("--max-uses", required=True, type=int)
    approval.add_argument("--validity-ms", required=True, type=int)
    approval.set_defaults(func=sign_approval)
    workload_public = subparsers.add_parser("workload-key")
    workload_public.add_argument("--key-dir", required=True, type=pathlib.Path)
    workload_public.add_argument("--kid", required=True)
    workload_public.set_defaults(func=workload_key)
    workload_token = subparsers.add_parser("workload-token")
    workload_token.add_argument("--key-dir", required=True, type=pathlib.Path)
    workload_token.add_argument("--kid", required=True)
    workload_token.add_argument("--issuer", required=True)
    workload_token.add_argument("--subject", required=True)
    workload_token.add_argument("--audience", required=True)
    workload_token.add_argument("--jti", required=True)
    workload_token.add_argument("--now", required=True, type=int)
    workload_token.add_argument("--validity-seconds", required=True, type=int)
    workload_token.set_defaults(func=sign_workload_token)
    args = parser.parse_args()
    if (
        getattr(args, "max_uses", 1) < 1
        or getattr(args, "validity_ms", 1) < 1
        or getattr(args, "validity_seconds", 1) < 1
    ):
        raise SystemExit("max uses and validity must be positive")
    args.func(args)


if __name__ == "__main__":
    main()
