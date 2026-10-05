#!/usr/bin/env python3
"""Real 0.4 CLI/Authority contracts with disposable synthetic secrets only."""
import base64
import json
import os
from pathlib import Path
import socket
import sqlite3
import struct
import subprocess
import sys
import tempfile
import time
import uuid

binary = Path(sys.argv[1]).resolve()
with tempfile.TemporaryDirectory(prefix='rk-human-') as root:
    state = Path(root) / 'vault'
    password = 'synthetic-human-vault-password'
    canary = 'synthetic-glm-key-canary'
    rotated = 'synthetic-rotated-key-canary'
    secrets = [password, canary, rotated]
    tokens = []
    environment = {'HOME': root, 'PATH': os.environ.get('PATH', '/usr/bin:/bin'), 'LANG': 'en_US.UTF-8'}

    def safe_output(output):
        assert all(value.encode() not in output for value in secrets), 'secret reached public output'

    def call(args, body='', ok=True):
        result = subprocess.run([str(binary), '--state-dir', str(state), *args],
                                input=body.encode(), capture_output=True, timeout=30, env=environment)
        safe_output(result.stdout + result.stderr)
        if ok and result.returncode:
            raise RuntimeError(result.stderr.decode())
        if not ok:
            assert result.returncode != 0, args
            assert not result.stdout, 'failure returned stdout'
        return result.stdout

    def start_broker():
        process = subprocess.Popen([str(binary.parent / 'rekeyd'), 'serve', '--state-dir', str(state)],
                                   stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                   stderr=subprocess.DEVNULL, env=environment)
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            assert process.poll() is None, 'synthetic broker exited during startup'
            try:
                call(['status', '--passive'])
                return process
            except (RuntimeError, OSError):
                time.sleep(.1)
        process.terminate()
        process.wait(timeout=10)
        raise AssertionError('synthetic broker startup timed out')

    def scan(value, expected=None):
        # Send the known synthetic value only in the SCAN frame body; no file,
        # argv, environment, provider call or plaintext export is needed.
        metadata = json.dumps({'path': 'synthetic-human-vault.txt'}).encode()
        body = value.encode()
        request_id = uuid.uuid4().bytes
        header = struct.pack('>4sHBBHH16sII', b'RKIP', 1, 2, 0, 15, 0,
                             request_id, len(metadata), len(body))
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as stream:
            stream.settimeout(10)
            stream.connect(str(state / 'runtime/agent.sock'))
            stream.sendall(header + metadata + body)

            def read_exact(count):
                output = bytearray()
                while len(output) < count:
                    chunk = stream.recv(count - len(output))
                    assert chunk, 'truncated scan response'
                    output.extend(chunk)
                return bytes(output)

            magic, version, channel, flags, message, reserved, reply_id, meta_len, body_len = struct.unpack(
                '>4sHBBHH16sII', read_exact(36))
            assert (magic, version, channel, flags, reserved, reply_id) == (b'RKIP', 1, 2, 0, 0, request_id)
            assert meta_len <= 65536 and body_len <= 4194304
            response_metadata, response_body = read_exact(meta_len), read_exact(body_len)
        safe_output(response_metadata + response_body)
        if expected is None:
            assert message == 101 and not response_body
            assert json.loads(response_metadata)['code'] == 'LOCKED'
            return
        assert message == 100, 'signed Connection scan failed'
        findings = json.loads(response_body)['findings']
        assert {finding['connection'] for finding in findings} == set(expected)
        assert len(findings) == len(expected)
        assert all(finding['path'] == 'synthetic-human-vault.txt' and
                   finding['line'] == 1 and finding['column'] == 1 for finding in findings)

    call(['init', '--mode', 'personal', '--password-stdin'], password + '\n')
    # Each fixture uses its own service port, independently of other test lanes.
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(('127.0.0.1', 0))
        port = listener.getsockname()[1]
    (state / 'service.json').write_text(json.dumps({'port': port}))
    (state / 'service.json').chmod(0o600)
    broker = start_broker()
    try:
        call(['unlock', '--password-stdin'], password+'\n')
        existing = json.loads(call(['credential', 'add', 'previously saved', '--stdin-secrets'], password+'\n'+canary+'\n'))
        token = call(['desktop-login'], password+'\n').decode()
        tokens.append(token)
        assert len(token) == 64
        saved = [existing]
        for name in ['GLM personal', 'GLM work']:
            saved.append(json.loads(call(['desktop-add', name], token+'\n'+canary+'\n')))
        assert len({item['id'] for item in saved}) == 3
        assert all(item['current_version'] == 1 for item in saved)
        listed = json.loads(call(['credential', 'list']))['credentials']
        assert {item['id'] for item in listed} == {item['id'] for item in saved}
        # Default 0.4 has no human or Agent plaintext-export command.
        call(['desktop-reveal', existing['id'], '--password-stdin'], password+'\n', ok=False)

        # Software P-256 signs the daemon's actual canonical Connection draft.
        # This is not Touch ID or Secure Enclave hardware acceptance.
        key = Path(root) / 'signing-key.pem'
        subprocess.run(['openssl', 'ecparam', '-name', 'prime256v1', '-genkey', '-noout', '-out', str(key)],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, env=environment)
        key.chmod(0o600)
        public = subprocess.run(['openssl', 'pkey', '-in', str(key), '-pubout', '-outform', 'DER'],
                                check=True, capture_output=True, env=environment).stdout[-65:]
        assert len(public) == 65 and public[0] == 4
        trust = {'format_version': 1, 'algorithm': 'secure-enclave-p256',
                 'signer_id': str(uuid.uuid4()), 'public_key': public.hex()}
        call(['policy', 'trust', 'install', '--stdin-request', '--step-up-stdin'], password+'\n'+json.dumps(trust)+'\n')
        preset = json.loads(call(['connection', 'preset', 'generic-bearer', '--origin', 'https://example.com']))
        connections = [{**preset, 'preset': preset['name'], 'name': 'human-saved-'+str(index),
                        'credential_id': item['id'], 'enabled': True, 'grade': 'T0',
                        'bindings': {}, 'caller_overrides': {}, 'llm': None, 'oauth': None,
                        'limits': {'requests_per_hour': 600, 'max_request_bytes': 4096, 'max_response_bytes': 4096}}
                       for index, item in enumerate(saved)]
        draft = json.loads(call(['policy', 'draft', '--connections-stdin', '--expires-at-ms', str(int(time.time()*1000)+600000)],
                                json.dumps(connections)))
        sign_bytes = draft['sign_bytes'].encode()
        assert sign_bytes.startswith(b'RKPOLICY\0\x01')
        bundle = json.loads(sign_bytes[len(b'RKPOLICY\0\x01'):])
        signature = subprocess.run(['openssl', 'dgst', '-sha256', '-sign', str(key)], input=sign_bytes,
                                   check=True, capture_output=True, env=environment).stdout
        bundle['signature'] = base64.urlsafe_b64encode(signature).rstrip(b'=').decode()
        call(['policy', 'activate', '--stdin-request', '--step-up-stdin',
              '--expected-vault-id', draft['metadata']['vault_id'],
              '--expected-trust-sha256', draft['metadata']['trust_sha256']], password+'\n'+json.dumps(bundle)+'\n')
        names = {connection['name'] for connection in connections}
        configured = json.loads(call(['connection', 'list']))['connections']
        assert {connection['name'] for connection in configured if connection['enabled']} == names
        scan(canary, names)

        call(['credential', 'rotate', existing['id'], '--stdin-secrets'], 'forged-proof\n'+rotated+'\n', ok=False)
        time.sleep(1.1)
        token = call(['desktop-login'], password+'\n').decode()
        tokens.append(token)
        call(['credential', 'rotate', existing['id'], '--stdin-secrets'], token+'\n'+rotated+'\n', ok=False)
        listed = json.loads(call(['credential', 'list']))['credentials']
        assert all(item['current_version'] == 1 for item in listed), 'denied proof changed a value'
        time.sleep(1.1)
        changed = json.loads(call(['credential', 'rotate', existing['id'], '--stdin-secrets'], password+'\n'+rotated+'\n'))
        assert changed['current_version'] == 2
        scan(canary, names-{'human-saved-0'})
        scan(rotated, {'human-saved-0'})
        audit = call(['audit', 'list'])
        assert all(value.encode() not in audit for value in tokens)
        call(['lock'])
        scan(rotated)
        call(['desktop-add', 'locked must fail'], token+'\n'+canary+'\n', ok=False)
        fresh = call(['desktop-login'], password+'\n').decode()
        tokens.append(fresh)
        call(['desktop-add', 'old token must fail'], token+'\n'+canary+'\n', ok=False)
        expiry, remember_key = call(['desktop-remember'], password+'\n').decode().split('\n')
        broker.terminate()
        broker.wait(timeout=10)
        broker = start_broker()
        restored_expiry, fresh = call(['desktop-resume'], remember_key+'\n').decode().split('\n')
        tokens.extend([fresh, remember_key])
        assert restored_expiry == expiry
        scan(canary, names-{'human-saved-0'})
        scan(rotated, {'human-saved-0'})
        audit = call(['audit', 'list'])
        assert all(value.encode() not in audit for value in tokens)
        call(['lock'])
        call(['desktop-resume'], remember_key+'\n', ok=False)
        fresh = call(['desktop-login'], password+'\n').decode()
        call(['desktop-add', 'revoked token must fail'], token+'\n'+canary+'\n', ok=False)
        assert len(json.loads(call(['credential', 'list']))['credentials']) == 3
        # Fail a real default A2 mutation's durable audit. No new version/value
        # may be committed or returned, and the Authority must fault closed.
        db = sqlite3.connect(state/'vault.sqlite3')
        db.execute("CREATE TRIGGER fail_human_audit BEFORE INSERT ON audit_events BEGIN SELECT RAISE(ABORT, 'test audit unavailable'); END")
        db.commit()
        db.close()
        call(['credential', 'rotate', existing['id'], '--stdin-secrets'], password+'\n'+canary+'\n', ok=False)
        db = sqlite3.connect(state/'vault.sqlite3')
        assert db.execute('SELECT current_version FROM credentials WHERE credential_id = ?',
                          (uuid.UUID(existing['id']).bytes,)).fetchone()[0] == 2, 'audit failure committed a new version'
        db.close()
        status = subprocess.run([str(binary), '--state-dir', str(state), 'status'],
                                capture_output=True, timeout=10, env=environment)
        safe_output(status.stdout + status.stderr)
        if status.returncode == 0:
            assert json.loads(status.stdout)['state'] == 'faulted'
        else:
            assert b'IPC_UNAVAILABLE' in status.stderr
            assert broker.wait(timeout=10) != 0, 'audit fault must not claim a clean stop'
        print('PASS: opaque existing/new saves, signed Connection scan of current values, v2 rotation, per-call proof and token/locked denial, no default export, safe audit, fixed-expiry restart resume, manual revocation, real mutation audit failure closes without plaintext. Software signer only.')
    finally:
        if broker.poll() is None:
            broker.terminate()
        broker.wait(timeout=10)
