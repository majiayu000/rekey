"""One-step `rekey add` against a real daemon with disposable synthetic secrets.

Basic mode signs with a software P-256 key file; this is not Secure Enclave.
Usage: python3 scripts/test-cli-add.py target/debug/rekey
(rekeyd and rekey-policy-sign must be siblings of the rekey binary.)
"""
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time

binary = Path(sys.argv[1]).resolve()
with tempfile.TemporaryDirectory(prefix='rk-add-') as root:
    state = Path(root) / 'vault'
    password = 'synthetic-add-vault-password'
    glm_key = 'synthetic-glm-key-canary-0001'
    openai_key = 'synthetic-openai-key-canary-0002'
    secrets = [password, glm_key, openai_key]
    environment = {'HOME': root, 'PATH': os.environ.get('PATH', '/usr/bin:/bin'), 'LANG': 'en_US.UTF-8'}

    def safe_output(output):
        assert all(value.encode() not in output for value in secrets), 'secret reached public output'

    def run(args, body=''):
        result = subprocess.run([str(binary), '--state-dir', str(state), *args],
                                input=body.encode(), capture_output=True, timeout=60, env=environment)
        safe_output(result.stdout + result.stderr)
        return result

    def call(args, body=''):
        result = run(args, body)
        if result.returncode:
            raise RuntimeError(result.stderr.decode())
        return result

    def fails(args, body, code):
        result = run(args, body)
        assert result.returncode != 0, args
        assert code.encode() in result.stderr, result.stderr.decode()
        return result

    def connections():
        return {item['name']: item for item in json.loads(call(['connection', 'list']).stdout)['connections']}

    call(['init', '--mode', 'personal', '--password-stdin'], password + '\n')
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(('127.0.0.1', 0))
        port = listener.getsockname()[1]
    (state / 'service.json').write_text(json.dumps({'port': port}))
    (state / 'service.json').chmod(0o600)
    broker = subprocess.Popen([str(binary.parent / 'rekeyd'), 'serve', '--state-dir', str(state)],
                              stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL, env=environment)
    try:
        deadline = time.monotonic() + 10
        while run(['status', '--passive']).returncode:
            assert broker.poll() is None and time.monotonic() < deadline, 'broker did not start'
            time.sleep(.1)

        # Locked vault: rejected before any secret is read.
        fails(['add', 'glm', '--stdin-secrets'], '', 'LOCKED')
        call(['unlock', '--password-stdin'], password + '\n')

        # First add installs basic-mode trust, saves the key, signs and activates.
        fails(['add', 'glm', '--stdin-secrets'], password + '\n' + glm_key + '\n', '--model')
        first = call(['add', 'glm', '--model', 'glm-test', '--stdin-secrets'], password + '\n' + glm_key + '\n')
        assert b'not Secure Enclave' in first.stdout + first.stderr
        assert b'glm.messages' in first.stdout
        key_file = state / 'policy-signer-p256.p8'
        assert key_file.is_file() and (key_file.stat().st_mode & 0o777) == 0o600
        active = connections()
        assert active['glm']['enabled'] and active['glm']['preset'] == 'glm'
        assert active['glm']['llm']['models'] == ['glm-test']
        status = json.loads(call(['policy', 'status']).stdout)
        assert status['trust_installed'] and status['status'] == 'active', status

        # Second add reuses the installed trust and keeps the first Connection.
        second = call(['add', 'openai', '--model', 'gpt-test', '--stdin-secrets'], password + '\n' + openai_key + '\n')
        assert b'gpt-test' in second.stdout
        assert set(connections()) == {'glm', 'openai'}
        assert connections()['openai']['llm']['models'] == ['gpt-test']

        # Duplicate name fails on public input, before secrets are consumed.
        fails(['add', 'glm', '--model', 'glm-test', '--stdin-secrets'], password + '\n' + glm_key + '\n', 'already exists')
        assert set(connections()) == {'glm', 'openai'}

        # Wrong password changes nothing.
        before = len(json.loads(call(['credential', 'list']).stdout)['credentials'])
        fails(['add', 'glm', '--name', 'glm-bad', '--model', 'glm-test', '--stdin-secrets'], 'wrong-password\n' + glm_key + '\n', 'INVALID_UNLOCK_CREDENTIAL')
        assert set(connections()) == {'glm', 'openai'}
        assert len(json.loads(call(['credential', 'list']).stdout)['credentials']) == before

        # Reuse a saved credential: only the password is read.
        glm_id = connections()['glm']['credential_id']
        call(['add', 'glm', '--name', 'glm-second', '--model', 'glm-test', '--credential-id', glm_id, '--stdin-secrets'], password + '\n')
        assert connections()['glm-second']['credential_id'] == glm_id
        assert len(json.loads(call(['credential', 'list']).stdout)['credentials']) == before

        # Agents discover the signed operations without a token.
        listed = call(['list']).stdout
        assert b'glm.messages' in listed

        # OAuth presets are routed to the App, generic presets need an origin.
        fails(['add', 'slack', '--stdin-secrets'], password + '\n', '--app')
        fails(['add', 'generic-bearer', '--stdin-secrets'], password + '\n' + glm_key + '\n', '--origin')

        # A vault whose trust this CLI does not hold is refused, never re-keyed.
        key_file.rename(state / 'moved-signer.p8')
        fails(['add', 'anthropic', '--model', 'claude-test', '--stdin-secrets'], password + '\n' + glm_key + '\n', 'TRUST_MISMATCH')
        assert set(connections()) == {'glm', 'openai', 'glm-second'}
        print('PASS: one-step add (trust install, save, sign, activate), trust reuse, duplicate/locked/'
              'wrong-password/OAuth/generic/trust-mismatch refusals, credential reuse, Agent discovery. '
              'Software signer (basic mode), not Secure Enclave.')
    finally:
        broker.terminate()
        broker.wait(timeout=10)
