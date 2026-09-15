#!/usr/bin/env python3
"""Real CLI contract with synthetic secrets only; no real vault/provider access."""
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import time

binary = Path(sys.argv[1]).resolve()
with tempfile.TemporaryDirectory(prefix='rk-human-') as root:
    state = Path(root) / 'vault'
    password = 'synthetic-human-vault-password'
    canary = 'synthetic-glm-key-canary'
    def call(args, body='', ok=True):
        result = subprocess.run([str(binary), '--state-dir', str(state), *args],
                                input=body.encode(), capture_output=True, timeout=30)
        if ok and result.returncode:
            raise RuntimeError(result.stderr.decode())
        if not ok:
            assert result.returncode != 0, args
            assert not result.stdout, 'failure returned stdout'
        return result.stdout
    call(['init', '--password-stdin'], password + '\n')
    broker = subprocess.Popen([str(binary.parent / 'rekeyd'), 'serve', '--state-dir', str(state)],
                              stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL)
    try:
        for _ in range(40):
            if (state / 'runtime/admin.sock').exists():
                break
            time.sleep(.1)
        old = json.loads(call(['unlock', '--password-stdin'], password+'\n'))
        existing = json.loads(call(['credential', 'add', 'previously saved', '--stdin-secrets'], password+'\n'+canary+'\n'))
        token = call(['desktop-login'], password+'\n').decode()
        assert len(token) == 64
        for name in ['GLM personal', 'GLM work']:
            item = json.loads(call(['desktop-add', name], token+'\n'+canary+'\n'))
            assert call(['desktop-reveal', item['id']], token+'\n') == canary.encode()
        assert call(['desktop-reveal', existing['id']], token+'\n') == canary.encode()
        call(['desktop-reveal', existing['id']], 'forged-token\n', ok=False)
        audit = call(['audit', 'list'])
        assert canary.encode() not in audit and token.encode() not in audit
        call(['lock'])
        call(['desktop-reveal', existing['id']], token+'\n', ok=False)
        fresh = call(['desktop-login'], password+'\n').decode()
        call(['desktop-reveal', existing['id']], token+'\n', ok=False)
        # Fail the durable audit before decryption/release: no value may reach stdout.
        db = sqlite3.connect(state/'vault.sqlite3')
        db.execute("CREATE TRIGGER fail_human_audit BEFORE INSERT ON audit_events BEGIN SELECT RAISE(ABORT, 'test audit unavailable'); END")
        db.commit()
        db.close()
        call(['desktop-reveal', existing['id']], fresh+'\n', ok=False)
        assert json.loads(call(['status']))['state'] == 'faulted'
        print('PASS: existing/new keys, repeated saves, body-only reveal, forged/locked/stale denial, audit canaries, audit failure closes without plaintext')
    finally:
        broker.terminate()
        broker.wait(timeout=10)
