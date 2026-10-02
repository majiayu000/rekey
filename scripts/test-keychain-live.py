#!/usr/bin/env python3
"""Real disposable macOS file-Keychain source through Broker/CLI and local TLS."""
import argparse
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import tempfile
import time
import uuid

ROOT = Path(__file__).resolve().parent.parent
SWIFT = r'''
import Foundation
import Security
func checked(_ value: OSStatus) throws {
    if value != errSecSuccess { throw NSError(domain: "Keychain fixture", code: Int(value)) }
}
let mode = CommandLine.arguments[1], path = CommandLine.arguments[2]
try checked(SecKeychainSetUserInteractionAllowed(false))
var keychain: SecKeychain?
if mode == "create" {
    let password = Array(readLine()!.utf8), secret = Data(readLine()!.utf8)
    try password.withUnsafeBytes { bytes in
        try checked(SecKeychainCreate(path, UInt32(bytes.count), bytes.baseAddress, false, nil, &keychain))
    }
    var trusted: SecTrustedApplication?, myself: SecTrustedApplication?, access: SecAccess?
    try checked(SecTrustedApplicationCreateFromPath(CommandLine.arguments[3], &trusted))
    try checked(SecTrustedApplicationCreateFromPath(nil, &myself))
    try checked(SecAccessCreate("Rekey disposable test" as CFString, [trusted!, myself!] as CFArray, &access))
    try checked(SecItemAdd([
        kSecClass: kSecClassGenericPassword, kSecAttrService: "Rekey.QA.Source",
        kSecAttrAccount: "exact.account", kSecValueData: secret,
        kSecUseKeychain: keychain!, kSecAttrAccess: access!
    ] as CFDictionary, nil))
} else {
    try checked(SecKeychainOpen(path, &keychain))
    if mode == "lock" { try checked(SecKeychainLock(keychain)) }
    else if mode == "delete" { try checked(SecKeychainDelete(keychain)) }
    else { fatalError("unknown fixture operation") }
}
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bin-dir', type=Path, required=True)
    args = parser.parse_args()
    if sys.platform != 'darwin':
        parser.error('actual macOS Keychain is required')
    os.umask(0o077)
    binaries = args.bin_dir.resolve()
    with tempfile.TemporaryDirectory(prefix='rk-keychain-', dir='/private/tmp') as temporary:
        root = Path(temporary)
        state, keychain, helper = root / 'state', root / 'test.keychain-db', root / 'keychain-fixture'
        proof, secret = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
        broker = None

        def run(command, data=None, code=0):
            result = subprocess.run(list(map(str, command)), input=data, text=True,
                                    capture_output=True, timeout=90)
            if result.returncode != code:
                raise RuntimeError(f'fixture command failed: {Path(str(command[0])).name} exit {result.returncode}')
            return result.stdout

        def cli(*arguments, data=None, code=0):
            return run([binaries / 'rekey', '--state-dir', state, *arguments], data, code)

        def write(name, value):
            path = root / name
            path.write_text(json.dumps(value))
            return path

        try:
            source = root / 'keychain.swift'
            source.write_text(SWIFT)
            run(['xcrun', 'swiftc', '-framework', 'Security', source, '-o', helper])
            fixture = binaries / 'examples/p1_policy_fixture'
            run([helper, 'create', keychain, fixture], secrets.token_urlsafe(32) + '\n' + secret + '\n')
            cli('init', '--password-stdin', data=proof + '\n')
            with (root / 'broker.log').open('w') as log:
                broker = subprocess.Popen([str(fixture), str(state), str(root / 'ready'), str(root / 'hits')],
                                          stdout=log, stderr=log)
            deadline = time.monotonic() + 15
            while not (root / 'ready').exists() or not (state / 'runtime/admin.sock').exists():
                if broker.poll() is not None or time.monotonic() >= deadline:
                    raise RuntimeError('broker readiness failed')
                time.sleep(.05)
            cli('unlock', '--password-stdin', data=proof + '\n')
            profile = write('source.json', dict(credential_type='macos-keychain-source-v1',
                keychain_path=str(keychain), service='Rekey.QA.Source', account='exact.account',
                reference_expires_at_ms=int(time.time() * 1000) + 300000))
            credential = json.loads(cli('credential', 'add-macos-keychain', 'native-source', '--file',
                                        str(profile), '--password-stdin', data=proof + '\n'))
            definition = write('action.json', dict(name='keychain-source', credential_id=credential['id'],
                origin='https://api.test.local', method='POST', exact_path='/v1/sealing',
                auth_header='authorization', auth_prefix='Bearer ', timeout_ms=10000,
                request_max_bytes=4096, allowed_extra_headers=[], response_max_bytes=4096,
                allowed_response_headers=['content-type']))
            action = json.loads(cli('action', 'create', '--file', str(definition), '--password-stdin', data=proof + '\n'))
            reference = action['id'] + '@' + str(action['version'])
            session = json.loads(cli('session', 'create', '--action', reference, '--ttl', '10m',
                                    '--max-uses', '5', '--password-stdin', data=proof + '\n'))
            resource = dict(type='keychain-test', id=action['id'])
            snapshot = write('snapshot.json', dict(format_version=3, version=1,
                expires_at_ms=int(time.time() * 1000) + 300000, approvers=[], workload_identities=[],
                bindings=[dict(action_id=action['id'], version=action['version'], resource=resource,
                               parameter_schema_id='keychain/v1', parameter_schema={'type': 'object'})],
                rules=[dict(id=str(uuid.uuid4()), effect='permit', principal_id=session['principal_id'],
                            action_id=action['id'], version=action['version'], resource=resource,
                            parameters={'kind': 'any_validated'})]))
            run([sys.executable, ROOT / 'scripts/sign-test-policy.py', 'policy', '--key-dir', root / 'signer',
                 '--snapshot', snapshot, '--bundle', root / 'policy.json', '--trust', root / 'trust.json'])
            cli('policy', 'trust', 'install', '--file', str(root / 'trust.json'), '--step-up-stdin', data=proof + '\n')
            target = json.loads(cli('policy', 'status'))
            cli('policy', 'activate', '--file', str(root / 'policy.json'), '--expected-vault-id', target['vault_id'],
                '--expected-trust-sha256', target['trust_sha256'], '--step-up-stdin', data=proof + '\n')
            body = write('body.json', {'mode': 'clean'})
            execute = ['execute', reference, '--capability', '-', '--body-file', str(body), '--content-type', 'application/json']
            response = cli(*execute, data=session['capability_token'] + '\n')
            assert '"upstream_status": 200' in response and secret not in response
            write('body.json', {'mode': 'raw'})
            cli(*execute, data=session['capability_token'] + '\n', code=8)
            assert (root / 'hits').read_text().strip() == '2'
            print('PASS: actual Keychain source and reflected-value denial', flush=True)
            run([helper, 'lock', keychain])
            # This must return without any native prompt or additional upstream effect.
            denied = subprocess.run([str(binaries / 'rekey'), '--state-dir', str(state), *execute],
                input=session['capability_token'] + '\n', text=True, capture_output=True, timeout=15)
            assert denied.returncode == 4 and 'error [CREDENTIAL_UNAVAILABLE]:' in denied.stderr, (
                f'locked Keychain did not return its typed denial (exit {denied.returncode})')
            assert (root / 'hits').read_text().strip() == '2'
            audit = cli('audit', 'list', '--limit', '100')
            assert secret not in audit and proof not in audit and session['capability_token'] not in audit
            events = json.loads(audit)['events']
            assert any(e['event_type'] == 'credential.source.finished' and e['outcome'] == 'failure' for e in events)
            print('PASS: actual file-Keychain source -> Broker/TLS; reflected secret sealed; locked keychain denied without UI/effect; audit canaries absent')
        finally:
            try:
                if broker is not None:
                    broker.terminate()
                    try:
                        broker.wait(timeout=15)
                    except subprocess.TimeoutExpired as error:
                        broker.kill()
                        broker.wait(timeout=15)
                        raise RuntimeError('Broker did not shut down gracefully') from error
            finally:
                if keychain.exists():
                    run([helper, 'delete', keychain])
                    assert not keychain.exists()
    print('PASS: disposable Keychain, broker and private artifacts removed')


if __name__ == '__main__':
    main()
