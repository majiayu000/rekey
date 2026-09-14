#!/usr/bin/env python3
"""APR-08 local signer real Broker acceptance using disposable synthetic identities.

Build rekey, rekeyd, rekey-approval-sign and example p1_policy_fixture first.
Local TLS access exists only in that test fixture, never production rekeyd.
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
    parser.add_argument('--bin-dir', type=pathlib.Path, required=True)
    args = parser.parse_args()
    binaries = args.bin_dir.resolve()
    test_signer = pathlib.Path(__file__).resolve().with_name('sign-test-policy.py')
    with tempfile.TemporaryDirectory(prefix='rkapr-', dir='/tmp') as temporary:
        root = pathlib.Path(temporary)
        state = root / 'state'
        proof = 'synthetic approval acceptance proof\n'

        def run(command, stdin=None, code=0):
            result = subprocess.run(list(map(str, command)), input=stdin, text=True,
                                    capture_output=True, timeout=30, check=False)
            assert result.returncode == code, (result.returncode, result.stderr)
            return result.stdout

        def cli(*arguments, **kwargs):
            return run([binaries / 'rekey', '--state-dir', state, *arguments], **kwargs)

        def write(name, value):
            path = root / name
            path.write_text(json.dumps(value))
            path.chmod(0o600)
            return path

        cli('init', '--password-stdin', stdin=proof)
        ready, hits = root / 'port', root / 'hits'
        with (root / 'broker.log').open('w') as log:
            broker = subprocess.Popen([str(binaries / 'examples/p1_policy_fixture'),
                                       str(state), str(ready), str(hits)], stdout=log, stderr=log)
            try:
                deadline = time.monotonic() + 20
                while not ready.exists() or not (state / 'runtime/admin.sock').exists():
                    assert broker.poll() is None, 'fixture exited'
                    assert time.monotonic() < deadline, 'fixture startup timeout'
                    time.sleep(0.05)
                cli('unlock', '--password-stdin', stdin=proof)
                credential = json.loads(cli('credential', 'add', 'apr-test', '--stdin-secrets',
                                            stdin=proof + 'APR-LOCAL-SYNTHETIC-CANARY\n'))
                definition = write('definition.json', {
                    'name': 'apr-local', 'credential_id': credential['id'],
                    'origin': 'https://api.test.local:' + ready.read_text().strip(),
                    'method': 'POST', 'exact_path': '/v1/approval',
                    'auth_header': 'authorization', 'auth_prefix': 'Bearer ',
                    'timeout_ms': 10000, 'request_max_bytes': 4096,
                    'allowed_extra_headers': [], 'response_max_bytes': 4096,
                    'allowed_response_headers': ['content-type'],
                })
                action = json.loads(cli('action', 'create', '--file', definition,
                                        '--password-stdin', stdin=proof))
                trusted_action = write('trusted-action.json', action)
                ref = f"{action['id']}@{action['version']}"
                session = json.loads(cli('session', 'create', '--action', ref, '--ttl', '10m',
                                         '--max-uses', '20', '--password-stdin', stdin=proof))
                token = session['capability_token'] + '\n'
                identity = json.loads(run(['python3', test_signer, 'approval-identity',
                                           '--key-dir', root / 'approver']))
                key = root / 'approver.der'
                run(['openssl', 'pkey', '-in', root / 'approver/approver-key.pem',
                     '-outform', 'DER', '-out', key])
                key.chmod(0o600)
                resource = {'type': 'fixed-http-action', 'id': action['id']}
                snapshot = write('snapshot.json', {
                    'format_version': 3, 'version': 1,
                    'expires_at_ms': int(time.time() * 1000) + 300000,
                    'approvers': [identity], 'workload_identities': [],
                    'bindings': [{'action_id': action['id'], 'version': action['version'],
                                  'resource': resource, 'parameter_schema_id': 'apr/message',
                                  'parameter_schema': {'type': 'object', 'required': ['message'],
                                                       'properties': {'message': {'type': 'string'}},
                                                       'additionalProperties': False}}],
                    'rules': [{'id': str(uuid.uuid4()), 'effect': 'require-approval',
                               'principal_id': session['principal_id'], 'action_id': action['id'],
                               'version': action['version'], 'resource': resource,
                               'parameters': {'kind': 'any_validated'},
                               'approval': {'approver_ids': [identity['approver_id']], 'quorum': 1,
                                            'mode': 'one-time', 'max_uses': 1}}],
                })
                policy, trust = root / 'policy.json', root / 'trust.json'
                run(['python3', test_signer, 'policy', '--key-dir', root / 'policy-key',
                     '--snapshot', snapshot, '--bundle', policy, '--trust', trust])
                cli('policy', 'trust', 'install', '--file', trust, '--step-up-stdin', stdin=proof)
                cli('policy', 'activate', '--file', policy, '--step-up-stdin', stdin=proof)
                body = write('body.json', {'message': 'approved'})
                changed = write('changed.json', {'message': 'changed'})
                challenge = json.loads(cli('approval', 'prepare', ref, '--capability', '-',
                                           '--body-file', body, '--content-type', 'application/json', stdin=token))
                origin = json.loads(cli('approval', 'origin'))
                request = write('request.json', {'challenge': challenge, 'content_type': 'application/json',
                                                'headers': [], 'body': body.read_text()})
                options = [request, '--policy', policy, '--trust', trust, '--action', trusted_action,
                           '--approver-id', identity['approver_id'], '--origin-key', origin['public_key']]
                review = json.loads(run([binaries / 'rekey-approval-sign', 'review', *options]))
                grant = root / 'grant.json'
                run([binaries / 'rekey-approval-sign', 'sign', *options, '--reviewed-sha256',
                     review['reviewed_sha256'], '--key-file', key, '--output', grant])

                def execute(path, capability=token, code=0):
                    return cli('execute', ref, '--capability', '-', '--body-file', path,
                               '--content-type', 'application/json', '--approval', grant,
                               stdin=capability, code=code)

                execute(changed, code=4)
                other = json.loads(cli('session', 'create', '--action', ref, '--ttl', '10m',
                                       '--max-uses', '3', '--password-stdin', stdin=proof))
                execute(body, other['capability_token'] + '\n', code=4)
                assert int(hits.read_text()) == 0, 'rejected request reached upstream'
                assert '"ok":true' in execute(body)
                execute(body, code=4)
                assert int(hits.read_text()) == 1, 'replay reached upstream'
                print('PASS: independent signer grant accepted by real Broker; changed body, wrong session and replay denied; exactly one TLS upstream request')
            finally:
                broker.terminate()
                broker.wait(timeout=15)
    print('PASS: disposable state, keys and fixture process cleaned up')


if __name__ == '__main__':
    main()
