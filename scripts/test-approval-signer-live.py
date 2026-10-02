#!/usr/bin/env python3
"""APR-08 local signer real Broker acceptance using disposable synthetic identities.

Build rekey, rekeyd, rekey-approval-sign and example p1_policy_fixture first.
Local TLS access exists only in that test fixture, never production rekeyd.
"""
import argparse
import base64
import hashlib
import http.server
import socket
import ssl
import threading
import urllib.error
import urllib.parse
import urllib.request
import json
import pathlib
import subprocess
import tempfile
import time
import uuid


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


class RelayFixture:
    """Actual HTTPS relay plus disposable fixed introspection identity fixture."""
    def __init__(self, binary, root, run, challenge, origin, identity):
        self.process = None
        self.idp = None
        self.thread = None
        try:
            self._start(binary, root, run, challenge, origin, identity)
        except BaseException:
            self.close()
            raise

    def _start(self, binary, root, run, challenge, origin, identity):
        approver = identity["approver_id"]
        self.process = None
        self.idp = None
        self.thread = None
        self.active = True
        self.calls = 0
        self.directory_active = {"operator": True, "reviewer": True}
        self.directory_token = "SYNTHETIC-SCIM-SOURCE-CANARY"
        self.root = root
        self.up = 'SYNTHETIC-RELAY-UPLOADER-CANARY'
        self.ap = 'SYNTHETIC-RELAY-APPROVER-CANARY'
        cert, key = root / 'relay-cert.pem', root / 'relay-key.pem'
        run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
             '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost',
             '-addext', 'basicConstraints=critical,CA:FALSE',
             '-keyout', key, '-out', cert])
        cert.chmod(0o600)
        key.chmod(0o600)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)
        fixture = self

        class IdP(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                assert self.headers['Authorization'] == 'Bearer ' + fixture.directory_token
                subject = self.path.removeprefix('/scim/Users/')
                assert self.path == '/scim/Users/' + subject
                assert subject in fixture.directory_active
                body = json.dumps({'schemas': ['urn:ietf:params:scim:schemas:core:2.0:User'],
                                   'id': subject, 'externalId': 'fixture-' + subject,
                                   'active': fixture.directory_active[subject]}).encode()
                self.send_response(200)
                self.send_header('Content-Type', 'application/scim+json')
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_POST(self):
                assert self.path == '/introspect'
                assert self.headers['Authorization'] == 'Basic ' + base64.b64encode(
                    b'relay-fixture:SYNTHETIC-IDP-SECRET-CANARY').decode()
                data = urllib.parse.parse_qs(self.rfile.read(int(self.headers['Content-Length'])).decode())
                assert data['token_type_hint'] == ['access_token']
                fixture.calls += 1
                sub = {fixture.up: 'operator', fixture.ap: 'reviewer'}.get(data['token'][0], 'unlisted')
                body = json.dumps({'active': fixture.active, 'iss': fixture.issuer,
                                   'aud': 'relay', 'client_id': 'human-fixture', 'token_type': 'Bearer',
                                   'sub': sub, 'iat': int(time.time()) - 1,
                                   'exp': int(time.time()) + 120}).encode()
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        self.idp = http.server.ThreadingHTTPServer(('127.0.0.1', 0), IdP)
        self.idp.socket = context.wrap_socket(self.idp.socket, server_side=True)
        self.issuer = 'https://localhost:' + str(self.idp.server_port)
        self.thread = threading.Thread(target=self.idp.serve_forever, daemon=True)
        self.thread.start()
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            port = sock.getsockname()[1]
        relay_state = root / 'relay-state'
        relay_state.mkdir(mode=0o700)
        secret = root / 'relay-idp-secret'
        secret.write_text('SYNTHETIC-IDP-SECRET-CANARY')
        secret.chmod(0o600)
        directory_token = root / 'relay-directory-token.json'
        directory_token.write_text(json.dumps({'accessToken': self.directory_token,
                                              'expiresAtMs': int(time.time() * 1000) + 300000}))
        directory_token.chmod(0o600)
        confirmed_at = int(time.time() * 1000)
        links = [
            {'sourceUserId': 'operator', 'externalId': 'fixture-operator', 'issuer': self.issuer,
             'subject': 'operator', 'adminAllowed': True, 'principalId': challenge['challenge']['principal_id'],
             'confirmedBy': 'fixture-admin', 'confirmedAtMs': confirmed_at},
            {'sourceUserId': 'reviewer', 'externalId': 'fixture-reviewer', 'issuer': self.issuer,
             'subject': 'reviewer', 'adminAllowed': False, 'principalId': str(uuid.uuid4()), 'approverId': approver,
             'publicKeySha256': hashlib.sha256(bytes.fromhex(identity['public_key'])).hexdigest(),
             'confirmedBy': 'fixture-admin', 'confirmedAtMs': confirmed_at},
        ]
        directory = {'baseUrl': self.issuer + '/scim', 'caCertificateFile': str(cert),
                     'accessTokenFile': str(directory_token), 'mappingVersion': 1,
                     'nodes': [{'nodeId': str(uuid.uuid4()), 'vaultId': challenge['challenge']['tenant_id']},
                               {'nodeId': str(uuid.uuid4()), 'vaultId': str(uuid.uuid4())}],
                     'links': links}
        config = root / 'relay-config.json'
        config.write_text(json.dumps({
            'formatVersion': 2, 'instanceId': str(uuid.uuid4()), 'endpoint': f'https://localhost:{port}/v1',
            'listenAddress': f'127.0.0.1:{port}', 'stateDir': str(relay_state),
            'tlsCertificateFile': str(cert), 'tlsKeyFile': str(key), 'idpIssuer': self.issuer,
            'introspectionUrl': self.issuer + '/introspect', 'idpCaCertificateFile': str(cert),
            'introspectionClientId': 'relay-fixture', 'introspectionClientSecretFile': str(secret),
            'personnelClientId': 'human-fixture', 'audience': 'relay',
            'tenantId': challenge['challenge']['tenant_id'], 'originPublicKey': origin['public_key'],
            'uploaderSubject': 'operator', 'approvers': [{'subject': 'reviewer', 'approverId': approver}],
            'directory': directory}))
        config.chmod(0o600)
        self.approver = approver
        self.origin_label = 'ed25519:' + origin['public_key']
        self.base = f"https://localhost:{port}/v1/requests/{challenge['challenge']['approval_request_id']}"
        self.client = urllib.request.build_opener(urllib.request.ProxyHandler({}),
            urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=cert)), NoRedirect())
        self.log_path = root / 'relay.log'
        self.log = self.log_path.open('w')
        self.process = subprocess.Popen([str(binary.resolve()), 'serve', '--config', str(config)],
                                        stdout=self.log, stderr=self.log)
        deadline = time.monotonic() + 10
        while True:
            assert self.process.poll() is None, 'relay startup failed'
            try:
                self.exchange('GET', 'receipt', self.up, code=404)
                break
            except urllib.error.URLError:
                assert time.monotonic() < deadline, 'relay startup timeout'
                time.sleep(0.025)

    def exchange(self, method, kind, token, data=None, code=200):
        headers = {'Authorization': 'Bearer ' + token}
        if method == 'PUT' and kind == 'challenge':
            headers['X-Rekey-Approver-Id'] = self.approver
        request = urllib.request.Request(self.base + '/' + kind, data=data, method=method, headers=headers)
        try:
            response = self.client.open(request, timeout=10)
        except urllib.error.HTTPError as failure:
            response = failure
        with response:
            assert response.code == code, ('relay status', response.code, code)
            body = response.read()
            if response.headers.get('X-Rekey-Sha256'):
                assert response.headers['X-Rekey-Sha256'] == hashlib.sha256(body).hexdigest()
            return body

    def inbox(self, token):
        endpoint = self.base.split('/requests/', 1)[0] + '/inbox'
        request = urllib.request.Request(endpoint, headers={'Authorization': 'Bearer ' + token})
        with self.client.open(request, timeout=10) as response:
            assert response.code == 200
            raw = response.read()
        assert len(raw) <= 16 * 1024 and b'CANARY' not in raw
        page = json.loads(raw)
        assert page['recordType'] == 'rekey.approval.inbox.v1'
        assert 'Broker revalidates at execute' in page['snapshot']
        for item in page['items']:
            assert item['sourceLabel'] == self.origin_label, 'origin pin differs from trusted Admin channel'
        return page['items']

    def close(self):
        if self.process is not None:
            self.process.terminate()
            self.process.wait(timeout=15)
            self.log.close()
            assert 'CANARY' not in self.log_path.read_text(), 'relay leaked secret canary'
        if self.idp is not None:
            self.idp.shutdown()
            self.idp.server_close()
            if self.thread is not None:
                self.thread.join(timeout=5)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bin-dir', type=pathlib.Path, required=True)
    parser.add_argument('--relay-bin', type=pathlib.Path, help='explicit actual HTTPS transport fixture mode')
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
            if arguments[:2] == ("policy", "activate"):
                target = json.loads(cli("policy", "status"))
                arguments = (*arguments, "--expected-vault-id", target["vault_id"], "--expected-trust-sha256", target["trust_sha256"])
            return run([binaries / 'rekey', '--state-dir', state, *arguments], **kwargs)

        def write(name, value):
            path = root / name
            path.write_text(json.dumps(value))
            path.chmod(0o600)
            return path

        cli('init', '--mode', 'team', '--password-stdin', stdin=proof)
        ready, hits = root / 'port', root / 'hits'
        with (root / 'broker.log').open('w') as log:
            relay = None
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
                if args.relay_bin:
                    relay = RelayFixture(args.relay_bin, root, run, challenge, origin, identity)
                    envelope = json.dumps(challenge).encode()
                    receipt = relay.exchange('PUT', 'challenge', relay.up, envelope, code=201)
                    assert json.loads(receipt)['sha256'] == hashlib.sha256(envelope).hexdigest()
                    assert relay.exchange('PUT', 'challenge', relay.up, envelope) == receipt
                    relay.exchange('PUT', 'challenge', relay.up, envelope + b' ', code=409)
                    relay.exchange('GET', 'challenge', 'unlisted', code=404)
                    tampered = json.loads(envelope)
                    tampered['signature'] = 'invalid'
                    relay.exchange('PUT', 'challenge', relay.up, json.dumps(tampered).encode(), code=409)
                    pending = [item for item in relay.inbox(relay.ap) if item['transportStatus'] in ('awaiting-review', 'transport-failed')]
                    assert len(pending) == 1, 'inbox did not uniquely expose pending request'
                    relay.base = relay.base.rsplit('/', 1)[0] + '/' + pending[0]['requestId']
                    assert pending[0]['detailPath'] == '/v1/requests/' + pending[0]['requestId'] + '/challenge'
                    challenge = json.loads(relay.exchange('GET', 'challenge', relay.ap))
                    relay.active = False
                    relay.exchange('GET', 'challenge', relay.ap, code=401)
                    relay.active = True
                request = write('request.json', {'challenge': challenge, 'content_type': 'application/json',
                                                'headers': [], 'body': body.read_text()})
                options = [request, '--policy', policy, '--trust', trust, '--action', trusted_action,
                           '--approver-id', identity['approver_id'], '--origin-key', origin['public_key']]
                review = json.loads(run([binaries / 'rekey-approval-sign', 'review', *options]))
                grant = root / 'grant.json'
                run([binaries / 'rekey-approval-sign', 'sign', *options, '--reviewed-sha256',
                     review['reviewed_sha256'], '--key-file', key, '--output', grant])

                if relay:
                    original_grant = grant.read_bytes()
                    fake = json.loads(original_grant)
                    fake['signature'] = 'invalid'
                    relay.exchange('PUT', 'grant', relay.ap, json.dumps(fake).encode(), code=201)
                    transported_fake = root / 'transported-fake-grant.json'
                    transported_fake.write_bytes(relay.exchange('GET', 'grant', relay.up))
                    transported_fake.chmod(0o600)
                    cli('execute', ref, '--capability', '-', '--body-file', body,
                        '--content-type', 'application/json', '--approval', transported_fake, stdin=token, code=4)
                    assert int(hits.read_text()) == 0, 'transported fake signature reached upstream'
                    # Immutable file cannot be replaced, so prepare/review/sign a new request.
                    relay.exchange('PUT', 'grant', relay.ap, original_grant, code=409)
                    challenge = json.loads(cli('approval', 'prepare', ref, '--capability', '-',
                        '--body-file', body, '--content-type', 'application/json', stdin=token))
                    relay.base = relay.base.rsplit('/', 1)[0] + '/' + challenge['challenge']['approval_request_id']
                    envelope = json.dumps(challenge).encode()
                    relay.exchange('PUT', 'challenge', relay.up, envelope, code=201)
                    pending = [item for item in relay.inbox(relay.ap) if item['transportStatus'] in ('awaiting-review', 'transport-failed')]
                    assert len(pending) == 1, 'inbox did not uniquely expose pending request'
                    relay.base = relay.base.rsplit('/', 1)[0] + '/' + pending[0]['requestId']
                    assert pending[0]['detailPath'] == '/v1/requests/' + pending[0]['requestId'] + '/challenge'
                    challenge = json.loads(relay.exchange('GET', 'challenge', relay.ap))
                    request = write('request2.json', {'challenge': challenge, 'content_type': 'application/json',
                                                    'headers': [], 'body': body.read_text()})
                    options[0] = request
                    review = json.loads(run([binaries / 'rekey-approval-sign', 'review', *options]))
                    grant = root / 'grant2.json'
                    run([binaries / 'rekey-approval-sign', 'sign', *options, '--reviewed-sha256',
                         review['reviewed_sha256'], '--key-file', key, '--output', grant])
                    original_grant = grant.read_bytes()
                    receipt = relay.exchange('PUT', 'grant', relay.ap, original_grant, code=201)
                    assert relay.exchange('PUT', 'grant', relay.ap, original_grant) == receipt
                    grant = root / 'transported-grant.json'
                    delivered = [item for item in relay.inbox(relay.up)
                                 if item['requestId'] == challenge['challenge']['approval_request_id']]
                    assert len(delivered) == 1 and delivered[0]['transportStatus'] == 'grant-stored'
                    relay.base = relay.base.rsplit('/', 1)[0] + '/' + delivered[0]['requestId']
                    grant.write_bytes(relay.exchange('GET', 'grant', relay.up))
                    grant.chmod(0o600)
                    assert grant.read_bytes() == original_grant
                    assert relay.calls >= 15, 'fresh introspection missing'
                    print('PASS: authenticated pull inbox discovered request IDs over real HTTPS; relay transported origin envelope and immutable grants; fresh revocation/cross-subject/conflict denied; fake grant transported but real Broker rejected')

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
                if relay:
                    relay.close()
                broker.terminate()
                broker.wait(timeout=15)
    print('PASS: disposable state, keys and fixture process cleaned up')


if __name__ == '__main__':
    main()
