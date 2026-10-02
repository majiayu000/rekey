#!/usr/bin/env python3
"""AUD-08 synthetic S3 protocol and durable receipt tests; no AWS account needed."""
import base64
import contextlib
import hashlib
import http.server
import importlib.util
import io
import multiprocessing
import os
from pathlib import Path
import socket
import ssl
import subprocess
import tempfile
import time
import types
import unittest
from unittest import mock
import urllib.parse
import uuid

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('archive', ROOT / 'scripts/rekey-audit-archive.py')
A = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(A)
D = A.delivery
SECRETS = ('synthetic-access-id-canary-947', 'synthetic-secret-key-canary-835', 'synthetic-sts-token-canary-613')


def private(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(data)


class S3:
    def __init__(self):
        self.calls = []
        self.object = None
        self.mode = 'normal'
        self.version = 'synthetic-version-1'

    def __call__(self, host, method, path, query, body, headers, timeout):
        self.calls.append((method, query, bytes(body), dict(headers)))
        assert host == 'rekey-test-bucket.s3.us-east-1.amazonaws.com'
        assert headers['x-amz-expected-bucket-owner'] == '123456789012'
        assert headers['x-amz-security-token'] == SECRETS[2]
        assert headers['x-amz-content-sha256'] == hashlib.sha256(body).hexdigest()
        assert headers['authorization'].startswith('AWS4-HMAC-SHA256 Credential=' + SECRETS[0] + '/')
        parameters = dict(urllib.parse.parse_qsl(query, keep_blank_values=True))
        if 'versionId' in parameters:
            assert parameters['versionId'] == self.version
        request_headers = {'x-amz-request-id': 'synthetic-s3-request-' + str(len(self.calls))}
        if method == 'PUT' and 'legal-hold' not in parameters:
            assert headers['if-none-match'] == '*'
            assert headers['x-amz-sdk-checksum-algorithm'] == 'SHA256'
            assert headers['x-amz-checksum-sha256'] == base64.b64encode(hashlib.sha256(body).digest()).decode()
            assert headers['x-amz-server-side-encryption'] == 'AES256'
            if self.mode in ('denied', 'redirect', 'conflict'):
                return {'denied': 403, 'redirect': 307, 'conflict': 409}[self.mode], {}, b''
            self.object = {'body': body, 'mode': headers['x-amz-object-lock-mode'],
                           'until': headers['x-amz-object-lock-retain-until-date'],
                           'hold': headers['x-amz-object-lock-legal-hold']}
            if self.mode == 'lost-upload':
                raise A.Error('network-failure')
            if self.mode == 'collision':
                return 412, {}, b''
            return 200, dict(request_headers, **{'x-amz-version-id': self.version}), b''
        if self.object is None:
            return 404, {}, b''
        if method == 'HEAD':
            result = dict(request_headers, **{
                'x-amz-version-id': self.version, 'x-amz-checksum-type': 'FULL_OBJECT',
                'x-amz-checksum-sha256': base64.b64encode(hashlib.sha256(self.object['body']).digest()).decode(),
                'content-length': str(len(self.object['body'])), 'x-amz-server-side-encryption': 'AES256'})
            return 200, result, b''
        if method == 'GET' and 'retention' in parameters:
            return 200, request_headers, ('<Retention xmlns="' + A.NS + '"><Mode>' + self.object['mode'] + '</Mode><RetainUntilDate>' + self.object['until'] + '</RetainUntilDate></Retention>').encode()
        if 'legal-hold' in parameters:
            if method == 'PUT':
                assert headers['content-md5'] == base64.b64encode(hashlib.md5(body, usedforsecurity=False).digest()).decode()
                value = A.xml_values(body, 'LegalHold', ['Status'])['Status']
                self.object['hold'] = value
                if self.mode == 'lost-hold':
                    raise A.Error('network-failure')
                return 200, request_headers, b''
            return 200, request_headers, ('<LegalHold xmlns="' + A.NS + '"><Status>' + self.object['hold'] + '</Status></LegalHold>').encode()
        raise AssertionError('unexpected operation')


class ArchiveTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.profile = dict(format_version=1, purpose='archive', bucket='rekey-test-bucket', region='us-east-1',
                            expected_bucket_owner='123456789012', prefix='audit/frozen',
                            source_instance_id=str(uuid.uuid4()), vault_id=str(uuid.uuid4()), operator_label='operator-test',
                            access_key_id=SECRETS[0], secret_access_key=SECRETS[1], session_token=SECRETS[2],
                            expires_at_ms=A.now_ms() + 300000)
        self.profile_path = self.root / 'profile.json'
        private(self.profile_path, A.encode(self.profile))
        header = dict(record_type='rekey.audit.export.v2', schema='rekey.audit.v2', snapshot_max_sequence=2,
                      created_at_ms=A.now_ms(), **{k: None for k in D.FILTERS})
        raw = b''.join(A.encode(value) for value in [header, dict(record_type='rekey.audit.v2', sequence=2),
                   dict(record_type='rekey.audit.v2', sequence=1), dict(record_type='rekey.audit.export.complete.v2', row_count=2)])
        self.batch = dict(record_type='rekey.audit.delivery.batch.v1', batch_id=str(uuid.uuid4()),
                          source_instance_id=self.profile['source_instance_id'], vault_id=self.profile['vault_id'],
                          first_sequence=1, last_sequence=2, snapshot_max_sequence=2, row_count=2,
                          sha256_hex=hashlib.sha256(raw).hexdigest(), created_at_ms=A.now_ms(), export_jsonl=raw.decode())
        self.batch_path = self.root / 'batch.json'
        private(self.batch_path, A.encode(self.batch))
        self.state = self.root / 'state'
        self.until = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(time.time() + 86400))
        self.s3 = S3()

    def box(self, create=False):
        box = A.Journal(self.state, create=create)
        self.addCleanup(box.close)
        return box

    def archive(self, box, transport=None, **kwargs):
        return A.archive(box, self.profile, self.batch_path, kwargs.get('mode', 'COMPLIANCE'),
                         kwargs.get('until', self.until), kwargs.get('hold', 'ON'), transport=transport or self.s3)

    def no_secrets(self):
        for path in self.state.iterdir():
            raw = path.read_bytes()
            for secret in SECRETS:
                for form in (secret.encode(), base64.b64encode(secret.encode()), secret.encode().hex().encode(), hashlib.sha256(secret.encode()).hexdigest().encode()):
                    self.assertNotIn(form, raw)

    def test_public_aws_sigv4_vector(self):
        # AWS's documented example credentials are public test vectors, not live keys.
        profile = dict(region='us-east-1', access_key_id='AKIAIOSFODNN7EXAMPLE',
                       secret_access_key='wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY', session_token='')
        signed = A.sign_headers(profile, 'GET', 'examplebucket.s3.amazonaws.com', '/test.txt', '', b'',
                                {'range': 'bytes=0-9'}, '20130524T000000Z')
        self.assertTrue(signed['authorization'].endswith('Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41'))

    def test_archive_readback_and_exact_version(self):
        box = self.box(create=True)
        receipt = self.archive(box)
        self.assertEqual(receipt['status'], 'verified-readback')
        self.assertEqual(receipt['legal_hold'], 'ON')
        self.assertEqual([c[0] for c in self.s3.calls], ['PUT', 'HEAD', 'GET', 'GET'])
        self.assertEqual(box.read('receipt.json'), receipt)
        for method, query, _, _ in self.s3.calls[1:]:
            self.assertIn('versionId=synthetic-version-1', query)
        self.assertEqual(self.s3.calls[0][2], A.encode(self.batch))
        self.no_secrets()

    def test_lost_upload_response_restart_only_reads_same_object(self):
        self.s3.mode = 'lost-upload'
        box = self.box(create=True)
        with self.assertRaisesRegex(A.Error, 'network-failure'):
            self.archive(box)
        self.assertFalse(box.exists('receipt.json'))
        box.close()
        self.s3.mode = 'normal'
        receipt = self.archive(self.box())
        self.assertEqual(receipt['version_id'], self.s3.version)
        self.assertEqual(sum(c[0] == 'PUT' for c in self.s3.calls), 1)

    def test_intent_before_first_send_can_resume_conditional_put(self):
        box = self.box(create=True)
        with self.assertRaisesRegex(A.Error, 'before-send'):
            self.archive(box, lambda *args: (_ for _ in ()).throw(A.Error('before-send')))
        box.close()
        self.archive(self.box())
        self.assertEqual([c[0] for c in self.s3.calls], ['HEAD', 'PUT', 'HEAD', 'GET', 'GET'])

    def test_recovered_version_stays_pinned_when_retention_readback_fails(self):
        self.s3.mode = 'lost-upload'
        box = self.box(create=True)
        with self.assertRaises(A.Error): self.archive(box)
        box.close()
        box = self.box()
        def unavailable(*args):
            if args[1] == 'GET' and 'retention=' in args[3]:
                return 503, {}, b''
            return self.s3(*args)
        with self.assertRaisesRegex(A.Error, 'retention-readback-failed'):
            self.archive(box, unavailable)
        self.assertEqual(box.read('version.json')['version_id'], self.s3.version)
        self.assertFalse(box.exists('receipt.json'))
        box.close()
        self.s3.mode = 'normal'
        self.archive(self.box())
        heads = [c for c in self.s3.calls if c[0] == 'HEAD']
        self.assertEqual(len(heads), 2)
        self.assertEqual(heads[0][1], '')
        self.assertIn('versionId=synthetic-version-1', heads[1][1])

    def test_same_412_object_is_verified_and_different_bytes_fail(self):
        self.s3.mode = 'collision'
        self.assertEqual(self.archive(self.box(create=True))['version_id'], self.s3.version)

    def test_wrong_readback_each_binding_fails_without_receipt(self):
        cases = ('version', 'checksum', 'length', 'checksum-type', 'encryption', 'mode', 'until', 'hold')
        for case in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                box = A.Journal(Path(directory).resolve() / 'state', create=True)
                fake = S3()
                def changed(*args):
                    code, headers, body = fake(*args)
                    if args[1] == 'HEAD':
                        if case == 'version': headers['x-amz-version-id'] = 'wrong-version'
                        if case == 'checksum': headers['x-amz-checksum-sha256'] = 'wrong'
                        if case == 'length': headers['content-length'] = '0'
                        if case == 'checksum-type': headers['x-amz-checksum-type'] = 'COMPOSITE'
                        if case == 'encryption': headers['x-amz-server-side-encryption'] = 'wrong'
                    if case in ('mode', 'until', 'hold') and fake.object:
                        fake.object[case] = {'mode': 'GOVERNANCE', 'until': '2099-01-01T00:00:00Z', 'hold': 'OFF'}[case]
                    return code, headers, body
                try:
                    with self.assertRaises(A.Error): self.archive(box, changed)
                    self.assertFalse(box.exists('receipt.json'))
                finally:
                    box.close()

    def test_no_retry_on_denied_redirect_or_conflict(self):
        for mode in ('denied', 'redirect', 'conflict'):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as directory:
                box = A.Journal(Path(directory).resolve() / 'state', create=True)
                fake = S3()
                fake.mode = mode
                try:
                    with self.assertRaisesRegex(A.Error, 'upload-result-unknown'): self.archive(box, fake)
                    self.assertEqual(len(fake.calls), 1)
                    self.assertFalse(box.exists('receipt.json'))
                finally: box.close()

    def test_identity_and_intent_conflicts_do_not_send(self):
        box = self.box(create=True)
        self.archive(box)
        calls = len(self.s3.calls)
        with self.assertRaisesRegex(A.Error, 'archive-intent-conflict'):
            self.archive(box, mode='GOVERNANCE')
        changed = dict(self.profile, expected_bucket_owner='987654321098')
        with self.assertRaisesRegex(A.Error, 'archive-target-mismatch'):
            A.verify(box, changed, transport=self.s3)
        self.assertEqual(len(self.s3.calls), calls)

    def test_wrong_source_filtered_and_incomplete_batch_never_send(self):
        for change in ('source', 'filtered', 'trailer', 'digest'):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as directory:
                batch = dict(self.batch)
                if change == 'source': batch['source_instance_id'] = str(uuid.uuid4())
                if change == 'digest': batch['sha256_hex'] = 'a' * 64
                if change in ('filtered', 'trailer'):
                    rows = [A.decode(line) for line in batch['export_jsonl'].splitlines()]
                    if change == 'filtered': rows[0]['outcome'] = 'success'
                    else: rows.pop()
                    batch['export_jsonl'] = ''.join(A.encode(row).decode() for row in rows)
                path = Path(directory).resolve() / 'bad.json'
                private(path, A.encode(batch))
                box = A.Journal(Path(directory).resolve() / 'state', create=True)
                try:
                    with self.assertRaises(A.Error):
                        A.archive(box, self.profile, path, 'COMPLIANCE', self.until, 'ON', transport=self.s3)
                    self.assertFalse(box.exists('plan.json'))
                finally: box.close()
        self.assertEqual(self.s3.calls, [])

    def test_legal_hold_separate_role_exact_version_and_lost_response(self):
        box = self.box(create=True)
        self.archive(box)
        operation = str(uuid.uuid4())
        with self.assertRaisesRegex(A.Error, 'wrong-identity-purpose'):
            A.legal_hold(box, self.profile, operation, 'OFF', transport=self.s3)
        profile = dict(self.profile, purpose='legal-hold', operator_label='hold-manager')
        self.s3.mode = 'lost-hold'
        with self.assertRaisesRegex(A.Error, 'network-failure'):
            A.legal_hold(box, profile, operation, 'OFF', transport=self.s3)
        box.close()
        self.s3.mode = 'normal'
        box = self.box()
        result = A.legal_hold(box, profile, operation, 'OFF', transport=self.s3)
        self.assertEqual((result['before']['legal_hold'], result['after']['legal_hold']), ('ON', 'OFF'))
        writes = [c for c in self.s3.calls if c[0] == 'PUT' and 'legal-hold=' in c[1]]
        self.assertEqual(len(writes), 1)
        self.assertIn('versionId=synthetic-version-1', writes[0][1])
        self.assertFalse(any('bypass' in name for c in self.s3.calls for name in c[3]))
        self.assertEqual(A.legal_hold(box, profile, operation, 'OFF', transport=self.s3), result)
        with self.assertRaisesRegex(A.Error, 'hold-intent-conflict'):
            A.legal_hold(box, profile, operation, 'ON', transport=self.s3)
        self.no_secrets()

    def test_verify_reports_changed_hold_without_claiming_old_on(self):
        box = self.box(create=True)
        self.archive(box)
        self.s3.object['hold'] = 'OFF'
        result = A.verify(box, self.profile, transport=self.s3)
        self.assertEqual(result['legal_hold'], 'OFF')
        self.assertEqual(box.read('receipt.json')['legal_hold'], 'ON')

    def test_expiry_before_and_after_io_fails_closed(self):
        box = self.box(create=True)
        expired = dict(self.profile, expires_at_ms=1)
        with self.assertRaisesRegex(A.Error, 'identity-expired'):
            A.archive(box, expired, self.batch_path, 'COMPLIANCE', self.until, 'ON', transport=self.s3)
        self.assertEqual(self.s3.calls, [])
        def expiry(*args):
            result = self.s3(*args)
            self.profile['expires_at_ms'] = 1
            return result
        with self.assertRaisesRegex(A.Error, 'identity-expired'):
            self.archive(box, expiry)
        self.assertFalse(box.exists('receipt.json'))

    def test_credential_reflection_is_not_persisted(self):
        box = self.box(create=True)
        def reflection(*args):
            status, headers, body = self.s3(*args)
            headers['x-amz-version-id'] = base64.b64encode(SECRETS[2].encode()).decode()
            return status, headers, body
        with self.assertRaisesRegex(A.Error, 'credential-reflection'):
            self.archive(box, reflection)
        self.assertFalse(box.exists('version.json'))
        self.no_secrets()

    def test_private_files_symlinks_duplicates_and_profile_target_limits(self):
        self.assertEqual(A.load_profile(self.profile_path), self.profile)
        link = self.root / 'link.json'
        link.symlink_to(self.profile_path)
        with self.assertRaises(OSError): A.load_profile(link)
        self.profile_path.chmod(0o644)
        with self.assertRaises(A.Error): A.load_profile(self.profile_path)
        self.profile_path.chmod(0o600)
        for key, value in [('region', 'us-gov-west-1'), ('bucket', 'example.com'), ('prefix', '../escape'),
                           ('expected_bucket_owner', 'wrong'), ('format_version', True), ('endpoint', 'http://localhost')]:
            profile = dict(self.profile, **{key: value})
            path = self.root / (str(uuid.uuid4()) + '.json')
            private(path, A.encode(profile))
            with self.assertRaises(A.Error): A.load_profile(path)
        duplicate = self.root / 'duplicate.json'
        private(duplicate, b'{"format_version":1,"format_version":1}')
        with self.assertRaisesRegex(A.Error, 'invalid-json'): A.load_profile(duplicate)

    def test_exclusive_lock_and_parent_replacement(self):
        box = self.box(create=True)
        with self.assertRaises(OSError): A.Journal(self.state)
        self.state.rename(self.root / 'old-state')
        self.state.mkdir(mode=0o700)
        with self.assertRaisesRegex(A.Error, 'path-replaced'): self.archive(box)
        self.assertEqual(self.s3.calls, [])

    def test_local_fsync_failure_retains_partial_and_never_uploads(self):
        box = self.box(create=True)
        with mock.patch.object(A.os, 'fsync', side_effect=OSError('synthetic disk failure')):
            with self.assertRaises(OSError): self.archive(box)
        self.assertEqual(self.s3.calls, [])
        self.assertTrue(any(p.name.startswith('.partial-') for p in self.state.iterdir()))
        box.close()
        with self.assertRaisesRegex(A.Error, 'partial-journal-review-required'): A.Journal(self.state)

    def test_capacity_reserves_hold_terminal_receipt(self):
        box = self.box(create=True)
        self.archive(box)
        profile = dict(self.profile, purpose='legal-hold')
        original = box.verify
        def nearly_full():
            total, _ = original()
            return total, 998
        with mock.patch.object(box, 'verify', side_effect=nearly_full):
            with self.assertRaisesRegex(A.Error, 'journal-capacity'):
                A.legal_hold(box, profile, str(uuid.uuid4()), 'OFF', transport=self.s3)
        self.assertEqual(sum(c[0] == 'PUT' for c in self.s3.calls), 1)

    def test_xml_rejects_entities_duplicates_or_wrong_namespace(self):
        for data in (b'<!DOCTYPE x [<!ENTITY a "bad">]><x>&a;</x>',
                     b'<LegalHold><Status>ON</Status></LegalHold>',
                     ('<LegalHold xmlns="' + A.NS + '"><Status>ON</Status><Status>OFF</Status></LegalHold>').encode()):
            with self.assertRaises(A.Error): A.xml_values(data, 'LegalHold', ['Status'])

    def test_main_errors_do_not_expose_protected_profile_values(self):
        self.profile_path.chmod(0o644)
        error = io.StringIO()
        with contextlib.redirect_stderr(error):
            code = A.main(['archive', '--profile', str(self.profile_path), '--state', str(self.state),
                           '--batch', str(self.batch_path), '--mode', 'COMPLIANCE', '--retain-until', self.until, '--legal-hold', 'ON'])
        self.assertEqual(code, 1)
        for secret in SECRETS: self.assertNotIn(secret, error.getvalue())

    def test_whole_dns_deadline_kills_child_before_late_network(self):
        marker = self.root / 'late'
        def resolver(*args, **kwargs):
            time.sleep(0.25)
            marker.write_text('resolver continued')
            return []
        with self.assertRaisesRegex(A.Error, 'network-timeout'):
            A.request('test.example', 'PUT', '/one', '', b'x', {}, 0.03, resolver=resolver)
        time.sleep(0.3)
        self.assertFalse(marker.exists())

    def test_private_or_mixed_dns_results_never_connect(self):
        for addresses in (['127.0.0.1'], ['1.1.1.1', '10.0.0.1'], ['::1']):
            def resolve(*args, **kwargs):
                return [(socket.AF_INET6 if ':' in ip else socket.AF_INET, socket.SOCK_STREAM, 6, '', (ip, 443)) for ip in addresses]
            with self.assertRaisesRegex(A.Error, 'non-public-endpoint'):
                A.request('test.example', 'PUT', '/one', '', b'x', {}, 1, resolver=resolve)


class TLSArchiveTests(unittest.TestCase):
    setUp = ArchiveTests.setUp
    box = ArchiveTests.box
    archive = ArchiveTests.archive
    no_secrets = ArchiveTests.no_secrets

    def test_real_tls_signed_requests_and_proxy_ignored(self):
        cert, key = self.root / 'cert.pem', self.root / 'key.pem'
        host = 'rekey-test-bucket.s3.us-east-1.amazonaws.com'
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                        '-keyout', str(key), '-out', str(cert), '-subj', '/CN=' + host,
                        '-addext', 'subjectAltName=DNS:' + host], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        key.chmod(0o600)
        fixture = self.s3
        context = multiprocessing.get_context('fork')
        count = context.Value('i', 0)
        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = 'HTTP/1.1'
            def log_message(self, *args): pass
            def operate(self):
                parsed = urllib.parse.urlsplit(self.path)
                body = self.rfile.read(int(self.headers.get('Content-Length', 0)))
                headers = {k.lower(): v for k, v in self.headers.items()}
                status, result, response = fixture(host, self.command, parsed.path, parsed.query, body, headers, 2)
                count.value += 1
                self.send_response(status)
                for k, v in result.items(): self.send_header(k, v)
                if self.command != 'HEAD': self.send_header('Content-Length', str(len(response)))
                self.send_header('Connection', 'close')
                self.end_headers()
                if self.command != 'HEAD': self.wfile.write(response)
            do_PUT = do_GET = do_HEAD = operate
        server = http.server.HTTPServer(('127.0.0.1', 0), Handler)
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.load_cert_chain(cert, key)
        server.socket = tls.wrap_socket(server.socket, server_side=True)
        process = context.Process(target=server.serve_forever)
        process.start()
        self.addCleanup(process.join, 3)
        self.addCleanup(process.terminate)
        self.addCleanup(server.server_close)
        client = ssl.create_default_context(cafile=str(cert))
        def resolver(*args, **kwargs):
            return socket.getaddrinfo('127.0.0.1', server.server_port, type=socket.SOCK_STREAM)
        def transport(*args):
            # The custom CA and post-screen loopback substitution exist only in this test.
            with mock.patch.object(A.ipaddress, 'ip_address', return_value=types.SimpleNamespace(is_global=True)):
                return A.request(*args, context=client, resolver=resolver)
        with mock.patch.dict(os.environ, {'HTTPS_PROXY': 'http://127.0.0.1:1', 'HTTP_PROXY': 'http://127.0.0.1:1'}):
            receipt = self.archive(self.box(create=True), transport)
        self.assertEqual(receipt['version_id'], self.s3.version)
        self.assertEqual(count.value, 4)
        self.no_secrets()


if __name__ == '__main__':
    unittest.main(verbosity=2)
