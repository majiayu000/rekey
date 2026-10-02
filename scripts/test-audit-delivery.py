#!/usr/bin/env python3
"""Run after cargo build -p rekey-cli -p rekey-broker; all credentials are synthetic."""
import contextlib
import hashlib
import http.server
import importlib.util
import io
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import types
import unittest
from unittest import mock
import uuid
import warnings

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('delivery', ROOT / 'scripts/rekey-audit-delivery.py')
D = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(D)
TOKEN = 'synthetic-delivery-token-canary-7b12'
PASSWORD = 'synthetic-vault-password-7b12-long'


def private_file(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(data)


def snapshot(sequences=(3, 2, 1), **changes):
    header = dict(record_type='rekey.audit.export.v2', schema='rekey.audit.v2',
                  snapshot_max_sequence=max(sequences), created_at_ms=1, **{field: None for field in D.FILTERS})
    header.update(changes)
    records = [header] + [dict(record_type='rekey.audit.v2', sequence=sequence) for sequence in sequences]
    records.append(dict(record_type='rekey.audit.export.complete.v2', row_count=len(sequences)))
    return b''.join(D.encode(record) for record in records)


class DeliveryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.source, self.vault = str(uuid.uuid4()), str(uuid.uuid4())
        self.path = self.root / 'outbox'
        self.receipt = self.root / 'receipt.json'
        private_file(self.receipt, D.encode(dict(vault_id=self.vault, format_version=21,
                     created_at_ms=1, sha256_hex='a' * 64, output_path='synthetic.backup',
                     snapshot_cut=dict(audit_sequence=27, policy=None))))
        self.args = ['--outbox', str(self.path), '--source-instance-id', self.source, '--vault-id', self.vault]
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(D.main(self.args + ['init', '--vault-receipt', str(self.receipt),
                                                '--endpoint', 'https://example.com/audit']), 0)

    def box(self):
        box = D.Outbox(self.path, self.source, self.vault)
        self.addCleanup(box.close)
        return box

    def queued(self, data=None):
        export = self.root / ('export-%s.jsonl' % uuid.uuid4())
        private_file(export, snapshot() if data is None else data)
        box = self.box()
        return box, D.enqueue(box, str(export))

    def test_complete_ack_and_continued_full_snapshot(self):
        box, batch = self.queued()
        self.assertEqual(D.send(box, TOKEN, lambda *args: (200, D.encode(D.expected_ack(batch)))), 3)
        self.assertEqual(box.journal()[:2], (3, None))
        box.close()
        box = self.box()
        path = self.root / 'next.jsonl'
        private_file(path, snapshot((5, 4, 3, 2, 1)))
        next_batch = D.enqueue(box, str(path))
        self.assertEqual(next_batch['first_sequence'], 4)
        self.assertEqual(next_batch['row_count'], 5)
        self.assertTrue((self.path / 'batch-1.json').exists())
        self.assertTrue((self.path / 'ack-1.json').exists())

    def test_wrong_ack_all_bindings_and_types_permanent(self):
        for field in D.ACK_FIELDS + ('record_type', 'durable'):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as root:
                root = str(Path(root).resolve())
                box = D.Outbox(Path(root) / 'box', self.source, self.vault, create=True)
                try:
                    box.write('identity.json', dict(source_instance_id=self.source, vault_id=self.vault, endpoint='https://example.com/audit'))
                    box.identity = box.read('identity.json')
                    path = Path(root) / 'export'
                    private_file(path, snapshot())
                    batch = D.enqueue(box, str(path))
                    ack = D.expected_ack(batch)
                    ack[field] = False if field == 'durable' else 'wrong'
                    with self.assertRaisesRegex(D.DeliveryError, 'invalid-durable-ack'):
                        D.send(box, TOKEN, lambda *args: (200, D.encode(ack)))
                    self.assertEqual(box.journal()[0], 0)
                    with self.assertRaisesRegex(D.DeliveryError, 'permanent-failure-review-required'):
                        D.send(box, TOKEN, lambda *args: self.fail('must not send'))
                finally:
                    box.close()

    def test_missing_ack_and_http200_are_not_receipts(self):
        box, batch = self.queued()
        with self.assertRaises(D.DeliveryError):
            D.send(box, TOKEN, lambda *args: (200, b'{}'))
        self.assertEqual(box.journal()[0], 0)

    def test_deeply_nested_ack_is_permanent_and_does_not_resend(self):
        box, batch = self.queued()
        calls = []
        def malformed(*args):
            calls.append(1)
            return 200, b'[' * 20000 + b'0' + b']' * 20000
        # Python versions differ in JSON nesting limits. A parser that accepts
        # this array must still reject it as an ACK, durably and without retry.
        with self.assertRaisesRegex(D.DeliveryError, 'invalid-(json|durable-ack)$'):
            D.send(box, TOKEN, malformed)
        self.assertTrue((self.path / 'failure-1.json').exists())
        with self.assertRaisesRegex(D.DeliveryError, 'permanent-failure-review-required'):
            D.send(box, TOKEN, malformed)
        self.assertEqual(calls, [1])
        self.assertEqual(box.journal()[0], 0)

    def test_admission_reserves_durable_ack_capacity(self):
        box, batch = self.queued()
        usage = sum(path.stat().st_size for path in self.path.iterdir())
        self.assertGreater(usage, 0)
        box.close()
        # A fresh outbox with room for the batch but none for its ACK must
        # refuse admission and retain cursor zero without writing a batch.
        (self.path / 'batch-1.json').unlink()
        box = self.box()
        export = self.root / 'capacity.jsonl'
        private_file(export, snapshot())
        with mock.patch.object(D, 'MAX_OUTBOX', usage), self.assertRaisesRegex(D.DeliveryError, 'backlog-limit'):
            D.enqueue(box, str(export))
        self.assertEqual(box.journal()[:2], (0, None))

    def test_lost_ack_and_restart_replay_same_batch(self):
        box, batch = self.queued()
        seen = []
        def lost(url, body, token, timeout):
            seen.append(body)
            raise D.DeliveryError('network-failure')
        with mock.patch.object(D.time, 'sleep'), self.assertRaisesRegex(D.DeliveryError, 'network-failure'):
            D.send(box, TOKEN, lost)
        self.assertEqual(len(seen), 3)
        self.assertEqual(len(set(seen)), 1)
        box.close()
        box = self.box()
        self.assertEqual(box.journal()[1]['batch_id'], batch['batch_id'])
        def recovered(url, body, token, timeout):
            self.assertEqual(body, seen[0])
            return 200, D.encode(D.expected_ack(batch))
        self.assertEqual(D.send(box, TOKEN, recovered), 3)

    def test_pending_stops_new_reads_and_keeps_oldest(self):
        box, batch = self.queued()
        with self.assertRaisesRegex(D.DeliveryError, 'pending-batch'):
            D.enqueue(box, str(self.root / 'nonexistent'))
        self.assertEqual(box.journal()[1], batch)

    def test_partial_filters_trailers_gaps_and_regression(self):
        cases = [snapshot().rsplit(b'\n', 2)[0] + b'\n', snapshot()[:-1], snapshot(action_id='filter'),
                 snapshot((3, 1)), snapshot((3, 2)), snapshot((3, 2, 1)).replace(b'"row_count":3', b'"row_count":4'),
                 snapshot((3, 2, 1)).replace(b'"row_count":3', b'"row_count":true'),
                 snapshot((3, 2, 1)).replace(b'"snapshot_max_sequence":3', b'"snapshot_max_sequence":true'),
                 snapshot(unknown_filter='unsupported')]
        for raw in cases:
            with self.subTest(raw=raw[:30]), self.assertRaises(D.DeliveryError):
                D.export_info(raw, 0)
        with self.assertRaisesRegex(D.DeliveryError, 'regression'):
            D.export_info(snapshot(), 3)
        with self.assertRaisesRegex(D.DeliveryError, 'sequence-gap'):
            D.export_info(snapshot((6, 5)), 3)
        self.assertEqual(D.export_info(snapshot((6, 5, 4)), 3), (6, 3))
        self.assertEqual(D.export_info(snapshot((6, 5, 4, 2)), 3), (6, 4))
        self.assertEqual(D.export_info(snapshot((5, 4, 3, 1)), 3), (5, 4))

    def test_secure_files_symlinks_modes_and_fifo(self):
        path = self.root / 'input'
        private_file(path, snapshot())
        os.chmod(path, 0o644)
        with self.assertRaisesRegex(D.DeliveryError, 'unsafe-permissions'):
            D.read_external(str(path), D.MAX_EXPORT)
        link = self.root / 'link'
        link.symlink_to(path)
        with self.assertRaises(OSError):
            D.read_external(str(link), D.MAX_EXPORT)
        fifo = self.root / 'fifo'
        os.mkfifo(fifo, 0o600)
        with self.assertRaisesRegex(D.DeliveryError, 'unsafe-permissions'):
            D.read_external(str(fifo), D.MAX_EXPORT)
        parent_link = self.root / 'parent-link'
        parent_link.symlink_to(self.path)
        with self.assertRaises(OSError):
            D.Outbox(parent_link, self.source, self.vault)

    def test_outbox_mode_identity_and_concurrent_lock(self):
        with self.assertRaisesRegex(D.DeliveryError, 'identity-mismatch'):
            D.Outbox(self.path, str(uuid.uuid4()), self.vault)
        os.chmod(self.path, 0o755)
        with self.assertRaisesRegex(D.DeliveryError, 'unsafe-permissions'):
            self.box()
        os.chmod(self.path, 0o700)
        box = self.box()
        with self.assertRaises(BlockingIOError):
            self.box()
        self.assertIsNotNone(box.fd)

    def test_path_replacement_during_http_never_advances(self):
        box, batch = self.queued()
        def replaced(*args):
            self.path.rename(self.root / 'old-box')
            self.path.mkdir(mode=0o700)
            return 200, D.encode(D.expected_ack(batch))
        with self.assertRaisesRegex(D.DeliveryError, 'path-replaced'):
            D.send(box, TOKEN, replaced)
        self.assertFalse((self.root / 'old-box' / 'ack-1.json').exists())
        self.assertFalse((self.path / 'ack-1.json').exists())

    def test_lock_replacement_during_http_never_advances(self):
        box, batch = self.queued()
        def replaced(*args):
            (self.path / '.lock').rename(self.root / 'old-lock')
            private_file(self.path / '.lock', b'')
            return 200, D.encode(D.expected_ack(batch))
        with self.assertRaisesRegex(D.DeliveryError, 'path-replaced'):
            D.send(box, TOKEN, replaced)
        self.assertFalse((self.path / 'ack-1.json').exists())

    def test_file_path_replacement_during_read_is_rejected(self):
        path = self.root / 'input'
        private_file(path, snapshot())
        original = D.os.fstat
        calls = 0
        def fstat(fd):
            nonlocal calls
            info = original(fd)
            if info.st_size == len(snapshot()):
                calls += 1
                if calls == 2:
                    path.rename(self.root / 'original')
                    private_file(path, snapshot())
            return info
        with mock.patch.object(D.os, 'fstat', side_effect=fstat), self.assertRaisesRegex(D.DeliveryError, 'path-replaced'):
            D.read_external(str(path), D.MAX_EXPORT)

    def test_disk_failure_preserves_partial_and_stops_restart(self):
        box = self.box()
        with mock.patch.object(D.os, 'fsync', side_effect=OSError('synthetic ENOSPC')):
            with self.assertRaises(OSError):
                box.write('batch-1.json', {'synthetic': True})
        self.assertTrue(any(name.startswith('.partial-') for name in os.listdir(self.path)))
        box.close()
        with self.assertRaisesRegex(D.DeliveryError, 'partial-outbox-review-required'):
            self.box()

    def test_ack_directory_sync_failure_is_not_success(self):
        box, batch = self.queued()
        real = D.os.fsync
        def fsync(fd):
            if fd == box.fd:
                raise OSError('synthetic sync failure')
            return real(fd)
        with mock.patch.object(D.os, 'fsync', side_effect=fsync), self.assertRaises(OSError):
            D.send(box, TOKEN, lambda *args: (200, D.encode(D.expected_ack(batch))))
        self.assertTrue((self.path / 'ack-1.json').exists())
        box.close()
        self.assertEqual(self.box().journal()[:2], (3, None))

    def test_backlog_size_age_and_deadline_bounds_preserve(self):
        box = self.box()
        path = self.root / 'export'
        private_file(path, snapshot())
        with mock.patch.object(D, 'MAX_OUTBOX', 1), self.assertRaisesRegex(D.DeliveryError, 'backlog-limit'):
            D.enqueue(box, str(path))
        self.assertEqual(box.journal()[:2], (0, None))
        batch = D.enqueue(box, str(path))
        with mock.patch.object(D, 'MAX_AGE', -1), self.assertRaisesRegex(D.DeliveryError, 'batch-age-limit'):
            D.send(box, TOKEN, lambda *args: self.fail('expired batch'))
        with mock.patch.object(D, 'RUN_TIMEOUT', -1), self.assertRaisesRegex(D.DeliveryError, 'retry-time-limit'):
            D.send(box, TOKEN, lambda *args: self.fail('expired deadline'))
        self.assertEqual(box.journal()[1], batch)

    def test_auth_and_redirect_fail_once_and_persist(self):
        for status in (401, 403, 302, 400):
            with self.subTest(status=status):
                box, batch = self.queued()
                calls = []
                def reject(*args):
                    calls.append(True)
                    return status, TOKEN.encode()
                with self.assertRaises(D.DeliveryError):
                    D.send(box, TOKEN, reject)
                self.assertEqual(calls, [True])
                self.assertEqual(box.journal()[0], 0)
                box.close()
                # Start an independent source/outbox for the next case.
                self.path = self.root / ('box-' + str(status))
                new = D.Outbox(self.path, self.source, self.vault, create=True)
                new.write('identity.json', dict(source_instance_id=self.source, vault_id=self.vault, endpoint='https://example.com/audit'))
                new.close()

    def test_retryable_status_bounded_to_three(self):
        box, batch = self.queued()
        calls = []
        def reject(*args):
            calls.append(True)
            return 429 if len(calls) == 1 else 503, b''
        with mock.patch.object(D.time, 'sleep'), self.assertRaisesRegex(D.DeliveryError, 'retryable-http-failure'):
            D.send(box, TOKEN, reject)
        self.assertEqual(len(calls), 3)
        self.assertEqual(box.journal()[1], batch)

    def test_tty_token_and_canary_never_logs_or_state(self):
        box, batch = self.queued()
        box.close()
        stdout, stderr = io.StringIO(), io.StringIO()
        response = b'{"reflected":"' + TOKEN.encode() + b'"}'
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr), \
                mock.patch.object(D.sys, 'stdin', types.SimpleNamespace(buffer=io.BytesIO(TOKEN.encode() + b'\n'), isatty=lambda: False)), \
                mock.patch.object(D, 'request', return_value=(200, response)):
            # send's default function is bound at definition; inject through a wrapper.
            real_send = D.send
            with mock.patch.object(D, 'send', side_effect=lambda box, token: real_send(box, token, D.request)):
                self.assertEqual(D.main(self.args + ['send', '--token-stdin']), 1)
        evidence = stdout.getvalue() + stderr.getvalue()
        for path in self.path.iterdir():
            evidence += path.read_text()
        self.assertNotIn(TOKEN, evidence)
        with contextlib.redirect_stderr(io.StringIO()), mock.patch.object(D.sys.stdin, 'isatty', return_value=False), \
                mock.patch.object(D.getpass, 'getpass', side_effect=AssertionError('must not echo')):
            self.assertEqual(D.main(self.args + ['send']), 1)

    def test_malformed_receipt_and_reinit_refused(self):
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            self.assertEqual(D.main(self.args + ['init', '--vault-receipt', str(self.receipt), '--endpoint', 'https://example.com/audit']), 1)
        self.assertEqual(self.box().identity['vault_id'], self.vault)

    def test_receipt_cut_is_pinned_without_advancing_delivery_cursor(self):
        box = self.box()
        self.assertEqual(box.identity['vault_receipt_sha256'], hashlib.sha256(self.receipt.read_bytes()).hexdigest())
        self.assertEqual(box.journal()[0], 0)
        receipt = D.decode(self.receipt.read_bytes())
        del receipt['snapshot_cut']
        old_receipt = self.root / 'old-receipt.json'
        private_file(old_receipt, D.encode(receipt))
        outbox = self.root / 'old-outbox'
        args = ['--outbox', str(outbox), '--source-instance-id', self.source, '--vault-id', self.vault,
                'init', '--vault-receipt', str(old_receipt), '--endpoint', 'https://example.com/audit']
        with contextlib.redirect_stderr(io.StringIO()) as error:
            self.assertEqual(D.main(args), 1)
        self.assertIn('invalid-vault-receipt', error.getvalue())
        self.assertFalse(outbox.exists())

    def test_hidden_tty_echo_failure_refuses_fallback(self):
        box, batch = self.queued()
        box.close()
        def fallback(*args):
            warnings.warn('synthetic terminal echo failure', D.getpass.GetPassWarning)
            self.fail('visible fallback must not read token')
        error = io.StringIO()
        with mock.patch.object(D.sys.stdin, 'isatty', return_value=True), \
                mock.patch.object(D.getpass, 'getpass', side_effect=fallback), contextlib.redirect_stderr(error):
            self.assertEqual(D.main(self.args + ['send']), 1)
        self.assertIn('hidden-tty-required', error.getvalue())
        self.assertNotIn(TOKEN, error.getvalue())
        self.assertEqual(self.box().journal()[0], 0)

    def test_invalid_endpoints_and_private_ip_rejected(self):
        for url in ('http://example.com/a', 'https://user:secret@example.com/a', 'https://example.com/a#x',
                    'https://example.com/a?token=secret', 'https://example.com/a\n'):
            with self.subTest(url=url), self.assertRaises(D.DeliveryError):
                D.endpoint(url)
        with self.assertRaisesRegex(D.DeliveryError, 'non-public-endpoint'):
            D.request('https://localhost/a', b'{}', TOKEN, 1)

    def test_dns_absolute_timeout(self):
        def stuck(*args, **kwargs):
            time.sleep(.3)
            return []
        start = time.monotonic()
        with self.assertRaisesRegex(D.DeliveryError, 'network-timeout'):
            D.request('https://example.com/a', b'{}', TOKEN, .05, resolver=stuck)
        self.assertLess(time.monotonic() - start, .2)

    def test_deadline_kills_dns_before_any_later_connection(self):
        marker = self.root / 'late-connection'
        def late_dns(*args, **kwargs):
            time.sleep(.12)
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('8.8.8.8', 443))]
        def connection(*args, **kwargs):
            marker.write_text('connection started after deadline')
            raise OSError('synthetic connection')
        with mock.patch.object(D.http.client, 'HTTPSConnection', side_effect=connection), \
                self.assertRaisesRegex(D.DeliveryError, 'network-timeout'):
            D.request('https://example.com/a', b'{}', TOKEN, .02, resolver=late_dns)
        time.sleep(.2)
        self.assertFalse(marker.exists(), 'network worker continued after absolute deadline')


class TLSReceiver:
    def __init__(self, root):
        self.root = Path(root)
        cert, key = self.root / 'cert.pem', self.root / 'key.pem'
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                        '-keyout', str(key), '-out', str(cert), '-subj', '/CN=localhost',
                        '-addext', 'subjectAltName=DNS:localhost'], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.context = ssl.create_default_context(cafile=cert)
        self.received, self.unique = [], {}
        self.mode = 'success'
        receiver = self
        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_POST(self):
                try:
                    size = int(self.headers['Content-Length'])
                    batch = D.decode(self.rfile.read(size))
                    receiver.received.append(batch)
                    if self.headers.get('Authorization') != 'Bearer ' + TOKEN:
                        self.send_response(401)
                        self.end_headers()
                        return
                    if receiver.mode == 'oversized':
                        body = b'x' * (D.MAX_RESPONSE + 1)
                    elif receiver.mode == 'slow':
                        self.send_response(200)
                        self.end_headers()
                        for _ in range(10):
                            self.wfile.write(b'x')
                            self.wfile.flush()
                            time.sleep(.05)
                        return
                    else:
                        ack = D.expected_ack(batch)
                        digest = hashlib.sha256(D.encode(batch)).hexdigest()
                        previous = receiver.unique.get(batch['batch_id'])
                        if previous:
                            if previous != digest:
                                self.send_error(400)
                                return
                        else:
                            # The fixture ACK is emitted only after a real durable write.
                            private_file(receiver.root / (batch['batch_id'] + '.json'), D.encode(batch))
                            with open(receiver.root / (batch['batch_id'] + '.json'), 'rb') as stream:
                                os.fsync(stream.fileno())
                            fd = os.open(receiver.root, os.O_RDONLY | os.O_DIRECTORY)
                            os.fsync(fd)
                            os.close(fd)
                            receiver.unique[batch['batch_id']] = digest
                        if receiver.mode == 'lost':
                            self.connection.shutdown(socket.SHUT_RDWR)
                            self.connection.close()
                            return
                        body = D.encode(ack)
                    self.send_response(200)
                    self.send_header('Content-Length', str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                except (BrokenPipeError, ConnectionResetError, ssl.SSLError):
                    pass
        self.server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.load_cert_chain(cert, key)
        self.server.socket = tls.wrap_socket(self.server.socket, server_side=True)
        self.url = 'https://localhost:%d/audit' % self.server.server_port
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def transport(self, url, body, token, timeout):
        # Only test code injects loopback allowance and binds this fixture CA.
        with warnings.catch_warnings(), mock.patch.object(D.ipaddress, 'ip_address', return_value=types.SimpleNamespace(is_global=True)):
            # Production entry is single-threaded; this fixture runs a threaded receiver.
            warnings.filterwarnings('ignore', message='.*multi-threaded.*', category=DeprecationWarning)
            return D.request(url, body, token, timeout, context=self.context,
                             resolver=lambda *args, **kwargs: socket.getaddrinfo('127.0.0.1', self.server.server_port, type=socket.SOCK_STREAM))

    def close(self):
        self.server.shutdown()
        self.server.server_close()


class TLSAndCLITests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.receiver = TLSReceiver(self.root)
        self.addCleanup(self.receiver.close)

    def test_real_tls_response_and_trickle_limits(self):
        batch = dict(batch_id=str(uuid.uuid4()), **{field: 'fixture' for field in D.ACK_FIELDS if field != 'batch_id'})
        self.receiver.mode = 'oversized'
        with self.assertRaisesRegex(D.DeliveryError, 'response-size-limit'):
            self.receiver.transport(self.receiver.url, D.encode(batch), TOKEN, 1)
        self.receiver.mode = 'slow'
        start = time.monotonic()
        with self.assertRaisesRegex(D.DeliveryError, 'network-timeout'):
            self.receiver.transport(self.receiver.url, D.encode(batch), TOKEN, .08)
        self.assertLess(time.monotonic() - start, .3)

    def test_real_tls_auth_reject_and_untrusted_ca(self):
        batch = dict(batch_id=str(uuid.uuid4()), **{field: 'fixture' for field in D.ACK_FIELDS if field != 'batch_id'})
        self.assertEqual(self.receiver.transport(self.receiver.url, D.encode(batch), 'wrong-synthetic-token', 1), (401, b''))
        with warnings.catch_warnings(), mock.patch.object(D.ipaddress, 'ip_address', return_value=types.SimpleNamespace(is_global=True)):
            warnings.filterwarnings('ignore', message='.*multi-threaded.*', category=DeprecationWarning)
            with self.assertRaisesRegex(D.DeliveryError, 'network-failure'):
                D.request(self.receiver.url, D.encode(batch), TOKEN, 1,
                          resolver=lambda *args, **kwargs: socket.getaddrinfo('127.0.0.1', self.receiver.server.server_port, type=socket.SOCK_STREAM))

    def test_actual_cli_export_tls_lost_ack_dedup_and_restart(self):
        rekey = Path(os.environ.get('REKEY_TEST_BINARY', ROOT / 'target/debug/rekey'))
        rekeyd = Path(os.environ.get('REKEYD_TEST_BINARY', ROOT / 'target/debug/rekeyd'))
        self.assertTrue(rekey.is_file() and rekeyd.is_file(), 'build real fixture binaries first')
        state = self.root / 'state'
        def run(binary, args, stdin=None):
            result = subprocess.run([str(binary), *args, '--state-dir', str(state)], input=stdin,
                                    capture_output=True, timeout=30)
            self.assertEqual(result.returncode, 0, 'real CLI operation failed (output suppressed)')
            return result.stdout
        run(rekeyd, ['init', '--password-stdin'], (PASSWORD + '\n').encode())
        process = subprocess.Popen([str(rekeyd), 'serve', '--state-dir', str(state)],
                                   stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        def stop():
            process.terminate()
            process.wait(timeout=10)
        self.addCleanup(stop)
        deadline = time.monotonic() + 10
        while not (state / 'runtime/admin.sock').exists() and time.monotonic() < deadline:
            time.sleep(.02)
        self.assertTrue((state / 'runtime/admin.sock').exists())
        run(rekey, ['unlock', '--password-stdin'], (PASSWORD + '\n').encode())
        receipt_raw = run(rekey, ['backup', '--output', str(self.root / 'fixture.backup'), '--password-stdin'],
                          (PASSWORD + '\n').encode())
        receipt = D.decode(receipt_raw)
        receipt_path = self.root / 'receipt.json'
        private_file(receipt_path, receipt_raw)
        export = self.root / 'real-export.jsonl'
        export_receipt = D.decode(run(rekey, ['audit', 'export', '--output', str(export)]))
        self.assertTrue(export_receipt['exported'])
        source = str(uuid.uuid4())
        outbox = self.root / 'outbox'
        args = ['--outbox', str(outbox), '--source-instance-id', source, '--vault-id', receipt['vault_id']]
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(D.main(args + ['init', '--vault-receipt', str(receipt_path), '--endpoint', self.receiver.url]), 0)
            self.assertEqual(D.main(args + ['enqueue', '--export', str(export)]), 0)
        box = D.Outbox(outbox, source, receipt['vault_id'])
        self.addCleanup(box.close)
        self.receiver.mode = 'lost'
        with mock.patch.object(D.time, 'sleep'), self.assertRaisesRegex(D.DeliveryError, 'network-failure'):
            D.send(box, TOKEN, self.receiver.transport)
        self.assertEqual(len(self.receiver.unique), 1)
        original = box.journal()[1]
        self.assertEqual(box.journal()[0], 0)
        box.close()
        box = D.Outbox(outbox, source, receipt['vault_id'])
        self.addCleanup(box.close)
        self.receiver.mode = 'success'
        cursor = D.send(box, TOKEN, self.receiver.transport)
        self.assertEqual(cursor, export_receipt['snapshot_max_sequence'])
        self.assertEqual(len(self.receiver.unique), 1)
        self.assertEqual(len(self.receiver.received), 4)
        self.assertTrue(all(item['batch_id'] == original['batch_id'] for item in self.receiver.received))
        stored = D.decode((self.root / (original['batch_id'] + '.json')).read_bytes())
        self.assertEqual(stored['export_jsonl'].encode(), export.read_bytes())
        self.assertNotIn(TOKEN.encode(), b''.join(path.read_bytes() for path in outbox.iterdir()))


if __name__ == '__main__':
    unittest.main(verbosity=2)
