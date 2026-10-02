#!/usr/bin/env python3
"""Bounded, at-least-once delivery of complete Rekey audit exports."""
import argparse
import fcntl
import getpass
import hashlib
import http.client
import ipaddress
import json
import os
import signal
import socket
import ssl
import stat
import sys
import time
import urllib.parse
import uuid
import warnings

MAX_EXPORT = 16 * 1024 * 1024
MAX_OUTBOX = 256 * 1024 * 1024
MAX_RESPONSE = 64 * 1024
MAX_AGE = 24 * 60 * 60
REQUEST_TIMEOUT = 10
RUN_TIMEOUT = 35
FILTERS = ('request_id', 'session_id', 'action_id', 'credential_id', 'outcome', 'since_ms', 'until_ms')
ACK_FIELDS = ('batch_id', 'source_instance_id', 'vault_id', 'first_sequence', 'last_sequence',
              'snapshot_max_sequence', 'row_count', 'sha256_hex')


class DeliveryError(Exception):
    pass


def require(condition, category):
    if not condition:
        raise DeliveryError(category)


def encode(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True) + '\n').encode()


def decode(data):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, 'invalid-json')
            result[key] = value
        return result
    try:
        return json.loads(data, object_pairs_hook=pairs, parse_constant=lambda _: require(False, 'invalid-json'))
    except (ValueError, UnicodeError, RecursionError):
        raise DeliveryError('invalid-json') from None


def number(value):
    return type(value) is int and 0 <= value <= 2**63 - 1


def secure_stat(info, directory=False):
    require(info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == (0o700 if directory else 0o600)
            and (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode) and info.st_nlink == 1),
            'unsafe-permissions')


def open_directory(path):
    # Walk every component through O_NOFOLLOW, including ancestors.
    parts = os.path.abspath(path).split(os.sep)
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in parts:
            if part:
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                os.close(fd)
                fd = child
        return fd
    except BaseException:
        os.close(fd)
        raise


def read_external(path, limit):
    parent = open_directory(os.path.dirname(os.path.abspath(path)))
    fd = None
    try:
        name = os.path.basename(path)
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        before = os.fstat(fd)
        secure_stat(before)
        require(before.st_size <= limit, 'size-limit')
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            data = stream.read(limit + 1)
        after = os.fstat(fd)
        named = os.stat(name, dir_fd=parent, follow_symlinks=False)
        require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
                == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
                and (named.st_dev, named.st_ino) == (before.st_dev, before.st_ino), 'path-replaced')
        check = open_directory(os.path.dirname(os.path.abspath(path)))
        try:
            a, b = os.fstat(check), os.fstat(parent)
            require((a.st_dev, a.st_ino) == (b.st_dev, b.st_ino), 'path-replaced')
        finally:
            os.close(check)
        require(len(data) <= limit, 'size-limit')
        return data
    finally:
        if fd is not None:
            os.close(fd)
        os.close(parent)


class Outbox:
    def __init__(self, path, source, vault, create=False):
        self.path = os.path.abspath(path)
        self.fd = None
        self.lock = None
        self.source, self.vault = source, vault
        # Source IDs are operator UUIDs; clone/restore must choose a new UUID.
        require(str(uuid.UUID(source)) == source and uuid.UUID(source).int > 0
                and str(uuid.UUID(vault)) == vault and uuid.UUID(vault).int > 0, 'invalid-identity')
        if create:
            parent = open_directory(os.path.dirname(self.path))
            try:
                os.mkdir(os.path.basename(self.path), 0o700, dir_fd=parent)
                os.fsync(parent)
            finally:
                os.close(parent)
        try:
            self.fd = open_directory(self.path)
            secure_stat(os.fstat(self.fd), True)
            self.lock = os.open('.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600, dir_fd=self.fd)
            secure_stat(os.fstat(self.lock))
            fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.verify()
            require(not any(name.startswith('.partial-') for name in os.listdir(self.fd)), 'partial-outbox-review-required')
            self.identity = None if create else self.read('identity.json')
            if not create:
                require(self.identity['source_instance_id'] == source and self.identity['vault_id'] == vault, 'identity-mismatch')
                endpoint(self.identity['endpoint'])
        except BaseException:
            self.close()
            raise

    def close(self):
        if self.lock is not None:
            os.close(self.lock)
            self.lock = None
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None

    def verify(self):
        current = open_directory(self.path)
        try:
            a, b = os.fstat(current), os.fstat(self.fd)
            secure_stat(a, True)
            require((a.st_dev, a.st_ino) == (b.st_dev, b.st_ino), 'path-replaced')
            if self.lock is not None:
                named = os.stat('.lock', dir_fd=self.fd, follow_symlinks=False)
                held = os.fstat(self.lock)
                secure_stat(named)
                require((named.st_dev, named.st_ino) == (held.st_dev, held.st_ino), 'path-replaced')
        finally:
            os.close(current)

    def read(self, name):
        self.verify()
        # read_external checks ownership, inode stability, mode and size.
        result = decode(read_external(os.path.join(self.path, name), MAX_EXPORT * 7))
        self.verify()
        return result

    def write(self, name, value):
        self.verify()
        temporary = '.partial-' + str(uuid.uuid4())
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=self.fd)
        try:
            with os.fdopen(fd, 'wb', closefd=False) as stream:
                stream.write(encode(value))
                stream.flush()
                os.fsync(fd)
            self.verify()
            os.link(temporary, name, src_dir_fd=self.fd, dst_dir_fd=self.fd, follow_symlinks=False)
            os.unlink(temporary, dir_fd=self.fd)
            os.fsync(self.fd)
            self.verify()
        finally:
            os.close(fd)

    def journal(self):
        self.verify()
        names = os.listdir(self.fd)
        batches = []
        total = 0
        for name in names:
            info = os.stat(name, dir_fd=self.fd, follow_symlinks=False)
            secure_stat(info)
            total += info.st_size
            require(name in ('.lock', 'identity.json') or name.startswith(('batch-', 'ack-', 'failure-')), 'unknown-outbox-file')
            if name.startswith('batch-'):
                batch = self.read(name)
                validate_batch(batch, self.source, self.vault)
                require(name == 'batch-%d.json' % batch['first_sequence'], 'invalid-journal')
                batches.append(batch)
        batches.sort(key=lambda item: item['first_sequence'])
        cursor, pending = 0, None
        ack_names, failure_names = set(), set()
        for batch in batches:
            require(pending is None and batch['first_sequence'] == cursor + 1, 'sequence-gap')
            ack_name = 'ack-%d.json' % batch['first_sequence']
            if ack_name in names:
                receipt = self.read(ack_name)
                require(set(receipt) == {'ack', 'acked_at_ms'} and number(receipt['acked_at_ms']), 'invalid-journal')
                validate_ack(receipt['ack'], batch)
                cursor = batch['last_sequence']
                ack_names.add(ack_name)
            else:
                pending = batch
                failure_name = 'failure-%d.json' % batch['first_sequence']
                if failure_name in names:
                    failure = self.read(failure_name)
                    require(set(failure) == {'batch_id', 'category', 'failed_at_ms'}
                            and failure['batch_id'] == batch['batch_id'] and type(failure['category']) is str
                            and number(failure['failed_at_ms']), 'invalid-journal')
                    failure_names.add(failure_name)
        require({name for name in names if name.startswith('ack-')} == ack_names, 'orphan-ack')
        require({name for name in names if name.startswith('failure-')} == failure_names, 'orphan-failure')
        return cursor, pending, total


def endpoint(url):
    parsed = urllib.parse.urlsplit(url)
    require(parsed.scheme == 'https' and parsed.hostname and not parsed.username and not parsed.password
            and not parsed.fragment and not parsed.query and parsed.path.startswith('/')
            and all(32 < ord(char) < 127 for char in url), 'invalid-endpoint')
    require(parsed.port is None or 1 <= parsed.port <= 65535, 'invalid-endpoint')
    return parsed


def export_info(raw, cursor):
    require(raw.endswith(b'\n') and len(raw) <= MAX_EXPORT, 'incomplete-export')
    records = [decode(line) for line in raw.splitlines()]
    require(len(records) >= 2 and all(type(record) is dict for record in records), 'incomplete-export')
    header, trailer = records[0], records[-1]
    require(set(header) == set(FILTERS) | {'record_type', 'schema', 'created_at_ms', 'snapshot_max_sequence'}
            and header.get('record_type') == 'rekey.audit.export.v2' and header.get('schema') == 'rekey.audit.v2'
            and number(header.get('created_at_ms'))
            and all(field in header and header[field] is None for field in FILTERS), 'filtered-or-invalid-export')
    maximum = header.get('snapshot_max_sequence')
    require(number(maximum) and maximum > cursor, 'snapshot-regression-or-no-new-events')
    events = records[1:-1]
    require(trailer == {'record_type': 'rekey.audit.export.complete.v2', 'row_count': len(events)}
            and type(trailer.get('row_count')) is int and events, 'incomplete-export')
    expected, previous = maximum, maximum + 1
    for record in events:
        require(record.get('record_type') == 'rekey.audit.v2' and number(record.get('sequence'))
                and 0 < record['sequence'] < previous, 'sequence-gap')
        if record['sequence'] > cursor:
            require(record['sequence'] == expected, 'sequence-gap')
            expected -= 1
        previous = record['sequence']
    require(expected <= cursor, 'sequence-gap')
    return maximum, len(events)


def validate_batch(batch, source, vault):
    require(type(batch) is dict and set(batch) == set(ACK_FIELDS) | {'record_type', 'created_at_ms', 'export_jsonl'}, 'invalid-batch')
    require(batch['record_type'] == 'rekey.audit.delivery.batch.v1' and batch['source_instance_id'] == source
            and batch['vault_id'] == vault and number(batch['first_sequence']) and batch['first_sequence'] > 0
            and number(batch['created_at_ms']) and type(batch['export_jsonl']) is str, 'invalid-batch')
    require(str(uuid.UUID(batch['batch_id'])) == batch['batch_id'], 'invalid-batch')
    raw = batch['export_jsonl'].encode('utf-8')
    maximum, count = export_info(raw, batch['first_sequence'] - 1)
    require(batch['sha256_hex'] == hashlib.sha256(raw).hexdigest() and type(batch['row_count']) is int
            and batch['row_count'] == count and type(batch['last_sequence']) is int and batch['last_sequence'] == maximum
            and type(batch['snapshot_max_sequence']) is int and batch['snapshot_max_sequence'] == maximum, 'invalid-batch')


def expected_ack(batch):
    return dict(record_type='rekey.audit.delivery.ack.v1', durable=True,
                **{field: batch[field] for field in ACK_FIELDS})


def validate_ack(ack, batch):
    expected = expected_ack(batch)
    require(type(ack) is dict and set(ack) == set(expected)
            and all(type(ack[key]) is type(value) and ack[key] == value for key, value in expected.items()), 'invalid-durable-ack')


def enqueue(box, path):
    cursor, pending, total = box.journal()
    require(pending is None, 'pending-batch')
    raw = read_external(path, MAX_EXPORT)
    maximum, count = export_info(raw, cursor)
    batch = dict(record_type='rekey.audit.delivery.batch.v1', batch_id=str(uuid.uuid4()),
                 source_instance_id=box.source, vault_id=box.vault, first_sequence=cursor + 1,
                 last_sequence=maximum, snapshot_max_sequence=maximum, row_count=count,
                 sha256_hex=hashlib.sha256(raw).hexdigest(), created_at_ms=int(time.time() * 1000),
                 export_jsonl=raw.decode('utf-8'))
    # Reserve the exact bound ACK receipt before admitting a batch. Completing
    # delivery must not need space beyond the declared logical outbox limit.
    receipt_size = len(encode({'ack': expected_ack(batch), 'acked_at_ms': 2**63 - 1}))
    require(total + len(encode(batch)) + receipt_size <= MAX_OUTBOX, 'backlog-limit')
    box.write('batch-%d.json' % batch['first_sequence'], batch)
    return batch


def request(url, body, token, timeout, *, context=None, resolver=None):
    """Whole DNS/TLS/HTTP operation has an absolute deadline, including trickle headers."""
    parsed = endpoint(url)
    parent, child = socket.socketpair()
    started = time.monotonic()
    try:
        pid = os.fork()
    except BaseException:
        parent.close()
        child.close()
        raise
    if pid == 0:
        parent.close()
        connection = None
        try:
            addresses = (resolver or socket.getaddrinfo)(parsed.hostname, parsed.port or 443, type=socket.SOCK_STREAM)
            require(addresses and all(ipaddress.ip_address(item[4][0]).is_global for item in addresses), 'non-public-endpoint')
            connection = http.client.HTTPSConnection(parsed.hostname, parsed.port or 443, timeout=timeout,
                                                     context=context or ssl.create_default_context())
            # Connect to the validated address; TLS/Host retain the original hostname.
            sock = socket.socket(addresses[0][0], socket.SOCK_STREAM)
            connection.sock = sock
            sock.settimeout(timeout)
            sock.connect(addresses[0][4])
            connection.sock = connection._context.wrap_socket(sock, server_hostname=parsed.hostname)
            connection.request('POST', parsed.path, body, {'Authorization': 'Bearer ' + token,
                                                        'Content-Type': 'application/json'})
            response = connection.getresponse()
            if response.status != 200:
                value = {'status': response.status, 'data': ''}
            else:
                data = response.read(MAX_RESPONSE + 1)
                require(len(data) <= MAX_RESPONSE, 'response-size-limit')
                value = {'status': response.status, 'data': data.decode('latin1')}
        except DeliveryError as error:
            value = {'error': str(error)}
        except (OSError, ValueError, http.client.HTTPException):
            value = {'error': 'network-failure'}
        except Exception:
            value = {'error': 'network-worker-failure'}
        try:
            child.settimeout(timeout)
            child.sendall(encode(value))
        except OSError:
            pass
        finally:
            if connection:
                connection.close()
            child.close()
            os._exit(0)
    child.close()
    try:
        response = bytearray()
        while True:
            remaining = timeout - (time.monotonic() - started)
            require(remaining > 0, 'network-timeout')
            parent.settimeout(remaining)
            part = parent.recv(8192)
            if not part:
                break
            response.extend(part)
            require(len(response) <= MAX_RESPONSE * 6 + 1024, 'response-size-limit')
        value = decode(response)
        if 'error' in value:
            raise DeliveryError(value['error'])
        return value['status'], value['data'].encode('latin1')
    except socket.timeout:
        raise DeliveryError('network-timeout') from None
    finally:
        parent.close()
        finished, _ = os.waitpid(pid, os.WNOHANG)
        if finished == 0:
            os.kill(pid, signal.SIGKILL)
            os.waitpid(pid, 0)


def send(box, token, transport=request):
    require(token and len(token.encode()) <= 8192 and all(32 < ord(char) < 127 for char in token), 'invalid-token')
    _, batch, _ = box.journal()
    require(batch is not None, 'no-pending-batch')
    require('failure-%d.json' % batch['first_sequence'] not in os.listdir(box.fd), 'permanent-failure-review-required')
    require(0 <= time.time() - batch['created_at_ms'] / 1000 <= MAX_AGE, 'batch-age-limit')
    deadline = time.monotonic() + RUN_TIMEOUT
    for attempt in range(3):
        box.verify()
        remaining = deadline - time.monotonic()
        require(remaining > 0, 'retry-time-limit')
        try:
            status, data = transport(box.identity['endpoint'], encode(batch), token, min(REQUEST_TIMEOUT, remaining))
        except DeliveryError as error:
            if str(error) not in ('network-failure', 'network-timeout'):
                box.write('failure-%d.json' % batch['first_sequence'],
                          {'batch_id': batch['batch_id'], 'category': str(error), 'failed_at_ms': int(time.time() * 1000)})
                raise
            failure = str(error)
        else:
            box.verify()
            if status == 200:
                try:
                    ack = decode(data)
                    validate_ack(ack, batch)
                except DeliveryError as error:
                    box.write('failure-%d.json' % batch['first_sequence'],
                              {'batch_id': batch['batch_id'], 'category': str(error), 'failed_at_ms': int(time.time() * 1000)})
                    raise
                box.write('ack-%d.json' % batch['first_sequence'], {'ack': ack, 'acked_at_ms': int(time.time() * 1000)})
                return batch['last_sequence']
            if status != 429 and not 500 <= status <= 599:
                failure = 'authentication-rejected' if status in (401, 403) else 'permanent-http-failure'
                box.write('failure-%d.json' % batch['first_sequence'],
                          {'batch_id': batch['batch_id'], 'category': failure, 'failed_at_ms': int(time.time() * 1000)})
                raise DeliveryError(failure)
            failure = 'retryable-http-failure'
        if attempt == 2:
            raise DeliveryError(failure)
        delay = 2**attempt
        require(time.monotonic() + delay < deadline, 'retry-time-limit')
        time.sleep(delay)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--outbox', required=True)
    parser.add_argument('--source-instance-id', required=True)
    parser.add_argument('--vault-id', required=True)
    commands = parser.add_subparsers(dest='command', required=True)
    init = commands.add_parser('init')
    init.add_argument('--vault-receipt', required=True)
    init.add_argument('--endpoint', required=True)
    pending = commands.add_parser('enqueue')
    pending.add_argument('--export', required=True)
    deliver = commands.add_parser('send')
    deliver.add_argument('--token-stdin', action='store_true')
    args = parser.parse_args(argv)
    box = None
    try:
        receipt = None
        if args.command == 'init':
            endpoint(args.endpoint)
            raw = read_external(args.vault_receipt, MAX_RESPONSE)
            receipt = decode(raw)
            require(type(receipt) is dict and set(receipt) == {'vault_id', 'format_version', 'created_at_ms', 'sha256_hex', 'output_path', 'snapshot_cut'}
                    and receipt['vault_id'] == args.vault_id and type(receipt['format_version']) is int
                    and receipt['format_version'] > 0 and number(receipt['created_at_ms'])
                    and type(receipt['sha256_hex']) is str and len(receipt['sha256_hex']) == 64
                    and all(char in '0123456789abcdef' for char in receipt['sha256_hex'])
                    and type(receipt['output_path']) is str, 'invalid-vault-receipt')
        box = Outbox(args.outbox, args.source_instance_id, args.vault_id, create=args.command == 'init')
        if args.command == 'init':
            box.write('identity.json', dict(source_instance_id=box.source, vault_id=box.vault,
                                           endpoint=args.endpoint, vault_receipt_sha256=hashlib.sha256(raw).hexdigest()))
            print('initialized')
        elif args.command == 'enqueue':
            enqueue(box, args.export)
            print('queued')
        else:
            require(args.token_stdin or sys.stdin.isatty(), 'hidden-tty-required')
            if args.token_stdin:
                token = sys.stdin.buffer.readline(8194)
            else:
                with warnings.catch_warnings():
                    warnings.simplefilter('error', getpass.GetPassWarning)
                    try:
                        token = getpass.getpass('Delivery token: ').encode()
                    except getpass.GetPassWarning:
                        raise DeliveryError('hidden-tty-required') from None
            if args.token_stdin:
                require(token.endswith(b'\n') and len(token) <= 8193, 'invalid-token-input')
                token = token[:-1]
            cursor = send(box, token.decode('ascii'))
            print('acknowledged cursor=%d' % cursor)
        return 0
    except Exception as error:
        # Never reflect upstream bodies, exceptions, tokens or secret paths into logs.
        print('delivery failed: ' + (str(error) if isinstance(error, DeliveryError) else 'local-io-or-format-failure'), file=sys.stderr)
        return 1
    finally:
        if box:
            box.close()


if __name__ == '__main__':
    sys.exit(main())
