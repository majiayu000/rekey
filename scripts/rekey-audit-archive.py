#!/usr/bin/env python3
"""Archive one sealed audit batch to a fixed S3 Object Lock object version."""
import argparse
import base64
import datetime
import fcntl
import hashlib
import hmac
import http.client
import importlib.util
import ipaddress
import os
import pathlib
import re
import signal
import socket
import ssl
import sys
import time
import urllib.parse
import uuid
import xml.etree.ElementTree as ET

_spec = importlib.util.spec_from_file_location('rekey_audit_delivery', pathlib.Path(__file__).with_name('rekey-audit-delivery.py'))
delivery = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(delivery)
Error = delivery.DeliveryError
require, encode, decode = delivery.require, delivery.encode, delivery.decode
MAX_BATCH = delivery.MAX_EXPORT * 7
MAX_STATE = 128 * 1024 * 1024
MAX_RESPONSE = 65536
NS = 'http://s3.amazonaws.com/doc/2006-03-01/'


def now_ms():
    return int(time.time() * 1000)


def canonical_uuid(value):
    require(type(value) is str and str(uuid.UUID(value)) == value and uuid.UUID(value).int > 0, 'invalid-uuid')
    return value


def utc(value):
    require(type(value) is str and re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z', value), 'invalid-retention-time')
    return datetime.datetime.strptime(value, '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=datetime.timezone.utc).timestamp()


def load_profile(path):
    profile = decode(delivery.read_external(path, 65536))
    fields = {'format_version', 'purpose', 'bucket', 'region', 'expected_bucket_owner', 'prefix',
              'source_instance_id', 'vault_id', 'operator_label', 'access_key_id', 'secret_access_key',
              'session_token', 'expires_at_ms'}
    require(type(profile) is dict and set(profile) == fields and type(profile['format_version']) is int
            and profile['format_version'] == 1 and profile['purpose'] in ('archive', 'legal-hold'), 'invalid-profile')
    for key in fields - {'format_version', 'expires_at_ms'}:
        require(type(profile[key]) is str, 'invalid-profile')
    require(re.fullmatch(r'[a-z0-9][a-z0-9-]{1,61}[a-z0-9]', profile['bucket'])
            and not profile['bucket'].startswith(('xn--', 'sthree-', 'amzn-s3-demo-'))
            and not profile['bucket'].endswith(('-s3alias', '--ol-s3', '--x-s3', '--table-s3'))
            and re.fullmatch(r'(us|eu|ap|sa|ca|me|af|il|mx)-[a-z]+-[1-9][0-9]*', profile['region'])
            and re.fullmatch(r'[0-9]{12}', profile['expected_bucket_owner'])
            and re.fullmatch(r'[A-Za-z0-9_-]{1,64}(/[A-Za-z0-9_-]{1,64}){0,3}', profile['prefix'])
            and re.fullmatch(r'[A-Za-z0-9_.@-]{1,128}', profile['operator_label']), 'invalid-profile')
    for key in ('access_key_id', 'secret_access_key', 'session_token'):
        require(0 < len(profile[key]) <= 8192 and all(32 < ord(c) < 127 for c in profile[key]), 'invalid-profile')
    canonical_uuid(profile['source_instance_id'])
    canonical_uuid(profile['vault_id'])
    check_expiry(profile)
    return profile


def check_expiry(profile):
    require(delivery.number(profile['expires_at_ms']) and profile['expires_at_ms'] > now_ms(), 'identity-expired')


def public(value, profile):
    """An upstream identifier must not become a credential reflection in a receipt."""
    text = encode(value).decode()
    for key in ('access_key_id', 'secret_access_key', 'session_token'):
        secret = profile[key].encode()
        forms = [secret.decode(), urllib.parse.quote_from_bytes(secret, safe=''), secret.hex(),
                 base64.b64encode(secret).decode(), base64.urlsafe_b64encode(secret).decode(),
                 hashlib.sha256(secret).hexdigest()]
        require(not any(form and (form in text or form.rstrip('=') in text) for form in forms), 'credential-reflection')
    return value


def sign_headers(profile, method, host, path, query, body, headers, timestamp=None):
    stamp = timestamp or datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    digest = hashlib.sha256(body).hexdigest()
    result = {key.lower(): value for key, value in headers.items()}
    result.update(host=host, **{'x-amz-date': stamp, 'x-amz-content-sha256': digest})
    if profile.get('session_token'):
        result['x-amz-security-token'] = profile['session_token']
    keys = sorted(result)
    names = ';'.join(keys)
    canonical = '\n'.join([method, path, query, ''.join(key + ':' + ' '.join(result[key].split()) + '\n' for key in keys), names, digest])
    scope = stamp[:8] + '/' + profile['region'] + '/s3/aws4_request'
    message = '\n'.join(['AWS4-HMAC-SHA256', stamp, scope, hashlib.sha256(canonical.encode()).hexdigest()])
    key = ('AWS4' + profile['secret_access_key']).encode()
    for part in (stamp[:8], profile['region'], 's3', 'aws4_request'):
        key = hmac.new(key, part.encode(), hashlib.sha256).digest()
    signature = hmac.new(key, message.encode(), hashlib.sha256).hexdigest()
    result['authorization'] = 'AWS4-HMAC-SHA256 Credential=' + profile['access_key_id'] + '/' + scope + ',SignedHeaders=' + names + ',Signature=' + signature
    return result


def request(host, method, path, query, body, headers, timeout, *, context=None, resolver=None):
    """Kill the whole DNS/TLS/HTTP child on deadline; no late upload survives."""
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
            addresses = (resolver or socket.getaddrinfo)(host, 443, type=socket.SOCK_STREAM)
            require(addresses and all(ipaddress.ip_address(item[4][0]).is_global for item in addresses), 'non-public-endpoint')
            connection = http.client.HTTPSConnection(host, timeout=timeout, context=context or ssl.create_default_context())
            sock = socket.socket(addresses[0][0], socket.SOCK_STREAM)
            connection.sock = sock
            sock.settimeout(timeout)
            sock.connect(addresses[0][4])
            connection.sock = connection._context.wrap_socket(sock, server_hostname=host)
            connection.request(method, path + ('?' + query if query else ''), body, headers)
            response = connection.getresponse()
            pairs = response.getheaders()
            require(sum(len(k) + len(v) for k, v in pairs) <= MAX_RESPONSE, 'response-size-limit')
            values = {}
            for key, value in pairs:
                key = key.lower()
                if key in ('x-amz-version-id', 'x-amz-request-id', 'x-amz-checksum-sha256', 'x-amz-checksum-type', 'x-amz-server-side-encryption', 'content-length'):
                    require(key not in values, 'duplicate-response-header')
                    values[key] = value
            data = response.read(MAX_RESPONSE + 1) if method != 'HEAD' and response.status == 200 else b''
            require(len(data) <= MAX_RESPONSE, 'response-size-limit')
            value = {'status': response.status, 'headers': values, 'body': base64.b64encode(data).decode()}
        except Error as error:
            value = {'error': str(error)}
        except Exception:
            value = {'error': 'network-failure'}
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
        result = bytearray()
        while True:
            remaining = timeout - (time.monotonic() - started)
            require(remaining > 0, 'network-timeout')
            parent.settimeout(remaining)
            part = parent.recv(8192)
            if not part:
                break
            result.extend(part)
            require(len(result) <= MAX_RESPONSE * 8, 'response-size-limit')
        value = decode(result)
        if 'error' in value:
            raise Error(value['error'])
        return value['status'], value['headers'], base64.b64decode(value['body'], validate=True)
    except socket.timeout:
        raise Error('network-timeout') from None
    finally:
        parent.close()
        finished, _ = os.waitpid(pid, os.WNOHANG)
        if finished == 0:
            os.kill(pid, signal.SIGKILL)
            os.waitpid(pid, 0)


class Journal:
    def __init__(self, path, create=False):
        self.path = os.path.abspath(path)
        self.fd = self.lock = None
        if create:
            parent = delivery.open_directory(os.path.dirname(self.path))
            try:
                os.mkdir(os.path.basename(self.path), 0o700, dir_fd=parent)
                os.fsync(parent)
            finally:
                os.close(parent)
        try:
            self.fd = delivery.open_directory(self.path)
            delivery.secure_stat(os.fstat(self.fd), True)
            self.lock = os.open('.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600, dir_fd=self.fd)
            delivery.secure_stat(os.fstat(self.lock))
            fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.verify()
            require(not any(n.startswith('.partial-') for n in os.listdir(self.fd)), 'partial-journal-review-required')
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
        current = delivery.open_directory(self.path)
        try:
            a, b = os.fstat(current), os.fstat(self.fd)
            delivery.secure_stat(a, True)
            require((a.st_dev, a.st_ino) == (b.st_dev, b.st_ino), 'path-replaced')
            held, named = os.fstat(self.lock), os.stat('.lock', dir_fd=self.fd, follow_symlinks=False)
            delivery.secure_stat(named)
            require((held.st_dev, held.st_ino) == (named.st_dev, named.st_ino), 'path-replaced')
            names = os.listdir(self.fd)
            require(len(names) <= 1000, 'journal-capacity')
            total = 0
            for name in names:
                info = os.stat(name, dir_fd=self.fd, follow_symlinks=False)
                delivery.secure_stat(info)
                total += info.st_size
            require(total <= MAX_STATE, 'journal-capacity')
            return total, len(names)
        finally:
            os.close(current)

    def exists(self, name):
        self.verify()
        return name in os.listdir(self.fd)

    def read(self, name, raw=False):
        self.verify()
        data = delivery.read_external(os.path.join(self.path, name), MAX_BATCH if raw else 65536)
        self.verify()
        return data if raw else decode(data)

    def write(self, name, value, raw=False):
        data = value if raw else encode(value)
        total, count = self.verify()
        # Keep bounded room for the terminal receipt and the temporary hardlink.
        require(total + len(data) + 65536 <= MAX_STATE and count + 2 <= 1000, 'journal-capacity')
        temporary = '.partial-' + str(uuid.uuid4())
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=self.fd)
        try:
            with os.fdopen(fd, 'wb', closefd=False) as stream:
                stream.write(data)
                stream.flush()
                os.fsync(fd)
            self.verify()
            os.link(temporary, name, src_dir_fd=self.fd, dst_dir_fd=self.fd, follow_symlinks=False)
            os.unlink(temporary, dir_fd=self.fd)
            os.fsync(self.fd)
            self.verify()
        finally:
            os.close(fd)


def target(profile):
    return {k: profile[k] for k in ('bucket', 'region', 'expected_bucket_owner', 'prefix', 'source_instance_id', 'vault_id')}


def call(profile, plan, method, query=None, body=b'', headers=None, transport=request, deadline=None):
    check_expiry(profile)
    remaining = (deadline if deadline is not None else time.monotonic() + 8) - time.monotonic()
    require(remaining > 0, 'operation-timeout')
    host = profile['bucket'] + '.s3.' + profile['region'] + '.amazonaws.com'
    path = '/' + urllib.parse.quote(plan['object_key'], safe='/~')
    query = '&'.join(urllib.parse.quote(k, safe='~') + '=' + urllib.parse.quote(v, safe='~') for k, v in sorted((query or {}).items()))
    headers = dict(headers or {})
    headers['x-amz-expected-bucket-owner'] = profile['expected_bucket_owner']
    headers['content-length'] = str(len(body))
    headers['accept-encoding'] = 'identity'
    signed = sign_headers(profile, method, host, path, query, body, headers)
    status, result, data = transport(host, method, path, query, body, signed, min(8, remaining))
    check_expiry(profile)
    require(time.monotonic() < (deadline if deadline is not None else float('inf')), 'operation-timeout')
    # Only selected public receipt fields leave this boundary.
    public(result, profile)
    return status, result, data


def version_header(headers):
    version = headers.get('x-amz-version-id')
    require(type(version) is str and version != 'null' and 0 < len(version) <= 1024
            and all(32 < ord(c) < 127 for c in version), 'missing-or-invalid-version')
    return version


def xml_values(data, root, children):
    require(len(data) <= MAX_RESPONSE and b'<!' not in data, 'invalid-s3-xml')
    try:
        node = ET.fromstring(data)
        expected = ['{' + NS + '}' + child for child in children]
        require(node.tag == '{' + NS + '}' + root and not node.attrib
                and len(node) == len(expected) and sorted(child.tag for child in node) == sorted(expected)
                and all(not child.attrib and not len(child) and child.text is not None for child in node), 'invalid-s3-xml')
        return {child.tag.split('}', 1)[1]: child.text for child in node}
    except ET.ParseError:
        raise Error('invalid-s3-xml') from None


def observed(profile, plan, version=None, *, transport=request, deadline=None, head=None, journal=None):
    query = {'versionId': version} if version is not None else {}
    status, headers, _ = head if head is not None else call(profile, plan, 'HEAD', query, headers={'x-amz-checksum-mode': 'ENABLED'}, transport=transport, deadline=deadline)
    require(status == 200, 'object-readback-failed')
    actual_version = version_header(headers)
    require(version is None or actual_version == version, 'version-mismatch')
    require(headers.get('x-amz-checksum-sha256') == base64.b64encode(bytes.fromhex(plan['object_sha256_hex'])).decode()
            and headers.get('x-amz-checksum-type') == 'FULL_OBJECT'
            and headers.get('content-length') == str(plan['byte_length'])
            and headers.get('x-amz-server-side-encryption') == 'AES256', 'object-checksum-mismatch')
    if version is None and journal is not None:
        # A verified version remains pinned even if later retention/hold readback fails.
        journal.write('version.json', {'version_id': actual_version})
    status, retention_headers, data = call(profile, plan, 'GET', {'versionId': actual_version, 'retention': ''}, transport=transport, deadline=deadline)
    require(status == 200, 'retention-readback-failed')
    retention = xml_values(data, 'Retention', ['Mode', 'RetainUntilDate'])
    # S3 can serialize zero fractional seconds. Compare the actual timestamp, not spelling.
    actual_time = retention['RetainUntilDate']
    if actual_time.endswith('.000Z'):
        actual_time = actual_time[:-5] + 'Z'
    require(retention['Mode'] == plan['mode'] and utc(actual_time) == utc(plan['retain_until']), 'retention-mismatch')
    status, hold_headers, data = call(profile, plan, 'GET', {'versionId': actual_version, 'legal-hold': ''}, transport=transport, deadline=deadline)
    require(status == 200, 'hold-readback-failed')
    hold = xml_values(data, 'LegalHold', ['Status'])['Status']
    require(hold in ('ON', 'OFF'), 'invalid-hold-state')
    return {'version_id': actual_version, 'mode': retention['Mode'], 'retain_until': plan['retain_until'],
            'legal_hold': hold, 'observed_at_ms': now_ms(), 'request_ids': [h.get('x-amz-request-id') for h in (headers, retention_headers, hold_headers)]}


def read_plan(box, profile):
    plan = box.read('plan.json')
    require(plan.get('record_type') == 'rekey.audit.archive.intent.v1' and plan.get('target') == target(profile), 'archive-target-mismatch')
    payload = box.read('batch.json', raw=True)
    require(hashlib.sha256(payload).hexdigest() == plan['object_sha256_hex'] and len(payload) == plan['byte_length'], 'journal-content-mismatch')
    public(plan, profile)
    return plan, payload


def archive(box, profile, batch_path, mode, retain_until, hold, *, transport=request):
    require(profile['purpose'] == 'archive', 'wrong-identity-purpose')
    require(mode in ('GOVERNANCE', 'COMPLIANCE') and hold in ('ON', 'OFF') and utc(retain_until) > time.time(), 'invalid-retention-intent')
    batch = decode(delivery.read_external(batch_path, MAX_BATCH))
    delivery.validate_batch(batch, profile['source_instance_id'], profile['vault_id'])
    payload = encode(batch)
    require(len(payload) <= MAX_BATCH, 'size-limit')
    wanted = {'target': target(profile), 'batch': {k: batch[k] for k in delivery.ACK_FIELDS},
              'object_key': profile['prefix'] + '/' + profile['source_instance_id'] + '/' + profile['vault_id'] + '/' + batch['batch_id'] + '-' + batch['sha256_hex'] + '.json',
              'mode': mode, 'retain_until': retain_until, 'initial_legal_hold': hold,
              'object_sha256_hex': hashlib.sha256(payload).hexdigest(), 'byte_length': len(payload)}
    public(wanted, profile)
    fresh = not box.exists('plan.json')
    if fresh:
        require(os.listdir(box.fd) == ['.lock'], 'partial-journal-review-required')
        plan = dict(wanted, record_type='rekey.audit.archive.intent.v1', operator_label=profile['operator_label'], created_at_ms=now_ms())
        box.write('batch.json', payload, raw=True)
        box.write('plan.json', plan)
    else:
        plan, stored = read_plan(box, profile)
        require(all(plan.get(k) == v for k, v in wanted.items()) and stored == payload, 'archive-intent-conflict')
    deadline = time.monotonic() + 30
    known = box.read('version.json')['version_id'] if box.exists('version.json') else None
    head = None
    if not fresh and known is None:
        head = call(profile, plan, 'HEAD', headers={'x-amz-checksum-mode': 'ENABLED'}, transport=transport, deadline=deadline)
        require(head[0] in (200, 404), 'object-readback-failed')
    if fresh or (head is not None and head[0] == 404):
        status, headers, _ = call(profile, plan, 'PUT', body=payload, headers={
            'content-type': 'application/json', 'if-none-match': '*', 'x-amz-server-side-encryption': 'AES256',
            'x-amz-sdk-checksum-algorithm': 'SHA256', 'x-amz-checksum-sha256': base64.b64encode(bytes.fromhex(plan['object_sha256_hex'])).decode(),
            'x-amz-object-lock-mode': mode, 'x-amz-object-lock-retain-until-date': retain_until,
            'x-amz-object-lock-legal-hold': hold}, transport=transport, deadline=deadline)
        require(status in (200, 412), 'upload-result-unknown')
        if status == 200:
            known = version_header(headers)
            box.write('version.json', {'version_id': known})
        head = None
    result = observed(profile, plan, known, transport=transport, deadline=deadline, head=head, journal=box)
    require(result['legal_hold'] == hold, 'hold-mismatch')
    receipt = dict(record_type='rekey.audit.archive.receipt.v1', target=plan['target'], object_key=plan['object_key'],
                   batch=plan['batch'], object_sha256_hex=plan['object_sha256_hex'], byte_length=plan['byte_length'],
                   operator_label=plan['operator_label'], status='verified-readback', **result)
    public(receipt, profile)
    if box.exists('receipt.json'):
        original = box.read('receipt.json')
        require(original['version_id'] == receipt['version_id'] and original['object_sha256_hex'] == receipt['object_sha256_hex'], 'receipt-conflict')
        return original
    box.write('receipt.json', receipt)
    return receipt


def verify(box, profile, *, transport=request):
    plan, _ = read_plan(box, profile)
    receipt = box.read('receipt.json')
    result = observed(profile, plan, receipt['version_id'], transport=transport, deadline=time.monotonic() + 30)
    value = dict(record_type='rekey.audit.archive.verification.v1', object_key=plan['object_key'],
                 object_sha256_hex=plan['object_sha256_hex'], operator_label=profile['operator_label'],
                 within_retention=utc(plan['retain_until']) > time.time(), **result)
    public(value, profile)
    box.write('verification-' + str(uuid.uuid4()) + '.json', value)
    return value


def legal_hold(box, profile, operation_id, status, *, transport=request):
    require(profile['purpose'] == 'legal-hold' and status in ('ON', 'OFF'), 'wrong-identity-purpose')
    canonical_uuid(operation_id)
    plan, _ = read_plan(box, profile)
    receipt = box.read('receipt.json')
    version = receipt['version_id']
    name = 'hold-intent-' + operation_id + '.json'
    result_name = 'hold-receipt-' + operation_id + '.json'
    deadline = time.monotonic() + 30
    before = observed(profile, plan, version, transport=transport, deadline=deadline)
    if box.exists(name):
        intent = box.read(name)
        require(intent['status'] == status and intent['operator_label'] == profile['operator_label']
                and intent['version_id'] == version, 'hold-intent-conflict')
    else:
        total, count = box.verify()
        require(total + 2 * 65536 <= MAX_STATE and count + 3 <= 1000, 'journal-capacity')
        intent = {'record_type': 'rekey.audit.legal-hold.intent.v1', 'operation_id': operation_id, 'status': status,
                  'operator_label': profile['operator_label'], 'version_id': version, 'before': before, 'created_at_ms': now_ms()}
        public(intent, profile)
        box.write(name, intent)
    require(before['legal_hold'] in (intent['before']['legal_hold'], status), 'hold-state-conflict')
    if box.exists(result_name):
        require(before['legal_hold'] == status, 'hold-state-conflict')
        return box.read(result_name)
    if before['legal_hold'] != status:
        body = ('<LegalHold xmlns="' + NS + '"><Status>' + status + '</Status></LegalHold>').encode()
        code, _, _ = call(profile, plan, 'PUT', {'versionId': version, 'legal-hold': ''}, body,
                          {'content-type': 'application/xml', 'content-md5': base64.b64encode(hashlib.md5(body, usedforsecurity=False).digest()).decode()},
                          transport=transport, deadline=deadline)
        require(code == 200, 'hold-result-unknown')
    after = observed(profile, plan, version, transport=transport, deadline=deadline)
    require(after['legal_hold'] == status, 'hold-mismatch')
    value = {'record_type': 'rekey.audit.legal-hold.receipt.v1', 'operation_id': operation_id,
             'operator_label': profile['operator_label'], 'object_key': plan['object_key'], 'version_id': version,
             'before': intent['before'], 'after': after, 'status': status}
    public(value, profile)
    box.write(result_name, value)
    return value


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    for name in ('archive', 'verify', 'legal-hold'):
        command = commands.add_parser(name)
        command.add_argument('--profile', required=True)
        command.add_argument('--state', required=True)
        if name == 'archive':
            command.add_argument('--batch', required=True)
            command.add_argument('--mode', choices=('GOVERNANCE', 'COMPLIANCE'), required=True)
            command.add_argument('--retain-until', required=True)
            command.add_argument('--legal-hold', choices=('ON', 'OFF'), required=True)
        elif name == 'legal-hold':
            command.add_argument('--operation-id', required=True)
            command.add_argument('--status', choices=('ON', 'OFF'), required=True)
    args = parser.parse_args(argv)
    box = None
    try:
        profile = load_profile(args.profile)
        box = Journal(args.state, create=args.command == 'archive' and not os.path.lexists(args.state))
        if args.command == 'archive':
            result = archive(box, profile, args.batch, args.mode, args.retain_until, args.legal_hold)
        elif args.command == 'verify':
            result = verify(box, profile)
        else:
            result = legal_hold(box, profile, args.operation_id, args.status)
        public(result, profile)
        sys.stdout.buffer.write(encode(result))
        return 0
    except Error as error:
        sys.stderr.write('audit archive failed: ' + str(error) + '; remote result may be unknown; pending state retained\n')
        return 1
    except (OSError, ValueError, KeyError, TypeError, RecursionError):
        sys.stderr.write('audit archive failed: invalid input or local storage failure; pending state retained\n')
        return 1
    finally:
        if box:
            box.close()


if __name__ == '__main__':
    sys.exit(main())
