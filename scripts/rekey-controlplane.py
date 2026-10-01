#!/usr/bin/env python3
"""Fixed two-node private policy file box; no signing or unlock-proof handling.

publish consumes canonical policy.json/trust.json from the independent signer.
Artifact hashes pin those exact bytes; only real Authority status and audit can
confirm activation. Private file ownership is administrator trust, not isolation.
"""
import argparse
import errno
import fcntl
import hashlib
import json
import os
import re
import selectors
import stat
import subprocess
import sys
import termios
import time
import uuid

MAX_JSON = 65536
MAX_POLICY = 60 * 1024
MAX_JOURNAL = 20 * 1024 * 1024
MAX_COMMANDS = 100
RUN_SECONDS = 45
NODE_FIELDS = {'node_id', 'vault_id', 'state_dir', 'runtime_dir', 'admin_uid', 'platform',
               'responsibility_domain', 'signer_id', 'trust_sha256', 'approval_origin_sha256',
               'audit_destination', 'backup_destination', 'policy_max_lifetime_ms'}
PROFILE_FIELDS = {'format_version', 'customer_id', 'registration_expires_at_ms', 'box_dir', 'cli_path', 'nodes'}
COMMAND_FIELDS = {'format_version', 'profile_sha256', 'customer_id', 'node_id', 'vault_id',
                  'signer_id', 'trust_sha256', 'approval_origin_sha256', 'command_id',
                  'version', 'bundle_sha256', 'expires_at_ms'}


class Error(Exception):
    pass


def require(condition, message):
    if not condition:
        raise Error(message)


def now_ms():
    return int(time.time() * 1000)


def number(value, maximum=2**63 - 1):
    return type(value) is int and 0 <= value <= maximum


def digest(data):
    return hashlib.sha256(data).hexdigest()


def hex_digest(value):
    return type(value) is str and re.fullmatch('[0-9a-f]{64}', value) is not None


def identity(value):
    try:
        require(type(value) is str and str(uuid.UUID(value)) == value and uuid.UUID(value).int > 0, 'invalid-uuid')
    except (ValueError, AttributeError):
        raise Error('invalid-uuid') from None
    return value


def encode(value):
    # Transport records only. Never use this encoder to normalize signed artifacts.
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True) + '\n').encode()


def decode(data):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, 'duplicate-json-key')
            result[key] = value
        return result
    try:
        return json.loads(data, object_pairs_hook=pairs,
                          parse_constant=lambda _: require(False, 'invalid-json'))
    except (ValueError, UnicodeError, RecursionError):
        raise Error('invalid-json') from None


def path_value(path):
    require(type(path) is str and path.startswith('/') and path != '/' and '\x00' not in path
            and os.path.normpath(path) == path, 'noncanonical-path')
    return path


def same(a, b):
    return (a.st_dev, a.st_ino) == (b.st_dev, b.st_ino)


def secure(info, directory=False, owner=None):
    require(info.st_uid == (os.geteuid() if owner is None else owner)
            and stat.S_IMODE(info.st_mode) == (0o700 if directory else 0o600)
            and (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode) and info.st_nlink == 1),
            'unsafe-permissions')


def directory(path, executable_owner=None):
    # Ancestors can be shared system directories, but every component is no-follow.
    path_value(path)
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        if executable_owner is not None:
            info = os.fstat(fd)
            require(info.st_uid in (0, executable_owner)
                    and (info.st_mode & 0o022 == 0 or info.st_uid == 0 and info.st_mode & stat.S_ISVTX),
                    'unsafe-cli-ancestor')
        for part in path.split('/')[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            try:
                named = os.stat(part, dir_fd=fd, follow_symlinks=False)
                info = os.fstat(child)
                require(same(named, info), 'path-replaced')
                if executable_owner is not None:
                    require(info.st_uid in (0, executable_owner)
                            and (info.st_mode & 0o022 == 0 or info.st_uid == 0 and info.st_mode & stat.S_ISVTX),
                            'unsafe-cli-ancestor')
            except BaseException:
                os.close(child)
                raise
            os.close(fd)
            fd = child
        return fd
    except BaseException:
        os.close(fd)
        raise


def read_file(path, limit=MAX_JSON, durable=False, expected=None):
    path_value(path)
    parent = directory(os.path.dirname(path))
    fd = None
    try:
        name = os.path.basename(path)
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        before = os.fstat(fd)
        secure(before)
        require(before.st_size <= limit, 'size-limit')
        data = bytearray()
        while len(data) <= limit:
            part = os.read(fd, min(8192, limit + 1 - len(data)))
            if not part:
                break
            data.extend(part)
        if durable:
            require(expected is not None and bytes(data) == expected, 'receipt-content-changed')
            # Reconcile changes no bytes: establish durability before historical use.
            os.fsync(fd)
            os.fsync(parent)
        after = os.fstat(fd)
        named = os.stat(name, dir_fd=parent, follow_symlinks=False)
        secure(after)
        secure(named)
        require(same(before, named) and same(before, after)
                and (before.st_size, before.st_mtime_ns, before.st_ctime_ns)
                == (after.st_size, after.st_mtime_ns, after.st_ctime_ns), 'path-replaced')
        check = directory(os.path.dirname(path))
        try:
            require(same(os.fstat(check), os.fstat(parent)), 'path-replaced')
        finally:
            os.close(check)
        require(len(data) <= limit, 'size-limit')
        return bytes(data)
    finally:
        if fd is not None:
            os.close(fd)
        os.close(parent)


def load_profile(path):
    raw = read_file(path)
    value = decode(raw)
    require(type(value) is dict and set(value) == PROFILE_FIELDS and type(value['format_version']) is int
            and value['format_version'] == 1 and type(value['customer_id']) is str
            and 0 < len(value['customer_id']) <= 128 and number(value['registration_expires_at_ms'])
            and type(value['nodes']) is list and len(value['nodes']) == 2, 'invalid-profile')
    for key in ('box_dir', 'cli_path'):
        path_value(value[key])
    for node in value['nodes']:
        require(type(node) is dict and set(node) == NODE_FIELDS, 'invalid-node-registration')
        for key in ('node_id', 'vault_id', 'signer_id'):
            identity(node[key])
        for key in ('trust_sha256', 'approval_origin_sha256'):
            require(hex_digest(node[key]), 'invalid-node-registration')
        for key in ('state_dir', 'runtime_dir', 'audit_destination', 'backup_destination'):
            path_value(node[key])
        require(node['runtime_dir'] == node['state_dir'] + '/runtime', 'runtime-target-mismatch')
        require(number(node['admin_uid'], 2**32 - 1) and node['platform'] in ('linux', 'darwin')
                and type(node['responsibility_domain']) is str and 0 < len(node['responsibility_domain']) <= 128
                and number(node['policy_max_lifetime_ms'], 300000) and node['policy_max_lifetime_ms'] > 0,
                'invalid-node-registration')
    for key in ('node_id', 'vault_id', 'signer_id', 'trust_sha256', 'state_dir', 'runtime_dir'):
        require(value['nodes'][0][key] != value['nodes'][1][key], 'nodes-not-distinct')
    check_expiry(value)
    return value, digest(raw)


def check_expiry(profile):
    require(profile['registration_expires_at_ms'] > now_ms(), 'registration-expired')


class Box:
    """One exclusively locked node journal; all writes are create-new and synced."""
    def __init__(self, profile, node):
        self.root_path = profile['box_dir']
        self.path = self.root_path + '/nodes/' + node['node_id']
        self.fds = []
        self.lock = None
        self.children = {}
        self.command_inodes = {}
        try:
            root = directory(self.root_path)
            secure(os.fstat(root), True)
            self.fds.append(root)
            for name in ('nodes', node['node_id']):
                parent = self.fds[-1]
                if name not in os.listdir(parent):
                    os.mkdir(name, 0o700, dir_fd=parent)
                    os.fsync(parent)
                child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
                secure(os.fstat(child), True)
                self.fds.append(child)
            self.fd = self.fds[-1]
            self.lock = os.open('.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK,
                                0o600, dir_fd=self.fd)
            secure(os.fstat(self.lock))
            fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            for name in ('commands', 'receipts'):
                if name not in os.listdir(self.fd):
                    os.mkdir(name, 0o700, dir_fd=self.fd)
                    os.fsync(self.fd)
                child = directory(self.path + '/' + name)
                secure(os.fstat(child), True)
                self.children[name] = child
            self.verify()
        except BaseException:
            self.close()
            raise

    def close(self):
        if self.lock is not None:
            os.close(self.lock)
            self.lock = None
        for fd in self.children.values():
            os.close(fd)
        self.children = {}
        for fd in reversed(self.fds):
            os.close(fd)
        self.fds = []

    def verify(self):
        for path, held in zip((self.root_path, self.root_path + '/nodes', self.path), self.fds):
            check = directory(path)
            try:
                secure(os.fstat(check), True)
                require(same(os.fstat(check), os.fstat(held)), 'path-replaced')
            finally:
                os.close(check)
        named = os.stat('.lock', dir_fd=self.fd, follow_symlinks=False)
        secure(named)
        require(same(named, os.fstat(self.lock)), 'path-replaced')
        require(set(os.listdir(self.fd)) == {'.lock', 'commands', 'receipts'}, 'unexpected-journal-entry')
        total, count = 0, 0
        for kind in ('commands', 'receipts'):
            fd = directory(self.path + '/' + kind)
            try:
                secure(os.fstat(fd), True)
                require(same(os.fstat(fd), os.fstat(self.children[kind])), 'path-replaced')
                names = os.listdir(fd)
                require(len(names) <= MAX_COMMANDS, 'journal-capacity')
                if kind == 'commands':
                    require(set(self.command_inodes) <= set(names), 'path-replaced')
                    count = len(names)
                    require(count <= MAX_COMMANDS, 'journal-capacity')
                for name in names:
                    if kind == 'receipts':
                        identity(name.removesuffix('.json'))
                        require(name.endswith('.json'), 'invalid-receipt-name')
                        info = os.stat(name, dir_fd=fd, follow_symlinks=False)
                        secure(info)
                        require(info.st_size <= MAX_JSON, 'size-limit')
                        total += info.st_size
                    else:
                        identity(name)
                        command_fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                        try:
                            secure(os.fstat(command_fd), True)
                            info = os.fstat(command_fd)
                            inode = (info.st_dev, info.st_ino)
                            require(name not in self.command_inodes or self.command_inodes[name] == inode, 'path-replaced')
                            self.command_inodes[name] = inode
                            children = os.listdir(command_fd)
                            require(set(children) <= {'command.json', 'policy.json', 'intent.json'}, 'unexpected-command-entry')
                            for child in children:
                                info = os.stat(child, dir_fd=command_fd, follow_symlinks=False)
                                secure(info)
                                require(info.st_size <= (MAX_POLICY if child == 'policy.json' else MAX_JSON), 'size-limit')
                                total += info.st_size
                        finally:
                            os.close(command_fd)
            finally:
                os.close(fd)
        require(total <= MAX_JOURNAL, 'journal-capacity')
        return total, count

    def path_for(self, command_id, name):
        identity(command_id)
        return self.path + ('/receipts/' + command_id + '.json' if name == 'receipt'
                            else '/commands/' + command_id + '/' + name)

    def exists(self, command_id, name):
        self.verify()
        return os.path.lexists(self.path_for(command_id, name))

    def read(self, command_id, name, raw=False):
        self.verify()
        data = read_file(self.path_for(command_id, name), MAX_POLICY if name == 'policy.json' else MAX_JSON)
        self.verify()
        return data if raw else decode(data)

    def write(self, command_id, name, value, raw=False):
        data = value if raw else encode(value)
        require(len(data) <= (MAX_POLICY if name == 'policy.json' else MAX_JSON), 'size-limit')
        total, _ = self.verify()
        require(total + len(data) <= MAX_JOURNAL, 'journal-capacity')
        path = self.path_for(command_id, name)
        parent = directory(os.path.dirname(path))
        fd = None
        try:
            secure(os.fstat(parent), True)
            fd = os.open(os.path.basename(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                         0o600, dir_fd=parent)
            secure(os.fstat(fd))
            offset = 0
            while offset < len(data):
                written = os.write(fd, data[offset:])
                require(written > 0, 'write-failed')
                offset += written
            os.fsync(fd)
            self.verify()
            check = directory(os.path.dirname(path))
            try:
                require(same(os.fstat(parent), os.fstat(check))
                        and same(os.fstat(fd), os.stat(os.path.basename(path), dir_fd=check, follow_symlinks=False)),
                        'path-replaced')
            finally:
                os.close(check)
            os.fsync(parent)
            self.verify()
        finally:
            if fd is not None:
                os.close(fd)
            os.close(parent)

    def create(self, command_id, required_bytes):
        total, count = self.verify()
        require(count < MAX_COMMANDS and total + required_bytes + 2 * MAX_JSON <= MAX_JOURNAL, 'journal-capacity')
        parent = directory(self.path + '/commands')
        try:
            os.mkdir(identity(command_id), 0o700, dir_fd=parent)
            os.fsync(parent)
            self.verify()
        finally:
            os.close(parent)


def artifact(raw, node, valid_time=True):
    bundle = decode(raw)
    require(type(bundle) is dict and set(bundle) == {'format_version', 'signer_id', 'snapshot', 'signature'}
            and type(bundle['format_version']) is int and bundle['format_version'] == 1
            and bundle['signer_id'] == node['signer_id'] and type(bundle['signature']) is str
            and type(bundle['snapshot']) is dict, 'invalid-policy-artifact')
    snapshot = bundle['snapshot']
    require(number(snapshot.get('version'), 2**64 - 1) and snapshot['version'] > 0
            and number(snapshot.get('expires_at_ms')), 'invalid-policy-artifact')
    if valid_time:
        remaining = snapshot['expires_at_ms'] - now_ms()
        require(0 < remaining <= node['policy_max_lifetime_ms'], 'policy-expired-or-lifetime')
    return snapshot


def bindings(profile, profile_sha, node, command_id, raw):
    snapshot = artifact(raw, node, valid_time=False)
    return {'format_version': 1, 'profile_sha256': profile_sha, 'customer_id': profile['customer_id'],
            'node_id': node['node_id'], 'vault_id': node['vault_id'], 'signer_id': node['signer_id'],
            'trust_sha256': node['trust_sha256'], 'approval_origin_sha256': node['approval_origin_sha256'],
            'command_id': identity(command_id), 'version': snapshot['version'],
            'bundle_sha256': digest(raw), 'expires_at_ms': snapshot['expires_at_ms']}


def publish(box, profile, profile_sha, node, command_id, policy_path, trust_path):
    check_expiry(profile)
    raw = read_file(policy_path, MAX_POLICY)
    artifact(raw, node)
    trust_raw = read_file(trust_path)
    trust = decode(trust_raw)
    require(type(trust) is dict and set(trust) == {'format_version', 'signer_id', 'algorithm', 'public_key'}
            and type(trust['format_version']) is int and trust['format_version'] == 1
            and trust['signer_id'] == node['signer_id'] and trust['algorithm'] == 'ed25519'
            and hex_digest(trust['public_key']) and digest(trust_raw) == node['trust_sha256'], 'trust-artifact-mismatch')
    command = bindings(profile, profile_sha, node, command_id, raw)
    if os.path.lexists(box.path + '/commands/' + identity(command_id)):
        require(box.read(command_id, 'command.json') == command
                and box.read(command_id, 'policy.json', True) == raw, 'command-id-conflict')
    else:
        box.create(command_id, len(raw) + len(encode(command)))
        box.write(command_id, 'policy.json', raw, True)
        box.write(command_id, 'command.json', command)
    return {'status': 'uploaded/unconfirmed', 'command': command}


def read_command(box, profile, profile_sha, node, command_id):
    raw = box.read(command_id, 'policy.json', True)
    command = box.read(command_id, 'command.json')
    require(type(command) is dict and set(command) == COMMAND_FIELDS
            and encode(command) == encode(bindings(profile, profile_sha, node, command_id, raw)), 'command-target-or-content-mismatch')
    return command, raw


class Cli:
    def __init__(self, profile, node, deadline, admin_session_file=None):
        self.profile, self.node, self.deadline = profile, node, deadline
        require(admin_session_file is None or (type(admin_session_file) is str
                and os.path.isabs(admin_session_file)), 'session-file-must-be-absolute')
        self.admin_session_file = admin_session_file

    def local_target(self):
        require(os.geteuid() == self.node['admin_uid'] and sys.platform == self.node['platform'], 'wrong-local-node')
        for path in (self.node['state_dir'], self.node['runtime_dir']):
            fd = directory(path)
            try:
                secure(os.fstat(fd), True, self.node['admin_uid'])
            finally:
                os.close(fd)
        executable = self.profile['cli_path']
        parent = directory(os.path.dirname(executable), executable_owner=self.node['admin_uid'])
        try:
            info = os.stat(os.path.basename(executable), dir_fd=parent, follow_symlinks=False)
            require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == self.node['admin_uid']
                    and info.st_mode & 0o111 and info.st_mode & 0o022 == 0, 'unsafe-cli-executable')
        finally:
            os.close(parent)

    def call(self, args):
        check_expiry(self.profile)
        self.local_target()
        require(time.monotonic() < self.deadline, 'operation-timeout')
        tty_fd, tty_attrs = None, None
        if args[:2] == ['policy', 'activate']:
            try:
                tty_fd = os.open('/dev/tty', os.O_RDONLY | os.O_NOCTTY | os.O_NONBLOCK)
            except OSError as error:
                if error.errno not in (errno.ENXIO, errno.ENOENT):
                    raise Error('tty-state-capture-failed') from None
            if tty_fd is not None:
                try:
                    tty_attrs = termios.tcgetattr(tty_fd)
                except (OSError, termios.error):
                    os.close(tty_fd)
                    raise Error('tty-state-capture-failed') from None
        result = None
        try:
            # No new session/process group: the CLI retains its controlling hidden TTY.
            command = [self.profile['cli_path'], '--state-dir', self.node['state_dir']]
            if self.admin_session_file is not None:
                command += ['--admin-session-file', self.admin_session_file]
            child = subprocess.Popen(command + args,
                                     stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                     cwd=self.node['state_dir'], env={'LANG': 'C', 'LC_ALL': 'C'}, shell=False)
            output = [bytearray(), bytearray()]
            issue = None
            selector = selectors.DefaultSelector()
            try:
                for index, stream in enumerate((child.stdout, child.stderr)):
                    os.set_blocking(stream.fileno(), False)
                    selector.register(stream, selectors.EVENT_READ, index)
                while selector.get_map():
                    remaining = self.deadline - time.monotonic()
                    if remaining <= 0:
                        issue = 'child-timeout'
                        break
                    for key, _ in selector.select(min(remaining, 0.1)):
                        part = os.read(key.fileobj.fileno(), 8192)
                        if not part:
                            selector.unregister(key.fileobj)
                        else:
                            output[key.data].extend(part)
                            if len(output[key.data]) > MAX_JSON:
                                del output[key.data][MAX_JSON:]
                                issue = 'child-output-limit'
                                break
                    if issue:
                        break
                if issue:
                    child.kill()
                try:
                    child.wait(timeout=max(0.001, self.deadline - time.monotonic()))
                except subprocess.TimeoutExpired:
                    issue = 'child-timeout'
                    child.kill()
                    child.wait()
            finally:
                if child.poll() is None:
                    child.kill()
                    child.wait()
                selector.close()
                child.stdout.close()
                child.stderr.close()
            # Preserve an open CLI code without storing arbitrary messages or proof text.
            match = re.search(rb'error \[([^\]\r\n]{1,128})\]:', output[1])
            code = match.group(1).decode('ascii', 'replace') if match else None
            result = {'exit': child.returncode, 'code': code, 'issue': issue, 'stdout': bytes(output[0])}
            return result
        finally:
            if tty_fd is not None:
                try:
                    # Metadata only: discard unread input, never read proof bytes.
                    termios.tcsetattr(tty_fd, termios.TCSAFLUSH, tty_attrs)
                except (OSError, termios.error):
                    if result is not None:
                        raise CliError(dict(result, issue='tty-state-restore-failed')) from None
                    raise Error('tty-state-restore-failed') from None
                finally:
                    os.close(tty_fd)

    def json(self, args):
        result = self.call(args)
        if result['exit'] != 0 or result['issue']:
            raise CliError(result)
        return decode(result['stdout'])


class CliError(Error):
    def __init__(self, result):
        self.result = result
        super().__init__(result['issue'] or 'cli-error')


def preflight(cli, node):
    actual = cli.json(['policy', 'status'])
    require(type(actual) is dict and actual.get('vault_id') == node['vault_id']
            and actual.get('tenant_id') == node['vault_id'] and actual.get('trust_installed') is True
            and actual.get('trust_sha256') == node['trust_sha256'], 'actual-target-or-root-mismatch')
    origin = cli.json(['approval', 'origin'])
    require(type(origin) is dict and set(origin) == {'algorithm', 'public_key'}
            and origin['algorithm'] == 'ed25519' and hex_digest(origin['public_key'])
            and digest(bytes.fromhex(origin['public_key'])) == node['approval_origin_sha256'], 'actual-origin-mismatch')
    return actual


def audit_evidence(cli, command, actual):
    snapshot, cursor = None, None
    reason = 'policy-activated:' + str(command['version']) + ':' + command['bundle_sha256']
    for _ in range(10):
        args = ['audit', 'list', '--limit', '25']
        if snapshot is not None:
            args += ['--snapshot-max-sequence', str(snapshot)]
        if cursor is not None:
            args += ['--before-sequence', str(cursor)]
        page = cli.json(args)
        require(type(page) is dict and set(page) == {'schema', 'snapshot_max_sequence', 'events', 'next_before_sequence'}
                and page['schema'] == 'rekey.audit.v2' and number(page['snapshot_max_sequence'])
                and page['snapshot_max_sequence'] > 0 and type(page['events']) is list
                and len(page['events']) <= 25, 'invalid-audit-page')
        require(snapshot is None or snapshot == page['snapshot_max_sequence'], 'audit-snapshot-changed')
        snapshot = page['snapshot_max_sequence']
        previous = cursor if cursor is not None else snapshot + 1
        found = None
        for event in page['events']:
            require(type(event) is dict and number(event.get('sequence')) and 0 < event['sequence'] < previous
                    and event['sequence'] <= snapshot and event.get('record_type') == 'rekey.audit.v2', 'invalid-audit-order')
            previous = event['sequence']
            if (event.get('event_type') == 'policy.activated' and event.get('outcome') == 'success'
                    and event.get('reason_code') == reason and number(event.get('created_at_ms'))):
                found = {key: event[key] for key in ('sequence', 'event_id', 'event_type', 'outcome', 'reason_code', 'created_at_ms')}
                require(type(found['event_id']) is str and re.fullmatch('[0-9a-f]{32}', found['event_id']), 'invalid-audit-event')
        next_cursor = page['next_before_sequence']
        require(next_cursor is None or (number(next_cursor) and 0 < next_cursor <= snapshot
                and (cursor is None or next_cursor < cursor)
                and all(event['sequence'] >= next_cursor for event in page['events'])
                and (page['events'] or next_cursor < snapshot)), 'invalid-audit-cursor')
        if found:
            return found, snapshot
        if next_cursor is None:
            break
        cursor = next_cursor
    raise Error('activation-audit-unconfirmed')


def historical_receipt(box, command):
    if not box.exists(command['command_id'], 'receipt'):
        return None
    raw = box.read(command['command_id'], 'receipt', raw=True)
    receipt = decode(raw)
    require(type(receipt) is dict and set(receipt) == {'format_version', 'status', 'command', 'tenant_id',
            'policy_sha256', 'activated_at_ms', 'observed_at_ms', 'current_policy_status', 'audit_event', 'audit_snapshot'}
            and type(receipt['format_version']) is int and receipt['format_version'] == 1
            and receipt['status'] == 'applied' and encode(receipt['command']) == encode(command)
            and receipt['tenant_id'] == command['vault_id'] and hex_digest(receipt['policy_sha256'])
            and number(receipt['activated_at_ms']) and number(receipt['observed_at_ms'])
            and receipt['current_policy_status'] in ('active', 'expired') and number(receipt['audit_snapshot']), 'invalid-receipt')
    event = receipt['audit_event']
    require(type(event) is dict and set(event) == {'sequence', 'event_id', 'event_type', 'outcome', 'reason_code', 'created_at_ms'}
            and number(event['sequence']) and 0 < event['sequence'] <= receipt['audit_snapshot']
            and type(event['event_id']) is str and re.fullmatch('[0-9a-f]{32}', event['event_id'])
            and event['event_type'] == 'policy.activated' and event['outcome'] == 'success'
            and number(event['created_at_ms'])
            and event['reason_code'] == 'policy-activated:' + str(command['version']) + ':' + command['bundle_sha256'],
            'invalid-receipt')
    box.verify()
    read_file(box.path_for(command['command_id'], 'receipt'), durable=True, expected=raw)
    box.verify()
    return receipt


def observe(box, cli, node, command):
    actual = preflight(cli, node)
    receipt = historical_receipt(box, command)
    exact = (actual.get('status') in ('active', 'expired') and actual.get('bundle_persisted') is True
             and actual.get('signer_id') == node['signer_id'] and actual.get('version') == command['version']
             and actual.get('bundle_sha256') == command['bundle_sha256']
             and actual.get('expires_at_ms') == command['expires_at_ms']
             and number(actual.get('activated_at_ms')) and hex_digest(actual.get('policy_sha256')))
    if not exact:
        if receipt:
            return dict(receipt, historical_confirmation=True, current_policy_status=actual.get('status'),
                        current_version=actual.get('version'))
        raise Error('activation-status-unconfirmed')
    event, snapshot = audit_evidence(cli, command, actual)
    return {'format_version': 1, 'status': 'applied', 'command': command, 'tenant_id': actual['tenant_id'],
            'policy_sha256': actual['policy_sha256'], 'activated_at_ms': actual['activated_at_ms'],
            'observed_at_ms': now_ms(), 'current_policy_status': actual['status'],
            'audit_event': event, 'audit_snapshot': snapshot}


def execute(operation, box, profile, profile_sha, node, command_id, cli=None):
    deadline = time.monotonic() + RUN_SECONDS
    cli = cli or Cli(profile, node, deadline)
    dispatched = False
    mutation = None
    try:
        command, raw = read_command(box, profile, profile_sha, node, command_id)
        check_expiry(profile)
        if operation == 'status':
            actual = preflight(cli, node)
            require(time.monotonic() < cli.deadline if isinstance(cli, Cli) else time.monotonic() < deadline, 'operation-timeout')
            return {'status': 'observed/unconfirmed', 'command': command, 'actual': actual}, 0
        # Once intent exists a crash may have dispatched. Never automatically resend.
        if operation == 'reconcile' or box.exists(command_id, 'intent.json'):
            dispatched = box.exists(command_id, 'intent.json')
            if dispatched:
                require(box.read(command_id, 'intent.json') == {'format_version': 1, 'command': command}, 'intent-conflict')
            result = observe(box, cli, node, command)
            require(time.monotonic() < cli.deadline if isinstance(cli, Cli) else time.monotonic() < deadline, 'operation-timeout')
            return result, 0
        preflight(cli, node)
        artifact(raw, node)
        check_expiry(profile)
        require(time.monotonic() < deadline, 'operation-timeout')
        box.write(command_id, 'intent.json', {'format_version': 1, 'command': command})
        # Everything after durable intent is conservative: starting a child can fail.
        dispatched = True
        mutation = cli.call(['policy', 'activate', '--file', box.path_for(command_id, 'policy.json'),
                             '--expected-vault-id', node['vault_id'], '--expected-trust-sha256', node['trust_sha256']])
        result = observe(box, cli, node, command)
        require(time.monotonic() < cli.deadline if isinstance(cli, Cli) else time.monotonic() < deadline, 'operation-timeout')
        if not box.exists(command_id, 'receipt'):
            box.write(command_id, 'receipt', result)
        else:
            historical_receipt(box, command)
        require(time.monotonic() < cli.deadline if isinstance(cli, Cli) else time.monotonic() < deadline, 'operation-timeout')
        if mutation:
            result = dict(result, cli_exit=mutation['exit'], cli_code=mutation['code'], cli_issue=mutation['issue'])
        return result, mutation['exit'] if mutation['exit'] != 0 else 0
    except (Error, OSError, ValueError, KeyError, TypeError, RecursionError) as error:
        result = {'status': 'unknown' if dispatched or operation == 'reconcile' else 'rejected',
                  'command_id': command_id, 'node_id': node['node_id'],
                  'error': str(error) if isinstance(error, Error) else 'local-storage-or-input-failure'}
        failure = mutation or (error.result if isinstance(error, CliError) else None)
        exit_code = 1
        if failure:
            result.update(cli_exit=failure['exit'], cli_code=failure['code'], cli_issue=failure['issue'])
            exit_code = failure['exit'] if failure['exit'] != 0 else 1
        return result, exit_code


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='operation', required=True)
    for name in ('publish', 'apply', 'status', 'reconcile'):
        command = commands.add_parser(name)
        for flag in ('profile', 'node', 'command-id'):
            command.add_argument('--' + flag, required=True)
        if name == 'publish':
            command.add_argument('--policy', required=True, help='independent signer canonical policy.json')
            command.add_argument('--trust', required=True, help='independent signer canonical trust.json')
        else:
            command.add_argument('--admin-session-file', help='explicit absolute private login file for this node')
    args = parser.parse_args(argv)
    box = None
    try:
        started = time.monotonic()
        profile, profile_sha = load_profile(args.profile)
        identity(args.node)
        identity(args.command_id)
        matches = [node for node in profile['nodes'] if node['node_id'] == args.node]
        require(len(matches) == 1, 'node-not-registered')
        node = matches[0]
        box = Box(profile, node)
        require(time.monotonic() - started < RUN_SECONDS, 'operation-timeout')
        if args.operation == 'publish':
            result = publish(box, profile, profile_sha, node, args.command_id, args.policy, args.trust)
            code = 0
        else:
            cli = Cli(profile, node, started + RUN_SECONDS, args.admin_session_file)
            result, code = execute(args.operation, box, profile, profile_sha, node, args.command_id, cli)
        require(time.monotonic() - started < RUN_SECONDS or result.get('status') == 'unknown', 'operation-timeout')
        sys.stdout.buffer.write(encode(result))
        return code if code >= 0 else 128 - code
    except (Error, OSError, ValueError, KeyError, TypeError, RecursionError) as error:
        sys.stdout.buffer.write(encode({'status': 'rejected', 'error': str(error) if isinstance(error, Error)
                                      else 'local-storage-or-input-failure'}))
        return 1
    finally:
        if box:
            box.close()


if __name__ == '__main__':
    sys.exit(main())
