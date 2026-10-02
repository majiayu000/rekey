#!/usr/bin/env python3
"""Supervise two Docker Rekey nodes with encrypted replicas and fenced failover."""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import sys
import tempfile
import time
import uuid

STATE = '/vault/state'
LABEL = 'rekey.ha.cluster'


class HAError(Exception):
    pass


def command(args, data=None, timeout=90):
    try:
        result = subprocess.run(args, input=data, capture_output=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        raise HAError('command timed out; outcome unconfirmed') from None
    if result.returncode:
        raise HAError('command failed with exit ' + str(result.returncode))
    return result.stdout


def docker(*args, data=None, timeout=90):
    return command(['docker', *args], data, timeout)


def require(condition, message):
    if not condition:
        raise HAError(message)


def private_directory(path):
    info = path.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid()
            and stat.S_IMODE(info.st_mode) == 0o700, 'directory must be owned and mode 0700')


def write_json(path, value):
    temporary = path.parent / ('.write-' + uuid.uuid4().hex)
    try:
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'w', encoding='utf-8') as handle:
            handle.write(json.dumps(value, indent=2) + '\n')
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    finally:
        temporary.unlink(missing_ok=True)


def proof_from_stdin():
    proof = sys.stdin.buffer.readline(4097)
    require(proof.endswith(b'\n') and 1 < len(proof) <= 4096 and b'\0' not in proof
            and b'\r' not in proof, 'expected one nonempty proof line on stdin')
    return proof


class Controller:
    def __init__(self, directory, state):
        self.directory = directory
        self.state = state

    def save(self):
        write_json(self.directory / 'cluster.json', self.state)

    def nodes(self):
        # A daemon failure must raise, never look like an absent container.
        return docker('container', 'ls', '--all', '--no-trunc', '--format', '{{.ID}}').decode().split()

    def owned(self, identity):
        if identity in self.nodes():
            info = json.loads(docker('inspect', identity))[0]
            require(info['Config'].get('Labels', {}).get(LABEL) == self.state['cluster'],
                    'refusing unowned container')
            return info
        return None

    def cli(self, node, *args, proof=None):
        return json.loads(docker('exec', '-i', node['id'], 'rekey', '--state-dir', STATE,
                                 *args, data=proof, timeout=5 if args == ('status',) else 90))

    def new_node(self):
        suffix = uuid.uuid4().hex
        volume = 'rekey-ha-' + suffix
        label = LABEL + '=' + self.state['cluster']
        docker('volume', 'create', '--label', label, volume)
        # Persist volume ownership before effects whose completion may be unknown.
        self.state['volumes'].append(volume)
        self.save()
        docker('run', '--rm', '--label', label, '--network', 'none', '--read-only',
               '--mount', 'type=volume,src=' + volume + ',dst=/vault', self.state['image'],
               'sh', '-c', 'chown 10001:10001 /vault && chmod 0700 /vault')
        identity = docker('run', '-d', '--name', volume, '--label', label,
                          '--user', '10001:10001', '--network', self.state['network'],
                          '--restart', 'no', '--read-only', '--cap-drop', 'ALL',
                          '--security-opt', 'no-new-privileges', '--log-driver', 'none',
                          '--tmpfs', '/tmp:rw,noexec,nosuid,size=16m', '--mount',
                          'type=volume,src=' + volume + ',dst=/vault', self.state['image'],
                          'sleep', 'infinity').decode().strip()
        return {'id': identity, 'volume': volume}

    def start(self, node):
        docker('exec', '-d', node['id'], 'rekeyd', 'serve', '--state-dir', STATE)
        end = time.monotonic() + 20
        while time.monotonic() < end:
            try:
                require(self.cli(node, 'status')['state'] == 'locked', 'startup must be locked')
                return
            except HAError:
                time.sleep(.1)
        raise HAError('broker startup failed')

    def validate_node(self, node):
        info = self.owned(node['id'])
        require(info is not None, 'recorded container is absent')
        host = info['HostConfig']
        require(info['Image'] == self.state['image'] and info['Config']['User'] == '10001:10001'
                and host['RestartPolicy']['Name'] == 'no' and host['ReadonlyRootfs']
                and host['CapDrop'] == ['ALL'] and host['NetworkMode'] == self.state['network']
                and host['PidMode'] == '' and host['IpcMode'] == 'private'
                and len(info['Mounts']) == 1 and info['Mounts'][0]['Name'] == node['volume'],
                'node isolation or identity changed')

    def replicate(self, proof):
        primary, standby = self.state['primary'], self.state['standby']
        self.validate_node(primary)
        self.validate_node(standby)
        path = '/vault/replica-' + uuid.uuid4().hex + '.rkbackup'
        receipt = self.cli(primary, 'backup', '--output', path, '--password-stdin', proof=proof)
        with tempfile.TemporaryDirectory(prefix='.transfer-', dir=self.directory) as directory:
            local = Path(directory) / 'snapshot.rkbackup'
            docker('cp', primary['id'] + ':' + path, str(local))
            digest = hashlib.sha256()
            with local.open('rb') as source:
                for block in iter(lambda: source.read(1024 * 1024), b''):
                    digest.update(block)
            require(digest.hexdigest() == receipt['sha256_hex'], 'source replica digest mismatch')
            with local.open('rb') as source:
                try:
                    copied = subprocess.run(['docker', 'exec', '-i', standby['id'], 'sh', '-c',
                        'umask 077; set -C; cat > "$1"', 'sh', path], stdin=source,
                        capture_output=True, timeout=90)
                except subprocess.TimeoutExpired:
                    raise HAError('replica transfer timed out; outcome unconfirmed') from None
                require(copied.returncode == 0, 'replica transfer failed')
        actual = docker('exec', standby['id'], 'sha256sum', path).decode().split()[0]
        require(actual == receipt['sha256_hex'], 'standby replica digest mismatch')
        docker('exec', standby['id'], 'sync', '-f', path)
        receipt['output_path'] = path
        docker('exec', '-i', standby['id'], 'sh', '-c', 'umask 077; set -C; cat > "$1"',
               'sh', path + '.json', data=(json.dumps(receipt) + '\n').encode())
        docker('exec', standby['id'], 'sync', '-f', path + '.json')
        # Status publication occurs only after verified, durable transport.
        previous = self.state.get('replica')
        if previous:
            require(isinstance(previous['receipt']['output_path'], str)
                    and re.fullmatch(r'/vault/replica-[0-9a-f]{32}\.rkbackup', previous['receipt']['output_path']) is not None,
                    'previous replica path is outside the owned namespace')
        self.state['replica'] = {'receipt': receipt, 'container_id': standby['id'],
                                 'completed_at_ms': time.time_ns() // 1_000_000}
        self.save()
        docker('exec', primary['id'], 'rm', '--', path)
        if previous and previous['container_id'] == standby['id']:
            prior = previous['receipt']['output_path']
            docker('exec', standby['id'], 'rm', '--', prior, prior + '.json')

    def fence(self, primary):
        if self.owned(primary['id']) is not None:
            docker('container', 'rm', '--force', primary['id'])
        require(self.owned(primary['id']) is None, 'primary fencing unconfirmed')
        # A second container mounting the old state would invalidate quiescence.
        require(not docker('container', 'ls', '--all', '--filter', 'volume=' + primary['volume'],
                           '--format', '{{.ID}}').strip(),
                'old volume remains attached to another container')

    def copy_final_state(self, primary, standby):
        volume = json.loads(docker('volume', 'inspect', primary['volume']))[0]
        require(volume.get('Labels', {}).get(LABEL) == self.state['cluster'],
                'final source volume is missing or unowned')
        require(self.owned(primary['id']) is None, 'primary is not fenced')
        # The entire committed DB+WAL is now quiescent. Never copy a live DB or
        # substitute the periodic replica when final state is unavailable.
        script = '''set -eu
test -f /source/state/vault.sqlite3
test ! -e /vault/state
mkdir -m 700 /vault/state
tar -C /source/state --exclude=./runtime --exclude=./broker.lock -cf /tmp/final.tar .
tar -C /vault/state -xf /tmp/final.tar
sync -f /vault/state
'''
        docker('run', '--rm', '--label', LABEL + '=' + self.state['cluster'],
               '--network', 'none', '--user', '10001:10001', '--read-only', '--cap-drop', 'ALL',
               '--security-opt', 'no-new-privileges', '--log-driver', 'none',
               '--tmpfs', '/tmp:rw,noexec,nosuid', '--mount',
               'type=volume,src=' + primary['volume'] + ',dst=/source,readonly', '--mount',
               'type=volume,src=' + standby['volume'] + ',dst=/vault',
               self.state['image'], 'sh', '-c', script)

    def promote(self, proof):
        primary, standby = self.state['primary'], self.state['standby']
        self.validate_node(standby)
        self.state['phase'] = 'fencing'
        self.save()
        started = time.monotonic_ns()
        self.fence(primary)
        self.copy_final_state(primary, standby)
        self.start(standby)
        self.cli(standby, 'unlock', '--password-stdin', proof=proof)
        require(self.cli(standby, 'status')['state'] == 'unlocked', 'promoted broker is not ready')
        self.state['primary'] = standby
        self.state['generation'] += 1
        self.state['last_recovery_ms'] = (time.monotonic_ns() - started) / 1_000_000
        self.state['standby'] = self.new_node()
        self.state['replica'] = None
        self.state['phase'] = 'ready'
        self.save()

    def healthy(self):
        self.nodes()  # Confirm daemon availability before interpreting health.
        node = self.owned(self.state['primary']['id'])
        if node is None or not node['State']['Running']:
            return False
        try:
            status = self.cli(self.state['primary'], 'status')
        except HAError:
            return False
        require(status['state'] != 'locked', 'primary is locked; supervision stopped')
        return status['state'] == 'unlocked'

    def tick(self, proof):
        if not self.healthy():
            self.promote(proof)
        try:
            self.replicate(proof)
        except HAError:
            # The primary may die during backup/transfer/cleanup. A failed
            # replication alone cannot authorize fencing: check health anew.
            if self.healthy():
                raise
            self.promote(proof)
            self.replicate(proof)


def create(directory, image, proof):
    directory.mkdir(mode=0o700)  # Existing directories/vaults are never overwritten.
    descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        info = json.loads(docker('image', 'inspect', image))[0]
        require(info['Os'] == 'linux', 'Linux image required')
        cluster = uuid.uuid4().hex
        state = {'cluster': cluster, 'image': info['Id'], 'network': 'rekey-ha-' + cluster,
                 'phase': 'creating', 'volumes': [], 'generation': 1, 'replica': None}
        controller = Controller(directory, state)
        controller.save()
        docker('network', 'create', '--label', LABEL + '=' + cluster, state['network'])
        state['primary'] = controller.new_node()
        state['standby'] = controller.new_node()
        controller.save()
        recovery = docker('exec', '-i', state['primary']['id'], 'rekeyd', 'init', '--state-dir', STATE,
                          '--password-stdin', data=proof)
        controller.start(state['primary'])
        state['phase'] = 'ready'
        controller.save()
        return recovery
    finally:
        os.close(descriptor)


def destroy(controller):
    label = LABEL + '=' + controller.state['cluster']
    # Enumeration includes helpers whose create/remove reply may have been lost.
    for kind, template, remove in [('container', '{{.ID}}', ('rm', '--force')),
                                   ('volume', '{{.Name}}', ('rm',)),
                                   ('network', '{{.ID}}', ('rm',))]:
        args = [kind, 'ls', '--filter', 'label=' + label, '--format', template]
        if kind == 'container':
            args.insert(2, '--all')
        resources = docker(*args).decode().split()
        if resources:
            docker(kind, *remove, *resources)
        require(not docker(*args).strip(), 'owned cleanup incomplete')
    controller.state['phase'] = 'destroyed'
    controller.save()


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, required=True)
    commands = parser.add_subparsers(dest='operation', required=True)
    initialize = commands.add_parser('create')
    initialize.add_argument('--image', required=True)
    initialize.add_argument('--password-stdin', action='store_true', required=True)
    watch = commands.add_parser('run')
    watch.add_argument('--interval-seconds', type=int, default=30)
    watch.add_argument('--password-stdin', action='store_true', required=True)
    commands.add_parser('status')
    commands.add_parser('destroy')
    args = parser.parse_args()
    if args.operation == 'create':
        sys.stdout.buffer.write(create(args.directory, args.image, proof_from_stdin()))
        return
    private_directory(args.directory)
    descriptor = os.open(args.directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        if args.operation != 'status':
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        state = json.loads((args.directory / 'cluster.json').read_bytes())
        controller = Controller(args.directory, state)
        if args.operation == 'status':
            print(json.dumps(state, indent=2))
        elif args.operation == 'destroy':
            destroy(controller)
        else:
            require(1 <= args.interval_seconds <= 3600, 'interval must be 1..3600 seconds')
            require(state['phase'] == 'ready', 'interrupted transition requires operator recovery')
            proof = proof_from_stdin()
            primary = controller.owned(state['primary']['id'])
            if primary is not None and primary['State']['Running']:
                controller.validate_node(state['primary'])
                try:
                    locked = controller.cli(state['primary'], 'status')['state'] == 'locked'
                except HAError:
                    locked = False  # tick must independently prove fence before recovery.
                if locked:
                    controller.cli(state['primary'], 'unlock', '--password-stdin', proof=proof)
            while True:
                controller.tick(proof)
                time.sleep(args.interval_seconds)
    finally:
        os.close(descriptor)


if __name__ == '__main__':
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(143))
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)
    except (HAError, OSError, ValueError, KeyError) as error:
        # No raw subprocess output or arbitrary configuration content.
        print('Docker HA operation failed: ' + (str(error) if isinstance(error, HAError) else type(error).__name__), file=sys.stderr)
        sys.exit(1)
