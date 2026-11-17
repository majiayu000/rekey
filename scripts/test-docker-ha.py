#!/usr/bin/env python3
"""Controller failure contracts; --image additionally runs real disposable Docker HA."""
import copy
import fcntl
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import tempfile
import time
import types
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).with_name('rekey-docker-ha.py')
SPEC = importlib.util.spec_from_file_location('ha', SCRIPT)
ha = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ha)


class Contracts(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.directory = Path(self.temporary.name)
        self.primary = {'id': 'a' * 64, 'volume': 'primary'}
        self.standby = {'id': 'b' * 64, 'volume': 'standby'}
        self.state = {'primary': self.primary, 'standby': self.standby, 'phase': 'ready',
                      'cluster': 'test', 'generation': 1}
        self.controller = ha.Controller(self.directory, self.state)
        self.addCleanup(self.temporary.cleanup)

    def test_daemon_failure_is_not_absence(self):
        with patch.object(ha, 'docker', side_effect=ha.HAError('daemon unavailable')):
            with self.assertRaises(ha.HAError):
                self.controller.fence(self.primary)

    def test_stopped_primary_requires_delete_and_absence(self):
        with patch.object(self.controller, 'owned', side_effect=[{'State': {'Running': False}}, None]), \
             patch.object(ha, 'docker', return_value=b'') as docker:
            self.controller.fence(self.primary)
        self.assertEqual(docker.call_args_list[0].args[1:], ('container', 'rm', '--force', self.primary['id']))

    def test_unowned_container_is_refused(self):
        with patch.object(self.controller, 'nodes', return_value=[self.primary['id']]), \
             patch.object(ha, 'docker', return_value=json.dumps([{'Config': {'Labels': {ha.LABEL: 'other'}}}]).encode()):
            with self.assertRaisesRegex(ha.HAError, 'unowned'):
                self.controller.owned(self.primary['id'])

    def test_fence_failure_never_copies_or_publishes(self):
        with patch.object(self.controller, 'validate_node'), \
             patch.object(self.controller, 'fence', side_effect=ha.HAError('no fence')), \
             patch.object(self.controller, 'copy_final_state') as copy:
            with self.assertRaises(ha.HAError):
                self.controller.promote(b'synthetic\n')
            copy.assert_not_called()
        self.assertEqual(json.loads((self.directory / 'cluster.json').read_text())['phase'], 'fencing')

    def test_missing_final_state_never_falls_back_to_replica(self):
        with patch.object(self.controller, 'validate_node'), patch.object(self.controller, 'fence'), \
             patch.object(self.controller, 'copy_final_state', side_effect=ha.HAError('disk lost')), \
             patch.object(self.controller, 'start') as start:
            with self.assertRaises(ha.HAError):
                self.controller.promote(b'synthetic\n')
            start.assert_not_called()

    def test_locked_primary_is_not_automatically_unlocked(self):
        with patch.object(self.controller, 'nodes'), \
             patch.object(self.controller, 'owned', return_value={'State': {'Running': True}}), \
             patch.object(self.controller, 'cli', return_value={'state': 'locked'}) as cli, \
             patch.object(self.controller, 'promote') as promote:
            with self.assertRaisesRegex(ha.HAError, 'locked'):
                self.controller.tick(b'synthetic\n')
            self.assertEqual(cli.call_count, 1)
            promote.assert_not_called()

    def test_replica_failure_alone_does_not_trigger_fencing(self):
        with patch.object(self.controller, 'healthy', return_value=True), \
             patch.object(self.controller, 'replicate', side_effect=ha.HAError('copy failed')), \
             patch.object(self.controller, 'promote') as promote:
            with self.assertRaisesRegex(ha.HAError, 'copy failed'):
                self.controller.tick(b'synthetic\n')
            promote.assert_not_called()

    def test_primary_death_during_replication_recovers_without_retrying_old_node(self):
        with patch.object(self.controller, 'healthy', side_effect=[True, False]), \
             patch.object(self.controller, 'replicate', side_effect=[ha.HAError('copy failed'), None]) as replicate, \
             patch.object(self.controller, 'promote') as promote:
            self.controller.tick(b'synthetic\n')
            promote.assert_called_once()
            self.assertEqual(replicate.call_count, 2)

    def saved(self):
        return json.loads((self.directory / 'cluster.json').read_text())

    def promotion_patches(self, cli):
        return [patch.object(self.controller, name) for name in
                ('validate_node', 'fence', 'copy_final_state', 'start')] + \
               [patch.object(self.controller, 'cli', side_effect=cli)]

    def test_duplicate_controller_is_refused_without_disclosing_proof(self):
        directory = self.directory / 'cluster'
        directory.mkdir(mode=0o700)
        (directory / 'cluster.json').write_text(json.dumps(self.state))
        holder = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(os.close, holder)
        fcntl.flock(holder, fcntl.LOCK_EX | fcntl.LOCK_NB)
        no_docker = self.directory / 'empty-path'
        no_docker.mkdir()  # The refusal must not depend on reaching any daemon.
        proof = b'synthetic-duplicate-proof-' + secrets.token_hex(16).encode()
        environment = {'PATH': str(no_docker), 'PYTHONDONTWRITEBYTECODE': '1'}
        duplicate = subprocess.run([sys.executable, str(SCRIPT), '--directory', str(directory),
                                    'run', '--password-stdin'], input=proof + b'\n',
                                   capture_output=True, timeout=30, env=environment)
        self.assertNotEqual(duplicate.returncode, 0)
        self.assertIn(b'another controller holds this cluster directory', duplicate.stderr)
        self.assertNotIn(proof, duplicate.stdout + duplicate.stderr)
        # Read-only status stays available while the supervisor holds the lock.
        status = subprocess.run([sys.executable, str(SCRIPT), '--directory', str(directory), 'status'],
                                capture_output=True, timeout=30, env=environment)
        self.assertEqual(status.returncode, 0, status.stderr)
        self.assertEqual(json.loads(status.stdout)['phase'], 'ready')

    def replica_docker(self, content, standby_digest, calls):
        def docker(*args, **_):
            calls.append(args)
            if 'cp' in args:
                Path(args[-1]).write_bytes(content)
            elif 'sha256sum' in args:
                return (standby_digest + '  replica\n').encode()
            return b''
        return docker

    def test_replica_digest_mismatch_neither_saves_nor_publishes(self):
        content = b'synthetic encrypted replica'
        digest = hashlib.sha256(content).hexdigest()
        previous = {'receipt': {'output_path': '/vault/replica-' + 'c' * 32 + '.rkbackup'},
                    'container_id': self.standby['id'], 'completed_at_ms': 1}
        for mismatch, receipt_digest, standby_digest in (('source', 'e' * 64, digest),
                                                          ('standby', digest, 'f' * 64)):
            self.state['replica'] = copy.deepcopy(previous)
            calls = []
            with patch.object(self.controller, 'validate_node'), \
                 patch.object(self.controller, 'cli', return_value={'sha256_hex': receipt_digest}), \
                 patch.object(self.controller, 'save') as save, \
                 patch.object(ha, 'docker', side_effect=self.replica_docker(content, standby_digest, calls)), \
                 patch.object(ha.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, b'', b'')):
                with self.assertRaisesRegex(ha.HAError, mismatch + ' replica digest mismatch'):
                    self.controller.replicate(b'synthetic\n')
            save.assert_not_called()
            self.assertEqual(self.state['replica'], previous)
            self.assertFalse(any('rm' in args for args in calls), calls)

    def test_verified_replica_is_published_after_durable_transfer_and_before_cleanup(self):
        content = b'synthetic encrypted replica'
        digest = hashlib.sha256(content).hexdigest()
        prior = '/vault/replica-' + 'c' * 32 + '.rkbackup'
        self.state['replica'] = {'receipt': {'output_path': prior}, 'container_id': self.standby['id'],
                                 'completed_at_ms': 1}
        calls = []
        docker = self.replica_docker(content, digest, calls)
        with patch.object(self.controller, 'validate_node'), \
             patch.object(self.controller, 'cli', return_value={'sha256_hex': digest}), \
             patch.object(self.controller, 'save', side_effect=lambda: calls.append('save')), \
             patch.object(ha, 'docker', side_effect=docker), \
             patch.object(ha.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, b'', b'')):
            self.controller.replicate(b'synthetic\n')
        published = calls.index('save')
        self.assertTrue(any('sync' in args for args in calls[:published]))
        self.assertTrue(all('rm' not in args for args in calls[:published]))
        self.assertTrue(any(prior in args for args in calls[published:]))
        receipt = self.state['replica']['receipt']
        self.assertEqual((receipt['sha256_hex'], self.state['replica']['container_id']), (digest, self.standby['id']))
        self.assertNotEqual(receipt['output_path'], prior)

    def test_unlock_or_status_failure_after_fencing_keeps_fencing_and_primary(self):
        # Unlock fails, status reports not unlocked, or the status call itself fails.
        for cli in (ha.HAError('rekey unlock failed with exit 3'), [{}, {'state': 'locked'}],
                    [{}, ha.HAError('rekey status timed out; outcome unconfirmed')]):
            self.state.update(phase='ready', primary=self.primary, standby=self.standby, generation=1)
            patches = self.promotion_patches(cli) + [patch.object(self.controller, 'new_node')]
            for item in patches:
                item.start()
            try:
                with self.assertRaises(ha.HAError):
                    self.controller.promote(b'synthetic\n')
                self.controller.new_node.assert_not_called()
            finally:
                patch.stopall()
            saved = self.saved()
            self.assertEqual((saved['phase'], saved['primary'], saved['generation']), ('fencing', self.primary, 1))

    def test_promotion_never_persists_the_promoted_node_as_its_own_standby(self):
        self.state.update(volumes=[], image='sha256:' + '1' * 64, network='rekey-ha-test', replica=None)
        snapshots = []
        real_write = ha.write_json

        def record(path, value):
            snapshots.append(copy.deepcopy(value))
            real_write(path, value)

        def docker(*args, **_):
            return b'c' * 64 + b'\n' if '-d' in args else b''
        patches = self.promotion_patches([{}, {'state': 'unlocked'}]) + \
            [patch.object(ha, 'write_json', side_effect=record), patch.object(ha, 'docker', side_effect=docker)]
        for item in patches:
            item.start()
        try:
            self.controller.promote(b'synthetic\n')
        finally:
            patch.stopall()
        for state in snapshots:
            self.assertFalse(state.get('standby') and state['standby']['id'] == state['primary']['id'], state)
        ready = next(state for state in snapshots if state['phase'] == 'ready')
        self.assertEqual((ready['primary'], ready['standby'], ready['generation'], ready['replica']),
                         (self.standby, None, 2, None))
        final = self.saved()
        self.assertEqual((final['phase'], final['primary'], final['standby']['id']), ('ready', self.standby, 'c' * 64))

    def test_spare_failure_keeps_the_unlocked_primary_published_ready(self):
        patches = self.promotion_patches([{}, {'state': 'unlocked'}]) + \
            [patch.object(self.controller, 'new_node', side_effect=ha.HAError('create volume failed with exit 1'))]
        for item in patches:
            item.start()
        try:
            with self.assertRaisesRegex(ha.HAError, 'spare preparation failed'):
                self.controller.promote(b'synthetic\n')
        finally:
            patch.stopall()
        saved = self.saved()
        self.assertEqual((saved['phase'], saved['primary'], saved['standby'], saved['generation']),
                         ('ready', self.standby, None, 2))

    def test_missing_spare_is_prepared_before_replication_resumes(self):
        self.state.update(standby=None, volumes=[])
        order = []
        spare = {'id': 'c' * 64, 'volume': 'spare'}
        with patch.object(self.controller, 'healthy', return_value=True), \
             patch.object(self.controller, 'new_node', side_effect=lambda: order.append('spare') or spare), \
             patch.object(self.controller, 'replicate', side_effect=lambda _: order.append('replicate')):
            self.controller.tick(b'synthetic\n')
        self.assertEqual(order, ['spare', 'replicate'])
        self.assertEqual(self.saved()['standby'], spare)

    def test_failed_primary_without_standby_is_never_fenced(self):
        self.state['standby'] = None
        with patch.object(self.controller, 'healthy', return_value=False), \
             patch.object(self.controller, 'fence') as fence:
            with self.assertRaisesRegex(ha.HAError, 'no standby'):
                self.controller.tick(b'synthetic\n')
        fence.assert_not_called()

    def test_docker_errors_carry_a_fixed_operation_label_and_no_child_output(self):
        proof = b'synthetic-label-proof-' + secrets.token_hex(16).encode()
        leaked = b'raw daemon diagnostics ' + proof
        failed = subprocess.CompletedProcess([], 125, leaked, leaked)
        with patch.object(ha.subprocess, 'run', return_value=failed):
            with self.assertRaises(ha.HAError) as listing:
                self.controller.nodes()
            with self.assertRaises(ha.HAError) as unlock:
                self.controller.cli(self.primary, 'unlock', '--password-stdin', proof=proof + b'\n')
        with patch.object(ha.subprocess, 'run', side_effect=subprocess.TimeoutExpired(['docker'], 5)):
            with self.assertRaises(ha.HAError) as status:
                self.controller.cli(self.primary, 'status')
        self.assertEqual(str(listing.exception), 'list containers failed with exit 125')
        self.assertEqual(str(unlock.exception), 'rekey unlock failed with exit 125')
        self.assertEqual(str(status.exception), 'rekey status timed out; outcome unconfirmed')

    def test_create_hands_over_recovery_output_before_starting_the_broker(self):
        directory = self.directory / 'new-cluster'
        proof = b'synthetic-create-proof\n'
        recovery = b'{"recovery_key":"SYNTHETIC-RECOVERY-OUTPUT"}\n'
        output = io.BytesIO()
        nodes = [{'id': 'a' * 64, 'volume': 'rekey-ha-a'}, {'id': 'b' * 64, 'volume': 'rekey-ha-b'}]

        def docker(*args, data=None, **_):
            if 'inspect' in args:
                return json.dumps([{'Os': 'linux', 'Id': 'sha256:' + '1' * 64}]).encode()
            if 'init' in args:
                self.assertEqual(data, proof)
                return recovery
            return b''
        previous = os.umask(0o077)
        self.addCleanup(os.umask, previous)
        argv = ['rekey-docker-ha.py', '--directory', str(directory), 'create', '--image', 'synthetic',
                '--password-stdin']
        with patch.object(ha.sys, 'argv', argv), \
             patch.object(ha.sys, 'stdin', types.SimpleNamespace(buffer=io.BytesIO(proof))), \
             patch.object(ha.sys, 'stdout', types.SimpleNamespace(buffer=output)), \
             patch.object(ha, 'docker', side_effect=docker), \
             patch.object(ha.Controller, 'new_node', side_effect=nodes), \
             patch.object(ha.Controller, 'start', side_effect=ha.HAError('broker startup failed')):
            with self.assertRaisesRegex(ha.HAError, 'broker startup failed.*keep it.*destroy'):
                ha.main()
        self.assertEqual(output.getvalue(), recovery)
        self.assertEqual(json.loads((directory / 'cluster.json').read_text())['phase'], 'creating')


def live(image):
    os.umask(0o077)
    with tempfile.TemporaryDirectory(prefix='rekey-ha-test-') as temporary:
        directory = Path(temporary) / 'cluster'
        proof = secrets.token_urlsafe(32).encode() + b'\n'
        supervisor = None

        def controller():
            return ha.Controller(directory, json.loads((directory / 'cluster.json').read_bytes()))

        def await_state(predicate):
            deadline = time.monotonic() + 60
            while time.monotonic() < deadline:
                if supervisor is not None:
                    ha.require(supervisor.poll() is None, 'supervisor exited before expected transition')
                state = controller().state
                if predicate(state):
                    return state
                time.sleep(.1)
            raise ha.HAError('live transition timed out')

        try:
            ha.create(directory, image, proof, io.BytesIO())  # Discard synthetic recovery output.
            c = controller()
            primary = c.state['primary']
            c.cli(primary, 'unlock', '--password-stdin', proof=proof)
            retained = c.cli(primary, 'credential', 'add', 'retained', '--stdin-secrets',
                             proof=proof + secrets.token_urlsafe(32).encode() + b'\n')
            c.replicate(proof)
            first = c.state['replica']['receipt']
            c.cli(primary, 'credential', 'rotate', retained['id'], '--stdin-secrets',
                  proof=proof + secrets.token_urlsafe(32).encode() + b'\n')
            c.replicate(proof)
            second = c.state['replica']['receipt']
            replica = c.state['replica']
            remote_receipt = json.loads(ha.docker('read standby receipt', 'exec', replica['container_id'], 'cat',
                                                second['output_path'] + '.json'))
            ha.require(remote_receipt == second, 'standby receipt missing or mismatched')
            ha.require(second['snapshot_cut']['audit_sequence'] > first['snapshot_cut']['audit_sequence']
                       and second['sha256_hex'] != first['sha256_hex'], 'replication did not advance')
            print('PASS: real encrypted replicas advance after committed writes', flush=True)
            supervisor = subprocess.Popen([sys.executable, str(Path(ha.__file__)), '--directory', str(directory),
                'run', '--interval-seconds', '10', '--password-stdin'], stdin=subprocess.PIPE,
                stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            supervisor.stdin.write(proof)
            supervisor.stdin.close()
            prior = second['sha256_hex']
            observed = await_state(lambda state: state['replica']['receipt']['sha256_hex'] != prior)
            # Both writes are newer than the last replicated cut. A stale backup
            # restore would lose the new credential AND undo this revocation.
            c.cli(primary, 'credential', 'revoke', retained['id'], '--password-stdin', proof=proof)
            late = c.cli(primary, 'credential', 'add', 'after-replica', '--stdin-secrets',
                         proof=proof + secrets.token_urlsafe(32).encode() + b'\n')
            token = ha.docker('desktop login', 'exec', '-i', primary['id'], 'rekey', '--state-dir', ha.STATE,
                              'desktop-login', data=proof)
            ha.require(controller().state['replica'] == observed['replica'], 'test mutations must be after the last replica')
            ha.docker('kill primary', 'kill', primary['id'])
            promoted = await_state(lambda state: state['generation'] == 2 and state['phase'] == 'ready')
            c = controller()
            entries = c.cli(promoted['primary'], 'credential', 'list')['credentials']
            by_id = {entry['id']: entry for entry in entries}
            ha.require(by_id[retained['id']]['state'] == 'revoked' and by_id[retained['id']]['current_version'] == 2
                       and by_id[late['id']]['state'] == 'active', 'final committed state or revocation lost')
            route = json.loads((directory / 'cluster.json').read_bytes())
            ha.require(route['phase'] == 'ready' and route['primary']['id'] == promoted['primary']['id'], 'route not updated')
            ha.require(c.owned(primary['id']) is None, 'old primary can restart')
            rejected = subprocess.run(['docker', 'exec', '-i', promoted['primary']['id'], 'rekey',
                '--state-dir', ha.STATE, 'desktop-add', 'stale-session-must-fail'],
                input=token + b'\n' + secrets.token_urlsafe(32).encode() + b'\n', capture_output=True, timeout=10)
            ha.require(rejected.returncode != 0 and b'INVALID_UNLOCK_CREDENTIAL' in rejected.stderr,
                       'old desktop session was not explicitly rejected')
            fresh = ha.docker('desktop login', 'exec', '-i', promoted['primary']['id'], 'rekey', '--state-dir', ha.STATE,
                              'desktop-login', data=proof)
            ha.require(fresh != token, 'fresh desktop session was not issued')
            c.cli(promoted['primary'], 'desktop-add', 'fresh-session',
                  proof=fresh + b'\n' + secrets.token_urlsafe(32).encode() + b'\n')
            print('PASS: automatic fenced failover retains writes/revocation AFTER last replica', flush=True)
            await_state(lambda state: state['replica'] is not None)
            ha.docker('kill primary', 'kill', promoted['primary']['id'])
            # Ready is published before the spare exists; wait for the fresh spare too.
            await_state(lambda state: state['generation'] == 3 and state['phase'] == 'ready'
                        and state['standby'] is not None)
            print('PASS: second failover and fresh spare provisioning', flush=True)
            # Read-only status works while the supervisor holds its lock.
            ha.command('status', [sys.executable, str(Path(ha.__file__)), '--directory', str(directory), 'status'])
            duplicate = subprocess.run([sys.executable, str(Path(ha.__file__)), '--directory', str(directory),
                'run', '--password-stdin'], input=proof, capture_output=True, timeout=10)
            ha.require(duplicate.returncode != 0 and proof.strip() not in duplicate.stderr, 'duplicate controller admitted')
            supervisor.terminate()
            supervisor.wait(timeout=10)
            ha.require(supervisor.returncode == 143, 'supervisor termination failed')
            print('PASS: exclusive controller and readable live status; termination preserves nodes', flush=True)
        finally:
            if supervisor is not None:
                if supervisor.poll() is None:
                    supervisor.terminate()
                supervisor.wait(timeout=10)
                if supervisor.stderr:
                    # Controller errors contain fixed context only, but never
                    # relay untrusted Docker output or private init material.
                    diagnostic = supervisor.stderr.read().decode()
                    if diagnostic:
                        print(diagnostic, file=sys.stderr)
                    supervisor.stderr.close()
            if (directory / 'cluster.json').exists():
                ha.destroy(controller())
                print('PASS: owned Docker resource cleanup', flush=True)


if __name__ == '__main__':
    if len(sys.argv) == 3 and sys.argv[1] == '--image':
        image = sys.argv[2]
        result = unittest.TextTestRunner().run(unittest.defaultTestLoader.loadTestsFromTestCase(Contracts))
        if not result.wasSuccessful():
            sys.exit(1)
        live(image)
    else:
        unittest.main()
