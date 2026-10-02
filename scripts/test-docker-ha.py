#!/usr/bin/env python3
"""Controller failure contracts; --image additionally runs real disposable Docker HA."""
import importlib.util
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('ha', Path(__file__).with_name('rekey-docker-ha.py'))
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
        self.assertEqual(docker.call_args_list[0].args, ('container', 'rm', '--force', self.primary['id']))

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
            ha.create(directory, image, proof)  # Discard synthetic recovery output.
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
            remote_receipt = json.loads(ha.docker('exec', replica['container_id'], 'cat',
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
            definition = dict(name='ha-session', credential_id=late['id'], origin='https://example.com',
                method='GET', exact_path='/ha', auth_header='authorization', auth_prefix='Bearer ',
                timeout_ms=1000, request_max_bytes=4096, allowed_extra_headers=[],
                response_max_bytes=4096, allowed_response_headers=[])
            ha.docker('exec', '-i', primary['id'], 'sh', '-c', 'umask 077; cat > /vault/action.json',
                      data=json.dumps(definition).encode())
            action = c.cli(primary, 'action', 'create', '--file', '/vault/action.json', '--password-stdin', proof=proof)
            reference = action['id'] + '@' + str(action['version'])
            token = c.cli(primary, 'session', 'create', '--action', reference, '--password-stdin', proof=proof)['capability_token']
            ha.require(controller().state['replica'] == observed['replica'], 'test mutations must be after the last replica')
            ha.docker('kill', primary['id'])
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
                '--state-dir', ha.STATE, 'execute', reference, '--capability', '-'],
                input=(token + '\n').encode(), capture_output=True, timeout=10)
            ha.require(rejected.returncode != 0 and b'INVALID_CAPABILITY' in rejected.stderr,
                       'old capability was not explicitly rejected')
            fresh = c.cli(promoted['primary'], 'session', 'create', '--action', reference, '--password-stdin', proof=proof)
            ha.require(fresh['capability_token'] != token, 'fresh session was not issued')
            print('PASS: automatic fenced failover retains writes/revocation AFTER last replica', flush=True)
            await_state(lambda state: state['replica'] is not None)
            ha.docker('kill', promoted['primary']['id'])
            await_state(lambda state: state['generation'] == 3 and state['phase'] == 'ready')
            print('PASS: second failover and fresh spare provisioning', flush=True)
            # Read-only status works while the supervisor holds its lock.
            ha.command([sys.executable, str(Path(ha.__file__)), '--directory', str(directory), 'status'])
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
