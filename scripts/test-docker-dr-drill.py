#!/usr/bin/env python3
"""Fence admission regressions; actual isolation and timings require the Docker drill."""
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
from types import SimpleNamespace
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('docker_dr', Path(__file__).with_name('rekey-docker-dr-drill.py'))
DR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(DR)
PRIMARY = 'a' * 64


class FenceTests(unittest.TestCase):
    def test_existing_container_refuses_promotion_even_when_stopped(self):
        with patch.object(DR, 'docker', return_value=(PRIMARY + '\n').encode()) as engine:
            with self.assertRaisesRegex(DR.DrillError, 'primary-not-fenced'):
                DR.require_fenced(PRIMARY)
        args = engine.call_args.args
        self.assertIn('--all', args)
        self.assertIn('--no-trunc', args)
        self.assertIn('id=' + PRIMARY, args)

    def test_successful_external_daemon_enumeration_proves_absence(self):
        with patch.object(DR, 'docker', return_value=b'') as engine:
            DR.require_fenced(PRIMARY)
        self.assertEqual(engine.call_args.args[:2], ('container', 'ls'))

    def test_daemon_failure_and_timeout_never_prove_absence(self):
        for error in (DR.DrillError('command-status'), subprocess.TimeoutExpired('docker', 90)):
            with self.subTest(error=type(error).__name__), patch.object(DR, 'docker', side_effect=error):
                with self.assertRaises(type(error)):
                    DR.require_fenced(PRIMARY)

    def test_restore_uses_inspected_context_and_rechecks_fence_before_mutation(self):
        for failure in (None, 'inspect', 'confirm', 'fence', 'source-generation', 'restore-generation'):
            with self.subTest(failure=failure):
                events = []
                encrypted = b'encrypted synthetic DR fixture'
                backup = dict(vault_id='12345678-1234-4234-9234-123456789abc', generation=7,
                              sha256_hex=hashlib.sha256(encrypted).hexdigest(),
                              snapshot_cut=dict(audit_sequence=1, policy=None))
                context = dict(vault_id=backup['vault_id'], source_generation=7,
                               high_water=11, history_missing=False)
                restored = dict(vault_id=backup['vault_id'], input_sha256_hex=backup['sha256_hex'],
                                snapshot_cut=backup['snapshot_cut'], generation=12)
                fence_calls = 0

                def fence(primary):
                    nonlocal fence_calls
                    self.assertEqual(primary, PRIMARY)
                    fence_calls += 1
                    events.append('fence')
                    if fence_calls == 1:
                        raise DR.DrillError('primary-not-fenced')
                    if failure == 'fence' and 'inspect' in events:
                        raise DR.DrillError('synthetic-fence-failure')

                def docker(*args, data=None, expected=0):
                    if args[:2] == ('image', 'inspect'):
                        return json.dumps([dict(Os='linux', Id='synthetic-image')]).encode()
                    if args[0] == 'version':
                        return b'"synthetic-engine"'
                    if args[:4] == ('exec', PRIMARY, 'cat', '/vault/snapshot.rkbackup'):
                        return encrypted
                    if 'restore' in args:
                        self.assertEqual(data, b'synthetic-proof\n')
                        self.assertEqual(args[:6], ('exec', '-i', 'standby', 'rekeyd', 'restore', '--state-dir'))
                        self.assertIn('--password-stdin', args)
                        if '--inspect' in args:
                            events.append('inspect')
                            self.assertNotIn('--expected-context', args)
                            if failure == 'inspect':
                                raise DR.DrillError('synthetic-inspect-failure')
                            return json.dumps(dict(context, source_generation=8) if failure == 'source-generation' else context).encode()
                        self.assertEqual(events[-1], 'fence')
                        events.append('confirm')
                        self.assertEqual(json.loads(args[args.index('--expected-context') + 1]), context)
                        if failure == 'confirm':
                            raise DR.DrillError('synthetic-confirm-failure')
                        return json.dumps(dict(restored, generation=8) if failure == 'restore-generation' else restored).encode()
                    return b''

                def value(node, *args, data=None):
                    if args[:2] == ('action', 'create'):
                        return dict(id='action', version=1)
                    if args[:2] == ('policy', 'status'):
                        return dict(vault_id=backup['vault_id'], trust_sha256='a' * 64)
                    if args[:2] == ('session', 'create'):
                        return dict(capability_token='synthetic-capability')
                    if args[0] == 'backup':
                        return backup
                    if args[:2] == ('audit', 'list'):
                        return dict(events=[dict(sequence=2, event_type='credential.created', credential_id='lost')])
                    if args[0] == 'status':
                        return dict(state='unlocked')
                    return {}

                def command(args):
                    for flag in ('--bundle', '--trust'):
                        Path(args[args.index(flag) + 1]).write_text('{}')

                def start(node):
                    events.append('start-' + node)
                    if node == 'standby':
                        raise DR.DrillError('stop-after-restored-broker-admission')

                with patch.object(DR, 'docker', side_effect=docker), patch.object(DR, 'node', side_effect=[PRIMARY, 'standby']), \
                        patch.object(DR, 'require_fenced', side_effect=fence), patch.object(DR, 'value', side_effect=value), \
                        patch.object(DR, 'measure_write', side_effect=[(dict(id='retained'), 1, 2), (dict(id='lost'), 3, 4)]), \
                        patch.object(DR, 'put'), patch.object(DR, 'execute', return_value=b'{"upstream_status": 200}'), \
                        patch.object(DR, 'command', side_effect=command), patch.object(DR, 'start_broker', side_effect=start), \
                        patch.object(DR.secrets, 'token_urlsafe', return_value='synthetic-proof'):
                    with self.assertRaises(DR.DrillError) as error:
                        DR.run(SimpleNamespace(image='fixture'), {}, 'rekey.dr.run=synthetic')
                self.assertEqual(events.count('inspect'), 1)
                self.assertEqual(events.count('confirm'), 0 if failure in ('inspect', 'fence', 'source-generation') else 1)
                self.assertEqual('start-standby' in events, failure is None)
                if failure is None:
                    self.assertEqual(str(error.exception), 'stop-after-restored-broker-admission')
                    self.assertEqual(events[-4:], ['inspect', 'fence', 'confirm', 'start-standby'])

    def test_cleanup_only_selects_owned_label_before_removing_resources(self):
        with patch.object(DR, 'docker', return_value=b'') as engine:
            DR.cleanup('rekey.dr.run=synthetic')
        for call in engine.call_args_list:
            self.assertIn('label=rekey.dr.run=synthetic', call.args)
            self.assertIn('ls', call.args)


if __name__ == '__main__':
    unittest.main()
