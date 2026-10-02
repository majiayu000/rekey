"""Regression checks for honest probe verdicts and exact test-item cleanup."""
from contextlib import contextmanager
import importlib.util
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('v3_run', Path(__file__).with_name('run.py'))
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


class ProbeVerdicts(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.fixture = self.root / 'fixture'
        self.fixture.write_bytes(b'public test fixture')
        self.args = SimpleNamespace(identity='test', team_id='TEST', provisioning_profile=None,
                                    interactive_keychain=False)
        for name, value in [('invoke', SimpleNamespace(stderr='', returncode=0)),
                            ('sign', {}), ('signature_details', {})]:
            mock = patch.object(runner, name, return_value=value)
            mock.start()
            self.addCleanup(mock.stop)

    def test_create_lost_reply_still_cleans_exact_id_and_retains_error(self):
        with patch.object(runner, 'probe', side_effect=[RuntimeError('lost reply'), {'exit_code': 0}]) as probe:
            result = runner.keychain(self.root, self.args, {'keychain': self.fixture})
        self.assertEqual(result['status'], 'inconclusive')
        self.assertEqual(result['operation_error'], 'lost reply')
        self.assertEqual(probe.call_args_list[0].args[0][2], result['test_id'])
        self.assertEqual(probe.call_args_list[1].args[0][1:], ['cleanup', result['test_id'], 'TEST.com.rekey'])

    def test_cleanup_failure_cannot_downgrade_an_observed_leak(self):
        with patch.object(runner, 'probe', side_effect=[{'exit_code': 0}] * 4 + [{'exit_code': 2}]):
            result = runner.keychain(self.root, self.args, {'keychain': self.fixture})
        self.assertEqual(result['status'], 'failed')
        self.assertEqual(result['cleanup']['exit_code'], 2)

    def test_attacker_visibility_denial_still_requires_interactive_control(self):
        outcomes = [{'exit_code': 0}, {'exit_code': 2, 'outcome': 'environment_missing_entitlement'},
                    {'exit_code': 2, 'outcome': 'item_not_found'}, {'exit_code': 1}, {'exit_code': 0}]
        with patch.object(runner, 'probe', side_effect=outcomes):
            result = runner.keychain(self.root, self.args, {'keychain': self.fixture})
        self.assertEqual(result['status'], 'inconclusive')
        self.assertIn('positive control', result['reason'])

    def test_incomplete_peer_observation_never_passes(self):
        count = 0

        @contextmanager
        def process(_):
            nonlocal count
            count += 1
            valid = count == 1
            incomplete = count == 2
            observation = {'event': 'observation', 'outcome': 'inconclusive' if incomplete else 'observed',
                           'received_bytes': 30 if valid else 0, 'canary_match': valid, 'eof': not incomplete}
            yield SimpleNamespace(returncode=3 if incomplete else 0,
                                  communicate=lambda timeout: (json.dumps(observation), ''))

        with patch.object(runner, 'child', process), patch.object(runner, 'ready_json', return_value={'event': 'ready'}), \
                patch.object(runner, 'probe', side_effect=[{'exit_code': 0}, {'exit_code': 2}, {'exit_code': 2}]):
            result = runner.peer(self.root, self.args, {'peer': self.fixture})
        self.assertEqual(result['status'], 'inconclusive')


if __name__ == '__main__':
    unittest.main()
