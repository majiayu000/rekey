#!/usr/bin/env python3
"""Fence admission regressions; actual isolation and timings require the Docker drill."""
import importlib.util
from pathlib import Path
import subprocess
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

    def test_cleanup_only_selects_owned_label_before_removing_resources(self):
        with patch.object(DR, 'docker', return_value=b'') as engine:
            DR.cleanup('rekey.dr.run=synthetic')
        for call in engine.call_args_list:
            self.assertIn('label=rekey.dr.run=synthetic', call.args)
            self.assertIn('ls', call.args)


if __name__ == '__main__':
    unittest.main()
