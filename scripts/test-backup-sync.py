#!/usr/bin/env python3
"""Focused export publication and transfer failure tests (no real secrets)."""

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch


SPEC = importlib.util.spec_from_file_location('backup_sync', Path(__file__).with_name('rekey-backup-sync.py'))
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class BackupSyncTests(unittest.TestCase):
    def test_failed_cli_never_publishes_receipt(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            args = SimpleNamespace(outbox=root, rekey='rekey', state_dir=root / 'state')

            def failed(args, **kwargs):
                Path(args[-1]).write_bytes(b'partial archive')
                raise subprocess.CalledProcessError(5, 'rekey')

            with patch.object(MODULE, 'run', failed):
                with self.assertRaises(subprocess.CalledProcessError):
                    MODULE.export(args)
            self.assertTrue(all(p.name.startswith('.pending-') for p in root.iterdir()))
            self.assertEqual(list(root.rglob('receipt.json')), [])

    def test_hash_failure_prevents_network(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            entry = root / 'backup-test'
            entry.mkdir(mode=0o700)
            (entry / 'snapshot.rkbackup').write_bytes(b'corrupted')
            (entry / 'receipt.json').write_text(json.dumps({'sha256_hex': '0' * 64}))
            with patch.object(MODULE, 'run') as network:
                with self.assertRaisesRegex(ValueError, 'local digest mismatch'):
                    MODULE.sync(SimpleNamespace(outbox=root))
                network.assert_not_called()

    def test_missing_receipt_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'incomplete').mkdir(mode=0o700)
            with self.assertRaises(FileNotFoundError):
                MODULE.sync(SimpleNamespace(outbox=root))

    def test_remote_rejects_hash_mismatch_and_preserves_completed_copy(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            # Remote prepare validates the backup root as a private directory.
            os.chmod(root, 0o700)
            target = root / 'backup-test'
            target.mkdir(mode=0o700)
            artifact = b'encrypted test fixture'
            (target / 'snapshot.rkbackup').write_bytes(artifact)
            receipt = {'sha256_hex': hashlib.sha256(artifact).hexdigest()}
            (target / 'receipt.json').write_text(json.dumps(receipt))
            args = ['/usr/bin/python3', '-c', MODULE.REMOTE, 'prepare', tmp,
                    target.name, json.dumps(receipt), '.upload-test']
            ok = subprocess.run(args, capture_output=True)
            self.assertEqual(ok.returncode, 0, ok.stderr)
            self.assertEqual(ok.stdout.strip(), b'VERIFIED')
            args[-2] = json.dumps({'sha256_hex': '0' * 64})
            failed = subprocess.run(args, capture_output=True)
            self.assertNotEqual(failed.returncode, 0)
            self.assertIn(b'remote receipt or digest mismatch', failed.stderr)
            self.assertEqual((target / 'snapshot.rkbackup').read_bytes(), artifact)
            self.assertFalse((root / '.upload-test').exists())


if __name__ == '__main__':
    unittest.main()
