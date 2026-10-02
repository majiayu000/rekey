#!/usr/bin/env python3
"""Focused export publication and transfer failure tests (no real secrets)."""

import hashlib
import importlib.util
import json
import os
import select
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch


SPEC = importlib.util.spec_from_file_location('backup_sync', Path(__file__).with_name('rekey-backup-sync.py'))
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class BackupSyncTests(unittest.TestCase):
    def test_export_management_path_is_only_passed_to_authenticated_cli(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            outbox = root / 'outbox'
            outbox.mkdir()
            record = root / 'argv.jsonl'
            binary = root / 'fixture-cli'
            binary.write_text("#!/usr/bin/env python3\nimport hashlib,json,sys\nfrom pathlib import Path\n"
                              f"with open({str(record)!r}, 'a') as f:f.write(json.dumps(sys.argv[1:])+'\\n')\n"
                              "if sys.argv[-1]=='--version':print('fixture-version')\n"
                              "else:\n p=Path(sys.argv[-1]);p.write_bytes(b'fixture-encrypted-snapshot');print(json.dumps({'sha256_hex':hashlib.sha256(p.read_bytes()).hexdigest(),'output_path':str(p),'vault_id':'fixture-vault','created_at_ms':1,'format_version':19}))\n")
            binary.chmod(0o700)
            session = root / 'unreadable $session% path'
            session.symlink_to(root / 'missing-token')
            args = SimpleNamespace(outbox=outbox, rekey=str(binary), state_dir=root / 'state',
                                   admin_session_file=session)
            MODULE.export(args)
            calls = [json.loads(line) for line in record.read_text().splitlines()]
            self.assertEqual(calls[0][:5], ['--state-dir', str(args.state_dir),
                                         '--admin-session-file', str(session), 'backup'])
            self.assertEqual(calls[1], ['--version'])
            completed = list(outbox.iterdir())
            self.assertEqual(len(completed), 1)
            receipt = (completed[0] / 'receipt.json').read_text()
            self.assertNotIn(str(session), receipt)
            self.assertNotIn('admin_session', receipt)
            self.assertFalse(session.exists())

    def test_failed_cli_never_publishes_receipt(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            args = SimpleNamespace(outbox=root, rekey='rekey', state_dir=root / 'state', admin_session_file=None)

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
            for file in target.iterdir():
                file.chmod(0o600)
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


class ReceiverDurabilityTests(unittest.TestCase):
    """Run the exact SSH receiver source in real local child processes."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.home = Path(self.tmp.name)
        self.root = self.home / 'receiver'
        self.root.mkdir(mode=0o700)
        self.target = self.root / 'backup-test'
        self.stage = self.root / '.upload-test'
        self.artifact = b'RKBACKUP encrypted fixture\x00' * 85000
        self.receipt = {'sha256_hex': hashlib.sha256(self.artifact).hexdigest(),
                        'format_version': 2, 'runtime_version': 'test-only'}
        self.write_object(self.stage)

    def write_object(self, directory, artifact=None, receipt=None):
        directory.mkdir(mode=0o700)
        for name, content in (
            ('snapshot.rkbackup', self.artifact if artifact is None else artifact),
            ('receipt.json', json.dumps(self.receipt if receipt is None else receipt).encode()),
        ):
            (directory / name).write_bytes(content)
            (directory / name).chmod(0o600)

    def command(self, mode='publish', stage=None, receipt=None, failure=0, hook='', read_hook='', tag='call'):
        log = self.home / (tag + '.jsonl')
        # Faults affect real os.fsync in the receiver process, never the verifier.
        indented_hook = ''.join(' ' + line + '\n' for line in hook.splitlines())
        prefix = f"""import os,json
from pathlib import Path
_test_root=Path({str(self.root)!r})
_test_target=_test_root/'backup-test'
_test_stage=_test_root/{(stage or self.stage.name)!r}
_test_log=Path({str(log)!r})
_test_labels={{_test_root.stat().st_ino:'root'}}
_test_object=_test_target if _test_target.exists() else _test_stage
if _test_object.exists():
 _test_labels[_test_object.stat().st_ino]='object'
 for leaf,label in (('snapshot.rkbackup','artifact'),('receipt.json','receipt')):
  if (_test_object/leaf).exists():_test_labels[(_test_object/leaf).stat().st_ino]=label
_test_fsync=os.fsync
_test_count=0
def _test_sync(fd):
 global _test_count
 _test_count+=1
 with _test_log.open('a') as log:
  log.write(json.dumps({{'call':_test_count,'published':_test_target.exists(),'kind':_test_labels.get(os.fstat(fd).st_ino,'unexpected')}})+'\\n')
 if _test_count=={failure}:raise OSError('injected fsync failure')
 _test_fsync(fd)
{indented_hook}os.fsync=_test_sync
"""
        prefix += read_hook
        return [sys.executable, '-c', prefix + MODULE.REMOTE, mode, str(self.root),
                self.target.name, json.dumps(self.receipt if receipt is None else receipt),
                stage or self.stage.name], log

    def receiver(self, **kwargs):
        command, log = self.command(**kwargs)
        result = subprocess.run(command, capture_output=True, timeout=15)
        events = [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []
        return result, events

    def assert_rejected(self, result):
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertNotIn(b'VERIFIED', result.stdout)

    def test_new_publication_and_identical_retry_sync_every_phase(self):
        result, events = self.receiver()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), b'VERIFIED')
        self.assertEqual([event['kind'] for event in events], ['artifact', 'receipt', 'object', 'root'])
        self.assertEqual([event['published'] for event in events], [False, False, False, True])
        self.assertFalse(self.stage.exists())
        result, events = self.receiver(mode='prepare', tag='retry')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), b'VERIFIED')
        self.assertEqual([event['kind'] for event in events], ['artifact', 'receipt', 'object', 'root'])
        self.assertEqual([event['published'] for event in events], [True] * 4)
        self.assertEqual((self.target / 'snapshot.rkbackup').read_bytes(), self.artifact)

    def test_each_fsync_failure_is_non_success_and_retry_repairs(self):
        for retry in (False, True):
            for failure in range(1, 5):
                with self.subTest(retry=retry, phase=failure):
                    if self.target.exists():
                        self.target.rename(self.root / ('previous-' + str(retry) + str(failure)))
                    if not self.stage.exists():
                        self.write_object(self.stage)
                    if retry:
                        self.stage.rename(self.target)
                    result, events = self.receiver(mode='prepare' if retry else 'publish',
                                                   failure=failure, tag=f'fail-{retry}-{failure}')
                    self.assert_rejected(result)
                    self.assertIn(b'injected fsync failure', result.stderr)
                    self.assertEqual([event['kind'] for event in events],
                                     ['artifact', 'receipt', 'object', 'root'][:failure])
                    self.assertEqual(self.target.exists(), retry or failure == 4)
                    result, _ = self.receiver(mode='prepare' if self.target.exists() else 'publish',
                                              tag=f'repair-{retry}-{failure}')
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(result.stdout.strip(), b'VERIFIED')

    def test_wrong_receipt_hash_and_oversized_receipt_rejected(self):
        for kind in ('receipt', 'hash', 'oversized'):
            with self.subTest(kind=kind):
                receipt = self.stage / 'receipt.json'
                receipt.write_text(json.dumps(self.receipt))
                (self.stage / 'snapshot.rkbackup').write_bytes(self.artifact)
                if kind == 'receipt':
                    receipt.write_text(json.dumps(dict(self.receipt, runtime_version='different')))
                elif kind == 'hash':
                    (self.stage / 'snapshot.rkbackup').write_bytes(b'wrong encrypted data')
                else:
                    receipt.write_bytes(b' ' * 65537 + json.dumps(self.receipt).encode())
                result, _ = self.receiver(tag=kind)
                self.assert_rejected(result)
                self.assertFalse(self.target.exists())

    def test_existing_partial_different_or_extra_target_preserved(self):
        for kind in ('partial', 'different', 'extra'):
            with self.subTest(kind=kind):
                if self.target.exists():
                    self.target.rename(self.root / ('saved-' + kind))
                if kind == 'partial':
                    self.target.mkdir(mode=0o700)
                elif kind == 'different':
                    self.write_object(self.target, artifact=b'other encrypted object')
                else:
                    self.write_object(self.target)
                    (self.target / 'unexpected').write_bytes(b'not a completed export')
                identity = self.target.stat().st_ino
                result, _ = self.receiver(tag=kind)
                self.assert_rejected(result)
                self.assertEqual(self.target.stat().st_ino, identity)
                self.assertTrue(self.stage.exists())

    def test_symlinks_hardlinks_and_private_modes_rejected(self):
        for name in ('snapshot.rkbackup', 'receipt.json'):
            path = self.stage / name
            original = path.read_bytes()
            for kind in ('symlink', 'hardlink', 'public', 'fifo'):
                with self.subTest(name=name, kind=kind):
                    path.unlink()
                    outside = self.home / ('outside-' + name)
                    outside.write_bytes(original)
                    outside.chmod(0o600)
                    if kind == 'symlink':
                        path.symlink_to(outside)
                    elif kind == 'hardlink':
                        os.link(outside, path)
                    elif kind == 'fifo':
                        os.mkfifo(path, 0o600)
                    else:
                        path.write_bytes(original)
                        path.chmod(0o644)
                    result, _ = self.receiver(tag=name + kind)
                    self.assert_rejected(result)
                    path.unlink()
                    path.write_bytes(original)
                    path.chmod(0o600)
        for which in ('stage', 'root', 'target'):
            with self.subTest(directory=which):
                path = getattr(self, which)
                if which == 'target':
                    self.write_object(path)
                moved = self.home / ('moved-' + which)
                path.rename(moved)
                path.symlink_to(moved, target_is_directory=True)
                result, _ = self.receiver(tag=which)
                self.assert_rejected(result)
                path.unlink()
                moved.rename(path)
                if which == 'target':
                    path.rename(self.root / 'saved-target')
        self.stage.chmod(0o755)
        result, _ = self.receiver(tag='public-stage')
        self.assert_rejected(result)

    def test_file_and_directory_swaps_during_sync_rejected(self):
        for which in ('artifact', 'receipt', 'stage', 'root', 'target'):
            with self.subTest(which=which):
                # Each substitution occurs after a real file fsync, before ACK.
                if which == 'target':
                    self.stage.rename(self.target)
                parent = '_test_target' if which == 'target' else '_test_stage'
                if which in ('artifact', 'receipt'):
                    name = 'snapshot.rkbackup' if which == 'artifact' else 'receipt.json'
                    hook = f"if _test_count==1:\n p=_test_stage/{name!r}\n data=p.read_bytes()\n p.unlink()\n p.write_bytes(data)\n p.chmod(0o600)"
                else:
                    path = {'stage': '_test_stage', 'root': '_test_root', 'target': parent}[which]
                    hook = f"if _test_count==1:\n p={path}\n p.rename(p.with_name(p.name+'-detached'))\n p.mkdir(mode=0o700)"
                result, _ = self.receiver(mode='prepare' if which == 'target' else 'publish',
                                          hook=hook, tag='swap-' + which)
                self.assert_rejected(result)
                # Restore the fixture for the next independent substitution.
                if which in ('stage', 'root', 'target'):
                    path = getattr(self, which)
                    path.rmdir()
                    path.with_name(path.name + '-detached').rename(path)
                if which == 'target':
                    self.target.rename(self.stage)

    def test_streamed_reads_remain_bounded_and_substitution_rejected(self):
        for leaf in ('snapshot.rkbackup', 'receipt.json'):
            with self.subTest(leaf=leaf):
                read_hook = f"""_test_read=os.read
_test_inode=(_test_stage/{leaf!r}).stat().st_ino
_test_swapped=False
def _test_stream(fd,count):
 global _test_swapped
 if count>1024*1024:raise AssertionError('unbounded receiver read')
 block=_test_read(fd,count)
 if block and os.fstat(fd).st_ino==_test_inode and not _test_swapped:
  _test_swapped=True
  p=_test_stage/{leaf!r}
  # Mutate already-read bytes in place: digest alone cannot detect this race.
  with p.open('r+b') as changed:
   changed.write(b'X')
 return block
os.read=_test_stream
"""
                result, _ = self.receiver(read_hook=read_hook, tag='read-swap-' + leaf)
                self.assert_rejected(result)
                self.assertIn(b'remote file identity changed', result.stderr)
                (self.stage / leaf).write_bytes(self.artifact if leaf == 'snapshot.rkbackup'
                                               else json.dumps(self.receipt).encode())
        result, _ = self.receiver(read_hook="""_test_read=os.read
def _test_stream(fd,count):
 if count>1024*1024:raise AssertionError('unbounded receiver read')
 return _test_read(fd,count)
os.read=_test_stream
""", tag='bounded-stream')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), b'VERIFIED')

    def test_interruption_and_lost_ack_retry_same_completed_object(self):
        for phase in (3, 4):
            with self.subTest(phase=phase):
                command, log = self.command(tag='interrupt-' + str(phase),
                    hook=f"if _test_count=={phase}:\n print('PAUSED',flush=True)\n import time\n time.sleep(30)")
                process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                try:
                    ready, _, _ = select.select([process.stdout], [], [], 10)
                    self.assertTrue(ready, 'receiver did not reach fsync barrier')
                    self.assertEqual(process.stdout.readline().strip(), b'PAUSED')
                    process.kill()
                    stdout, _ = process.communicate(timeout=5)
                    self.assertNotIn(b'VERIFIED', stdout)
                    self.assertNotEqual(process.returncode, 0)
                finally:
                    if process.poll() is None:
                        process.kill()
                        process.communicate()
                self.assertEqual(self.target.exists(), phase == 4)
                result, _ = self.receiver(mode='prepare' if phase == 4 else 'publish',
                                          tag='interruption-retry-' + str(phase))
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout.strip(), b'VERIFIED')
                if phase == 3:
                    self.target.rename(self.stage)

    def test_concurrent_same_and_different_transfers_preserve_first_object(self):
        for same in (True, False):
            with self.subTest(same=same):
                other = self.root / '.upload-other'
                other_receipt = self.receipt if same else dict(self.receipt, runtime_version='other')
                self.write_object(other, receipt=other_receipt)
                first, _ = self.command(tag='first-' + str(same),
                                       hook="if _test_count==3:\n print('LOCKED',flush=True)\n import time\n time.sleep(0.4)")
                second, _ = self.command(stage=other.name, receipt=other_receipt,
                                         tag='second-' + str(same))
                one = subprocess.Popen(first, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                try:
                    ready, _, _ = select.select([one.stdout], [], [], 10)
                    self.assertTrue(ready, 'first receiver did not hold publication lock')
                    self.assertEqual(one.stdout.readline().strip(), b'LOCKED')
                    two = subprocess.Popen(second, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    out_one, err_one = one.communicate(timeout=10)
                    out_two, err_two = two.communicate(timeout=10)
                    self.assertEqual(one.returncode, 0, err_one)
                    self.assertIn(b'VERIFIED', out_one)
                    if same:
                        self.assertEqual(two.returncode, 0, err_two)
                        self.assertEqual(out_two.strip(), b'VERIFIED')
                    else:
                        self.assertNotEqual(two.returncode, 0)
                        self.assertNotIn(b'VERIFIED', out_two)
                    self.assertEqual(json.loads((self.target / 'receipt.json').read_text()), self.receipt)
                    self.assertEqual((self.target / 'snapshot.rkbackup').read_bytes(), self.artifact)
                finally:
                    if one.poll() is None:
                        one.kill()
                        one.communicate()
                self.target.rename(self.stage)
                if other.exists():
                    for file in other.iterdir():
                        file.unlink()
                    other.rmdir()


DR_SPEC = importlib.util.spec_from_file_location('dr_drill', Path(__file__).with_name('rekey-dr-drill.py'))
DR = importlib.util.module_from_spec(DR_SPEC)
DR_SPEC.loader.exec_module(DR)


class DrArtifactTests(unittest.TestCase):
    """Actual private files/receipts only; never a field recovery acceptance."""
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(os.path.realpath(self.temp.name))
        self.root.chmod(0o700)
        self.artifact = self.root / 'backup.rkbackup'
        self.artifact.write_bytes(b'encrypted fixture\x00' * 100000)
        self.artifact.chmod(0o600)
        self.restored = self.root / 'actual-state'
        self.restored.mkdir(mode=0o700)
        self.cut = {'audit_sequence': 27, 'policy': {'version': 3, 'bundle_sha256': 'a' * 64}}
        self.backup = dict(vault_id='12345678-1234-4234-9234-123456789abc', format_version=22,
                           created_at_ms=100, sha256_hex=hashlib.sha256(self.artifact.read_bytes()).hexdigest(),
                           output_path=str(self.artifact), snapshot_cut=self.cut)
        self.restore = dict(vault_id=self.backup['vault_id'], format_version=22,
                            input_sha256_hex=self.backup['sha256_hex'], output_path=str(self.restored),
                            snapshot_cut=self.cut)
        self.bp, self.rp, self.output = self.root / 'backup.json', self.root / 'restore.json', self.root / 'report'
        self.write(self.bp, self.backup)
        self.write(self.rp, self.restore)
        self.argv = ['--backup', str(self.artifact), '--backup-receipt', str(self.bp),
                     '--restore-receipt', str(self.rp), '--output', str(self.output)]

    def write(self, path, value):
        path.write_text(json.dumps(value))
        path.chmod(0o600)

    def test_streamed_artifact_matches_only_and_uses_actual_state_directory(self):
        self.assertEqual(DR.main(self.argv), 0)
        report = json.loads((self.output / 'report.json').read_text())
        self.assertEqual(report['outcome'], 'artifact_match')
        self.assertEqual(report['restored_state_dir'], str(self.restored))
        self.assertEqual(report['snapshot_cut'], self.cut)
        self.assertFalse(report['field_validated'])
        self.assertIsNone(report['rpo'])
        self.assertIsNone(report['rto'])
        self.assertEqual(self.output.stat().st_mode & 0o777, 0o700)
        self.assertEqual((self.output / 'report.json').stat().st_mode & 0o777, 0o600)

    def test_receipt_hash_vault_cut_format_and_unknown_fields_reject(self):
        import copy
        mutations = [('input_sha256_hex', '0' * 64), ('vault_id', '22345678-1234-4234-9234-123456789abc'),
                     ('snapshot_cut', dict(audit_sequence=26, policy=None)), ('format_version', 19),
                     ('extra', 'SYNTHETIC-DR-CANARY'), ('snapshot_cut', {'audit_sequence': 27}),
                     ('snapshot_cut', {'audit_sequence': True, 'policy': None}),
                     ('snapshot_cut', {'audit_sequence': 27, 'policy': {'version': 3, 'bundle_sha256': 'a' * 64, 'extra': 1}})]
        for key, value in mutations:
            with self.subTest(key=key, value=value):
                bad = copy.deepcopy(self.restore)
                bad[key] = value
                self.write(self.rp, bad)
                self.assertEqual(DR.main(self.argv), 1)
                self.assertFalse(self.output.exists())

    def test_actual_artifact_mutation_and_missing_partial_duplicate_receipt_reject(self):
        self.artifact.write_bytes(b'changed-encrypted-fixture')
        self.assertEqual(DR.main(self.argv), 1)
        self.artifact.write_bytes(b'encrypted fixture\x00' * 100000)
        for raw in (b'{', b'{"vault_id":1,"vault_id":2}', b'{}'):
            self.rp.write_bytes(raw)
            self.assertEqual(DR.main(self.argv), 1)
        self.rp.unlink()
        self.assertEqual(DR.main(self.argv), 1)
        self.assertFalse(self.output.exists())

    def test_symlink_public_hardlink_receipt_and_directory_filename_reject(self):
        self.bp.chmod(0o644)
        self.assertEqual(DR.main(self.argv), 1)
        self.bp.chmod(0o600)
        link = self.root / 'linked.json'
        os.link(self.bp, link)
        self.assertEqual(DR.main(self.argv), 1)
        link.unlink()
        saved = self.root / 'saved.json'
        self.rp.rename(saved)
        self.rp.symlink_to(saved)
        self.assertEqual(DR.main(self.argv), 1)
        self.rp.unlink()
        saved.rename(self.rp)
        database = self.restored / 'vault.sqlite3'
        database.write_bytes(b'opaque-no-database-read')
        self.write(self.rp, dict(self.restore, output_path=str(database)))
        self.assertEqual(DR.main(self.argv), 1)

    def test_output_collision_preserves_existing_content_and_field_before_effects(self):
        self.output.mkdir(mode=0o700)
        marker = self.output / 'existing'
        marker.write_text('preserve')
        self.assertEqual(DR.main(self.argv), 1)
        self.assertEqual(marker.read_text(), 'preserve')
        with patch.object(DR, 'verify') as read, patch.object(DR, 'create_output') as create:
            self.assertEqual(DR.main(self.argv + ['--require-field']), 1)
            read.assert_not_called()
            create.assert_not_called()

    def test_writable_output_ancestor_rejected_before_mkdir(self):
        parent = self.root / 'unsafe-output-parent'
        parent.mkdir(mode=0o700)
        parent.chmod(0o777)
        output = parent / 'report'
        mkdir = DR.os.mkdir
        with patch.object(DR.os, 'mkdir', wraps=mkdir) as create:
            with self.assertRaises(DR.FILES.Error):
                DR.create_output(output)
            create.assert_not_called()
        self.assertFalse(output.exists())

    def test_actual_output_directory_swap_before_write_rejects_without_publish(self):
        create = DR.create_output
        moved = self.root / 'moved-original'
        opened = []
        def swap(path):
            fd = create(path)
            opened.append(fd)
            path.rename(moved)
            path.mkdir(mode=0o700)
            return fd
        with patch.object(DR, 'create_output', swap):
            self.assertEqual(DR.main(self.argv), 1)
        self.assertFalse((self.output / 'report.json').exists())
        self.assertFalse((moved / 'report.json').exists())
        with self.assertRaises(OSError):
            os.fstat(opened[0])

    def test_actual_output_directory_swap_during_report_fsync_removes_success(self):
        original = os.fsync
        moved = self.root / 'moved-during-fsync'
        def swap(fd):
            original(fd)
            if (self.output / 'report.json').exists() and not moved.exists():
                self.output.rename(moved)
                self.output.mkdir(mode=0o700)
        with patch.object(DR.os, 'fsync', swap):
            self.assertEqual(DR.main(self.argv), 1)
        self.assertFalse((self.output / 'report.json').exists())
        self.assertFalse((moved / 'report.json').exists())

    def test_each_actual_fsync_failure_is_non_success(self):
        original = os.fsync
        for failure in range(1, 5):
            with self.subTest(failure=failure):
                output = self.root / ('fsync-' + str(failure))
                count = 0
                def fail(fd):
                    nonlocal count
                    count += 1
                    if count == failure:
                        raise OSError('SYNTHETIC-FSYNC-SECRET-CANARY')
                    original(fd)
                args = self.argv[:-1] + [str(output)]
                with patch.object(DR.os, 'fsync', fail):
                    self.assertEqual(DR.main(args), 1)
                self.assertFalse((output / 'report.json').exists())


if __name__ == '__main__':
    unittest.main()
