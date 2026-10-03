#!/usr/bin/env python3
"""Private filebox tests. Fake CLI fixtures NEVER prove real Authority activation."""
import copy
import errno
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock
import uuid

spec = importlib.util.spec_from_file_location('controlplane', Path(__file__).with_name('rekey-controlplane.py'))
cp = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cp)


def uid():
    return str(uuid.uuid4())


def put(path, data, mode=0o600):
    path = Path(path)
    path.write_bytes(data if type(data) is bytes else cp.encode(data))
    path.chmod(mode)
    return str(path)


class FakeCli:
    """Public response simulator; does not validate signatures or hold proof."""
    def __init__(self, node, command):
        self.node, self.command = node, command
        self.calls = []
        self.active = False
        self.return_exit = 0
        self.return_code = None
        self.commit = True
        self.status_patch = {}
        self.origin_patch = {}
        self.pages = None
        self.audit_patch = {}

    def status(self):
        result = dict(vault_id=self.node['vault_id'], tenant_id=self.node['vault_id'],
                      trust_sha256=self.node['trust_sha256'], trust_installed=True, bundle_persisted=self.active,
                      status='active' if self.active else 'unavailable', signer_id=self.node['signer_id'] if self.active else None,
                      version=self.command['version'] if self.active else None,
                      expires_at_ms=self.command['expires_at_ms'] if self.active else None,
                      bundle_sha256=self.command['bundle_sha256'] if self.active else None,
                      policy_sha256='b' * 64 if self.active else None, activated_at_ms=123 if self.active else None)
        result.update(self.status_patch)
        return result

    def event(self):
        event = dict(record_type='rekey.audit.v2', sequence=3, event_id='a' * 32, event_type='policy.activated',
                     outcome='success', reason_code='policy-activated:' + str(self.command['version']) + ':' + self.command['bundle_sha256'],
                     created_at_ms=123)
        event.update(self.audit_patch)
        return event

    def json(self, args):
        self.calls.append(args)
        if args[:2] == ['policy', 'status']:
            return self.status()
        if args[:2] == ['approval', 'origin']:
            return dict(dict(algorithm='ed25519', public_key='01' * 32), **self.origin_patch)
        if args[:2] == ['audit', 'list']:
            if self.pages is not None:
                return self.pages.pop(0)
            return dict(schema='rekey.audit.v2', snapshot_max_sequence=3, events=[self.event()], next_before_sequence=None)
        raise AssertionError(args)

    def call(self, args):
        self.calls.append(args)
        assert args[:2] == ['policy', 'activate']
        assert '--step-up-stdin' not in args
        assert '--password-stdin' not in args
        self.active = self.commit
        return dict(exit=self.return_exit, code=self.return_code, issue=None, stdout=b'')


class Fixture(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        # /tmp is a symlink on macOS; use the real canonical path.
        self.base = Path(os.path.realpath(self.temp.name))
        self.base.chmod(0o700)
        self.box_dir = self.base / 'box'
        self.box_dir.mkdir(mode=0o700)
        self.nodes = []
        self.trust_paths = []
        for index in range(2):
            state = self.base / ('state' + str(index))
            state.mkdir(mode=0o700)
            (state / 'runtime').mkdir(mode=0o700)
            signer = uid()
            trust = {'algorithm': 'ed25519', 'format_version': 1, 'public_key': ('0' + str(index + 2)) * 32, 'signer_id': signer}
            raw = json.dumps(trust, sort_keys=True, separators=(',', ':')).encode()
            self.trust_paths.append(put(self.base / ('trust' + str(index) + '.json'), raw))
            self.nodes.append(dict(node_id=uid(), vault_id=uid(), state_dir=str(state), runtime_dir=str(state / 'runtime'),
                admin_uid=os.geteuid(), platform=sys.platform, responsibility_domain='test' + str(index), signer_id=signer,
                trust_sha256=cp.digest(raw), approval_origin_sha256=cp.digest(bytes.fromhex('01' * 32)),
                audit_destination=str(self.base / ('audit' + str(index))), backup_destination=str(self.base / ('backup' + str(index))),
                policy_max_lifetime_ms=300000))
        self.cli_path = self.base / 'fake-cli'
        put(self.cli_path, ('#!' + sys.executable + '\nimport json\nprint("{}")\n').encode(), 0o700)
        self.profile = dict(format_version=1, customer_id='test-customer', registration_expires_at_ms=cp.now_ms() + 600000,
                            box_dir=str(self.box_dir), cli_path=str(self.cli_path), nodes=self.nodes)
        self.profile_path = put(self.base / 'profile.json', self.profile)
        self.profile, self.profile_sha = cp.load_profile(self.profile_path)
        self.node = self.profile['nodes'][0]
        self.box = cp.Box(self.profile, self.node)
        self.command_id = uid()
        self.bundle = dict(format_version=1, signer_id=self.node['signer_id'], signature='test-only-not-a-real-signature',
                           snapshot=dict(format_version=4, version=1, expires_at_ms=cp.now_ms() + 120000,
                                         approvers=[], workload_identities=[], bindings=[], rules=[]))
        self.raw = json.dumps(self.bundle, sort_keys=True, separators=(',', ':')).encode()
        self.policy_path = put(self.base / 'policy.json', self.raw)

    def tearDown(self):
        self.box.close()
        self.temp.cleanup()

    def publish(self):
        return cp.publish(self.box, self.profile, self.profile_sha, self.node, self.command_id, self.policy_path, self.trust_paths[0])

    def fake(self):
        return FakeCli(self.node, self.publish()['command'])

    def execute(self, operation, cli):
        return cp.execute(operation, self.box, self.profile, self.profile_sha, self.node, self.command_id, cli)

    def mutation_count(self, cli):
        return len([args for args in cli.calls if args[:2] == ['policy', 'activate']])


class FileTests(Fixture):
    def test_profile_is_closed_exact_two_and_distinct(self):
        for changed in (dict(self.profile, extra=1), dict(self.profile, nodes=self.nodes[:1]),
                        dict(self.profile, nodes=self.nodes + [self.nodes[0]]),
                        dict(self.profile, nodes=[self.nodes[0], self.nodes[0]])):
            with self.subTest(changed=changed):
                put(self.profile_path, changed)
                with self.assertRaises(cp.Error):
                    cp.load_profile(self.profile_path)

    def test_profile_invalid_types_paths_and_runtime(self):
        for key, value in [('admin_uid', True), ('policy_max_lifetime_ms', 0), ('policy_max_lifetime_ms', 300001),
                           ('runtime_dir', self.node['runtime_dir'] + '/other'), ('state_dir', '/tmp/../bad'),
                           ('trust_sha256', 'A' * 64), ('platform', 'other')]:
            p = copy.deepcopy(self.profile)
            p['nodes'][0][key] = value
            put(self.profile_path, p)
            with self.subTest(key=key, value=value), self.assertRaises(cp.Error):
                cp.load_profile(self.profile_path)

    def test_registration_expired(self):
        self.profile['registration_expires_at_ms'] = 0
        with self.assertRaisesRegex(cp.Error, 'registration-expired'):
            self.publish()

    def test_signed_duplicate_keys_rejected_without_dedup(self):
        put(self.policy_path, self.raw.replace(b'"version":1', b'"version":1,"version":1'))
        with self.assertRaisesRegex(cp.Error, 'duplicate-json-key'):
            self.publish()
        self.assertEqual(self.box.verify()[1], 0)

    def test_trust_duplicate_and_mismatched_sha(self):
        raw = Path(self.trust_paths[0]).read_bytes()
        for bad in (raw + b'\n', raw.replace(b'"format_version":1', b'"format_version":1,"format_version":1')):
            put(self.trust_paths[0], bad)
            with self.assertRaises(cp.Error):
                self.publish()

    def test_publish_preserves_raw_bytes_and_unconfirmed(self):
        result = self.publish()
        self.assertEqual(result['status'], 'uploaded/unconfirmed')
        self.assertEqual(result['command']['bundle_sha256'], cp.digest(self.raw))
        self.assertEqual(self.box.read(self.command_id, 'policy.json', True), self.raw)
        self.assertFalse(self.box.exists(self.command_id, 'receipt'))

    def test_duplicate_uuid_same_content_idempotent_different_rejected(self):
        first = self.publish()
        self.assertEqual(first, self.publish())
        self.bundle['snapshot']['version'] = 2
        put(self.policy_path, self.bundle)
        with self.assertRaisesRegex(cp.Error, 'command-id-conflict'):
            self.publish()
        self.assertEqual(self.box.read(self.command_id, 'policy.json', True), self.raw)

    def test_expired_and_lifetime_rejected(self):
        for expires in (0, cp.now_ms() + 400000):
            self.bundle['snapshot']['expires_at_ms'] = expires
            put(self.policy_path, self.bundle)
            with self.assertRaises(cp.Error):
                self.publish()

    def test_wrong_signer(self):
        self.bundle['signer_id'] = uid()
        put(self.policy_path, self.bundle)
        with self.assertRaises(cp.Error):
            self.publish()

    def test_file_permissions_symlink_hardlink_and_ancestor_symlink(self):
        for mode in (0o644, 0o400, 0o660):
            Path(self.policy_path).chmod(mode)
            with self.subTest(mode=mode), self.assertRaises(cp.Error):
                cp.read_file(self.policy_path)
        Path(self.policy_path).chmod(0o600)
        link = self.base / 'link.json'
        link.symlink_to(self.policy_path)
        with self.assertRaises(OSError):
            cp.read_file(str(link))
        link.unlink()
        os.link(self.policy_path, link)
        with self.assertRaises(cp.Error):
            cp.read_file(self.policy_path)
        link.unlink()
        alias = self.base / 'alias'
        alias.symlink_to(self.base, target_is_directory=True)
        with self.assertRaises(OSError):
            cp.read_file(str(alias / 'policy.json'))

    def test_owner_rejected(self):
        actual = os.stat(self.policy_path)
        values = list(actual)
        values[4] = actual.st_uid + 1
        with self.assertRaises(cp.Error):
            cp.secure(os.stat_result(values))

    def test_box_mode_and_symlink_rejected(self):
        self.box.close()
        self.box_dir.chmod(0o755)
        with self.assertRaises(cp.Error):
            cp.Box(self.profile, self.node)
        self.box_dir.chmod(0o700)
        moved = self.base / 'moved-box'
        self.box_dir.rename(moved)
        self.box_dir.symlink_to(moved, target_is_directory=True)
        with self.assertRaises(OSError):
            cp.Box(self.profile, self.node)

    def test_lock_exclusive(self):
        with self.assertRaises(BlockingIOError):
            cp.Box(self.profile, self.node)

    def test_root_and_child_inode_replacement_rejected(self):
        for relative in ('commands',):
            path = Path(self.box.path) / relative
            path.rename(self.base / (relative + '-old'))
            path.mkdir(mode=0o700)
            with self.assertRaisesRegex(cp.Error, 'path-replaced'):
                self.box.verify()
            path.rmdir()
            (self.base / (relative + '-old')).rename(path)
        self.publish()
        path = Path(self.box.path) / 'commands' / self.command_id
        path.rename(self.base / 'command-old')
        path.mkdir(mode=0o700)
        with self.assertRaisesRegex(cp.Error, 'path-replaced'):
            self.box.verify()

    def test_read_inode_replacement_during_read(self):
        original_read = os.read
        changed = False
        def replace(fd, size):
            nonlocal changed
            data = original_read(fd, size)
            if not changed:
                changed = True
                Path(self.policy_path).rename(self.policy_path + '.old')
                put(self.policy_path, self.raw)
            return data
        with mock.patch.object(cp.os, 'read', side_effect=replace), self.assertRaisesRegex(cp.Error, 'path-replaced'):
            cp.read_file(self.policy_path)

    def test_size_and_capacity(self):
        put(self.policy_path, b' ' * (cp.MAX_POLICY + 1))
        with self.assertRaisesRegex(cp.Error, 'size-limit'):
            self.publish()
        put(self.policy_path, self.raw)
        with mock.patch.object(cp, 'MAX_COMMANDS', 0), self.assertRaisesRegex(cp.Error, 'journal-capacity'):
            self.publish()
        with mock.patch.object(cp, 'MAX_JOURNAL', 10), self.assertRaisesRegex(cp.Error, 'journal-capacity'):
            self.publish()

    def test_actual_100_command_capacity(self):
        parent = Path(self.box.path) / 'commands'
        for _ in range(100):
            (parent / uid()).mkdir(mode=0o700)
        with self.assertRaisesRegex(cp.Error, 'journal-capacity'):
            self.publish()

    def test_partial_publication_failure_retains_no_replace(self):
        with mock.patch.object(cp.os, 'fsync', side_effect=OSError('test-fsync')), self.assertRaises(OSError):
            self.publish()
        self.assertTrue((Path(self.box.path) / 'commands' / self.command_id).exists())
        with self.assertRaises((OSError, cp.Error)):
            self.publish()

    def test_immutable_command_file_no_overwrite(self):
        self.publish()
        with self.assertRaises(FileExistsError):
            self.box.write(self.command_id, 'command.json', {})
        self.assertEqual(self.box.read(self.command_id, 'policy.json', True), self.raw)

    def test_boolean_command_version_rejected(self):
        self.publish()
        command = self.box.read(self.command_id, 'command.json')
        command['version'] = True
        put(self.box.path_for(self.command_id, 'command.json'), command)
        result, code = self.execute('apply', FakeCli(self.node, command))
        self.assertEqual((result['status'], code), ('rejected', 1))

    def test_corrupted_command_target_rejected(self):
        self.publish()
        command = self.box.read(self.command_id, 'command.json')
        command['vault_id'] = uid()
        put(self.box.path_for(self.command_id, 'command.json'), command)
        result, code = self.execute('apply', FakeCli(self.node, command))
        self.assertEqual((result['status'], code), ('rejected', 1))


class ApplyTests(Fixture):
    def test_apply_precise_receipt_and_fixed_flags(self):
        cli = self.fake()
        result, code = self.execute('apply', cli)
        self.assertEqual((result['status'], code), ('applied', 0))
        self.assertEqual(result['activated_at_ms'], 123)
        receipt = cp.historical_receipt(self.box, cli.command)
        self.assertEqual(receipt['audit_event']['reason_code'], 'policy-activated:1:' + cp.digest(self.raw))
        mutate = [args for args in cli.calls if args[:2] == ['policy', 'activate']][0]
        self.assertEqual(mutate[-4:], ['--expected-vault-id', self.node['vault_id'], '--expected-trust-sha256', self.node['trust_sha256']])
        self.assertTrue(self.box.exists(self.command_id, 'intent.json'))

    def test_target_root_tenant_and_origin_reject_before_dispatch(self):
        for field in ('vault_id', 'tenant_id', 'trust_sha256'):
            cli = self.fake()
            cli.status_patch[field] = uid() if field != 'trust_sha256' else 'a' * 64
            result, code = self.execute('apply', cli)
            with self.subTest(field=field):
                self.assertEqual((result['status'], code), ('rejected', 1))
                self.assertEqual(self.mutation_count(cli), 0)
                self.assertFalse(self.box.exists(self.command_id, 'intent.json'))
        cli = self.fake()
        cli.origin_patch = {'public_key': '02' * 32}
        result, _ = self.execute('apply', cli)
        self.assertEqual(result['status'], 'rejected')
        self.assertEqual(self.mutation_count(cli), 0)

    def test_origin_pin_hashes_decoded_key_not_json(self):
        cli = self.fake()
        self.node['approval_origin_sha256'] = cp.digest(cp.encode(dict(algorithm='ed25519', public_key='01' * 32)))
        # Republish binding with the changed registration to reach origin check.
        command = cp.bindings(self.profile, self.profile_sha, self.node, self.command_id, self.raw)
        put(self.box.path_for(self.command_id, 'command.json'), command)
        result, _ = self.execute('apply', cli)
        self.assertEqual(result['error'], 'actual-origin-mismatch')

    def test_commit_after_cli_error_confirmed_preserving_exit_code(self):
        cli = self.fake()
        cli.return_exit, cli.return_code = 7, 'ANY_PROVIDER_CODE'
        result, code = self.execute('apply', cli)
        self.assertEqual((result['status'], code, result['cli_code']), ('applied', 7, 'ANY_PROVIDER_CODE'))

    def test_dispatch_error_without_commit_unknown_no_second_mutation(self):
        cli = self.fake()
        cli.return_exit, cli.return_code, cli.commit = 7, 'OPEN_ERROR_CONTRACT', False
        result, code = self.execute('apply', cli)
        self.assertEqual((result['status'], code, result['cli_code']), ('unknown', 7, 'OPEN_ERROR_CONTRACT'))
        self.execute('apply', cli)
        self.execute('reconcile', cli)
        self.assertEqual(self.mutation_count(cli), 1)

    def test_expired_before_apply_no_intent(self):
        cli = self.fake()
        with mock.patch.object(cp, 'now_ms', return_value=cli.command['expires_at_ms'] + 1):
            result, _ = self.execute('apply', cli)
        self.assertEqual(result['status'], 'rejected')
        self.assertEqual(self.mutation_count(cli), 0)

    def test_intent_fsync_failure_no_mutation_but_retained(self):
        cli = self.fake()
        with mock.patch.object(cp.os, 'fsync', side_effect=OSError('fsync-failed')):
            result, _ = self.execute('apply', cli)
        self.assertEqual(result['status'], 'rejected')
        self.assertTrue(self.box.exists(self.command_id, 'intent.json'))
        self.execute('apply', cli)
        self.assertEqual(self.mutation_count(cli), 0)

    def test_receipt_fsync_failure_unknown_and_reconcile_no_resend(self):
        cli = self.fake()
        original_write = self.box.write
        def fail_receipt(command_id, name, value, raw=False):
            if name == 'receipt':
                raise OSError('receipt-fsync')
            return original_write(command_id, name, value, raw)
        with mock.patch.object(self.box, 'write', side_effect=fail_receipt):
            result, _ = self.execute('apply', cli)
        self.assertEqual(result['status'], 'unknown')
        self.assertFalse(self.box.exists(self.command_id, 'receipt'))
        result, _ = self.execute('reconcile', cli)
        self.assertEqual(result['status'], 'applied')
        self.assertFalse(self.box.exists(self.command_id, 'receipt'))
        self.assertEqual(self.mutation_count(cli), 1)

    def test_receipt_loss_reconcile_and_repeat_apply_readonly(self):
        cli = self.fake()
        self.execute('apply', cli)
        os.unlink(self.box.path_for(self.command_id, 'receipt'))
        self.assertEqual(self.execute('reconcile', cli)[0]['status'], 'applied')
        self.assertEqual(self.execute('apply', cli)[0]['status'], 'applied')
        self.assertEqual(self.mutation_count(cli), 1)
        self.assertFalse(self.box.exists(self.command_id, 'receipt'))

    def test_historical_receipt_requires_successful_readonly_fsync(self):
        cli = self.fake()
        self.execute('apply', cli)
        cli.status_patch.update(version=2, bundle_sha256='c' * 64)
        with mock.patch.object(cp.os, 'fsync', side_effect=OSError('readonly-sync-failed')):
            result, _ = self.execute('reconcile', cli)
        self.assertEqual(result['status'], 'unknown')
        self.assertTrue(self.box.exists(self.command_id, 'intent.json'))
        result, _ = self.execute('reconcile', cli)
        self.assertEqual(result['status'], 'applied')
        self.assertTrue(result['historical_confirmation'])
        self.assertEqual(self.mutation_count(cli), 1)

    def test_historical_receipt_real_sync_keeps_bytes(self):
        cli = self.fake()
        self.execute('apply', cli)
        path = Path(self.box.path_for(self.command_id, 'receipt'))
        before = path.read_bytes()
        cli.status_patch.update(version=2, bundle_sha256='c' * 64)
        self.assertEqual(self.execute('reconcile', cli)[0]['status'], 'applied')
        self.assertEqual(path.read_bytes(), before)

    def test_corrupt_receipt_unknown(self):
        cli = self.fake()
        self.execute('apply', cli)
        put(self.box.path_for(self.command_id, 'receipt'), {'status': 'applied'})
        result, _ = self.execute('reconcile', cli)
        self.assertEqual(result['status'], 'unknown')
        self.assertEqual(self.mutation_count(cli), 1)

    def test_current_higher_version_not_success_without_prior_receipt(self):
        cli = self.fake()
        cli.active = True
        cli.status_patch['version'] = 2
        result, _ = self.execute('reconcile', cli)
        self.assertEqual(result['status'], 'unknown')
        self.assertEqual(self.mutation_count(cli), 0)

    def test_prior_verified_receipt_confirms_history_after_next_version(self):
        cli = self.fake()
        self.execute('apply', cli)
        cli.status_patch.update(version=2, bundle_sha256='c' * 64)
        result, _ = self.execute('reconcile', cli)
        self.assertEqual(result['status'], 'applied')
        self.assertTrue(result['historical_confirmation'])
        self.assertEqual(result['current_version'], 2)
        self.assertEqual(self.mutation_count(cli), 1)

    def test_noncanonical_bundle_not_normalized_or_confirmed(self):
        pretty = json.dumps(self.bundle, indent=2).encode() + b'\n'
        put(self.policy_path, pretty)
        cli = self.fake()
        self.assertEqual(self.box.read(self.command_id, 'policy.json', True), pretty)
        cli.status_patch['bundle_sha256'] = cp.digest(self.raw)
        self.assertEqual(self.execute('apply', cli)[0]['status'], 'unknown')

    def test_status_is_real_preflight_unconfirmed_without_mutation(self):
        cli = self.fake()
        result, code = self.execute('status', cli)
        self.assertEqual((result['status'], code), ('observed/unconfirmed', 0))
        self.assertEqual(result['actual']['vault_id'], self.node['vault_id'])
        self.assertEqual(self.mutation_count(cli), 0)
        self.assertFalse(self.box.exists(self.command_id, 'intent.json'))

    def test_expired_actual_is_receiptable(self):
        cli = self.fake()
        cli.status_patch['status'] = 'expired'
        self.assertEqual(self.execute('apply', cli)[0]['current_policy_status'], 'expired')

    def test_missing_or_pruned_audit_and_same_version_other_sha_unknown(self):
        cli = self.fake()
        cli.active = True
        cli.pages = [dict(schema='rekey.audit.v2', snapshot_max_sequence=3, events=[], next_before_sequence=None)]
        self.assertEqual(self.execute('reconcile', cli)[0]['status'], 'unknown')
        cli.pages = None
        cli.audit_patch['reason_code'] = 'policy-activated:1:' + '0' * 64
        self.assertEqual(self.execute('reconcile', cli)[0]['status'], 'unknown')
        self.assertEqual(self.mutation_count(cli), 0)

    def test_commit_success_frame_without_status_audit_unknown(self):
        cli = self.fake()
        cli.commit = False
        result, code = self.execute('apply', cli)
        self.assertEqual((result['status'], code, result['cli_exit']), ('unknown', 1, 0))

    def test_out_of_order_dispatched_rejection_preserved_unknown(self):
        self.bundle['snapshot']['version'] = 3
        put(self.policy_path, self.bundle)
        cli = self.fake()
        cli.commit, cli.return_exit, cli.return_code = False, 4, 'POLICY_VERSION_CONFLICT'
        result, code = self.execute('apply', cli)
        self.assertEqual((result['status'], code, result['cli_code']), ('unknown', 4, 'POLICY_VERSION_CONFLICT'))
        self.assertEqual(self.mutation_count(cli), 1)

    def test_receipt_write_fsync_failure_after_file_creation_unknown(self):
        cli = self.fake()
        original_write = self.box.write
        def fail_receipt(command_id, name, value, raw=False):
            if name != 'receipt':
                return original_write(command_id, name, value, raw)
            with mock.patch.object(cp.os, 'fsync', side_effect=OSError('receipt-file-sync-failure')):
                return original_write(command_id, name, value, raw)
        with mock.patch.object(self.box, 'write', side_effect=fail_receipt):
            result, _ = self.execute('apply', cli)
        self.assertEqual(result['status'], 'unknown')
        self.assertTrue(self.box.exists(self.command_id, 'intent.json'))
        self.assertEqual(self.execute('reconcile', cli)[0]['status'], 'applied')
        self.assertEqual(self.mutation_count(cli), 1)

    def test_postdispatch_child_start_failure_unknown(self):
        cli = self.fake()
        with mock.patch.object(cli, 'call', side_effect=OSError('spawn-failure')):
            result, _ = self.execute('apply', cli)
        self.assertEqual(result['status'], 'unknown')
        self.assertTrue(self.box.exists(self.command_id, 'intent.json'))
        self.assertEqual(self.mutation_count(cli), 0)

    def test_exact_audit_reason_and_activation_time_required(self):
        for patch in ({'reason_code': 'policy-activated'}, {'reason_code': 'policy-activated:2:' + cp.digest(self.raw)},
                      {'created_at_ms': -1}, {'event_type': 'not-policy.activated'}, {'outcome': 'failure'}):
            cli = self.fake()
            cli.active = True
            cli.audit_patch = patch
            with self.subTest(patch=patch):
                self.assertEqual(self.execute('reconcile', cli)[0]['status'], 'unknown')

    def test_real_contract_independent_audit_and_activation_timestamps(self):
        cli = self.fake()
        cli.audit_patch['created_at_ms'] = 124
        result, _ = self.execute('apply', cli)
        self.assertEqual(result['status'], 'applied')
        self.assertEqual(result['activated_at_ms'], 123)
        self.assertEqual(result['audit_event']['created_at_ms'], 124)
        self.assertEqual(cp.historical_receipt(self.box, cli.command)['status'], 'applied')

    def test_fixed_snapshot_paging(self):
        cli = self.fake()
        cli.active = True
        cli.pages = [dict(schema='rekey.audit.v2', snapshot_max_sequence=10,
                          events=[dict(record_type='rekey.audit.v2', sequence=10)], next_before_sequence=9),
                     dict(schema='rekey.audit.v2', snapshot_max_sequence=10, events=[cli.event()], next_before_sequence=None)]
        result, _ = self.execute('reconcile', cli)
        self.assertEqual(result['status'], 'applied')
        self.assertEqual(cli.calls[-1][-4:], ['--snapshot-max-sequence', '10', '--before-sequence', '9'])

    def test_audit_fixed_25_row_query_and_overfull_page_unknown(self):
        cli = self.fake()
        cli.active = True
        events = [dict(record_type='rekey.audit.v2', sequence=sequence) for sequence in range(30, 4, -1)]
        cli.pages = [dict(schema='rekey.audit.v2', snapshot_max_sequence=30, events=events, next_before_sequence=None)]
        result, _ = self.execute('reconcile', cli)
        self.assertEqual(result['status'], 'unknown')
        self.assertEqual(cli.calls[-1], ['audit', 'list', '--limit', '25'])

    def test_snapshot_order_cursor_and_ten_page_bound(self):
        cli = self.fake()
        cli.active = True
        for second in (dict(schema='rekey.audit.v2', snapshot_max_sequence=11, events=[], next_before_sequence=None),
                       dict(schema='rekey.audit.v2', snapshot_max_sequence=10,
                            events=[dict(record_type='rekey.audit.v2', sequence=9)], next_before_sequence=None)):
            cli.pages = [dict(schema='rekey.audit.v2', snapshot_max_sequence=10, events=[], next_before_sequence=9), second]
            self.assertEqual(self.execute('reconcile', cli)[0]['status'], 'unknown')
        cli.calls = []
        cli.pages = [dict(schema='rekey.audit.v2', snapshot_max_sequence=100, events=[], next_before_sequence=99-i) for i in range(11)]
        self.assertEqual(self.execute('reconcile', cli)[0]['status'], 'unknown')
        self.assertEqual(len([args for args in cli.calls if args[:2] == ['audit', 'list']]), 10)

    def test_independent_nodes_partial_results(self):
        cli = self.fake()
        self.assertEqual(self.execute('apply', cli)[0]['status'], 'applied')
        self.assertFalse((self.box_dir / 'nodes' / self.nodes[1]['node_id']).exists())


class ChildTests(Fixture):
    def child(self, source, deadline=2):
        put(self.cli_path, ('#!' + sys.executable + '\n' + source).encode(), 0o700)
        return cp.Cli(self.profile, self.node, time.monotonic() + deadline)

    def test_actual_process_fixed_argv_no_ambient_env_and_same_session(self):
        cli = self.child('import os,json,sys\nprint(json.dumps({"argv":sys.argv[1:],"env":dict(os.environ),"sid":os.getsid(0)}))\n')
        with mock.patch.dict(os.environ, {'PROOF_CANARY': 'never-child'}, clear=False):
            result = cli.json(['policy', 'status'])
        self.assertEqual(result['argv'], ['--state-dir', self.node['state_dir'], 'policy', 'status'])
        self.assertNotIn('PROOF_CANARY', result['env'])
        self.assertNotIn('HOME', result['env'])
        self.assertEqual(result['sid'], os.getsid(0))

    def test_child_output_limit_each_stream(self):
        for stream in ('stdout', 'stderr'):
            cli = self.child('import sys\nsys.' + stream + '.write("x" * 100000)\nsys.' + stream + '.flush()\n')
            with self.subTest(stream=stream):
                result = cli.call(['policy', 'status'])
                self.assertEqual(result['issue'], 'child-output-limit')
                self.assertLessEqual(len(result['stdout']), cp.MAX_JSON)

    def test_child_deadline_owned_pid_killed(self):
        cli = self.child('import time\ntime.sleep(5)\n', deadline=0.8)
        real_popen = cp.subprocess.Popen
        owned = []
        def observe_popen(*args, **kwargs):
            child = real_popen(*args, **kwargs)
            owned.append(child)
            return child
        start = time.monotonic()
        with mock.patch.object(cp.subprocess, 'Popen', side_effect=observe_popen):
            result = cli.call(['policy', 'status'])
        self.assertLess(time.monotonic() - start, 2)
        self.assertEqual(result['issue'], 'child-timeout')
        self.assertEqual(result['exit'], -9)
        self.assertEqual(len(owned), 1)
        with self.assertRaises(ProcessLookupError):
            os.kill(owned[0].pid, 0)

    def test_child_exit_and_open_error_code_preserved(self):
        cli = self.child('import sys\nsys.stderr.write("error [UNLISTED_PROVIDER]: public failure\\n")\nsys.exit(9)\n')
        result = cli.call(['policy', 'status'])
        self.assertEqual((result['exit'], result['code']), (9, 'UNLISTED_PROVIDER'))

    def test_real_cli_pretty_complete_audit_rows_fit_fixed_page(self):
        # Real child emits ordinary full Rust AuditRecord JSON shape (including
        # all None/null fields); this is simulated CLI IO, not real Authority.
        fake = self.fake()
        fake.active = True
        rows = []
        for sequence in range(100, 0, -1):
            row = dict(record_type='rekey.audit.v2', sequence=sequence, event_id=f'{sequence:032x}',
                       request_id=None, session_id=None, action_id=None, action_version=None,
                       credential_id=None, credential_version=None, principal_id=None,
                       policy_version=None, policy_digest_hex=None, policy_rule_id=None,
                       approval_request_id=None, approval_id=None, approver_id=None,
                       event_type='vault.unlocked', outcome='success', reason_code='password-unlocked',
                       upstream_status=None, latency_ms=None, created_at_ms=123)
            rows.append(row)
        rows[0].update(event_type='policy.activated',
                       reason_code='policy-activated:1:' + fake.command['bundle_sha256'])
        page = dict(schema='rekey.audit.v2', snapshot_max_sequence=100, events=rows, next_before_sequence=None)
        self.assertGreater(len(json.dumps(page, indent=2, ensure_ascii=False).encode()), cp.MAX_JSON)
        page25 = dict(page, events=rows[:25], next_before_sequence=rows[24]['sequence'])
        self.assertLessEqual(len(json.dumps(page25, indent=2, ensure_ascii=False).encode()), cp.MAX_JSON)
        fixture = self.base / 'pretty-audit-fixture.json'
        put(fixture, dict(status=fake.status(), origin=dict(algorithm='ed25519', public_key='01' * 32), rows=rows))
        source = ('import json,sys\nfrom pathlib import Path\nx=json.loads(Path(' + repr(str(fixture)) + ').read_text())\n'
                  'a=sys.argv[3:]\n'
                  'if a[:2]==["policy","status"]: value=x["status"]\n'
                  'elif a[:2]==["approval","origin"]: value=x["origin"]\n'
                  'else:\n limit=int(a[a.index("--limit")+1])\n before=int(a[a.index("--before-sequence")+1]) if "--before-sequence" in a else 101\n'
                  ' rows=[row for row in x["rows"] if row["sequence"]<before][:limit]\n'
                  ' value=dict(schema="rekey.audit.v2",snapshot_max_sequence=100,events=rows,next_before_sequence=rows[-1]["sequence"] if len(rows)==limit else None)\n'
                  'print(json.dumps(value,indent=2,ensure_ascii=False))\n')
        cli = self.child(source, deadline=cp.RUN_SECONDS)
        result, code = self.execute('reconcile', cli)
        self.assertEqual((result['status'], code), ('applied', 0), result)
        self.assertEqual(result['audit_event']['reason_code'], rows[0]['reason_code'])
        self.assertEqual(result['audit_snapshot'], 100)

    def test_activation_tty_metadata_success_restores_flush_without_proof(self):
        cli = self.child('print("{}")\n', deadline=cp.RUN_SECONDS)
        real_open = cp.os.open
        fd = real_open('/dev/null', os.O_RDWR)
        attrs = [0, 0, 0, 0, 0, 0, []]
        def open_tty(path, *args, **kwargs):
            if path == '/dev/tty':
                self.assertEqual(args[0] & os.O_ACCMODE, os.O_RDONLY)
                return os.dup(fd)
            return real_open(path, *args, **kwargs)
        try:
            with mock.patch.object(cp.os, 'open', side_effect=open_tty), mock.patch.object(cp.termios, 'tcgetattr', return_value=attrs), mock.patch.object(cp.termios, 'tcsetattr') as restore:
                result = cli.call(['policy', 'activate'])
            self.assertEqual(result['exit'], 0)
            self.assertEqual(restore.call_args.args[1:], (cp.termios.TCSAFLUSH, attrs))
        finally:
            os.close(fd)

    def test_nonactivation_does_not_touch_tty_metadata(self):
        cli = self.child('print("{}")\n', deadline=cp.RUN_SECONDS)
        with mock.patch.object(cp.termios, 'tcgetattr') as capture, mock.patch.object(cp.termios, 'tcsetattr') as restore:
            result = cli.call(['policy', 'status'])
        self.assertEqual(result['exit'], 0)
        capture.assert_not_called()
        restore.assert_not_called()

    def test_activation_tty_capture_failure_before_child(self):
        cli = self.child('print("{}")\n', deadline=cp.RUN_SECONDS)
        real_open = cp.os.open
        def fail_tty(path, *args, **kwargs):
            if path == '/dev/tty':
                raise OSError(errno.EPERM, 'synthetic permission failure')
            return real_open(path, *args, **kwargs)
        with mock.patch.object(cp.os, 'open', side_effect=fail_tty), mock.patch.object(cp.subprocess, 'Popen') as spawn:
            with self.assertRaisesRegex(cp.Error, 'tty-state-capture-failed'):
                cli.call(['policy', 'activate'])
            spawn.assert_not_called()
        fd = real_open('/dev/null', os.O_RDWR)
        def open_tty(path, *args, **kwargs):
            return os.dup(fd) if path == '/dev/tty' else real_open(path, *args, **kwargs)
        try:
            with mock.patch.object(cp.os, 'open', side_effect=open_tty), mock.patch.object(cp.termios, 'tcgetattr', side_effect=cp.termios.error(errno.EIO, 'synthetic metadata failure')), mock.patch.object(cp.subprocess, 'Popen') as spawn:
                with self.assertRaisesRegex(cp.Error, 'tty-state-capture-failed'):
                    cli.call(['policy', 'activate'])
                spawn.assert_not_called()
        finally:
            os.close(fd)

    def test_activation_tty_restore_failure_preserves_actual_cli_exit_code(self):
        cli = self.child('import sys\nsys.stderr.write("error [OPEN_CODE]: public failure\\n")\nsys.exit(9)\n', deadline=cp.RUN_SECONDS)
        real_open = cp.os.open
        fd = real_open('/dev/null', os.O_RDWR)
        def open_tty(path, *args, **kwargs):
            return os.dup(fd) if path == '/dev/tty' else real_open(path, *args, **kwargs)
        try:
            with mock.patch.object(cp.os, 'open', side_effect=open_tty), mock.patch.object(cp.termios, 'tcgetattr', return_value=[0,0,0,0,0,0,[]]), mock.patch.object(cp.termios, 'tcsetattr', side_effect=cp.termios.error(errno.EIO, 'synthetic restore failure')):
                with self.assertRaises(cp.CliError) as raised:
                    cli.call(['policy', 'activate'])
            self.assertEqual(raised.exception.result['exit'], 9)
            self.assertEqual(raised.exception.result['code'], 'OPEN_CODE')
            self.assertEqual(raised.exception.result['issue'], 'tty-state-restore-failed')
        finally:
            os.close(fd)

    def test_synthetic_controlling_pty_raw_timeout_restores_original_metadata(self):
        # This fixture owns a separate SID/PTY. No user terminal or proof input.
        marker = self.base / 'synthetic-raw-entered'
        source = ('import os,termios,time\nfd=os.open("/dev/tty",os.O_RDWR)\na=termios.tcgetattr(fd)\n'
                  'a[3]&=~(termios.ECHO|termios.ICANON|termios.ECHONL|termios.ISIG)\n'
                  'termios.tcsetattr(fd,termios.TCSANOW,a)\n'
                  'open(' + repr(str(marker)) + ',"w").write("raw-mode-only-no-proof")\ntime.sleep(10)\n')
        self.child(source, deadline=3)
        master, slave = os.openpty()
        controller = ('import os,fcntl,termios,importlib.util,json,time\n'
                      'os.setsid()\ns=' + str(slave) + '\nfcntl.ioctl(s,termios.TIOCSCTTY,0)\n'
                      'before=termios.tcgetattr(s)\n'
                      'spec=importlib.util.spec_from_file_location("cp",' + repr(str(Path(cp.__file__))) + ')\n'
                      'cp=importlib.util.module_from_spec(spec)\nspec.loader.exec_module(cp)\n'
                      'p,_=cp.load_profile(' + repr(self.profile_path) + ')\n'
                      'r=cp.Cli(p,p["nodes"][0],time.monotonic()+3).call(["policy","activate"])\n'
                      'after=termios.tcgetattr(s)\n'
                      'print(json.dumps(dict(restored=before==after,exit=r["exit"],issue=r["issue"],raw_entered=os.path.exists(' + repr(str(marker)) + '))))\n')
        try:
            result = subprocess.run([sys.executable, '-B', '-c', controller], pass_fds=(slave,), capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            observed = json.loads(result.stdout)
            self.assertTrue(observed['raw_entered'])
            self.assertTrue(observed['restored'])
            self.assertEqual((observed['exit'], observed['issue']), (-9, 'child-timeout'))
        finally:
            os.close(master)
            os.close(slave)

    def test_cli_writable_nonsticky_ancestor_rejected_before_real_spawn(self):
        self.base.chmod(0o755)
        parent = self.base / 'writable-cli-parent'
        parent.mkdir(mode=0o777)
        parent.chmod(0o777)
        executable = parent / 'registered-cli'
        put(executable, ('#!' + sys.executable + '\nprint("unsafe-parent-child-executed")\n').encode(), 0o755)
        self.profile['cli_path'] = str(executable)
        cli = cp.Cli(self.profile, self.node, time.monotonic() + 2)
        real_popen = cp.subprocess.Popen
        owned = []
        def observe_popen(*args, **kwargs):
            child = real_popen(*args, **kwargs)
            owned.append(child)
            return child
        rejected = False
        result = None
        with mock.patch.object(cp.subprocess, 'Popen', side_effect=observe_popen):
            try:
                result = cli.call(['policy', 'status'])
            except cp.Error as error:
                self.assertEqual(str(error), 'unsafe-cli-ancestor')
                rejected = True
        self.assertTrue(rejected, 'unsafe ancestor admitted ' + str(len(owned)) + ' real child; result=' + repr(result))
        self.assertEqual(owned, [])

    def test_cli_ancestor_actual_other_uid_owner_rejected(self):
        # Real fstat ownership is another UID relative to this boundary's admin.
        actual = os.stat(self.base)
        self.assertEqual(actual.st_uid, os.geteuid())
        with self.assertRaisesRegex(cp.Error, 'unsafe-cli-ancestor'):
            cp.directory(str(self.base), executable_owner=os.geteuid() + 1)

    def test_cli_trusted_0755_ancestor_real_child_allowed(self):
        self.base.chmod(0o755)
        parent = self.base / 'trusted-cli-parent'
        parent.mkdir(mode=0o755)
        parent.chmod(0o755)
        executable = parent / 'registered-cli'
        put(executable, ('#!' + sys.executable + '\nprint("trusted-parent-child-executed")\n').encode(), 0o755)
        self.profile['cli_path'] = str(executable)
        cli = cp.Cli(self.profile, self.node, time.monotonic() + cp.RUN_SECONDS)
        result = cli.call(['policy', 'status'])
        self.assertEqual(result['exit'], 0)
        self.assertEqual(result['stdout'], b'trusted-parent-child-executed\n')

    def test_cli_root_owned_sticky_system_ancestor_real_child_allowed(self):
        system_tmp = os.path.realpath('/tmp')
        info = os.stat(system_tmp)
        self.assertEqual(info.st_uid, 0)
        self.assertTrue(info.st_mode & 0o1000)
        with tempfile.TemporaryDirectory(dir=system_tmp) as temporary:
            parent = Path(os.path.realpath(temporary))
            parent.chmod(0o700)
            executable = parent / 'registered-cli'
            put(executable, ('#!' + sys.executable + '\nprint("sticky-root-child-executed")\n').encode(), 0o755)
            self.profile['cli_path'] = str(executable)
            cli = cp.Cli(self.profile, self.node, time.monotonic() + cp.RUN_SECONDS)
            result = cli.call(['policy', 'status'])
            self.assertEqual(result['exit'], 0)
            self.assertEqual(result['stdout'], b'sticky-root-child-executed\n')

    def test_cli_admin_owned_sticky_writable_ancestor_rejected(self):
        self.base.chmod(0o1777)
        with self.assertRaisesRegex(cp.Error, 'unsafe-cli-ancestor'):
            cp.directory(str(self.base), executable_owner=os.geteuid())

    def test_local_uid_platform_and_executable_rejected(self):
        cli = self.child('print("{}")\n')
        for key, value in (('admin_uid', os.geteuid()+1), ('platform', 'other')):
            original = self.node[key]
            self.node[key] = value
            with self.assertRaises(cp.Error):
                cli.call(['policy', 'status'])
            self.node[key] = original
        self.cli_path.chmod(0o777)
        with self.assertRaises(cp.Error):
            cli.call(['policy', 'status'])

    def test_whole_deadline_exhausted_before_child(self):
        cli = self.child('print("{}")\n', deadline=-1)
        with self.assertRaisesRegex(cp.Error, 'operation-timeout'):
            cli.call(['policy', 'status'])

    def test_blackbox_fake_cli_end_to_end(self):
        # The executable simulates public responses and commit; no Authority/crypto.
        command = self.publish()['command']
        fixture = self.base / 'fixture.json'
        public = FakeCli(self.node, command)
        active = public.status()
        public.active = True
        committed = public.status()
        config = dict(before=active, after=committed, event=public.event(), count=0,
                      origin=dict(algorithm='ed25519', public_key='01' * 32))
        put(fixture, config)
        source = ('import json,sys\nfrom pathlib import Path\np=Path(' + repr(str(fixture)) + ')\n'
                  'x=json.loads(p.read_text())\na=sys.argv[3:]\n'
                  'if a[:2]==["policy","activate"]:\n x["count"]+=1\n p.write_text(json.dumps(x))\n print(json.dumps(x["after"]))\n'
                  'elif a[:2]==["policy","status"]: print(json.dumps(x["after"] if x["count"] else x["before"]))\n'
                  'elif a[:2]==["approval","origin"]: print(json.dumps(x["origin"]))\n'
                  'else: print(json.dumps(dict(schema="rekey.audit.v2",snapshot_max_sequence=3,events=[x["event"]],next_before_sequence=None)))\n')
        self.child(source)
        for op in ('apply', 'reconcile', 'apply'):
            args = [sys.executable, '-B', str(Path(cp.__file__)), op, '--profile', self.profile_path,
                    '--node', self.node['node_id'], '--command-id', self.command_id]
            self.box.close()
            result = subprocess.run(args, capture_output=True, timeout=5)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(json.loads(result.stdout)['status'], 'applied')
        self.assertEqual(json.loads(fixture.read_text())['count'], 1)


class AdminSessionChildTests(Fixture):
    def test_private_session_path_passed_to_every_actual_child_without_reading_token(self):
        session = put(self.base / 'admin session.token', b'SYNTHETIC-MANAGEMENT-TOKEN-CANARY', 0o600)
        put(self.cli_path, ('#!' + sys.executable + '\nimport os,json,sys\n'
            'print(json.dumps({"argv":sys.argv[1:],"env":dict(os.environ)}))\n').encode(), 0o700)
        cli = cp.Cli(self.profile, self.node, time.monotonic() + 5, str(session))
        for args in (['policy', 'status'], ['audit', 'query', '--limit', '25']):
            with self.subTest(args=args), mock.patch.dict(os.environ, {'TOKEN_CANARY': 'never-child'}):
                result = cli.json(args)
                self.assertEqual(result['argv'], ['--state-dir', self.node['state_dir'],
                    '--admin-session-file', str(session)] + args)
                self.assertNotIn('TOKEN_CANARY', result['env'])
                self.assertNotIn('SYNTHETIC-MANAGEMENT-TOKEN-CANARY', json.dumps(result))

    def test_session_path_is_not_opened_by_helper(self):
        missing = str(self.base / 'not-readable-by-helper.token')
        put(self.cli_path, ('#!' + sys.executable + '\nimport json,sys\n'
            'print(json.dumps({"argv":sys.argv[1:]}))\n').encode(), 0o700)
        cli = cp.Cli(self.profile, self.node, time.monotonic() + 2, missing)
        self.assertIn(missing, cli.json(['policy', 'status'])['argv'])

    def test_relative_session_path_rejects_before_child(self):
        with mock.patch.object(cp.subprocess, 'Popen') as spawn:
            for path in ('session.token', '../session.token', ''):
                with self.subTest(path=path), self.assertRaisesRegex(cp.Error, 'session-file-must-be-absolute'):
                    cp.Cli(self.profile, self.node, time.monotonic() + 2, path)
            spawn.assert_not_called()


ACCEPTANCE_SPEC = importlib.util.spec_from_file_location('enterprise_acceptance',
    Path(__file__).with_name('rekey-enterprise-acceptance.py'))
ACCEPTANCE = importlib.util.module_from_spec(ACCEPTANCE_SPEC)
ACCEPTANCE_SPEC.loader.exec_module(ACCEPTANCE)


class EnterpriseEntryTests(unittest.TestCase):
    """Fake children exercise orchestration errors, NEVER real or field gates."""
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(os.path.realpath(self.temp.name))
        self.root.chmod(0o700)
        self.output = self.root / 'output'
        self.binaries = self.root / 'bin'
        self.binaries.mkdir(mode=0o700)
        self.argv = ['--bin-dir', str(self.binaries), '--output', str(self.output)]
        self.script = self.root / 'fake-child.py'
        self.script.write_text('print("SYNTHETIC-CHILD-SECRET-CANARY")\n')
        self.script.chmod(0o600)
        self.gate = dict(name='policy_signer', scope='fake child error contract only', script=self.script,
                         argv=[sys.executable, str(self.script)], binaries=(), dependencies=())

    def execute(self, gate=None):
        return ACCEPTANCE.execute_gate(self.gate if gate is None else gate, self.binaries, self.output)

    def test_actual_child_nonzero_signal_and_redaction(self):
        for source, expected_exit, expected_signal in (
            ('import sys\nprint("SYNTHETIC-CHILD-SECRET-CANARY");print("SYNTHETIC-CHILD-SECRET-CANARY",file=sys.stderr);sys.exit(7)\n', 7, None),
            ('import os,signal\nos.kill(os.getpid(),signal.SIGTERM)\n', None, 15),
        ):
            with self.subTest(exit=expected_exit, signal=expected_signal):
                self.script.write_text(source)
                result = self.execute()
                self.assertEqual(result['outcome'], 'failed')
                self.assertEqual(result['exit'], expected_exit)
                self.assertEqual(result['signal'], expected_signal)
                self.assertGreaterEqual(result['duration_ns'], 0)
                self.assertNotIn('SYNTHETIC-CHILD-SECRET-CANARY', json.dumps(result))
                self.assertFalse(result['cleanup_confirmed'])

    def test_launch_exception_and_timeout_are_fixed_failures_without_text(self):
        for error in (OSError('SYNTHETIC-CHILD-SECRET-CANARY'),
                      RuntimeError('SYNTHETIC-CHILD-SECRET-CANARY'),
                      subprocess.TimeoutExpired('SYNTHETIC-CHILD-SECRET-CANARY', 1,
                                                output=b'SYNTHETIC-CHILD-SECRET-CANARY')):
            with self.subTest(kind=type(error).__name__), mock.patch.object(ACCEPTANCE, 'run_child', side_effect=error):
                result = self.execute()
                self.assertEqual(result['outcome'], 'failed')
                self.assertFalse(result['cleanup_confirmed'])
                self.assertNotIn('SYNTHETIC-CHILD-SECRET-CANARY', json.dumps(result))

    def test_exit_zero_missing_required_keycloak_and_journal_receipt_fails(self):
        for name in ('keycloak', 'journal'):
            with self.subTest(name=name), mock.patch.object(ACCEPTANCE, 'run_child',
                    return_value=subprocess.CompletedProcess([], 0)):
                result = self.execute(dict(self.gate, name=name))
                self.assertEqual(result['exit'], 0)
                self.assertEqual(result['outcome'], 'failed')

    def keycloak_receipt(self, **changes):
        folder = self.output / 'KEYCLOAK'
        folder.mkdir(mode=0o700, parents=True, exist_ok=True)
        value = {'pass': True, 'secret_scan_passed': True,
                 'cleanup': {key: True for key in ACCEPTANCE.CLEANUP_FIELDS},
                 'untrusted_extra': 'SYNTHETIC-CHILD-SECRET-CANARY'}
        value.update(changes)
        put(folder / 'receipt.json', value)
        return value

    def test_keycloak_cleanup_error_fails_and_selected_summary_redacts_extra_fields(self):
        value = self.keycloak_receipt()
        with mock.patch.object(ACCEPTANCE, 'run_child', return_value=subprocess.CompletedProcess([], 0)):
            result = self.execute(dict(self.gate, name='keycloak'))
            self.assertEqual(result['outcome'], 'passed')
            self.assertTrue(result['cleanup_confirmed'])
            self.assertNotIn('SYNTHETIC-CHILD-SECRET-CANARY', json.dumps(result))
            for key in ACCEPTANCE.CLEANUP_FIELDS:
                with self.subTest(key=key):
                    cleanup = dict(value['cleanup'], **{key: False})
                    self.keycloak_receipt(cleanup=cleanup)
                    self.assertEqual(self.execute(dict(self.gate, name='keycloak'))['outcome'], 'failed')

    def test_journal_exact_scenarios_required_and_arbitrary_receipt_text_not_imported(self):
        folder = self.output / 'JOURNAL'
        folder.mkdir(mode=0o700, parents=True)
        value = [{'gate': gate, 'untrusted': 'SYNTHETIC-CHILD-SECRET-CANARY'} for gate in ACCEPTANCE.JOURNAL_GATES]
        with mock.patch.object(ACCEPTANCE, 'run_child', return_value=subprocess.CompletedProcess([], 0)):
            for bad in (value[:-1], value[::-1], {'pass': True}):
                put(folder / 'evidence.json', bad)
                self.assertEqual(self.execute(dict(self.gate, name='journal'))['outcome'], 'failed')
            put(folder / 'evidence.json', value)
            result = self.execute(dict(self.gate, name='journal'))
            self.assertEqual(result['outcome'], 'passed')
            self.assertEqual(result['scenario_count'], 5)
            self.assertNotIn('SYNTHETIC-CHILD-SECRET-CANARY', json.dumps(result))

    def test_nonlinux_vault_skip_and_linux_install_are_unexecuted_before_child(self):
        for platform, reason in (('darwin', 'nonlinux-script-skip'),
                                 ('linux', 'existing-script-requires-build-install-and-fixed-binaries')):
            with self.subTest(platform=platform), mock.patch.object(ACCEPTANCE.sys, 'platform', platform), \
                    mock.patch.object(ACCEPTANCE, 'run_child') as child:
                result = self.execute(dict(self.gate, name='vault_oss'))
                self.assertEqual(result['outcome'], 'unexecuted')
                self.assertEqual(result['reason'], reason)
                self.assertIsNone(result['exit'])
                child.assert_not_called()

    def test_local_image_failure_and_missing_binary_do_not_launch_gate(self):
        with mock.patch.object(ACCEPTANCE, 'run_child', return_value=subprocess.CompletedProcess([], 1)) as child:
            result = self.execute(dict(self.gate, name='keycloak'))
            self.assertEqual(result['outcome'], 'unexecuted')
            self.assertEqual(child.call_args.args[0], ['docker', 'image', 'inspect', ACCEPTANCE.KEYCLOAK_IMAGE])
            self.assertEqual(child.call_count, 1)
        with mock.patch.object(ACCEPTANCE, 'run_child') as child:
            result = self.execute(dict(self.gate, binaries=('missing',)))
            self.assertEqual(result['outcome'], 'unexecuted')
            child.assert_not_called()

    def test_field_rejects_before_any_output_hash_or_child_and_collision_preserves(self):
        with mock.patch.object(ACCEPTANCE.DR, 'create_output') as create, \
                mock.patch.object(ACCEPTANCE.DR, 'stream_digest') as digest, \
                mock.patch.object(ACCEPTANCE, 'run_child') as child:
            self.assertEqual(ACCEPTANCE.main(self.argv + ['--require-field']), 1)
            create.assert_not_called()
            digest.assert_not_called()
            child.assert_not_called()
        self.output.mkdir(mode=0o700)
        marker = self.output / 'report.json'
        marker.write_text('preserve original')
        with mock.patch.object(ACCEPTANCE, 'run_child') as child:
            self.assertEqual(ACCEPTANCE.main(self.argv), 1)
            child.assert_not_called()
        self.assertEqual(marker.read_text(), 'preserve original')

    def test_world_writable_execution_ancestor_rejects_before_child(self):
        self.root.chmod(0o777)
        try:
            with mock.patch.object(ACCEPTANCE, 'run_child') as child:
                result = self.execute()
                self.assertEqual(result['outcome'], 'unexecuted')
                self.assertEqual(result['reason'], 'missing-or-unsafe-script-binary')
                child.assert_not_called()
        finally:
            self.root.chmod(0o700)

    def test_source_replaced_after_first_hash_is_rejected_before_child(self):
        digest = ACCEPTANCE.DR.stream_digest
        replaced = False
        def replace(path, **kwargs):
            nonlocal replaced
            result = digest(path, **kwargs)
            if path == self.script and not replaced:
                replacement = self.root / 'replacement.py'
                replacement.write_bytes(self.script.read_bytes())
                replacement.chmod(0o600)
                replacement.replace(self.script)
                replaced = True
            return result
        with mock.patch.object(ACCEPTANCE.DR, 'stream_digest', replace), \
                mock.patch.object(ACCEPTANCE, 'run_child') as child:
            result = self.execute()
            self.assertEqual(result['outcome'], 'failed')
            self.assertIsNone(result['exit'])
            child.assert_not_called()

    def test_actual_child_replaces_its_source_same_bytes_then_exit_zero_is_failed(self):
        self.script.write_text('from pathlib import Path\n'
            'p=Path(__file__);replacement=p.with_name("replacement.py")\n'
            'replacement.write_bytes(p.read_bytes());replacement.chmod(0o600);replacement.replace(p)\n')
        result = self.execute()
        self.assertEqual(result['exit'], 0)
        self.assertEqual(result['outcome'], 'failed')
        self.assertFalse(result['cleanup_confirmed'])

    def test_fixed_actual_dependencies_and_missing_delegated_binary_before_child(self):
        gates = {gate['name']: gate for gate in ACCEPTANCE.fixed_gates(self.binaries, self.output)}
        for name in ('approval_signer_relay', 'journal'):
            with self.subTest(name=name):
                self.assertIn('rekeyd', gates[name]['binaries'])
                self.assertIn('sign-test-policy.py', gates[name]['dependencies'])
                for relative in gates[name]['binaries']:
                    if relative == 'rekeyd':
                        continue
                    path = self.binaries / relative
                    path.parent.mkdir(mode=0o700, exist_ok=True)
                    path.write_text('fake executable only')
                    path.chmod(0o700)
                with mock.patch.object(ACCEPTANCE, 'run_child') as child:
                    result = ACCEPTANCE.execute_gate(gates[name], self.binaries, self.output)
                    self.assertEqual(result['outcome'], 'unexecuted')
                    self.assertEqual(result['reason'], 'missing-or-unsafe-script-binary')
                    child.assert_not_called()
        for gate in gates.values():
            for relative in gate['binaries']:
                path = self.binaries / relative
                path.parent.mkdir(mode=0o700, exist_ok=True)
                path.write_text('fake executable only')
                path.chmod(0o700)
        with mock.patch.object(ACCEPTANCE, 'run_child', return_value=subprocess.CompletedProcess([], 0)):
            result = ACCEPTANCE.execute_gate(gates['approval_signer_relay'], self.binaries, self.output)
        self.assertEqual(set(result['binary_sha256']), set(gates['approval_signer_relay']['binaries']))
        self.assertEqual(set(result['dependency_sha256']), {'sign-test-policy.py'})

    def test_missing_actual_journal_signer_dependency_before_child(self):
        gate = next(item for item in ACCEPTANCE.fixed_gates(self.binaries, self.output) if item['name'] == 'journal')
        for relative in gate['binaries']:
            path = self.binaries / relative
            path.parent.mkdir(mode=0o700, exist_ok=True)
            path.write_text('fake executable only')
            path.chmod(0o700)
        digest = ACCEPTANCE.DR.stream_digest
        def missing(path, **kwargs):
            if path.name == 'sign-test-policy.py':
                raise FileNotFoundError('SYNTHETIC-CHILD-SECRET-CANARY')
            return digest(path, **kwargs)
        with mock.patch.object(ACCEPTANCE.DR, 'stream_digest', missing), \
                mock.patch.object(ACCEPTANCE, 'run_child') as child:
            self.assertEqual(ACCEPTANCE.execute_gate(gate, self.binaries, self.output)['outcome'], 'unexecuted')
            child.assert_not_called()

    def test_actual_output_directory_swap_during_gate_fails_without_report(self):
        moved = self.root / 'moved-original'
        def swap(gate, binaries, output):
            output.rename(moved)
            output.mkdir(mode=0o700)
            return {'name': 'fake', 'outcome': 'passed'}
        with mock.patch.object(ACCEPTANCE, 'fixed_gates', return_value=[self.gate]), \
                mock.patch.object(ACCEPTANCE, 'execute_gate', side_effect=swap):
            self.assertEqual(ACCEPTANCE.main(self.argv), 1)
        self.assertFalse((self.output / 'report.json').exists())
        self.assertFalse((moved / 'report.json').exists())

    def test_actual_output_fsync_faults_fail_and_do_not_publish_report(self):
        original = os.fsync
        for failure in range(1, 5):
            with self.subTest(failure=failure):
                output = self.root / ('fsync-' + str(failure))
                args = self.argv[:-1] + [str(output)]
                count = 0
                def fail(fd):
                    nonlocal count
                    count += 1
                    if count == failure:
                        raise OSError('SYNTHETIC-CHILD-SECRET-CANARY')
                    original(fd)
                with mock.patch.object(ACCEPTANCE.os, 'fsync', fail), \
                        mock.patch.object(ACCEPTANCE, 'fixed_gates', return_value=[self.gate]), \
                        mock.patch.object(ACCEPTANCE, 'execute_gate', return_value={'name': 'fake', 'outcome': 'passed'}) as gate:
                    self.assertEqual(ACCEPTANCE.main(args), 1)
                    if failure <= 2:
                        gate.assert_not_called()
                self.assertFalse((output / 'report.json').exists())

    def test_all_fake_local_passes_never_validate_field_and_unexecuted_is_nonzero(self):
        fake = [dict(name='fake', outcome='passed')]
        with mock.patch.object(ACCEPTANCE, 'fixed_gates', return_value=[self.gate]), \
                mock.patch.object(ACCEPTANCE, 'execute_gate', return_value=fake[0]):
            self.assertEqual(ACCEPTANCE.main(self.argv), 0)
        report = json.loads((self.output / 'report.json').read_text())
        self.assertFalse(report['field_validated'])
        self.assertEqual(set(report['field_gates'].values()), {'unvalidated'})
        self.output = self.root / 'output-incomplete'
        self.argv[-1] = str(self.output)
        with mock.patch.object(ACCEPTANCE, 'fixed_gates', return_value=[self.gate]), \
                mock.patch.object(ACCEPTANCE, 'execute_gate', return_value={'name': 'fake', 'outcome': 'unexecuted'}):
            self.assertEqual(ACCEPTANCE.main(self.argv), 1)


if __name__ == '__main__':
    unittest.main(verbosity=2)
