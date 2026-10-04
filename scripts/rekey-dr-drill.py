#!/usr/bin/env python3
"""Compare an encrypted backup with original BackupReceipt and actual RestoreReceipt.

This performs no restore or promotion. Success proves artifact_match only.
"""
import argparse
import hashlib
import importlib.util
import json
import os
import stat
from pathlib import Path
import sys
import uuid

SPEC = importlib.util.spec_from_file_location('dr_files', Path(__file__).with_name('rekey-controlplane.py'))
FILES = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(FILES)
FORMAT_VERSION = 25


def stream_digest(path, private=True, pin=False):
    """Hash through one no-follow fd; reject replacement or concurrent writes."""
    FILES.path_value(str(path))
    owner = None if private else os.geteuid()
    parent = FILES.directory(str(path.parent), executable_owner=owner)
    fd = None
    try:
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        before = os.fstat(fd)
        if private:
            FILES.secure(before)
        else:
            FILES.require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                          and before.st_uid in (0, os.geteuid()) and not before.st_mode & 0o022, 'unsafe-source')
        result = hashlib.sha256()
        for block in iter(lambda: os.read(fd, 1024 * 1024), b''):
            result.update(block)
        after = os.fstat(fd)
        named = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
        FILES.require(FILES.same(before, named) and FILES.same(before, after)
                      and (before.st_size, before.st_mtime_ns, before.st_ctime_ns)
                      == (after.st_size, after.st_mtime_ns, after.st_ctime_ns), 'path-replaced')
        check = FILES.directory(str(path.parent), executable_owner=owner)
        try:
            FILES.require(FILES.same(os.fstat(check), os.fstat(parent)), 'path-replaced')
        finally:
            os.close(check)
        if pin:
            parent_info = os.fstat(parent)
            return (result.hexdigest(), before.st_dev, before.st_ino, before.st_mode, before.st_uid,
                    before.st_nlink, before.st_size, before.st_mtime_ns, before.st_ctime_ns,
                    parent_info.st_dev, parent_info.st_ino)
        return result.hexdigest()
    finally:
        if fd is not None:
            os.close(fd)
        os.close(parent)


def check_output(path, directory):
    """The create-new directory fd stays owned by the caller until publication ends."""
    FILES.secure(os.fstat(directory), directory=True)
    named = FILES.directory(str(path))
    try:
        FILES.secure(os.fstat(named), directory=True)
        FILES.require(FILES.same(os.fstat(directory), os.fstat(named)), 'output-replaced')
    finally:
        os.close(named)


def create_output(path):
    FILES.path_value(str(path))
    parent = FILES.directory(str(path.parent), executable_owner=os.geteuid())
    fd = None
    try:
        os.mkdir(path.name, mode=0o700, dir_fd=parent)
        fd = os.open(path.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
        check_output(path, fd)
        os.fsync(fd)
        os.fsync(parent)
        check_output(path, fd)
        return fd
    except BaseException:
        if fd is not None:
            os.close(fd)
        raise
    finally:
        os.close(parent)


def write_report(path, directory, report):
    fd = None
    created = False
    try:
        check_output(path, directory)
        fd = os.open('report.json', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o600, dir_fd=directory)
        created = True
        with os.fdopen(fd, 'w', encoding='utf-8') as handle:
            fd = None
            handle.write(json.dumps(report, indent=2, sort_keys=True) + '\n')
            handle.flush()
            check_output(path, directory)
            os.fsync(handle.fileno())
        check_output(path, directory)
        os.fsync(directory)
        check_output(path, directory)
    except (OSError, FILES.Error):
        if created:
            try:
                os.unlink('report.json', dir_fd=directory)
            except OSError:
                pass
        raise
    finally:
        if fd is not None:
            os.close(fd)



def hex_digest(value):
    return type(value) is str and len(value) == 64 and all(c in '0123456789abcdef' for c in value)


def integer(value, maximum):
    return type(value) is int and 0 <= value <= maximum


def receipt(path, restore=False):
    raw = FILES.read_file(str(path))
    value = FILES.decode(raw)
    fields = {'vault_id', 'format_version', 'output_path', 'snapshot_cut', 'generation'}
    fields |= {'input_sha256_hex'} if restore else {'sha256_hex', 'created_at_ms'}
    FILES.require(type(value) is dict and set(value) == fields, 'invalid-receipt')
    FILES.require(type(value['vault_id']) is str
                  and str(uuid.UUID(value['vault_id'])) == value['vault_id'], 'invalid-receipt')
    FILES.require(type(value['format_version']) is int and value['format_version'] == FORMAT_VERSION,
                  'invalid-receipt')
    FILES.require(integer(value['generation'], 2**64 - 1) and value['generation'] > 0, 'invalid-receipt')
    FILES.require(hex_digest(value['input_sha256_hex' if restore else 'sha256_hex']), 'invalid-receipt')
    if not restore:
        FILES.require(integer(value['created_at_ms'], 2**63 - 1), 'invalid-receipt')
    FILES.path_value(value['output_path'])
    cut = value['snapshot_cut']
    FILES.require(type(cut) is dict and set(cut) == {'audit_sequence', 'policy'}
                  and integer(cut['audit_sequence'], 2**64 - 1), 'invalid-receipt')
    policy = cut['policy']
    FILES.require(policy is None or type(policy) is dict and set(policy) == {'version', 'bundle_sha256'}
                  and integer(policy['version'], 2**64 - 1) and hex_digest(policy['bundle_sha256']),
                  'invalid-receipt')
    return value, hashlib.sha256(raw).hexdigest()


def verify(args):
    backup, backup_receipt_sha = receipt(args.backup_receipt)
    restored, restore_receipt_sha = receipt(args.restore_receipt, restore=True)
    actual = stream_digest(args.backup)
    FILES.require(actual == backup['sha256_hex'] == restored['input_sha256_hex']
                  and backup['vault_id'] == restored['vault_id']
                  and backup['snapshot_cut'] == restored['snapshot_cut']
                  and restored['generation'] > backup['generation'], 'artifact-mismatch')
    fd = FILES.directory(restored['output_path'])
    try:
        FILES.secure(os.fstat(fd), directory=True)
    finally:
        os.close(fd)
    return dict(outcome='artifact_match', field_validated=False,
                sha256_hex=actual, vault_id=backup['vault_id'], format_version=FORMAT_VERSION,
                snapshot_cut=backup['snapshot_cut'], restored_state_dir=restored['output_path'],
                backup_generation=backup['generation'], restored_generation=restored['generation'],
                backup_receipt_sha256=backup_receipt_sha, restore_receipt_sha256=restore_receipt_sha,
                rpo=None, rto=None, partition_validated=False, promotion_validated=False,
                fencing_validated=False)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--backup', type=Path, required=True)
    parser.add_argument('--backup-receipt', type=Path, required=True)
    parser.add_argument('--restore-receipt', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True, help='create-new absolute private directory')
    parser.add_argument('--require-field', action='store_true', help='fails before effects; no fencing facility exists')
    args = parser.parse_args(argv)
    if args.require_field:
        print('DR FAILED: field-facility-unavailable', file=sys.stderr)
        return 1
    os.umask(0o077)
    directory = None
    try:
        report = verify(args)
        directory = create_output(args.output)
        write_report(args.output, directory, report)
    except (OSError, ValueError, TypeError, FILES.Error):
        print('DR FAILED: artifact-or-output-invalid', file=sys.stderr)
        return 1
    finally:
        if directory is not None:
            os.close(directory)
    print('DR artifact_match; field unvalidated')
    return 0


if __name__ == '__main__':
    sys.exit(main())
