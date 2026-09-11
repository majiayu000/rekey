#!/usr/bin/env python3
"""Export with an interactive proof; sync only completed encrypted snapshots."""

import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import shlex
import stat
import subprocess
import sys
import uuid


def run(args, **kwargs):
    return subprocess.run(args, check=True, timeout=300, **kwargs)


def digest(path):
    result = hashlib.sha256()
    with path.open('rb') as source:
        for block in iter(lambda: source.read(1024 * 1024), b''):
            result.update(block)
    return result.hexdigest()


def require_private_outbox(path: Path):
    if path.exists():
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode):
            raise ValueError('outbox must not be a symlink')
        if not stat.S_ISDIR(info.st_mode):
            raise ValueError('outbox must be a directory')
        if info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise ValueError('outbox must be a current-user-owned 0700 directory')
    else:
        path.mkdir(parents=True, mode=0o700)
        info = path.lstat()
        if (
            stat.S_ISLNK(info.st_mode)
            or not stat.S_ISDIR(info.st_mode)
            or info.st_uid != os.getuid()
            or info.st_mode & 0o077
        ):
            raise ValueError('outbox must be a current-user-owned 0700 directory')


def require_private_export_dir(path: Path):
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise ValueError('outbox contains a non-directory entry: ' + path.name)
    if info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise ValueError('outbox entry must be a current-user-owned 0700 directory: ' + path.name)


def sync_dir(path: Path):
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def export(args):
    pending = args.outbox / ('.pending-' + uuid.uuid4().hex)
    pending.mkdir(mode=0o700)
    # stdin/stderr remain attached to the operator's terminal. No proof storage.
    output = run([args.rekey, '--state-dir', str(args.state_dir), 'backup',
                  '--output', str(pending / 'snapshot.rkbackup')],
                 stdout=subprocess.PIPE).stdout
    receipt = json.loads(output)
    if receipt['sha256_hex'] != digest(pending / 'snapshot.rkbackup'):
        raise ValueError('export digest mismatch')
    receipt.pop('output_path', None)
    receipt['runtime_version'] = run([args.rekey, '--version'],
                                    stdout=subprocess.PIPE).stdout.decode().strip()
    receipt_path = pending / 'receipt.json'
    with receipt_path.open('w', encoding='utf-8') as handle:
        handle.write(json.dumps(receipt, indent=2) + '\n')
        handle.flush()
        os.fsync(handle.fileno())
    sync_dir(pending)
    completed = args.outbox / ('backup-' + uuid.uuid4().hex)
    pending.rename(completed)
    sync_dir(args.outbox)
    print('EXPORTED ' + str(completed), flush=True)


# Source is fixed; all variable values are positional arguments, shell quoted.
REMOTE = '''import hashlib,json,os,stat,sys
from pathlib import Path
mode,base,name,expected,stage=sys.argv[1:]
root=Path(base); target=root/name
def require_private_dir(path, label):
 info=path.lstat()
 if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
  raise ValueError(label+' must be a non-symlink directory')
 if info.st_uid!=os.getuid() or info.st_mode&0o077:
  raise ValueError(label+' must be a current-user-owned 0700 directory')
def verify(p):
 r=json.loads((p/'receipt.json').read_text())
 h=hashlib.sha256()
 with (p/'snapshot.rkbackup').open('rb') as f:
  for b in iter(lambda:f.read(1024*1024),b''):h.update(b)
 if r!=json.loads(expected) or h.hexdigest()!=r['sha256_hex']:
  raise ValueError('remote receipt or digest mismatch')
os.umask(0o077)
if mode=='prepare':
 if root.exists():require_private_dir(root,'remote-dir')
 else:root.mkdir(parents=True,mode=0o700);require_private_dir(root,'remote-dir')
 if target.exists():verify(target);print('VERIFIED')
 else:(root/stage).mkdir(mode=0o700);print('UPLOAD')
else:
 require_private_dir(root,'remote-dir')
 verify(root/stage)
 if target.exists():raise FileExistsError('completed backup already exists')
 (root/stage).rename(target)
 print('VERIFIED')
'''


def sync(args):
    count = 0
    for entry in sorted(args.outbox.iterdir()):
        if entry.name.startswith('.'):
            continue  # Unpublished exports are ineligible.
        require_private_export_dir(entry)
        artifact, receipt_file = entry / 'snapshot.rkbackup', entry / 'receipt.json'
        if artifact.is_symlink() or receipt_file.is_symlink():
            raise ValueError('symlink in export: ' + entry.name)
        receipt = json.loads(receipt_file.read_text())
        if digest(artifact) != receipt['sha256_hex']:
            raise ValueError('local digest mismatch: ' + entry.name)
        stage = '.upload-' + uuid.uuid4().hex

        def remote(mode):
            command = shlex.join(['/usr/bin/python3', '-c', REMOTE, mode,
                                  args.remote_dir, entry.name, json.dumps(receipt), stage])
            return run(['/usr/bin/ssh', '-o', 'BatchMode=yes', '-o',
                        'ConnectTimeout=15', args.host, command],
                       stdout=subprocess.PIPE).stdout.decode().strip()

        state = remote('prepare')
        if state == 'UPLOAD':
            # scp legacy remote paths need shell quoting independently of argv.
            destination = args.host + ':' + shlex.quote(args.remote_dir + '/' + stage + '/')
            run(['/usr/bin/scp', '-q', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=15',
                 str(artifact), str(receipt_file), destination])
            state = remote('publish')
        if state != 'VERIFIED':
            raise ValueError('unexpected remote response')
        count += 1
        print('VERIFIED ' + entry.name, flush=True)
    print('SYNC OK exports=' + str(count), flush=True)


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--outbox', type=Path, required=True)
    sub = parser.add_subparsers(dest='operation', required=True)
    create = sub.add_parser('export')
    create.add_argument('--state-dir', type=Path, required=True)
    create.add_argument('--rekey', required=True)
    transfer = sub.add_parser('sync')
    transfer.add_argument('--host', required=True)
    transfer.add_argument('--remote-dir', required=True)
    args = parser.parse_args()
    print(datetime.datetime.now(datetime.timezone.utc).isoformat() + ' ' + args.operation,
          flush=True)
    try:
        if not args.outbox.is_absolute():
            raise ValueError('outbox must be absolute')
        require_private_outbox(args.outbox)
        if args.operation == 'export':
            export(args)
        else:
            sync(args)
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        # Child stdout/argv may include metadata; do not echo captured output.
        print('BACKUP FAILED: ' + (str(error) if not isinstance(error, subprocess.SubprocessError)
                                  else type(error).__name__), file=sys.stderr, flush=True)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
