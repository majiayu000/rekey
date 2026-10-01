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
    command = [args.rekey, '--state-dir', str(args.state_dir)]
    if args.admin_session_file is not None:
        command += ['--admin-session-file', str(args.admin_session_file)]
    output = run(command + ['backup', '--output', str(pending / 'snapshot.rkbackup')],
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
REMOTE = '''import fcntl,hashlib,json,os,stat,sys
from pathlib import Path
mode,base,name,expected,stage=sys.argv[1:]
root=Path(base)
for component in (name,stage):
 if component in ('','.','..') or '/' in component:
  raise ValueError('remote object name must be a directory entry')
def directory_identity(info):
 if not stat.S_ISDIR(info.st_mode) or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o700:
  raise ValueError('remote directory must be current-user-owned 0700')
 return (info.st_dev,info.st_ino,info.st_mode,info.st_uid)
def file_identity(info):
 if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or info.st_mode&0o077 or info.st_nlink!=1:
  raise ValueError('remote file must be private current-user-owned regular single-link')
 return (info.st_dev,info.st_ino,info.st_mode,info.st_uid,info.st_nlink,
         info.st_size,info.st_mtime_ns,info.st_ctime_ns)
def check_root():
 if directory_identity(os.fstat(root_fd))!=root_identity or directory_identity(root.lstat())!=root_identity:
  raise ValueError('remote root identity changed')
def target_exists():
 try:os.stat(name,dir_fd=root_fd,follow_symlinks=False)
 except FileNotFoundError:return False
 return True
def durable_object(entry,publish):
 directory_fd=os.open(entry,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=root_fd)
 files=[]
 try:
  identity=directory_identity(os.fstat(directory_fd))
  for leaf in ('snapshot.rkbackup','receipt.json'):
   fd=os.open(leaf,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=directory_fd)
   files.append((leaf,fd,None))
   files[-1]=(leaf,fd,file_identity(os.fstat(fd)))
  def check_object():
   check_root()
   if directory_identity(os.fstat(directory_fd))!=identity or directory_identity(os.stat(entry,dir_fd=root_fd,follow_symlinks=False))!=identity:
    raise ValueError('remote object directory identity changed')
   if set(os.listdir(directory_fd))!={'snapshot.rkbackup','receipt.json'}:
    raise ValueError('remote object must contain only artifact and receipt')
   for leaf,fd,before in files:
    if file_identity(os.fstat(fd))!=before or file_identity(os.stat(leaf,dir_fd=directory_fd,follow_symlinks=False))!=before:
     raise ValueError('remote file identity changed')
  check_object()
  receipt_bytes=bytearray()
  while len(receipt_bytes)<=65536:
   block=os.read(files[1][1],65537-len(receipt_bytes))
   if not block:break
   receipt_bytes.extend(block)
  if len(receipt_bytes)>65536:raise ValueError('remote receipt exceeds 64KiB')
  receipt=json.loads(receipt_bytes)
  digest=hashlib.sha256()
  for block in iter(lambda:os.read(files[0][1],1024*1024),b''):digest.update(block)
  check_object()
  if receipt!=json.loads(expected) or digest.hexdigest()!=receipt['sha256_hex']:
   raise ValueError('remote receipt or digest mismatch')
  for _,fd,_ in files:
   os.fsync(fd)
   check_object()
  os.fsync(directory_fd)
  check_object()
  if publish:
   # All normal receivers hold the same root flock across this check and rename.
   if target_exists():raise FileExistsError('completed backup already exists')
   os.rename(entry,name,src_dir_fd=root_fd,dst_dir_fd=root_fd)
   entry=name
   check_object()
  os.fsync(root_fd)
  check_object()
  print('VERIFIED',flush=True)
 finally:
  for _,fd,_ in files:os.close(fd)
  os.close(directory_fd)
os.umask(0o077)
if mode=='prepare':
 try:root.mkdir(parents=True,mode=0o700)
 except FileExistsError:pass
root_fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
try:
 root_identity=directory_identity(os.fstat(root_fd))
 check_root()
 # Lock the directory inode, not a replaceable lock file. No new lock service.
 fcntl.flock(root_fd,fcntl.LOCK_EX)
 check_root()
 if target_exists():durable_object(name,False)
 elif mode=='prepare':
  os.mkdir(stage,mode=0o700,dir_fd=root_fd)
  check_root()
  print('UPLOAD',flush=True)
 else:durable_object(stage,True)
finally:os.close(root_fd)
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
    create.add_argument('--admin-session-file', type=Path, help='operator management session file')
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
