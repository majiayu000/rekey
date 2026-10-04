#!/usr/bin/env python3
"""Disposable Docker DR reference: external fence, restore, reissue and measured recovery."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import signal
import subprocess
import sys
import tempfile
import time
import uuid

ROOT = Path(__file__).resolve().parent.parent
STATE = '/vault/state'


class DrillError(Exception):
    pass


def command(args, data=None, expected=0, timeout=90):
    result = subprocess.run(args, input=data, capture_output=True, timeout=timeout)
    if result.returncode != expected:
        raise DrillError('command-status-' + str(result.returncode))
    return result.stdout


def docker(*args, data=None, expected=0):
    return command(['docker', *args], data, expected)


def require(condition, reason):
    if not condition:
        raise DrillError(reason)


def require_fenced(primary):
    # Successful enumeration by the external daemon is mandatory. A stopped
    # container still exists and can restart; an unreachable daemon is not proof.
    present = docker('container', 'ls', '--all', '--no-trunc', '--filter',
                     'id=' + primary, '--format', '{{.ID}}')
    require(not present.strip(), 'primary-not-fenced')


def put(node, path, data):
    docker('exec', '-i', node, 'sh', '-c', 'umask 077; cat > "$1"', 'sh', path, data=data)


def cli(node, *args, data=None, expected=0):
    return docker('exec', '-i', node, 'rekey', '--state-dir', STATE, *args,
                  data=data, expected=expected)


def value(node, *args, data=None):
    return json.loads(cli(node, *args, data=data))


def start_broker(node):
    docker('exec', '-d', node, 'rekey-dr-fixture', STATE, '/vault/ready', '/vault/hits')
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        status = subprocess.run(['docker', 'exec', node, 'rekey', '--state-dir', STATE, 'status'],
                                capture_output=True, timeout=5)
        if status.returncode == 0:
            require(json.loads(status.stdout)['state'] == 'locked', 'startup-not-locked')
            return
        time.sleep(.1)
    raise DrillError('broker-readiness')


def cleanup(label):
    for kind, remove, template in [('container', ('rm', '--force'), '{{.ID}}'),
                                  ('volume', ('rm',), '{{.Name}}'),
                                  ('network', ('rm',), '{{.ID}}')]:
        args = [kind, 'ls', '--filter', 'label=' + label, '--format', template]
        if kind == 'container':
            args.insert(2, '--all')
        owned = docker(*args).decode().split()
        if owned:
            docker(kind, *remove, *owned)
        require(not docker(*args).strip(), 'cleanup-incomplete')


def node(image, name, volume, network, label):
    docker('volume', 'create', '--label', label, volume)
    docker('run', '--rm', '--label', label, '--network', 'none', '--mount',
           f'type=volume,src={volume},dst=/vault', image, 'sh', '-c',
           'chown 10001:10001 /vault; chmod 0700 /vault')
    identity = docker('run', '-d', '--name', name, '--label', label, '--user', '10001:10001',
                      '--network', network, '--restart', 'no', '--read-only', '--cap-drop', 'ALL',
                      '--security-opt', 'no-new-privileges', '--log-driver', 'none',
                      '--tmpfs', '/tmp:rw,noexec,nosuid,size=16m', '--mount',
                      f'type=volume,src={volume},dst=/vault', image, 'sleep', 'infinity').decode().strip()
    config = json.loads(docker('inspect', identity))[0]
    require(config['HostConfig']['RestartPolicy']['Name'] == 'no'
            and config['Config']['User'] == '10001:10001'
            and config['HostConfig']['ReadonlyRootfs']
            and config['HostConfig']['CapDrop'] == ['ALL']
            and len(config['Mounts']) == 1
            and config['Mounts'][0]['Name'] == volume, 'node-isolation')
    return identity


def execute(node_id, action, token, expected=0):
    return cli(node_id, 'execute', action, '--capability', '-', '--body-file', '/vault/body.json',
               '--content-type', 'application/json', data=(token + '\n').encode(), expected=expected)


def measure_write(node_id, proof, label):
    started = time.monotonic_ns()
    receipt = value(node_id, 'credential', 'add', label, '--stdin-secrets',
                    data=proof + secrets.token_urlsafe(32).encode() + b'\n')
    return receipt, started, time.monotonic_ns()


def run(args, report, label):
    stage = lambda name: report.update(stage=name)
    stage('image')
    info = json.loads(docker('image', 'inspect', args.image))[0]
    require(info['Os'] == 'linux', 'linux-image-required')
    image = info['Id']
    report.update(image_id=image, engine=json.loads(docker('version', '--format', '{{json .Server.Version}}')))
    suffix = label.split('=', 1)[1]
    network = 'rekey-dr-' + suffix
    docker('network', 'create', '--internal', '--label', label, network)
    stage('nodes')
    primary = node(image, network + '-primary', network + '-primary-state', network, label)
    standby = node(image, network + '-standby', network + '-standby-state', network, label)
    report.update(primary_id=primary, standby_id=standby)
    proof = secrets.token_urlsafe(32).encode() + b'\n'
    stage('initialize')
    docker('exec', '-i', primary, 'rekeyd', 'init', '--mode', 'team', '--state-dir', STATE, '--password-stdin', data=proof)
    start_broker(primary)
    value(primary, 'unlock', '--password-stdin', data=proof)
    retained, retained_start, retained_ack = measure_write(primary, proof, 'dr-retained')
    definition = dict(name='dr-reference', credential_id=retained['id'], origin='https://api.test.local',
                      method='POST', exact_path='/v1/policy', auth_header='authorization', auth_prefix='Bearer ',
                      timeout_ms=10000, request_max_bytes=4096, allowed_extra_headers=[],
                      response_max_bytes=4096, allowed_response_headers=['content-type'])
    put(primary, '/vault/action.json', json.dumps(definition).encode())
    action = value(primary, 'action', 'create', '--file', '/vault/action.json', '--password-stdin', data=proof)
    action_ref = action['id'] + '@' + str(action['version'])
    principal = str(uuid.uuid4())
    resource = dict(type='dr-reference', id=action['id'])
    policy = dict(format_version=6, version=1, expires_at_ms=int(time.time() * 1000) + 900000,
                  approvers=[], profiles=[], workload_identities=[], bindings=[dict(action_id=action['id'], version=action['version'],
                  resource=resource, parameter_schema_id='dr-reference/v1', parameter_schema={'type': 'object'})],
                  rules=[dict(id=str(uuid.uuid4()), effect='permit', principal_id=principal, action_id=action['id'],
                              version=action['version'], resource=resource, parameters={'kind': 'any_validated'})])
    with tempfile.TemporaryDirectory(prefix='rekey-dr-') as temporary:
        work = Path(temporary)
        snapshot, bundle, trust = (work / name for name in ('policy.json', 'bundle.json', 'trust.json'))
        snapshot.write_text(json.dumps(policy))
        command([sys.executable, str(ROOT / 'scripts/sign-test-policy.py'), 'policy', '--key-dir', str(work / 'key'),
                 '--snapshot', str(snapshot), '--bundle', str(bundle), '--trust', str(trust)])
        put(primary, '/vault/trust.json', trust.read_bytes())
        put(primary, '/vault/policy.json', bundle.read_bytes())
    value(primary, 'policy', 'trust', 'install', '--file', '/vault/trust.json', '--step-up-stdin', data=proof)
    target = value(primary, 'policy', 'status')
    value(primary, 'policy', 'activate', '--file', '/vault/policy.json', '--expected-vault-id', target['vault_id'],
          '--expected-trust-sha256', target['trust_sha256'], '--step-up-stdin', data=proof)
    active_policy = value(primary, 'policy', 'status')
    old = value(primary, 'session', 'create', '--action', action_ref, '--principal', principal,
                '--password-stdin', data=proof)['capability_token']
    body = b'{"message":"docker-dr"}'
    put(primary, '/vault/body.json', body)
    require(b'"upstream_status": 200' in execute(primary, action_ref, old), 'primary-business-response')
    stage('snapshot')
    backup = value(primary, 'backup', '--output', '/vault/snapshot.rkbackup', '--password-stdin', data=proof)
    # Retain the completed encrypted artifact in the primary volume; copy out
    # before fencing, but transfer into the standby only after verified fencing.
    encrypted = docker('exec', primary, 'cat', '/vault/snapshot.rkbackup')
    require(hashlib.sha256(encrypted).hexdigest() == backup['sha256_hex'], 'backup-digest')
    stage('unreplicated-write')
    lost, lost_start, lost_ack = measure_write(primary, proof, 'dr-unreplicated')
    stage('source-audit-cut')
    audit = value(primary, 'audit', 'list', '--limit', '100')
    lost_sequence = next(event['sequence'] for event in audit['events']
                         if event['event_type'] == 'credential.created' and event.get('credential_id') == lost['id'])
    require(lost_sequence > backup['snapshot_cut']['audit_sequence'], 'lost-write-cut')
    stage('partition')
    failure_start = time.monotonic_ns()
    docker('network', 'disconnect', '--force', network, primary)
    require(value(primary, 'status')['state'] == 'unlocked', 'partition-primary-still-live')
    try:
        require_fenced(primary)
    except DrillError as error:
        require(str(error) == 'primary-not-fenced', 'partition-daemon-failure')
    else:
        raise DrillError('split-brain-promotion-admitted')
    report['partition_promotion_refused'] = True
    stage('fence')
    docker('container', 'rm', '--force', primary)
    require_fenced(primary)
    docker('container', 'start', primary, expected=1)
    require_fenced(primary)
    report['old_primary_restart_refused'] = True
    stage('restore')
    # This check is the admission boundary, immediately before standby effects.
    require_fenced(primary)
    put(standby, '/vault/snapshot.rkbackup', encrypted)
    context = json.loads(docker('exec', '-i', standby, 'rekeyd', 'restore', '--state-dir', STATE,
                         '--input', '/vault/snapshot.rkbackup', '--sha256', backup['sha256_hex'],
                         '--inspect', '--password-stdin', data=proof))
    require(context['source_generation'] == backup['generation'], 'restore-source-generation')
    expected = json.dumps(context, separators=(',', ':'))
    # Inspect is read-only. Re-establish external fencing immediately before
    # the separate mutation; never refresh a rejected context or retry it.
    require_fenced(primary)
    restored = json.loads(docker('exec', '-i', standby, 'rekeyd', 'restore', '--state-dir', STATE,
                          '--input', '/vault/snapshot.rkbackup', '--sha256', backup['sha256_hex'],
                          '--expected-context', expected, '--password-stdin', data=proof))
    require(restored['input_sha256_hex'] == backup['sha256_hex']
            and restored['vault_id'] == backup['vault_id']
            and restored['snapshot_cut'] == backup['snapshot_cut']
            and restored['generation'] == max(context['source_generation'], context['high_water'] or 0) + 1,
            'restore-cut')
    start_broker(standby)
    value(standby, 'unlock', '--password-stdin', data=proof)
    credentials = value(standby, 'credential', 'list')['credentials']
    require(retained['id'] in [item['id'] for item in credentials]
            and lost['id'] not in [item['id'] for item in credentials], 'restored-write-observations')
    restored_policy = value(standby, 'policy', 'status')
    require(restored_policy['status'] == 'active'
            and restored_policy['bundle_sha256'] == active_policy['bundle_sha256'], 'restored-policy')
    put(standby, '/vault/body.json', body)
    execute(standby, action_ref, old, expected=4)
    fresh = value(standby, 'session', 'create', '--action', action_ref, '--principal', principal,
                  '--password-stdin', data=proof)['capability_token']
    require_fenced(primary)
    require(b'"upstream_status": 200' in execute(standby, action_ref, fresh), 'standby-business-response')
    recovered = time.monotonic_ns()
    require(docker('exec', standby, 'cat', '/vault/hits').strip() == b'1', 'one-standby-effect')
    report.update(fencing_validated=True, promotion_validated=True, old_capability_rejected=True,
                  snapshot_cut=backup['snapshot_cut'], backup_generation=backup['generation'],
                  restored_generation=restored['generation'], lost_credential_writes=1, lost_audit_sequence=lost_sequence,
                  rto_ms=(recovered - failure_start) / 1e6,
                  rpo_observed_ack_gap_ms=(lost_ack - retained_ack) / 1e6,
                  rpo_commit_gap_bounds_ms=[max(0, lost_start - retained_ack) / 1e6,
                                           max(0, lost_ack - retained_start) / 1e6])
    stage('complete')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', required=True, help='local image built using scripts/Dockerfile.dr')
    parser.add_argument('--output', required=True, type=Path, help='create-new private report directory')
    args = parser.parse_args(argv)
    os.umask(0o077)
    args.output.mkdir(mode=0o700, parents=False, exist_ok=False)
    label = 'rekey.dr.run=' + uuid.uuid4().hex
    report = dict(scope='Docker reference; real Broker/CLI/UDS plus injected local TLS; synthetic credentials',
                  pass_=False, stage='setup', script_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest())
    def interrupted(signum, frame):
        raise KeyboardInterrupt
    previous = signal.signal(signal.SIGTERM, interrupted)
    try:
        run(args, report, label)
        report['pass_'] = True
    except (Exception, KeyboardInterrupt) as error:
        report['failure_type'] = type(error).__name__
        if isinstance(error, DrillError):
            report['failure_reason'] = str(error)
        print('Docker DR failed at ' + report['stage'], file=sys.stderr)
    finally:
        signal.signal(signal.SIGTERM, previous)
        try:
            cleanup(label)
            report['cleanup_complete'] = True
        except (Exception, KeyboardInterrupt):
            report.update(pass_=False, cleanup_complete=False)
        report['pass'] = report.pop('pass_')
        with (args.output / 'report.json').open('x') as handle:
            json.dump(report, handle, indent=2)
            handle.write('\n')
            handle.flush()
            os.fsync(handle.fileno())
    print('Docker DR ' + ('passed' if report['pass'] else 'failed') + '; report: ' + str(args.output / 'report.json'))
    return 0 if report['pass'] else 1


if __name__ == '__main__':
    sys.exit(main())
