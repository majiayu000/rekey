#!/usr/bin/env python3
"""Run the three macOS v3 feasibility probes on disposable test artifacts."""
import argparse
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import plistlib
import secrets
import selectors
import shutil
import subprocess
import sys
import tempfile
import time
import uuid

SOURCE = Path(__file__).resolve().parent


def invoke(command, *, data=None, timeout=90, check=True):
    result = subprocess.run([str(x) for x in command], input=data, text=True,
                            capture_output=True, timeout=timeout)
    if check and result.returncode:
        raise RuntimeError(f'{Path(str(command[0])).name} exited {result.returncode}: {result.stderr.strip()}')
    return result


def probe(command):
    result = invoke(command, check=False)
    try:
        value = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise RuntimeError(f'{Path(str(command[0])).name}: invalid probe JSON, exit {result.returncode}') from error
    value['exit_code'] = result.returncode
    return value


def sign(binary, args, *, identifier, entitlements=None, adhoc=False):
    command = ['codesign', '--force', '--sign', '-' if adhoc else args.identity,
               '--identifier', identifier, '--timestamp=none']
    if not adhoc:
        command += ['--options', 'runtime']
    if entitlements:
        command += ['--entitlements', entitlements]
    invoke(command + [binary])
    invoke(['codesign', '--verify', '--strict', binary])
    return signature_details(binary)


def signature_details(binary):
    details = invoke(['codesign', '--display', '--verbose=4', binary], check=False)
    return {'sha256': hashlib.sha256(binary.read_bytes()).hexdigest(),
            'codesign': details.stderr.strip()}


@contextmanager
def child(command):
    process = subprocess.Popen([str(x) for x in command], stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, text=True)
    try:
        yield process
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
        process.stdout.close()
        process.stderr.close()


def ready_json(process):
    with selectors.DefaultSelector() as selector:
        selector.register(process.stdout, selectors.EVENT_READ)
        if not selector.select(timeout=20):
            raise RuntimeError('probe readiness timed out')
        line = process.stdout.readline()
    try:
        return json.loads(line)
    except json.JSONDecodeError as error:
        raise RuntimeError('probe did not produce readiness JSON') from error


def keychain(root, args, binaries):
    bundle = root / 'KeychainOwner.app'
    (bundle / 'Contents/MacOS').mkdir(parents=True)
    owner, attacker = bundle / 'Contents/MacOS/keychain-owner', root / 'keychain-attacker'
    (bundle / 'Contents/Info.plist').write_bytes(plistlib.dumps({
        'CFBundleIdentifier': 'com.rekey.v3.keychain', 'CFBundleExecutable': 'keychain-owner',
        'CFBundlePackageType': 'APPL', 'CFBundleVersion': '1'}))
    if args.provisioning_profile:
        shutil.copy2(args.provisioning_profile, bundle / 'Contents/embedded.provisionprofile')
    shutil.copy2(binaries['keychain'], owner)
    shutil.copy2(binaries['keychain'], attacker)
    group = args.team_id + '.com.rekey'
    entitlements = root / 'keychain.entitlements'
    entitlements.write_bytes(plistlib.dumps({'keychain-access-groups': [group],
                                           'com.apple.application-identifier': args.team_id + '.com.rekey.v3.keychain',
                                           'com.apple.developer.team-identifier': args.team_id}))
    signatures = {
        'owner': sign(owner, args, identifier='com.rekey.v3.keychain', entitlements=entitlements),
        'attacker': sign(attacker, args, identifier='com.rekey.v3.attacker', adhoc=True),
    }
    invoke(['codesign', '--force', '--sign', args.identity, '--options', 'runtime',
            '--timestamp=none', '--entitlements', entitlements, bundle])
    invoke(['codesign', '--verify', '--deep', '--strict', bundle])
    signatures['owner'] = signature_details(owner)
    test_id = str(uuid.uuid4())
    result = {'status': 'inconclusive', 'signatures': signatures, 'test_id': test_id}
    create_attempted = False
    try:
        create_attempted = True
        result['create'] = probe([owner, 'create', test_id, group])
        if result['create']['exit_code'] != 0:
            result['reason'] = 'Protected item creation failed; access control was not tested.'
            return result
        result['attacker_explicit_group'] = probe([attacker, 'read-no-ui', test_id, group])
        result['attacker_default_group'] = probe([attacker, 'read-no-ui', test_id, '-'])
        result['owner_no_ui'] = probe([owner, 'read-no-ui', test_id, group])
        reads = [result[k] for k in ('attacker_explicit_group', 'attacker_default_group', 'owner_no_ui')]
        if any(r['exit_code'] == 0 for r in reads):
            result.update(status='failed', reason='A fresh noninteractive read retrieved the canary.')
        elif result['owner_no_ui']['exit_code'] != 1 or any(
            r['exit_code'] != 1 and r.get('outcome') not in ('environment_missing_entitlement', 'item_not_found')
            for r in reads[:2]
        ):
            result['reason'] = 'At least one denial could not be classified as access control.'
        elif args.interactive_keychain:
            result['owner_with_ui'] = probe([owner, 'read-with-ui', test_id, group])
            if result['owner_with_ui']['exit_code'] == 0:
                result.update(status='passed', reason='Authorized read succeeded; all silent controls denied.')
            else:
                result['reason'] = 'Authorized user-presence read did not complete.'
        else:
            result['reason'] = 'Silent reads denied; explicit interactive positive control remains required.'
    except (RuntimeError, OSError, subprocess.TimeoutExpired) as error:
        result['operation_error'] = str(error)
        if result['status'] != 'failed':
            result.update(status='inconclusive', reason='Keychain operation did not complete; test identity retained for cleanup.')
    finally:
        if create_attempted:
            try:
                result['cleanup'] = probe([owner, 'cleanup', test_id, group])
            except (RuntimeError, OSError, subprocess.TimeoutExpired) as error:
                result['cleanup'] = {'exit_code': 2, 'error': str(error)}
            if result['cleanup']['exit_code'] != 0 and result['status'] != 'failed':
                result.update(status='inconclusive', reason='Test Keychain cleanup unconfirmed; see retained test_id.')
    return result


def memory(root, args, binaries):
    result = {'status': 'inconclusive', 'cases': {}}
    helper = binaries['memory']
    # A self-target confirms that the probe can obtain a task port at all.
    result['self_control'] = probe(['/bin/sh', '-c', 'exec "$1" --pid $$', 'probe', helper])
    for mode in ('adhoc', 'hardened'):
        daemon = root / ('rekeyd-' + mode)
        shutil.copy2(args.bin_dir / 'rekeyd', daemon)
        signature = sign(daemon, args, identifier='com.rekey.rekeyd', adhoc=mode == 'adhoc')
        state = root / ('state-' + mode)
        password = secrets.token_urlsafe(32)
        # Initialization prints a recovery key. Discard its output, never persist it.
        invoke([daemon, 'init', '--mode', 'team', '--state-dir', state, '--password-stdin'], data=password + '\n')
        with child([daemon, 'serve', '--state-dir', state]) as process:
            deadline = time.monotonic() + 20
            while not (state / 'runtime/admin.sock').exists():
                if process.poll() is not None or time.monotonic() >= deadline:
                    raise RuntimeError('disposable rekeyd failed readiness')
                time.sleep(.05)
            invoke([args.bin_dir / 'rekey', '--state-dir', state, 'unlock', '--password-stdin'],
                   data=password + '\n')
            result['cases'][mode] = {'signature': signature,
                                     'probe': probe([helper, '--pid', process.pid])}
        password = None
    hardened = result['cases']['hardened']['probe']
    control = result['cases']['adhoc']['probe']
    if hardened['exit_code'] == 0:
        result.update(status='failed', reason='Task port acquired for signed hardened rekeyd.')
    elif hardened['exit_code'] == 1 and control['exit_code'] == 0 and result['self_control']['exit_code'] == 0:
        result.update(status='passed', reason='Hardened target denied; ad-hoc target and self controls acquired.')
    else:
        result['reason'] = 'Denial alone does not establish hardened-runtime protection; inspect control results.'
    return result


def peer(root, args, binaries):
    result = {'status': 'inconclusive', 'cases': {}}
    for mode, identifier in [('valid', 'com.rekey.rekeyd'),
                             ('wrong_identifier', 'com.rekey.v3.wrong'),
                             ('adhoc', 'com.rekey.rekeyd')]:
        server = root / ('peer-' + mode)
        shutil.copy2(binaries['peer'], server)
        signature = sign(server, args, identifier=identifier, adhoc=mode == 'adhoc')
        socket = root / (mode + '.sock')
        with child([server, 'server', '--socket', socket]) as process:
            ready = ready_json(process)
            if ready.get('event') != 'ready':
                raise RuntimeError('peer server did not become ready')
            client = probe([binaries['peer'], 'client', '--socket', socket, '--team-id', args.team_id])
            stdout, _ = process.communicate(timeout=20)
            observations = [json.loads(line) for line in stdout.splitlines() if line.strip()]
            observation = next((x for x in observations if x.get('event') == 'observation'), None)
            result['cases'][mode] = {'signature': signature, 'client': client,
                                     'server': observation, 'server_exit_code': process.returncode}
    valid = result['cases']['valid']
    negatives = [result['cases'][m] for m in ('wrong_identifier', 'adhoc')]
    complete = all(x['server_exit_code'] == 0 and x['server'] and
                   x['server'].get('outcome') == 'observed' and x['server'].get('eof') is True
                   for x in result['cases'].values())
    if complete and valid['client']['exit_code'] == 0 and valid['server'].get('canary_match') is True and all(
        x['client']['exit_code'] == 2 and x['server'] and x['server'].get('received_bytes') == 0 for x in negatives
    ):
        result.update(status='passed', reason='Audit-token identity verified; rejected peers received zero proof bytes.')
    elif any(x['server'] and x['server'].get('received_bytes', 0) > 0 for x in negatives):
        result.update(status='failed', reason='Rejected identity received data.')
    else:
        result['reason'] = 'Identity positive/negative controls did not all complete as expected.'
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bin-dir', type=Path, required=True, help='directory containing built rekey and rekeyd')
    parser.add_argument('--identity', required=True, help='Developer ID Application signing identity (public name)')
    parser.add_argument('--team-id', required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--interactive-keychain', action='store_true', help='explicitly allow the V1 user-presence prompt')
    parser.add_argument('--provisioning-profile', type=Path, help='Developer ID profile authorizing the V1 bundle and access group')
    args = parser.parse_args()
    if sys.platform != 'darwin':
        parser.error('macOS is required')
    args.bin_dir = args.bin_dir.resolve()
    for binary in ('rekey', 'rekeyd'):
        if not (args.bin_dir / binary).is_file():
            parser.error('build both rekey and rekeyd before running')
    os.umask(0o077)
    args.output.mkdir(parents=True, exist_ok=False)
    report = {'schema': 1, 'scope': 'Disposable V1-V3 feasibility probes; not v3 product acceptance',
              'host': invoke(['sw_vers']).stdout.strip(), 'team_id': args.team_id,
              'base_commit': invoke(['git', '-C', SOURCE, 'rev-parse', 'HEAD']).stdout.strip(), 'results': {}}
    with tempfile.TemporaryDirectory(prefix='rk-v3-', dir='/private/tmp') as temporary:
        root = Path(temporary)
        binaries = {}
        for name in ('keychain', 'memory', 'peer'):
            binary = root / (name + '_probe')
            compiler = ['xcrun', 'clang', '-Wall', '-Wextra', '-Werror'] if name == 'memory' else ['xcrun', 'swiftc', '-warnings-as-errors']
            extension = '.c' if name == 'memory' else '.swift'
            source = SOURCE / (name + '_probe' + extension)
            invoke(compiler + [source, '-o', binary])
            binaries[name] = binary
        for label, execute in [('V1', keychain), ('V2', memory), ('V3', peer)]:
            try:
                report['results'][label] = execute(root, args, binaries)
            except (RuntimeError, OSError, subprocess.TimeoutExpired) as error:
                report['results'][label] = {'status': 'inconclusive', 'reason': str(error)}
            (args.output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
            print(label + ': ' + report['results'][label]['status'], flush=True)
    statuses = [x['status'] for x in report['results'].values()]
    return 1 if 'failed' in statuses else (2 if 'inconclusive' in statuses else 0)


if __name__ == '__main__':
    sys.exit(main())
