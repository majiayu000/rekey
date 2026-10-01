#!/usr/bin/env python3
"""Run fixed local acceptance scopes; no customer or field readiness is inferred."""
import argparse
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import time

SPEC = importlib.util.spec_from_file_location('acceptance_files', Path(__file__).with_name('rekey-dr-drill.py'))
DR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(DR)
ROOT = Path(__file__).resolve().parent.parent
KEYCLOAK_IMAGE = 'quay.io/keycloak/keycloak:26.7.3'
JOURNAL_GATES = ('issued_before_business', 'business_before_revoke', 'revoke_response_before_complete',
                 'maintenance', 'unknown')
FIELD_GATES = ('two_node_isolation', 'customer_idp_revocation', 'independent_fencing_ha',
               'cloud_iam_worm_hsm', 'native_gui')
CLEANUP_FIELDS = ('owned_container_removed', 'owned_container_absent',
                  'temporary_secret_directory_removed', 'broker_stopped')


def fixed_gates(binaries, output):
    scripts = ROOT / 'scripts'
    return [
        dict(name='policy_signer', script=scripts / 'test-policy-signer-live.py',
             argv=[sys.executable, str(scripts / 'test-policy-signer-live.py'), '--bin-dir', str(binaries)],
             binaries=('rekey', 'rekeyd', 'rekey-policy-sign'), dependencies=(),
             scope='actual CLI/UDS trust install, tamper rejection and independent policy signing; disposable keys'),
        dict(name='approval_signer_relay', script=scripts / 'test-approval-signer-live.py',
             argv=[sys.executable, str(scripts / 'test-approval-signer-live.py'), '--bin-dir', str(binaries),
                   '--relay-bin', str(binaries / 'rekey-approval-relay')],
             binaries=('rekey', 'rekeyd', 'rekey-approval-sign', 'rekey-approval-relay', 'examples/p1_policy_fixture'),
             dependencies=('sign-test-policy.py',),
             scope='actual CLI/UDS and HTTPS relay; synthetic IdP/provider and disposable signing keys'),
        dict(name='keycloak', script=scripts / 'test-keycloak-live.py',
             argv=[sys.executable, str(scripts / 'test-keycloak-live.py'), '--bin-dir', str(binaries),
                   '--output', str(output / 'KEYCLOAK')],
             binaries=('rekey', 'rekeyd', 'examples/oau02_keycloak_fixture'), dependencies=(),
             scope='actual locally present Keycloak Standard V2 and Broker/UDS with injected TLS; no customer SSO'),
        dict(name='vault_oss', script=scripts / 'p7-vault-oss-interop.sh',
             argv=['bash', str(scripts / 'p7-vault-oss-interop.sh')], binaries=(), dependencies=(),
             scope='existing local Vault OSS/PostgreSQL interoperability script; never executed by this entry'),
        dict(name='journal', script=scripts / 'p7-vault-journal-recovery.py',
             argv=[sys.executable, str(scripts / 'p7-vault-journal-recovery.py'), '--binaries', str(binaries),
                   '--artifacts', str(output / 'JOURNAL')],
             binaries=('rekey', 'rekeyd', 'examples/p7_vault_journal_fixture'), dependencies=('sign-test-policy.py',),
             scope='actual CLI/UDS/SIGKILL/restart with synthetic TLS provider; no actual Vault/fencing'),
    ]


def run_child(argv):
    # Keep trusted stdin/TTY behavior; provider and assertion text never enter reports/logs.
    return subprocess.run(argv, stdin=None, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                          cwd=ROOT, env={'PATH': os.defpath}, check=False, timeout=1200)


def required_receipt(name, output):
    if name == 'keycloak':
        value = DR.FILES.decode(DR.FILES.read_file(str(output / 'KEYCLOAK/receipt.json')))
        DR.FILES.require(type(value) is dict and type(value.get('pass')) is bool
                         and value['pass'] and value.get('secret_scan_passed') is True
                         and type(value.get('cleanup')) is dict
                         and all(value['cleanup'].get(key) is True for key in CLEANUP_FIELDS),
                         'receipt-or-cleanup-failed')
        return dict(receipt_passed=True, secret_scan_passed=True, cleanup_confirmed=True)
    if name == 'journal':
        value = DR.FILES.decode(DR.FILES.read_file(str(output / 'JOURNAL/evidence.json')))
        DR.FILES.require(type(value) is list and len(value) == len(JOURNAL_GATES)
                         and all(type(item) is dict and item.get('gate') == gate
                                 for item, gate in zip(value, JOURNAL_GATES)), 'receipt-missing-or-invalid')
        # Exact child exit covers its cleanup/assertions; no new receipt fields are invented.
        return dict(receipt_passed=True, scenario_count=len(JOURNAL_GATES))
    return dict(evidence_boundary='exact existing script exit; no structured receipt provided')


def execute_gate(gate, binaries, output):
    result = dict(name=gate['name'], scope=gate['scope'], outcome='unexecuted',
                  exit=None, signal=None, started_monotonic_ns=None, finished_monotonic_ns=None,
                  duration_ns=None, script_sha256=None, binary_sha256={}, dependency_sha256={})
    pinned = {}
    def source(path):
        pinned[path] = DR.stream_digest(path, private=False, pin=True)
        return pinned[path][0]

    def check_sources():
        # G1 drift detection; does not claim containment of a malicious same-user writer.
        for path, identity in pinned.items():
            DR.FILES.require(DR.stream_digest(path, private=False, pin=True) == identity,
                             'execution-source-changed')

    try:
        result['script_sha256'] = source(gate['script'])
        for name in gate['dependencies']:
            result['dependency_sha256'][name] = source(ROOT / 'scripts' / name)
        if gate['name'] == 'vault_oss':
            result['reason'] = ('nonlinux-script-skip' if sys.platform != 'linux'
                                else 'existing-script-requires-build-install-and-fixed-binaries')
            return result
        for name in gate['binaries']:
            path = binaries / name
            result['binary_sha256'][name] = source(path)
            DR.FILES.require(os.access(path, os.X_OK), 'binary-not-executable')
    except (OSError, ValueError, DR.FILES.Error):
        result['reason'] = 'missing-or-unsafe-script-binary'
        return result
    if gate['name'] == 'keycloak':
        try:
            image = run_child(['docker', 'image', 'inspect', KEYCLOAK_IMAGE])
            if image.returncode != 0:
                result['reason'] = 'local-keycloak-image-unavailable'
                return result
        except (OSError, subprocess.SubprocessError):
            result['reason'] = 'local-keycloak-image-unavailable'
            return result
    result['started_monotonic_ns'] = time.monotonic_ns()
    try:
        check_sources()
        child = run_child(gate['argv'])
        result['exit'] = child.returncode if child.returncode >= 0 else None
        result['signal'] = -child.returncode if child.returncode < 0 else None
        check_sources()
        if child.returncode != 0:
            result.update(outcome='failed', reason='child-nonzero-or-signal', cleanup_confirmed=False)
        else:
            result.update(required_receipt(gate['name'], output))
            result['outcome'] = 'passed'
    except subprocess.TimeoutExpired:
        result.update(outcome='failed', reason='child-timeout-cleanup-unknown', cleanup_confirmed=False)
    except Exception:
        result.update(outcome='failed', reason='child-or-receipt-invalid-cleanup-unknown', cleanup_confirmed=False)
    finally:
        result['finished_monotonic_ns'] = time.monotonic_ns()
        result['duration_ns'] = result['finished_monotonic_ns'] - result['started_monotonic_ns']
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bin-dir', type=Path, required=True, help='explicit absolute current binary directory')
    parser.add_argument('--output', type=Path, required=True, help='create-new absolute private output directory')
    parser.add_argument('--require-field', action='store_true', help='fails before effects; field gates unavailable')
    args = parser.parse_args(argv)
    if args.require_field:
        print('ACCEPTANCE FAILED: field-facility-unavailable', file=sys.stderr)
        return 1
    os.umask(0o077)
    directory = None
    try:
        DR.FILES.path_value(str(args.bin_dir))
        directory = DR.create_output(args.output)
        results = []
        for gate in fixed_gates(args.bin_dir, args.output):
            DR.check_output(args.output, directory)
            results.append(execute_gate(gate, args.bin_dir, args.output))
            DR.check_output(args.output, directory)
        passed = all(item['outcome'] == 'passed' for item in results)
        report = dict(outcome='local_gates_passed' if passed else 'local_gates_incomplete',
                      field_validated=False, field_gates={key: 'unvalidated' for key in FIELD_GATES},
                      gates=results)
        DR.write_report(args.output, directory, report)
    except (OSError, ValueError, TypeError, DR.FILES.Error):
        print('ACCEPTANCE FAILED: input-or-output-invalid', file=sys.stderr)
        return 1
    finally:
        if directory is not None:
            os.close(directory)
    print('ACCEPTANCE local gates recorded; field unvalidated')
    return 0 if passed else 1


if __name__ == '__main__':
    sys.exit(main())
