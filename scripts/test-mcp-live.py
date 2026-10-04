#!/usr/bin/env python3
"""Synthetic MCP acceptance: signed Profile -> real rekey run -> local TLS.

Builds the CLI, broker and test-only TLS fixture with --features lab, using
cargo metadata's target_directory (including CARGO_TARGET_DIR). Only temporary
synthetic vault/signing material is used; no capability or MCP manifest files.
Optional --codex [EXECUTABLE] uses real user configuration/auth and may start a
configured model request. It is NOT part of the default synthetic acceptance.
"""
import argparse
import hashlib
import json
import os
import pathlib
import queue
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
import uuid

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--output', type=pathlib.Path, required=True)
parser.add_argument('--codex', nargs='?', const='codex', help='opt in to installed Codex handshake; may use user auth/model')
args = parser.parse_args()
ROOT = pathlib.Path(__file__).resolve().parents[1]
OUTPUT = args.output.resolve()
OUTPUT.mkdir(parents=True, exist_ok=True)
D = pathlib.Path(tempfile.mkdtemp(prefix='rk-mcp-', dir='/tmp'))
S = D / 'state'
PASSWORD = 'mcp acceptance horse battery staple'
SECRET = 'MCP-LIVE-CREDENTIAL-CANARY'
ENV = dict(os.environ)
ENV.pop('REKEY_CAPABILITY', None)
ENV.pop('REKEY_AGENT_SOCKET', None)
stages = []
evidence = {'result': 'incomplete', 'codex': 'not requested', 'stages': stages}
processes = []


def scan(data):
    for canary in (PASSWORD, SECRET, 'capability_token'):
        if canary.encode() in data:
            raise RuntimeError('sensitive output detected; content withheld')


def stop_group(process):
    # Every process here was started in its own session. Never signal other groups.
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        process.wait(timeout=3)
        return
    try:
        process.wait(timeout=2)
    except subprocess.TimeoutExpired:
        pass
    # Descendants may retain pipes even after the parent exits.
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    process.wait(timeout=3)


def command(label, argv, stdin=None, timeout=30, expected=0, build=False):
    process = subprocess.Popen([str(x) for x in argv], cwd=ROOT, env=ENV,
                               stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, start_new_session=True)
    started = time.monotonic()
    try:
        stdout, stderr = process.communicate(None if stdin is None else stdin.encode(), timeout=timeout)
    except subprocess.TimeoutExpired:
        stop_group(process)
        stages.append({'stage': label, 'exit': process.returncode, 'timeout': True})
        raise RuntimeError(f'{label} timed out; temporary outputs withheld') from None
    except BaseException:
        stop_group(process)
        raise
    stages.append({'stage': label, 'exit': process.returncode, 'seconds': round(time.monotonic() - started, 3)})
    scan(stdout + stderr)
    if build:
        (OUTPUT / 'build.log').write_bytes(stdout + stderr)
    if process.returncode != expected:
        raise RuntimeError(f'{label} failed (exit {process.returncode}); temporary outputs withheld')
    return stdout, stderr


def save(name, value):
    path = D / name
    path.write_text(json.dumps(value))
    path.chmod(0o600)
    return path


def cli(arguments, stdin=None, expected=0):
    if arguments[:2] == ['policy', 'activate']:
        target = json.loads(cli(['policy', 'status']))
        arguments += ['--expected-vault-id', target['vault_id'], '--expected-trust-sha256', target['trust_sha256']]
    return command('cli ' + ' '.join(arguments[:2]), [BIN / 'rekey', '--state-dir', S, *arguments], stdin, expected=expected)[0]


class LiveProcess:
    def __init__(self, label, argv):
        self.label = label
        self.process = subprocess.Popen([str(x) for x in argv], cwd=D, env=ENV,
                                        stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE, start_new_session=True)
        self.stopped = False
        self.messages = queue.Queue()
        self.output = []
        self.done = [threading.Event(), threading.Event()]
        for index, stream in enumerate((self.process.stdout, self.process.stderr)):
            threading.Thread(target=self.collect, args=(index, stream), daemon=True).start()
        processes.append(self)

    def collect(self, index, stream):
        try:
            for line in stream:
                self.output.append(line)
                if index == 0:
                    self.messages.put(line)
        finally:
            if index == 0:
                self.messages.put(None)
            self.done[index].set()

    def send(self, request):
        self.process.stdin.write((json.dumps(request) + '\n').encode())
        self.process.stdin.flush()

    def request(self, method, params=None):
        request = {'jsonrpc': '2.0', 'id': 1, 'method': method}
        if params is not None:
            request['params'] = params
        self.send(request)
        try:
            raw = self.messages.get(timeout=10)
        except queue.Empty:
            raise RuntimeError('MCP response timed out') from None
        if raw is None:
            raise RuntimeError('MCP ended before its response')
        scan(raw)
        return json.loads(raw)

    def ended(self, expected):
        result = self.process.wait(timeout=10)
        if not all(event.wait(timeout=2) for event in self.done):
            raise RuntimeError('descendant retained stdio after owner ended')
        scan(b''.join(self.output))
        stages.append({'stage': self.label, 'exit': result})
        if result != expected:
            raise RuntimeError(f'{self.label} exited unexpectedly ({result})')

    def stop(self):
        if self.stopped:
            return
        try:
            if self.process.poll() is None or not all(event.is_set() for event in self.done):
                stop_group(self.process)
            self.process.stdin.close()
            if not all(event.wait(timeout=2) for event in self.done):
                raise RuntimeError('stdio cleanup did not finish')
            scan(b''.join(self.output))
        finally:
            self.stopped = True
            stages.append({'stage': self.label + ' cleanup', 'exit': self.process.returncode})


def mcp_start():
    live = LiveProcess('profile MCP', [BIN / 'rekey', '--state-dir', S, 'run', 'mcp-smoke', '--', BIN / 'rekey-mcp'])
    response = live.request('initialize', {'protocolVersion': '2025-06-18', 'capabilities': {}, 'clientInfo': {'name': 'acceptance', 'version': '1'}})
    assert response['result']['protocolVersion'] == '2025-06-18'
    live.send({'jsonrpc': '2.0', 'method': 'notifications/initialized'})
    listed = live.request('tools/list')['result']['tools']
    tools = [tool for tool in listed if tool['name'].startswith('rekey.')]
    assert len(tools) == 1 and len(listed) == 3
    return live, tools[0]['name']


def codex_handshake():
    # Trace only protocol method/version and tool count, never arguments/results.
    wrapper = D / 'trace.py'
    wrapper.write_text('''import sys,subprocess,threading,json
p=subprocess.Popen([sys.argv[1]],stdin=subprocess.PIPE,stdout=subprocess.PIPE)
f=open(sys.argv[2],"a",buffering=1)
def forward():
 for line in sys.stdin.buffer:
  v=json.loads(line);f.write(json.dumps({"direction":"in","method":v.get("method"),"protocolVersion":v.get("params",{}).get("protocolVersion")})+"\\n");p.stdin.write(line);p.stdin.flush()
 p.stdin.close()
threading.Thread(target=forward,daemon=True).start()
for line in p.stdout:
 v=json.loads(line);f.write(json.dumps({"direction":"out","id":v.get("id"),"tools":len(v.get("result",{}).get("tools",[]))})+"\\n");sys.stdout.buffer.write(line);sys.stdout.buffer.flush()
''')
    trace = D / 'codex-protocol.jsonl'
    version = command('codex version', [args.codex, '--version'])[0].decode().strip()
    live = LiveProcess('optional Codex', [BIN / 'rekey', '--state-dir', S, 'run', 'mcp-smoke', '--', args.codex,
        'exec', '--skip-git-repo-check', '--ephemeral', '-c', f'mcp_servers.rekey_acceptance.command={json.dumps(sys.executable)}',
        '-c', f'mcp_servers.rekey_acceptance.args={json.dumps([str(wrapper), str(BIN / "rekey-mcp"), str(trace)])}',
        '-c', 'mcp_servers.rekey_acceptance.env_vars=["REKEY_CAPABILITY","REKEY_AGENT_SOCKET"]',
        'Reply OK without using tools.'])
    deadline = time.monotonic() + 20
    records = []
    try:
        while time.monotonic() < deadline:
            if trace.exists():
                lines = trace.read_text().splitlines()
                records = [json.loads(line) for line in lines if line.endswith('}')]
                if any(row.get('tools') == 3 for row in records):
                    break
            time.sleep(0.1)
        assert any(row.get('method') == 'initialize' for row in records)
        assert any(row.get('method') == 'tools/list' for row in records)
        assert any(row.get('tools') == 3 for row in records)
    finally:
        live.stop()
    stages.append({'stage': 'optional Codex handshake', 'exit': live.process.returncode})
    return {'handshake': 'pass', 'version': version, 'trace': records,
            'scope': 'initialize/tools/list only; real user configuration/auth used and a model request may have started'}


broker = None
broker_log = None
try:
    metadata = json.loads(command('cargo metadata', ['cargo', 'metadata', '--offline', '--no-deps', '--format-version', '1'])[0])
    BIN = pathlib.Path(metadata['target_directory']) / 'debug'
    build_argv = ['cargo', 'build', '--offline', '--features', 'lab', '-p', 'rekey-cli', '-p', 'rekey-broker', '--bins', '--example', 'p1_policy_fixture']
    command('build lab binaries and TLS fixture', build_argv, timeout=600, build=True)
    evidence.update({'source_root': str(ROOT), 'script_sha256': hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest(),
        'target_directory': metadata['target_directory'], 'build_command': build_argv,
        'binaries': {str(path): hashlib.sha256(path.read_bytes()).hexdigest() for path in (BIN / 'rekey', BIN / 'rekeyd', BIN / 'rekey-mcp', BIN / 'examples/p1_policy_fixture')}})
    command('init synthetic team vault', [BIN / 'rekeyd', 'init', '--mode', 'team', '--state-dir', S, '--password-stdin'], PASSWORD + '\n')
    broker_log = open(D / 'broker.log', 'wb')
    broker = subprocess.Popen([str(BIN / 'examples/p1_policy_fixture'), str(S), str(D / 'port'), str(D / 'hits')], stdout=broker_log, stderr=broker_log, start_new_session=True, env=ENV)
    deadline = time.monotonic() + 10
    while not (D / 'port').exists() or not (S / 'runtime/admin.sock').exists():
        if broker.poll() is not None or time.monotonic() > deadline:
            raise RuntimeError('TLS fixture startup failed')
        time.sleep(0.05)
    cli(['unlock', '--password-stdin'], PASSWORD + '\n')
    credential = json.loads(cli(['credential', 'add', 'mcp-live', '--stdin-secrets'], PASSWORD + '\n' + SECRET + '\n'))['id']
    definition = {'source': {'kind': 'generic-bearer', 'origin': f'https://api.test.local:{(D / "port").read_text().strip()}', 'actions': [{'method': 'POST', 'path': '/v1/policy'}]},
        'credential_id': credential, 'bindings': [{}], 'capabilities': ['fixed-actions'], 'name_prefix': 'mcp-local-tls', 'timeout_ms': 10000,
        'request_max_bytes': 4096, 'allowed_extra_headers': [], 'response_max_bytes': 4096, 'allowed_response_headers': ['content-type']}
    installed = json.loads(cli(['template', 'install', '--stdin-request', '--password-stdin'], PASSWORD + '\n' + json.dumps(definition) + '\n'))
    action = installed['actions'][0]['action']
    reference = {'action_id': action['id'], 'version': action['version']}
    principal = str(uuid.uuid4())
    resource = {'type': 'mcp-smoke', 'id': action['id']}
    profile = {'name': 'mcp-smoke', 'principal_id': principal, 'grants': [{'instance': 'local-tls', 'capabilities': [{'capability': 'fixed-actions', 'rule': 'template-default', 'actions': [reference]}]}],
        'session': {'ttl_ms': 120000, 'max_uses': 10}, 'confirm_each_run': False, 'isolation': 'none', 'egress': 'allow', 'llm_limits': []}
    schema = {'type': 'object', 'required': ['message'], 'properties': {'message': {'type': 'string'}}, 'additionalProperties': False}
    policy = {'format_version': 6, 'version': 1, 'expires_at_ms': int(time.time() * 1000) + 600000, 'approvers': [], 'profiles': [profile], 'workload_identities': [],
        'bindings': [dict(reference, resource=resource, parameter_schema_id='mcp-test/v1', parameter_schema=schema)],
        'rules': [dict(reference, id=str(uuid.uuid4()), effect='permit', principal_id=principal, resource=resource, parameters={'kind': 'any_validated'})]}
    save('policy.json', policy)
    command('sign synthetic policy', [sys.executable, ROOT / 'scripts/sign-test-policy.py', 'policy', '--key-dir', D / 'policy-key', '--snapshot', D / 'policy.json', '--bundle', D / 'policy-bundle.json', '--trust', D / 'policy-trust.json'])
    cli(['policy', 'trust', 'install', '--file', str(D / 'policy-trust.json'), '--step-up-stdin'], PASSWORD + '\n')
    cli(['policy', 'activate', '--file', str(D / 'policy-bundle.json'), '--step-up-stdin'], PASSWORD + '\n')
    live, name = mcp_start()
    good = live.request('tools/call', {'name': name, 'arguments': {'body': {'message': 'allowed'}}})['result']
    assert good['isError'] is False and json.loads(good['content'][0]['text']) == {'ok': True}
    denied = live.request('tools/call', {'name': name, 'arguments': {'body': {'unexpected': 'denied'}}})['result']
    assert denied['isError'] is True
    malformed = live.request('tools/call', {'name': name, 'arguments': {'body': {'message': 'allowed'}, 'operation': '0'}})
    assert malformed['error']['code'] == -32602
    assert int((D / 'hits').read_text()) == 1
    live.process.stdin.close()
    live.ended(0)
    audit = json.loads(cli(['audit', 'list', '--limit', '100']))
    assert audit['next_before_sequence'] is None
    activity = [row for row in audit['events'] if row.get('request_context')]
    assert sum(row['event_type'] == 'execution.started' for row in activity) == 1
    assert sum(row['event_type'] == 'execution.blocked' for row in activity) == 1
    for row in activity:
        context = row['request_context']
        assert context['profile_name'] == 'mcp-smoke' and context['instance_slug'] == 'local-tls'
        assert context['capability'] == 'fixed-actions' and context['model'] is None
        assert len(context['policy_sha256']) == 64
    scan(json.dumps(audit).encode())
    activity_bytes = (json.dumps(audit, separators=(',', ':')) + '\n').encode()
    (OUTPUT / 'activity-page.json').write_bytes(activity_bytes)
    evidence['activity_audit'] = {'profile': 'mcp-smoke', 'admitted': 1, 'denied': 1, 'file': 'activity-page.json',
                                  'sha256': hashlib.sha256(activity_bytes).hexdigest()}
    if args.codex:
        evidence['codex'] = codex_handshake()
        assert int((D / 'hits').read_text()) == 1
    live, _ = mcp_start()
    cli(['lock'])
    live.ended(7)  # run reports the ended Profile; it kills the MCP child.
    output = b''.join(live.output)
    assert b'IPC_UNAVAILABLE' in output
    command('locked Profile mint rejected', [BIN / 'rekey', '--state-dir', S, 'run', 'mcp-smoke', '--', BIN / 'rekey-mcp'], expected=3)
    assert int((D / 'hits').read_text()) == 1
    cli(['shutdown', '--password-stdin'], PASSWORD + '\n')
    assert broker.wait(timeout=10) == 0
    stages.append({'stage': 'clean fixture shutdown', 'exit': broker.returncode})
    broker_log.close()
    scan((D / 'broker.log').read_bytes())
    assert not (D / 'session.json').exists() and not (D / 'mcp.json').exists()
    evidence.update({'result': 'pass', 'upstream_hits': 1, 'normal_mcp': 'pass', 'policy_parameter_denied': 'pass',
        'outer_parameter_denied': 'pass', 'lock_revokes_run_and_mcp': 'pass', 'clean_exit_and_shutdown': 'pass',
        'credential_and_proof_output_scan': 'pass', 'capability_or_manifest_file_created': False})
    print('PASS: signed Profile + real run/MCP + local TLS; success/parameter denial/owner lock; hits=1; synthetic canaries absent')
finally:
    already_failed = sys.exc_info()[0] is not None
    cleanup_errors = []
    for live in processes:
        try:
            live.stop()
        except Exception as error:
            cleanup_errors.append(type(error).__name__)
    try:
        if broker is not None and broker.poll() is None:
            stop_group(broker)
    except Exception as error:
        cleanup_errors.append(type(error).__name__)
    finally:
        if broker_log is not None:
            broker_log.close()
    try:
        shutil.rmtree(D)
    except OSError as error:
        cleanup_errors.append(type(error).__name__)
    evidence['temporary_state_and_signing_keys_removed'] = not D.exists()
    if cleanup_errors:
        evidence.update(result='cleanup failed', cleanup_errors=cleanup_errors)
    (OUTPUT / 'evidence.json').write_text(json.dumps(evidence, indent=2) + '\n')
    print('Evidence:', OUTPUT / 'evidence.json')
    if cleanup_errors and not already_failed:
        raise RuntimeError('synthetic process or file cleanup failed; see evidence')
