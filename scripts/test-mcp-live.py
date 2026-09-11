#!/usr/bin/env python3
"""Local MCP acceptance: real CLI, broker/TLS fixture and installed Codex.

Build first: cargo build -p rekey-cli -p rekey-broker --bins --example p1_policy_fixture
No production credentials are used. Temporary vault, signing keys and capability
files are always removed. Only redacted evidence is retained under --output.
"""
import argparse
import json
import os
import pathlib
import shutil
import signal
import subprocess
import tempfile
import time
import uuid
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--output', type=pathlib.Path, required=True)
parser.add_argument('--codex', default='codex', help='installed Codex executable')
args = parser.parse_args()
OUTPUT = args.output.resolve()
OUTPUT.mkdir(parents=True, exist_ok=True)
ROOT = pathlib.Path(__file__).resolve().parents[1]
D = pathlib.Path(tempfile.mkdtemp(prefix='rk-mcp-', dir='/tmp'))
S = D / 'state'
PASSWORD = 'mcp acceptance horse battery staple'
SECRET = 'MCP-LIVE-CREDENTIAL-CANARY'

def save(name, value):
    p = D / name
    p.write_text(json.dumps(value))
    p.chmod(384)
    return p

def command(args, stdin=None):
    r = subprocess.run([str(x) for x in args], input=None if stdin is None else stdin.encode(), capture_output=True)
    if r.returncode:
        raise RuntimeError(f'acceptance command failed (exit {r.returncode}); temporary outputs are not echoed')
    return r.stdout

def cli(args, stdin=None):
    return command([ROOT / 'target/debug/rekey', '--state-dir', S, *args], stdin)

def cj(args, stdin=None):
    return json.loads(cli(args, stdin))
broker = None
log = None
evidence = None
try:
    command([ROOT / 'target/debug/rekeyd', 'init', '--state-dir', S, '--password-stdin'], PASSWORD + '\n')
    log = open(D / 'broker.log', 'wb')
    broker = subprocess.Popen([str(ROOT / 'target/debug/examples/p1_policy_fixture'), str(S), str(D / 'port'), str(D / 'hits')], stdout=log, stderr=log)
    deadline = time.monotonic() + 10
    while not (D / 'port').exists():
        if time.monotonic() > deadline:
            raise RuntimeError('fixture startup timeout')
        time.sleep(0.1)
    cli(['unlock', '--password-stdin'], PASSWORD + '\n')
    cred = cj(['credential', 'add', 'mcp-live', '--stdin-secrets'], PASSWORD + '\n' + SECRET + '\n')['id']
    action_input = save('action-input.json', {'name': 'mcp-local-tls', 'credential_id': cred, 'origin': f"https://api.test.local:{(D / 'port').read_text().strip()}", 'method': 'POST', 'exact_path': '/v1/policy', 'auth_header': 'authorization', 'auth_prefix': 'Bearer ', 'timeout_ms': 10000, 'request_max_bytes': 4096, 'allowed_extra_headers': [], 'response_max_bytes': 4096, 'allowed_response_headers': ['content-type']})
    action = cj(['action', 'create', '--file', str(action_input), '--password-stdin'], PASSWORD + '\n')
    save('registered-action.json', action)
    ref = f"{action['id']}@{action['version']}"
    session = cj(['session', 'create', '--action', ref, '--ttl', '10m', '--max-uses', '10', '--password-stdin'], PASSWORD + '\n')
    save('session.json', session)
    manifest = save('mcp.json', {'agent_socket': str(S / 'runtime/agent.sock'), 'session_file': str(D / 'session.json'), 'tools': [{'action_file': str(D / 'registered-action.json'), 'input_schema': {'type': 'object', 'required': ['message'], 'properties': {'message': {'type': 'string'}}, 'additionalProperties': False}}]})
    resource = {'type': 'fixed-http-action', 'id': action['id']}
    policy = {'format_version': 3, 'version': 1, 'expires_at_ms': int(time.time() * 1000) + 600000, 'approvers': [], 'workload_identities': [], 'bindings': [{'action_id': action['id'], 'version': action['version'], 'resource': resource, 'parameter_schema_id': 'mcp-test/v1', 'parameter_schema': {'type': 'object', 'required': ['message'], 'properties': {'message': {'type': 'string'}}, 'additionalProperties': False}}], 'rules': [{'id': str(uuid.uuid4()), 'effect': 'permit', 'principal_id': session['principal_id'], 'action_id': action['id'], 'version': action['version'], 'resource': resource, 'parameters': {'kind': 'any_validated'}}]}
    save('policy.json', policy)
    command(['python3', ROOT / 'scripts/sign-test-policy.py', 'policy', '--key-dir', D / 'policy-key', '--snapshot', D / 'policy.json', '--bundle', D / 'policy-bundle.json', '--trust', D / 'policy-trust.json'])
    cli(['policy', 'trust', 'install', '--file', str(D / 'policy-trust.json'), '--step-up-stdin'], PASSWORD + '\n')
    cli(['policy', 'activate', '--file', str(D / 'policy-bundle.json'), '--step-up-stdin'], PASSWORD + '\n')
    token = session['capability_token']
    body = save('body.json', {'message': 'allowed'})
    direct = cli(['execute', ref, '--capability', '-', '--body-file', str(body), '--content-type', 'application/json'], token + '\n')
    assert b'"ok":true' in direct
    init = {'jsonrpc': '2.0', 'id': 1, 'method': 'initialize', 'params': {'protocolVersion': '2025-06-18', 'capabilities': {}, 'clientInfo': {'name': 'acceptance', 'version': '1'}}}
    ready = {'jsonrpc': '2.0', 'method': 'notifications/initialized'}

    def mcp(args):
        request = {'jsonrpc': '2.0', 'id': 3, 'method': 'tools/call', 'params': {'name': f"rekey.{action['id']}.v{action['version']}", 'arguments': args}}
        result = subprocess.run([str(ROOT / 'target/debug/rekey-mcp'), '--manifest', str(manifest)], input=''.join((json.dumps(v) + '\n' for v in [init, ready, request])).encode(), capture_output=True, timeout=15)
        assert result.returncode == 0, result.stderr
        for canary in [token, SECRET, PASSWORD]:
            assert canary.encode() not in result.stdout + result.stderr
        return json.loads(result.stdout.splitlines()[-1])['result']
    good = mcp({'message': 'allowed'})
    assert good['isError'] is False
    denied = mcp({'unexpected': 'denied'})
    assert denied['isError'] is True
    assert int((D / 'hits').read_text()) == 2
    wrapper = D / 'trace.py'
    wrapper.write_text('import sys,subprocess,threading,json\np=subprocess.Popen([sys.argv[1],"--manifest",sys.argv[2]],stdin=subprocess.PIPE,stdout=subprocess.PIPE)\nf=open(sys.argv[3],"a",buffering=1)\ndef forward():\n for line in sys.stdin.buffer:\n  v=json.loads(line);f.write(json.dumps({"direction":"in","method":v.get("method"),"protocolVersion":v.get("params",{}).get("protocolVersion")})+"\\n");p.stdin.write(line);p.stdin.flush()\n p.stdin.close()\nthreading.Thread(target=forward,daemon=True).start()\nfor line in p.stdout:\n v=json.loads(line);f.write(json.dumps({"direction":"out","id":v.get("id"),"tools":len(v.get("result",{}).get("tools",[])),"error":v.get("error")})+"\\n");sys.stdout.buffer.write(line);sys.stdout.buffer.flush()\n')
    trace = D / 'codex-protocol.jsonl'
    codex = subprocess.Popen([args.codex, 'exec', '--skip-git-repo-check', '--ephemeral', '-c', 'mcp_servers.rekey_acceptance.command="python3"', '-c', f"mcp_servers.rekey_acceptance.args={json.dumps([str(wrapper), str(ROOT / 'target/debug/rekey-mcp'), str(manifest), str(trace)])}", 'Reply OK without using tools.'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
    try:
        codex.wait(timeout=15)
    except subprocess.TimeoutExpired:
        os.killpg(codex.pid, signal.SIGTERM)
        codex.wait()
    records = [json.loads(x) for x in trace.read_text().splitlines()]
    assert any((x.get('method') == 'initialize' for x in records)), records
    assert any((x.get('method') == 'tools/list' for x in records)), records
    assert any((x.get('direction') == 'out' and x.get('tools') == 1 for x in records)), records
    assert int((D / 'hits').read_text()) == 2
    cli(['lock'])
    locked = mcp({'message': 'allowed'})
    assert locked['isError'] and 'LOCKED' in locked['content'][0]['text']
    evidence = {'cli_execute': 'pass', 'mcp_success': 'pass', 'mcp_policy_denied': 'pass', 'mcp_locked': 'pass', 'codex_version': command([args.codex, '--version']).decode().strip(), 'codex_initialize_and_tools_list': 'pass', 'upstream_hits': 2, 'secret_output_scan': 'pass', 'protocol_trace': records}
    print('PASS: real CLI + broker process + local TLS + MCP success/deny/lock + live Codex initialize/tools/list; hits=2; canaries absent')
finally:
    if broker is not None:
        broker.terminate()
        try:
            broker.wait(timeout=10)
        except subprocess.TimeoutExpired:
            broker.kill()
            broker.wait()
    if log is not None:
        log.close()
    shutil.rmtree(D)
    if evidence is not None:
        evidence['temporary_state_keys_and_capabilities_removed'] = not D.exists()
        (OUTPUT / 'evidence.json').write_text(json.dumps(evidence, indent=2) + '\n')
        print('Evidence:', OUTPUT / 'evidence.json')
