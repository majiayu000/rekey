#!/usr/bin/env python3
"""Disposable loopback Keycloak provider probe; never a Rekey acceptance claim."""
import base64
import datetime
import json
import os
from pathlib import Path
import re
import secrets
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

ROOT = Path(__file__).resolve().parent
os.umask(0o077)
CONFIG = json.loads((ROOT / 'config.json').read_text())
NAME = CONFIG['container']
PORT = CONFIG['port']
IMAGE = CONFIG['image']
REALM = 'rekey-oau02-probe'
BASE = f'http://127.0.0.1:{PORT}/realms/{REALM}/protocol/openid-connect'
client_secret = secrets.token_urlsafe(36)
target_secret = secrets.token_urlsafe(36)
tokens = []
receipt = {'started_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
           'scope': 'loopback provider probe only; no Rekey Broker or public HTTPS claim',
           'image': IMAGE, 'container': NAME, 'origin': f'http://127.0.0.1:{PORT}',
           'realm': REALM, 'requester_client': 'rekey-requester', 'audience': 'rekey-target',
           'steps': [], 'pass': False}
stage = 'setup'
created = False
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

def command(args):
    result = subprocess.run(args, capture_output=True)
    if result.returncode:
        raise RuntimeError('subprocess failed')
    return result.stdout

def post(endpoint, values):
    # All client authentication and tokens are in an HTTP body, never argv/env.
    introspection = endpoint == 'token/introspect'
    form = {'client_id': 'rekey-target' if introspection else 'rekey-requester',
            'client_secret': target_secret if introspection else client_secret, **values}
    request = urllib.request.Request(BASE + '/' + endpoint,
        data=urllib.parse.urlencode(form).encode(),
        headers={'Content-Type': 'application/x-www-form-urlencoded'})
    try:
        response = opener.open(request, timeout=15)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        body = response.read(65537)
        if len(body) > 65536:
            raise RuntimeError('oversized provider response')
        data = json.loads(body) if body else {}
        return response.status, data

def claims(token):
    part = token.split('.')[1]
    return json.loads(base64.urlsafe_b64decode(part + '=' * (-len(part) % 4)))

def record(step, **values):
    receipt['steps'].append({'step': step, **values})
    (ROOT / 'receipt.json').write_text(json.dumps(receipt, indent=2))
    print(step + ': ' + json.dumps(values), flush=True)

def exchange(subject):
    return post('token', {'grant_type': 'urn:ietf:params:oauth:grant-type:token-exchange',
        'subject_token': subject, 'subject_token_type': 'urn:ietf:params:oauth:token-type:access_token',
        'requested_token_type': 'urn:ietf:params:oauth:token-type:access_token',
        'audience': 'rekey-target'})

try:
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', PORT))
    realm = {'realm': REALM, 'enabled': True, 'sslRequired': 'none',
        'accessTokenLifespan': 20, 'revokeRefreshToken': True,
        'defaultDefaultClientScopes': [], 'defaultOptionalClientScopes': [],
        'clients': [
          {'clientId': 'rekey-requester', 'protocol': 'openid-connect',
           'publicClient': False, 'secret': client_secret,
           'defaultClientScopes': [], 'optionalClientScopes': [], 'fullScopeAllowed': False,
           'standardFlowEnabled': False, 'directAccessGrantsEnabled': False,
           'serviceAccountsEnabled': True,
           'attributes': {'standard.token.exchange.enabled': 'true', 'access.token.lifespan': '20'},
           'protocolMappers': [{'name': 'fixed-target', 'protocol': 'openid-connect',
             'protocolMapper': 'oidc-audience-mapper',
             'config': {'included.client.audience': 'rekey-target', 'access.token.claim': 'true', 'id.token.claim': 'false'}}]},
          {'clientId': 'rekey-target', 'protocol': 'openid-connect', 'publicClient': False,
           'secret': target_secret,
           'defaultClientScopes': [], 'optionalClientScopes': [], 'fullScopeAllowed': False,
           'standardFlowEnabled': False, 'directAccessGrantsEnabled': False}]}
    realm_file = ROOT / 'realm.json'
    realm_file.write_text(json.dumps(realm))
    image = json.loads(command(['docker', 'image', 'inspect', IMAGE]))[0]
    receipt['image_id'] = image['Id']
    receipt['image_digests'] = image.get('RepoDigests', [])
    command(['docker', 'create', '--name', NAME, '--user', '0', '--log-driver', 'none',
        '-p', f'127.0.0.1:{PORT}:{PORT}', '--mount',
        f'type=bind,src={realm_file},dst=/opt/keycloak/data/import/{REALM}-realm.json,readonly',
        IMAGE, 'start-dev', '--http-port', str(PORT), '--import-realm',
        '--features=token-exchange-standard:v2', '--features-disabled=token-exchange',
        '--log-level=error'])
    created = True
    command(['docker', 'start', NAME])
    stage = 'readiness'
    deadline = time.monotonic() + 120
    while True:
        try:
            with opener.open(f'http://127.0.0.1:{PORT}/realms/{REALM}/.well-known/openid-configuration', timeout=2) as response:
                discovery = json.load(response)
            assert discovery['issuer'] == f'http://127.0.0.1:{PORT}/realms/{REALM}'
            break
        except (OSError, urllib.error.URLError):
            pass
        state = json.loads(command(['docker', 'inspect', NAME]))[0]['State']
        if not state['Running']:
            raise RuntimeError('Keycloak exited during startup')
        if time.monotonic() > deadline:
            raise RuntimeError('Keycloak readiness timed out')
        time.sleep(1)
    record('ready', version=command(['docker', 'exec', NAME, '/opt/keycloak/bin/kc.sh', '--version']).decode().strip())
    stage = 'subject-client-credentials'
    status, initial = post('token', {'grant_type': 'client_credentials'})
    assert status == 200 and initial['token_type'] == 'Bearer'
    subject = initial['access_token']; tokens.append(subject)
    record(stage, status=status, expires_in=initial['expires_in'])
    stage = 'standard-v2-exchange'
    status, result = exchange(subject)
    if status != 200:
        code = result.get('error', '')
        record(stage, status=status, error=code if re.fullmatch('[a-z_]+', code) else 'redacted')
        raise RuntimeError('exchange rejected')
    issued = result['access_token']; tokens.append(issued)
    record('exchange-response-metadata', status=status, token_type=result.get('token_type'),
        issued_token_type=result.get('issued_token_type'), expires_in=result.get('expires_in'),
        refresh_token_present='refresh_token' in result, issued_audience=claims(issued).get('aud'))
    assert result['token_type'] == 'Bearer'
    assert result['issued_token_type'] == 'urn:ietf:params:oauth:token-type:access_token'
    assert 0 < result['expires_in'] <= 20 and 'refresh_token' not in result
    stage = 'issued-introspection'
    status, active = post('token/introspect', {'token': issued})
    record('issued-introspection-metadata', status=status, active=active.get('active'), audience=active.get('aud'))
    assert status == 200 and active['active'] is True
    aud = active.get('aud'); audience = [aud] if isinstance(aud, str) else aud
    assert audience == ['rekey-target'], 'not an exact target audience'
    record(stage, status=200, issued_token_type=result['issued_token_type'],
        expires_in=result['expires_in'], fixed_audience=audience, introspection_active=True)
    stage = 'direct-issued-token-revoke'
    status, revoked = post('revoke', {'token': issued, 'token_type_hint': 'access_token'})
    assert status == 200
    status, inactive = post('token/introspect', {'token': issued})
    assert status == 200 and inactive['active'] is False
    assert time.time() < claims(issued)['exp'], 'revocation result confounded by token expiry'
    record(stage, revoke_status=200, introspection_status=200, active=False,
        verified_before_expiry=True, remaining_ttl_seconds=claims(issued)['exp'] - time.time())
    stage = 'expired-subject-exchange'
    # A fresh subject keeps the expiry negative test independent of revocation.
    status, fresh = post('token', {'grant_type': 'client_credentials'})
    assert status == 200
    expired_subject = fresh['access_token']; tokens.append(expired_subject)
    expires = claims(expired_subject)['exp']
    print('Waiting for dedicated short-lived subject expiry', flush=True)
    time.sleep(max(0, expires + 2 - time.time()))
    status, rejected = exchange(expired_subject)
    code = rejected.get('error', '')
    record('expired-subject-response', status=status,
        error=code if re.fullmatch('[a-z_]+', code) else 'redacted',
        seconds_after_expiry=time.time() - expires)
    assert status == 400 and rejected.get('error') == 'invalid_request'
    record(stage, status=status, error=rejected['error'], expires_in=fresh['expires_in'])
    receipt['pass'] = True
except Exception as error:
    receipt['failure'] = {'stage': stage, 'class': type(error).__name__}
    print('Probe failed at ' + stage + ' (' + type(error).__name__ + ')', flush=True)
finally:
    cleanup = {'container': NAME, 'removed': not created, 'private_realm_file_removed': False}
    if created:
        result = subprocess.run(['docker', 'rm', '-f', '-v', NAME], capture_output=True)
        cleanup['removed'] = result.returncode == 0
        absent = subprocess.run(['docker', 'ps', '-a', '--filter', 'name=^/' + NAME + '$', '--format', '{{.Names}}'], capture_output=True)
        cleanup['container_absent'] = absent.returncode == 0 and not absent.stdout.strip()
    (ROOT / 'realm.json').unlink(missing_ok=True)
    cleanup['private_realm_file_removed'] = not (ROOT / 'realm.json').exists()
    receipt['cleanup'] = cleanup
    receipt['finished_at'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    encoded = json.dumps(receipt, indent=2)
    assert client_secret not in encoded and target_secret not in encoded and all(token not in encoded for token in tokens)
    receipt['secret_scan_passed'] = True
    (ROOT / 'receipt.json').write_text(json.dumps(receipt, indent=2))
    print('Cleanup: ' + json.dumps(cleanup), flush=True)
sys.exit(0 if receipt['pass'] and cleanup['removed'] else 1)
