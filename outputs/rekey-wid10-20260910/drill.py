import argparse
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import secrets
import subprocess
import tempfile
import time
import urllib.parse
import urllib.request
import uuid


def fetch(url, headers=None):
    with urllib.request.urlopen(urllib.request.Request(url, headers=headers or {}), timeout=30) as response:
        return json.load(response)


def decode(part):
    return json.loads(base64.urlsafe_b64decode(part + '=' * (-len(part) % 4)))


def run(argv, stdin=None, expected=0):
    result = subprocess.run(argv, input=stdin, capture_output=True, timeout=45)
    if result.returncode != expected:
        raise RuntimeError('unexpected CLI exit: ' + str(result.returncode))
    return result.stdout


def token(audience):
    url = os.environ['ACTIONS_ID_TOKEN_REQUEST_URL'] + '&audience=' + urllib.parse.quote(audience, safe='')
    return fetch(url, {'Authorization': 'Bearer ' + os.environ['ACTIONS_ID_TOKEN_REQUEST_TOKEN']})['value']


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser()
    parser.add_argument('--bin-dir', type=Path, required=True)
    parser.add_argument('--signer', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    rk, rd = [str((args.bin_dir / name).resolve()) for name in ['rekey', 'rekeyd']]
    audience = 'rekey://github-oidc-acceptance'
    jwt = token(audience)
    unused = token(audience + '/expiry')
    wrong = token(audience + '/wrong')
    header, claims = decode(jwt.split('.')[0]), decode(jwt.split('.')[1])
    expires = decode(unused.split('.')[1])['exp']
    assert header['alg'] == 'RS256'
    assert claims['iss'] == 'https://token.actions.githubusercontent.com'
    assert claims['repository'] == os.environ['GITHUB_REPOSITORY']
    assert claims['ref'] == 'refs/heads/main'
    assert 0 < expires - time.time() < 900
    keys = fetch('https://token.actions.githubusercontent.com/.well-known/jwks')['keys']
    public = next(k for k in keys if k['kid'] == header['kid'])
    key = {'algorithm':'rs256', 'kid':public['kid'], 'n':public['n'], 'e':public['e']}
    password, canary = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
    proof = (password + '\n').encode()
    spec = importlib.util.spec_from_file_location('signer', args.signer)
    signer = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(signer)
    with tempfile.TemporaryDirectory(prefix='rk-oidc-') as tmp:
        work = Path(tmp)
        state = work / 'state'
        base = [rk, '--state-dir', str(state)]
        run([rd, 'init', '--state-dir', str(state), '--password-stdin'], proof)
        with (work / 'broker.log').open('wb') as log:
            proc = subprocess.Popen([rd, 'serve', '--state-dir', str(state)], stdout=log, stderr=log)
            try:
                deadline = time.monotonic() + 15
                while not (state / 'runtime/admin.sock').exists():
                    assert proc.poll() is None and time.monotonic() < deadline
                    time.sleep(.05)
                run(base + ['unlock', '--password-stdin'], proof)
                cred = json.loads(run(base + ['credential','add','oidc-drill','--stdin-secrets'], proof + (canary+'\n').encode()))
                action = {'name':'oidc-public-read','credential_id':cred['id'],'origin':'https://api.github.com',
                    'method':'GET','exact_path':'/repos/majiayu000/rekey','auth_header':'x-api-key','auth_prefix':'',
                    'timeout_ms':30000,'request_max_bytes':1024,'allowed_extra_headers':['user-agent'],
                    'response_max_bytes':262144,'allowed_response_headers':[]}
                (work/'action.json').write_text(json.dumps(action))
                action = json.loads(run(base+['action','create','--file',str(work/'action.json'),'--password-stdin'], proof))
                ref = action['id']+'@1'
                principal = str(uuid.uuid4())
                resource = {'type':'fixed-http-action','id':action['id']}
                snapshot = {'format_version':3,'version':1,'expires_at_ms':int((expires+600)*1000),'approvers':[],
                    'workload_identities':[{'principal_id':principal,'issuer':claims['iss'],
                        'audiences':[audience],'max_token_age_ms':3600000,
                        'profile':{'kind':'ci-cloud','subject':claims['sub']},'keys':[key]}],
                    'bindings':[{'action_id':action['id'],'version':1,'resource':resource,
                        'parameter_schema_id':'oidc-read/v1','parameter_schema':{'type':'null'}}],
                    'rules':[{'id':str(uuid.uuid4()),'effect':'permit','principal_id':principal,
                        'action_id':action['id'],'version':1,'resource':resource,'parameters':{'kind':'any_validated'}}]}
                expiry_identity = json.loads(json.dumps(snapshot['workload_identities'][0]))
                expiry_identity['principal_id'] = str(uuid.uuid4())
                expiry_identity['audiences'] = [audience+'/expiry']
                snapshot['workload_identities'].append(expiry_identity)
                expiry_rule = dict(snapshot['rules'][0], id=str(uuid.uuid4()), principal_id=expiry_identity['principal_id'])
                snapshot['rules'].append(expiry_rule)
                (work/'draft.json').write_text(json.dumps(snapshot))
                signer.sign_policy(argparse.Namespace(key_dir=work/'signer', snapshot=work/'draft.json',
                    trust=work/'trust.json', bundle=work/'bundle.json'))
                for command, path in [(['policy','trust','install'],'trust.json'), (['policy','activate'],'bundle.json')]:
                    run(base+command+['--file',str(work/path),'--step-up-stdin'],proof)
                mint = base+['session','create','--action',ref,'--ttl','5m','--max-uses','2','--workload-token-stdin']
                print('JWT header fields:', sorted(header), 'TTL seconds:', claims['exp']-claims['iat'], flush=True)
                session = json.loads(run(mint,(jwt+'\n').encode()))
                response = run(base+['execute',ref,'--capability','-','--header','user-agent: rekey-oidc-drill'],
                    (session['capability_token']+'\n').encode())
                meta,end = json.JSONDecoder().raw_decode(response.decode())
                assert meta['upstream_status']==200
                assert json.loads(response.decode()[end:])['full_name']=='majiayu000/rekey'
                run(mint,(jwt+'\n').encode(),expected=4)
                run(mint,(wrong+'\n').encode(),expected=4)
                print('Real OIDC mint, fixed read 200, replay and wrong-audience rejection passed; waiting for natural expiry.',flush=True)
                time.sleep(max(0, expires-time.time()+2))
                run(mint,(unused+'\n').encode(),expected=4)
                # Force buffered broker logs to disk before scanning evidence.
                run(base+['shutdown','--password-stdin'],proof)
                proc.wait(timeout=15)
                for needle in [jwt,unused,wrong,password,canary,session['capability_token']]:
                    assert needle.encode() not in response
                    assert needle.encode() not in (work/'broker.log').read_bytes()
                receipt = {'issuer':claims['iss'],'subject':claims['sub'],'audience':audience,
                    'kid':header['kid'],'public_key_sha256':hashlib.sha256(json.dumps(key,sort_keys=True).encode()).hexdigest(),
                    'jwt_saved':False,'mint_success':True,'fixed_read_status':200,'replay_exit':4,'wrong_audience_exit':4,
                    'naturally_expired_unused_jwt_exit':4,'expiry_epoch':expires,'tested_at_epoch':int(time.time()),
                    'source_base':'358b3a5','source_fix':'bounded standard RS256 x5t metadata','runner_commit':os.environ['GITHUB_SHA'],'binary_sha256':{Path(p).name:hashlib.sha256(Path(p).read_bytes()).hexdigest() for p in [rk,rd]},
                    'limitation':'Static pinned GitHub public key; no broker JWKS fetching or general OAuth exchange; anonymous upstream read'}
            finally:
                if proc.poll() is None:
                    proc.terminate()
                    proc.wait(timeout=15)
    receipt['temporary_states_and_secrets_removed']=True
    args.output.write_text(json.dumps(receipt,indent=2)+'\n')
    print('GitHub Actions real OIDC interoperability: PASS')


if __name__ == '__main__':
    main()
