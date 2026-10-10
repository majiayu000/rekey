#!/usr/bin/env python3
"""Real CLI/daemon PKI issuance and previous-release rejection, disposable state only.

Build candidate binaries first. Previous binaries must be extracted, not installed;
pass the actual packaged bin directory, never an absolute installation symlink.
"""
import argparse
import base64
import hashlib
import json
import os
import pathlib
import secrets
import socket
import sqlite3
import subprocess
import tempfile
import time

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--binaries', type=pathlib.Path, required=True)
parser.add_argument('--previous-binaries', type=pathlib.Path, required=True)
parser.add_argument('--openssl', required=True)
parser.add_argument('--output', type=pathlib.Path, required=True)
args = parser.parse_args()
new = args.binaries.resolve(strict=True)
old = args.previous_binaries.resolve(strict=True)
openssl = args.openssl
for name in ['rekey', 'rekeyd']:
    assert subprocess.check_output([str(old / name), '--version'], text=True).strip().endswith('0.4.0-alpha.1'), 'expected actual v0.4.0-alpha.1 binaries'
    assert (old / name).resolve() != (new / name).resolve(), 'previous and candidate binaries must differ' 
receipt={'candidate_sha':subprocess.check_output(['git','rev-parse','HEAD'],cwd=pathlib.Path(__file__).resolve().parent.parent,text=True).strip(),'old_release':'v0.4.0-alpha.1','binaries':{k:hashlib.sha256((p/'rekeyd').read_bytes()).hexdigest() for k,p in [('candidate',new),('previous',old)]}}
with tempfile.TemporaryDirectory(prefix='rk-pki-') as folder:
 root=pathlib.Path(folder);env={'HOME':folder,'PATH':os.environ.get('PATH','/usr/bin:/bin'),'LANG':'en_US.UTF-8'}
 password=secrets.token_urlsafe(28).encode()+b'\n'
 sensitive=[password.strip()]
 def run(args,body=None,ok=True):
  r=subprocess.run([str(a) for a in args],input=body,capture_output=True,timeout=40,env=env)
  assert all(x not in r.stdout+r.stderr for x in sensitive),'secret reached process output'
  if ok:assert r.returncode==0,(str(args[0]),args[1] if len(args)>1 else '',r.returncode,r.stderr.decode()[:300])
  return r
 def cli(state,args,body=None,ok=True,binary=new):return run([binary/'rekey','--state-dir',state,*args],body,ok)
 state=root/'old-vault'
 cli(state,['init','--mode','personal','--password-stdin'],password,binary=old)
 db=state/'vault.sqlite3'
 with sqlite3.connect('file:'+str(db)+'?mode=ro&immutable=1',uri=True) as conn:receipt['previous_format']=conn.execute('select format_version from vault_header').fetchone()[0]
 assert receipt['previous_format']==26, 'previous release must create format26'
 conn.close()
 before={str(p.relative_to(state)):hashlib.sha256(p.read_bytes()).hexdigest() for p in state.rglob('*') if p.is_file()}
 r=run([new/'rekeyd','serve','--state-dir',state],ok=False)
 assert r.returncode==5 and b'state directory does not contain a supported vault layout' in r.stderr,('previous format was not explicitly rejected',r.returncode,r.stderr.decode()[:200])
 after={str(p.relative_to(state)):hashlib.sha256(p.read_bytes()).hexdigest() for p in state.rglob('*') if p.is_file()}
 assert all(after.get(k)==v for k,v in before.items()),('previous state modified', [k for k,v in before.items() if after.get(k)!=v])
 receipt['real_previous_format_rejected']=True;receipt['previous_files_preserved']=True
 state=root/'new-vault';cli(state,['init','--mode','personal','--password-stdin'],password)
 with sqlite3.connect('file:'+str(state/'vault.sqlite3')+'?mode=ro&immutable=1',uri=True) as conn:
  receipt['new_format']=conn.execute('select format_version from vault_header').fetchone()[0]
 conn.close()
 assert receipt['new_format']==27, 'candidate must create format27'
 with socket.socket() as listener:listener.bind(('127.0.0.1',0));port=listener.getsockname()[1]
 config=state/'service.json';config.write_text(json.dumps({'port':port}));config.chmod(0o600)
 def start():
  p=subprocess.Popen([str(new/'rekeyd'),'serve','--state-dir',str(state)],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,env=env)
  deadline=time.monotonic()+15
  while time.monotonic()<deadline:
   assert p.poll() is None,'candidate daemon exited'
   if cli(state,['status','--passive'],ok=False).returncode==0:return p
   time.sleep(.05)
  p.terminate();p.wait(timeout=10);raise AssertionError('candidate readiness timed out')
 def read_facts():
  with sqlite3.connect('file:'+str(state/'vault.sqlite3')+'?mode=ro',uri=True) as c:
   rows=c.execute('select hex(serial),state,certificate_der,issuer_der from pki_certificates order by serial').fetchall()
   audits=dict(c.execute("select event_type,count(*) from audit_events where event_type like 'pki.certificate.%' group by event_type").fetchall())
  c.close()
  return rows,audits
 key=run([openssl,'genpkey','-algorithm','EC','-pkeyopt','ec_paramgen_curve:P-256']).stdout
 # Key generators intentionally return synthetic key bytes into this process only.
 sensitive.append(key.strip())
 cert=run([openssl,'req','-new','-x509','-key','/dev/stdin','-subj','/CN=Disposable Rekey CA','-days','2','-addext','basicConstraints=critical,CA:TRUE','-addext','keyUsage=critical,keyCertSign,cRLSign'],key).stdout
 leaf=run([openssl,'genpkey','-algorithm','EC','-pkeyopt','ec_paramgen_curve:P-256']).stdout;sensitive.append(leaf.strip())
 csr=run([openssl,'req','-new','-key','/dev/stdin','-subj','/CN=client.test','-addext','subjectAltName=DNS:client.test'],leaf).stdout
 csrpath=root/'client.csr';csrpath.write_bytes(csr);csrpath.chmod(0o600)
 p=start()
 try:
  cli(state,['unlock','--password-stdin'],password)
  cred=json.loads(cli(state,['credential','add','disposable CA','--kind','pki-ca-signer','--stdin-secrets'],password+key+cert).stdout)
  issued=json.loads(cli(state,['credential','issue-client-csr',cred['id'],'--expected-version','1','--csr',csrpath,'--password-stdin'],password).stdout)
  rows,audits=read_facts();assert len(rows)==1 and rows[0][1]==1 and rows[0][2] and rows[0][3]
  pem=b''.join(issued['certificate_pem'].encode().splitlines()[1:-1]);assert base64.b64decode(pem)==rows[0][2]
  assert audits.get('pki.certificate.started')==1 and audits.get('pki.certificate.finished')==1
  first=rows[0];cli(state,['shutdown','--password-stdin'],password);assert p.wait(timeout=15)==0
  p=start();cli(state,['unlock','--password-stdin'],password)
  rows,_=read_facts();assert rows==[first],'certificate facts lost after restart'
  second=json.loads(cli(state,['credential','issue-client-csr',cred['id'],'--expected-version','1','--csr',csrpath,'--password-stdin'],password).stdout)
  assert issued['serial_hex']!=second['serial_hex'],'serial reused'
  rows,audits=read_facts();assert len(rows)==2 and first in rows and all(r[1]==1 and r[2] and r[3] for r in rows)
  assert audits.get('pki.certificate.started')==2 and audits.get('pki.certificate.finished')==2
  receipt.update({'cli_issuance':True,'returned_der_matches_persisted':True,'restart_retained_der':True,'serial_unique_after_restart':True,'started_and_terminal_audits':audits,'certificate_count':2})
  cli(state,['shutdown','--password-stdin'],password);assert p.wait(timeout=15)==0
 finally:
  if p.poll() is None:p.terminate();p.wait(timeout=15)
receipt['synthetic_state_cleaned']=True
args.output.write_text(json.dumps(receipt,indent=2)+'\n')
print(json.dumps(receipt))
