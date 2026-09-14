import hashlib,importlib.util,json,os,secrets,subprocess,sys,tempfile,time
from pathlib import Path

os.umask(0o077)
ROOT=Path('/Users/lifcc/Desktop/code/AI/tools/rekey')
OUT=ROOT/'outputs/rekey-backup-20260910'
spec=importlib.util.spec_from_file_location('qs',ROOT/'scripts/agent-quickstart.py')
qs=importlib.util.module_from_spec(spec);spec.loader.exec_module(qs)
rk=str(ROOT/'target/debug/rekey');rd=str(ROOT/'target/debug/rekeyd')
password=secrets.token_urlsafe(32);canary=secrets.token_urlsafe(32)
def call(args,body=None,expected=0):
 r=subprocess.run(args,input=body,capture_output=True)
 assert r.returncode==expected,('command exit',args[:2],r.returncode)
 return r.stdout
def invoke(state,args,proof=False):
 return json.loads(call([rk,'--state-dir',str(state)]+args,(password+'\n').encode() if proof else None))
def start(state,log):
 proc=subprocess.Popen([rd,'serve','--state-dir',str(state)],stdout=log,stderr=log)
 deadline=time.monotonic()+10
 while not (state/'runtime/admin.sock').exists():
  assert proc.poll() is None and time.monotonic()<deadline
  time.sleep(.05)
 return proc
with tempfile.TemporaryDirectory(prefix='rk-backup-drill-',dir='/tmp') as tmp:
 work=Path(tmp);source=work/'source';restored=work/'restored';archive=work/'snapshot.rkbackup';procs=[]
 with (work/'broker.log').open('w') as log:
  try:
   call([rd,'init','--state-dir',str(source),'--password-stdin'],(password+'\n').encode())
   procs.append(start(source,log));invoke(source,['unlock','--password-stdin'],True)
   cred=json.loads(call([rk,'--state-dir',str(source),'credential','add','backup-drill','--stdin-secrets'],(password+'\n'+canary+'\n').encode()))
   definition={'name':'backup-public-read','credential_id':cred['id'],'origin':'https://api.github.com','method':'GET','exact_path':'/repos/majiayu000/rekey','auth_header':'x-api-key','auth_prefix':'','timeout_ms':30000,'request_max_bytes':1024,'allowed_extra_headers':['user-agent'],'response_max_bytes':262144,'allowed_response_headers':[]}
   (work/'action.json').write_text(json.dumps(definition))
   action=invoke(source,['action','create','--file',str(work/'action.json'),'--password-stdin'],True)
   receipt=invoke(source,['backup','--output',str(archive),'--password-stdin'],True)
   digest=hashlib.sha256(archive.read_bytes()).hexdigest();assert digest==receipt['sha256_hex']
   assert archive.stat().st_mode & 0o777==0o600
   assert canary.encode() not in archive.read_bytes()
   # No-overwrite and bad-hash paths must leave the valid export intact.
   bad=subprocess.run([rk,'--state-dir',str(source),'backup','--output',str(archive),'--password-stdin'],input=(password+'\n').encode(),capture_output=True)
   assert bad.returncode!=0 and hashlib.sha256(archive.read_bytes()).hexdigest()==digest
   wrong=work/'wrong-hash'
   denied=subprocess.run([rd,'restore','--input',str(archive),'--state-dir',str(wrong),'--sha256','0'*64,'--password-stdin'],input=(password+'\n').encode(),capture_output=True)
   assert denied.returncode!=0 and not (wrong/'vault.sqlite3').exists()
   procs[0].terminate();procs[0].wait(timeout=15)
   result=call([rd,'restore','--input',str(archive),'--state-dir',str(restored),'--sha256',digest,'--password-stdin'],(password+'\n').encode())
   procs.append(start(restored,log))
   status=invoke(restored,['status']);assert status['state']=='locked' and status['sessions_active']==0
   invoke(restored,['unlock','--password-stdin'],True)
   creds=invoke(restored,['credential','list'])['credentials'];actions=invoke(restored,['action','list'])['actions']
   assert [c['id'] for c in creds]==[cred['id']] and [a['id'] for a in actions]==[action['id']]
   ref=action['id']+'@'+str(action['version'])
   session=invoke(restored,['session','create','--action',ref,'--ttl','5m','--max-uses','1','--password-stdin'],True)
   (work/'draft.json').write_text(json.dumps(qs.policy_draft(action,session,{'type':'null'})))
   call([sys.executable,str(ROOT/'scripts/sign-test-policy.py'),'policy','--key-dir',str(work/'signer'),'--snapshot',str(work/'draft.json'),'--trust',str(work/'trust.json'),'--bundle',str(work/'bundle.json')])
   for operation,file in [(['policy','trust','install'],'trust.json'),(['policy','activate'],'bundle.json')]:
    call([rk,'--state-dir',str(restored)]+operation+['--file',str(work/file),'--step-up-stdin'],(password+'\n').encode())
   output=call([rk,'--state-dir',str(restored),'execute',ref,'--capability','-','--header','user-agent: rekey-backup-drill'],(session['capability_token']+'\n').encode())
   meta,end=json.JSONDecoder().raw_decode(output.decode());assert meta['upstream_status']==200
   assert json.loads(output.decode()[end:])['full_name']=='majiayu000/rekey'
   assert canary.encode() not in output and password.encode() not in output
   evidence={'tested_at_utc':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),'source_commit':call(['git','-C',str(ROOT),'rev-parse','HEAD']).decode().strip(),'receipt':{k:v for k,v in receipt.items() if k!='output_path'},'independent_hash_match':True,'backup_mode':'0600','secret_canary_absent':True,'existing_backup_rejected_exit':bad.returncode,'bad_hash_rejected_exit':denied.returncode,'restore_status':status,'restore_started_locked':True,'credential_and_action_ids_preserved':True,'new_session_after_restore':True,'fixed_public_read_status':200,'limitation':'Anonymous read with synthetic x-api-key; no remote backup transfer or scheduled job'}
  finally:
   for proc in procs:
    if proc.poll() is None:proc.terminate();proc.wait(timeout=15)
evidence['temporary_states_and_secrets_removed']=True
(OUT/'local-receipt.json').write_text(json.dumps(evidence,indent=2)+'\n')
print('Local backup, independent hash, refusal paths, restore and fixed Action: PASS')
