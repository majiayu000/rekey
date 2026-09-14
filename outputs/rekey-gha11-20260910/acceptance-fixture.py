import base64, hashlib, hmac, importlib.util, json, os, secrets, subprocess, sys, time, urllib.request
from pathlib import Path

os.umask(0o077)
ROOT=Path('/Users/lifcc/Desktop/code/AI/tools/rekey')
OUT=Path('/tmp/rekey-gha11-20260910')
APP=json.loads((OUT/'github-app-private.json').read_text())
def run(args,body=None):
 r=subprocess.run(args,input=body,capture_output=True)
 if r.returncode: raise RuntimeError('command failed: '+str(args[:3])+' exit '+str(r.returncode))
 return r.stdout
def api(path,method='GET'):
 def b64(v): return base64.urlsafe_b64encode(v).rstrip(b'=')
 unsigned=b64(b'{"alg":"RS256","typ":"JWT"}')+b'.'+b64(json.dumps({'iat':int(time.time())-60,'exp':int(time.time())+300,'iss':APP['client_id']}).encode())
 key=OUT/'jwt.pem';key.write_text(APP['pem'])
 try: jwt=unsigned+b'.'+b64(run(['openssl','dgst','-sha256','-sign',str(key)],unsigned))
 finally:key.unlink()
 req=urllib.request.Request('https://api.github.com'+path,method=method,headers={'Authorization':'Bearer '+jwt.decode(),'User-Agent':'rekey-gha11-test','Accept':'application/vnd.github+json'})
 with urllib.request.urlopen(req,timeout=30) as r: body=r.read()
 return json.loads(body) if body else None
def save(name,data): (OUT/name).write_text(json.dumps(data,indent=2))
def delivery_bytes(d):
 headers={k.lower():v for k,v in d['request']['headers'].items()}
 sig=headers['x-hub-signature-256']
 payload=d['request']['payload']
 candidates=[]
 if isinstance(payload,str):candidates.append(payload.encode())
 else:
  for ascii_mode in (False,True):
   for indent in (None,2,4):
    for separators in (None,(',',':'),(',',': ')):
     text=json.dumps(payload,ensure_ascii=ascii_mode,indent=indent,separators=separators)
     for suffix in ('','\n'):candidates.append((text+suffix).encode())
 for raw in candidates:
  expected='sha256='+hmac.new(APP['webhook_secret'].encode(),raw,hashlib.sha256).hexdigest()
  if hmac.compare_digest(expected,sig):return raw,headers
 raise RuntimeError('Cannot recover exact GitHub-signed payload bytes')

STATE=OUT/'state'
BASE=[str(ROOT/'target/debug/rekey'),'--state-dir',str(STATE)]
def admin(args):return json.loads(run(BASE+args+['--password-stdin'],(OUT/'proof').read_bytes()+b'\n'))
def execute(name,expected,body=False):
 ctx=json.loads((OUT/'context.json').read_text())
 before=json.loads(run(BASE+['audit','list','--limit','1']))['events'][0]['sequence']
 handoff=OUT/'handoff'
 config=json.loads((handoff/'agent.json').read_text());config['action']=ctx['refs'][name];save('handoff/agent.json',config)
 args=[sys.executable,str(ROOT/'scripts/agent-quickstart.py'),'execute','--handoff',str(handoff)]
 if body:args+=['--body-file',str(OUT/'issue.json')]
 r=subprocess.run(args,capture_output=True)
 assert r.returncode==expected,('execute exit',name,r.returncode)
 events=json.loads(run(BASE+['audit','list','--limit','100']))['events']
 chain=sorted([e for e in events if e['sequence']>before],key=lambda e:e['sequence'])
 session=json.loads((handoff/'session.json').read_text())
 assert len({e['request_id'] for e in chain})==1 and chain[0]['request_id']
 assert all(e['session_id']==session['session_id'] and e['action_id']==ctx['refs'][name].split('@')[0] for e in chain)
 if expected:
  assert [e['event_type'] for e in chain]==['execution.started','execution.blocked']
  assert chain[-1]['reason_code']=='github-profile-mismatch' and chain[-1]['outcome']=='denied'
 else:
  assert [e['event_type'] for e in chain]==['execution.started','connector.github.authorized','connector.github.token_revoked','execution.finished']
  assert all(e['outcome']=='success' for e in chain)
  assert chain[1]['reason_code'].split('binding-sha256=')[1]==chain[2]['reason_code'].split('binding-sha256=')[1]
 save('last-execution-chain.json',chain)
 (OUT/('execute-'+name+'.out')).write_bytes(r.stdout)
 if expected:
  assert b'REQUEST_DENIED' in r.stderr, r.stderr[:120]
  return {'exit':r.returncode,'code':'REQUEST_DENIED'}
 text=r.stdout.decode();m,end=json.JSONDecoder().raw_decode(text)
 return {'status':m['upstream_status'],'body':json.loads(text[end:])}

def initialize():
 spec=importlib.util.spec_from_file_location('qt',ROOT/'scripts/test-agent-quickstart.py');t=importlib.util.module_from_spec(spec);spec.loader.exec_module(t)
 repos=[json.loads(run(['gh','api','repos/majiayu000/'+name])) for name in ['rekey-acceptance-20260910-ephemeral','rekey-gha11-b-20260910']]
 inst=api('/app/installations');assert len(inst)==1 and inst[0]['repository_selection']=='selected'
 der=run(['openssl','rsa','-traditional','-outform','DER'],APP['pem'].encode())
 profile={'credential_type':'github-app-installation-v2','client_id':APP['client_id'],'app_id':APP['id'],'installation_id':inst[0]['id'],'repositories':[{'id':repos[0]['id'],'owner':'majiayu000','name':repos[0]['name']}],'permissions':{'metadata':'read','issues':'write'},'webhook_secret':APP['webhook_secret'],'private_key_pkcs1_der_base64':base64.b64encode(der).decode()}
 save('profile.json',profile);(OUT/'proof').write_text(secrets.token_urlsafe(32))
 rd=str(ROOT/'target/debug/rekeyd');run([rd,'init','--state-dir',str(STATE),'--password-stdin'],(OUT/'proof').read_bytes()+b'\n')
 with (OUT/'broker.log').open('w') as log:
  broker=subprocess.Popen([rd,'serve','--state-dir',str(STATE)],stdout=log,stderr=log,start_new_session=True)
 (OUT/'broker.pid').write_text(str(broker.pid))
 deadline=time.monotonic()+15
 while not (STATE/'runtime/admin.sock').exists():
  assert time.monotonic()<deadline,'startup timeout';time.sleep(.1)
 admin(['unlock'])
 cred=admin(['credential','add-github-app','gha11-test','--file',str(OUT/'profile.json')])
 actions=[]
 for name,method,path in [('list','GET','/installation/repositories'),('issue-b','POST',f"/repos/majiayu000/{repos[1]['name']}/issues")]:
  definition={'name':name,'credential_id':cred['id'],'origin':'https://api.github.com','method':method,'exact_path':path,'auth_header':'authorization','auth_prefix':'Bearer ','timeout_ms':30000,'request_max_bytes':65536,'allowed_extra_headers':['accept','user-agent','x-github-api-version'],'response_max_bytes':262144,'allowed_response_headers':['content-type']}
  save('action.json',definition);actions.append(admin(['action','create','--file',str(OUT/'action.json')]))
 refs=[str(a['id'])+'@'+str(a['version']) for a in actions]
 session=admin(['session','create','--action',refs[0],'--action',refs[1],'--ttl','15m','--max-uses','12'])
 draft=t.APP.policy_draft(actions[0],session,{'type':'null'})
 second=t.APP.policy_draft(actions[1],session,{'type':'object','required':['title'],'properties':{'title':{'type':'string'},'body':{'type':'string'}},'additionalProperties':False})
 draft['bindings']+=second['bindings'];draft['rules']+=second['rules'];save('draft.json',draft)
 run([sys.executable,str(ROOT/'scripts/sign-test-policy.py'),'policy','--key-dir',str(OUT/'signer'),'--snapshot',str(OUT/'draft.json'),'--trust',str(OUT/'trust.json'),'--bundle',str(OUT/'bundle.json')])
 for args,file in [(['policy','trust','install'],'trust.json'),(['policy','activate'],'bundle.json')]:run(BASE+args+['--file',str(OUT/file),'--step-up-stdin'],(OUT/'proof').read_bytes()+b'\n')
 (OUT/'handoff').mkdir(mode=0o700);t.APP.write_new(OUT/'handoff/session.json',session)
 t.APP.write_new(OUT/'handoff/agent.json',{'rekey':BASE[0],'agent_socket':str(STATE/'runtime/agent.sock'),'action':refs[0],'headers':[]})
 save('context.json',{'installation_id':inst[0]['id'],'credential_id':cred['id'],'repos':[{'id':r['id'],'name':r['name']} for r in repos],'refs':dict(zip(['list','issue-b'],refs))})
 save('issue.json',{'title':'Disposable GHA-11 scope acceptance','body':'Fixed Action acceptance. Test repository will be deleted.'})
 result=execute('list',0);assert result['status']==200 and result['body']['total_count']==1
 save('initial-list.json',result)
 print('Initial real App list: 200, exact repository A')

def version(ctx):
 rows=json.loads(run(BASE+['credential','list']))['credentials']
 return next(c['current_version'] for c in rows if c['id']==ctx['credential_id'])
def apply_event(action):
 ctx=json.loads((OUT/'context.json').read_text());expected=version(ctx)
 deliveries=api('/app/hook/deliveries')
 matches=[d for d in deliveries if d['event']=='installation_repositories' and d['action']==action]
 assert len(matches)==1,('expected one delivery',action,len(matches))
 d=api('/app/hook/deliveries/'+str(matches[0]['id']));raw,headers=delivery_bytes(d)
 assert json.loads(raw)['installation']['id']==ctx['installation_id']
 path=OUT/(action+'-payload.json');path.write_bytes(raw)
 args=BASE+['credential','apply-github-webhook',ctx['credential_id'],'--expected-version',str(expected),'--event',headers['x-github-event'],'--delivery',headers['x-github-delivery'],'--signature',headers['x-hub-signature-256'],'--file',str(path),'--password-stdin']
 proof=(OUT/'proof').read_bytes()+b'\n'
 if action=='added':
  path.write_bytes(raw+b' ');bad=subprocess.run(args,input=proof,capture_output=True)
  assert bad.returncode==2 and version(ctx)==expected,'tamper must not mutate'
  path.write_bytes(raw)
 result=json.loads(run(args,proof));assert result['current_version']==expected+1
 replay=subprocess.run(args,input=proof,capture_output=True)
 assert replay.returncode==2 and version(ctx)==expected+1,'replay must not mutate'
 listed=execute('list',0);wanted=2 if action=='added' else 1
 assert listed['status']==200 and listed['body']['total_count']==wanted
 actual={r['id'] for r in listed['body']['repositories']};expect={r['id'] for r in ctx['repos'][:wanted]};assert actual==expect
 if action=='added':
  result_issue=execute('issue-b',0,True);assert result_issue['status']==201
  save('created-issue.json',result_issue)
 else:
  result_issue=execute('issue-b',4,True)
 save(action+'-receipt.json',{'delivery_id':d['id'],'guid':headers['x-github-delivery'],'event':d['event'],'action':action,'transport_status':d['status_code'],'retrieval':'GitHub App delivery REST API; exact bytes verified against GitHub HMAC','payload_sha256':hashlib.sha256(raw).hexdigest(),'payload_bytes':len(raw),'signature':headers['x-hub-signature-256'],'before_version':expected,'after_version':expected+1,'tampered_rejected':action=='added','stale_replay_exit':replay.returncode,'list':listed,'issue':result_issue})
 save('audit.json',json.loads(run(BASE+['audit','list','--limit','100'])))
 print(action+': real signature, version, replay, exact repository list and Action checks PASS')

if sys.argv[1]=='inspect':
 installs=api('/app/installations');save('installations.json',installs)
 deliveries=api('/app/hook/deliveries');save('deliveries.json',deliveries)
 print({'app_id':APP['id'],'installation_ids':[v['id'] for v in installs],'deliveries':[(d['id'],d['event'],d['action']) for d in deliveries]})
elif sys.argv[1]=='probe-delivery':
 d=api('/app/hook/deliveries/'+str(api('/app/hook/deliveries')[0]['id']))
 raw,h=delivery_bytes(d)
 print({'github_signature_matches':True,'bytes':len(raw),'event':h['x-github-event'],'delivery_status':d['status_code']})
elif sys.argv[1]=='init':initialize()
elif sys.argv[1] in ('added','removed'):apply_event(sys.argv[1])

elif sys.argv[1]=='initial-list':
 result=execute('list',0);assert result['status']==200 and result['body']['total_count']==1
 save('initial-list.json',result);print('Initial list 200 exact A: PASS')

elif sys.argv[1]=='verify':
 ctx=json.loads((OUT/'context.json').read_text())
 initial=json.loads((OUT/'initial-list.json').read_text())
 assert [r['id'] for r in initial['body']['repositories']]==[ctx['repos'][0]['id']]
 events=json.loads(run(BASE+['audit','list','--limit','100']))['events']
 assert len(events)<100
 session=json.loads((OUT/'handoff/session.json').read_text())
 chains=[]
 for end in [e for e in events if e['event_type']=='execution.finished']:
  chain=sorted([e for e in events if e['request_id']==end['request_id']],key=lambda e:e['sequence'])
  assert [e['event_type'] for e in chain]==['execution.started','connector.github.authorized','connector.github.token_revoked','execution.finished']
  assert all(e['outcome']=='success' and e['session_id']==session['session_id'] for e in chain)
  assert chain[1]['reason_code'].split('binding-sha256=')[1]==chain[2]['reason_code'].split('binding-sha256=')[1]
  chains.append(chain)
 assert len(chains)==4
 blocked=json.loads((OUT/'last-execution-chain.json').read_text())
 assert blocked[-1]['action_id']==ctx['refs']['issue-b'].split('@')[0] and blocked[-1]['reason_code']=='github-profile-mismatch'
 assert [e['event_type'] for e in blocked]==['execution.started','execution.blocked']
 assert all(e['session_id']==session['session_id'] for e in blocked)
 added=json.loads((OUT/'added-receipt.json').read_text());removed=json.loads((OUT/'removed-receipt.json').read_text())
 for action in ['added','removed']:
  p=json.loads((OUT/(action+'-payload.json')).read_text())
  assert p['installation']['id']==ctx['installation_id']
  assert [r['id'] for r in p['repositories_'+action]]==[ctx['repos'][1]['id']]
 save('final-receipt.json',{'app_id':APP['id'],'installation_id':ctx['installation_id'],'session_id':session['session_id'],'repositories':ctx['repos'],'initial':initial,'added':added,'removed':removed,'success_chains':chains,'removed_action_chain':blocked,'same_capability':True,'limitations':['GitHub delivery REST API retrieval and Admin apply; webhook HTTP target returned 403','No new provider private-key rotation claim; earlier two-key acceptance is separate'],'initial_fixture_correction':'Removed unsupported extra headers; two early list attempts correctly failed github-profile-mismatch before corrected successful run'})
 receipt=(OUT/'final-receipt.json').read_bytes()
 for secret in [APP['pem'],APP['webhook_secret'],session['capability_token'],(OUT/'proof').read_text()]:assert secret.encode() not in receipt
 print('All real event, exact scope, same session, per-request audit and secret exclusion assertions PASS')

elif sys.argv[1]=='uninstall':
 ctx=json.loads((OUT/'context.json').read_text());api('/app/installations/'+str(ctx['installation_id']),'DELETE');assert api('/app/installations')==[];print('Temporary installation removed: PASS')
