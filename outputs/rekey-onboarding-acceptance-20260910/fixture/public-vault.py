import contextlib, hashlib, http.server, importlib.util, json, os, re, secrets, socket, subprocess, sys, tempfile, threading, time, urllib.request, urllib.error
from pathlib import Path
import psycopg
ROOT=Path.cwd()
OUT=ROOT/'evidence'; OUT.mkdir(exist_ok=True)
S=importlib.util.spec_from_file_location('qs_tests',ROOT/'scripts/test-agent-quickstart.py'); T=importlib.util.module_from_spec(S); S.loader.exec_module(T)
os.umask(0o077)
VP,PP,GP=5579,5580,5581
NAME='rekey-public-20260910'
net=NAME+'-net'; vn=NAME+'-vault'; pn=NAME+'-pg'
processes=[]; containers=[]; network=False; server=None; hosts_line=None
http_client=urllib.request.build_opener(urllib.request.ProxyHandler({}))
def command(args, data=None):
 r=subprocess.run(args,input=data,capture_output=True,text=True)
 if r.returncode:raise RuntimeError('command failed: '+args[0]+' exit '+str(r.returncode))
 return r.stdout

def api(path,data=None,token=None):
 req=urllib.request.Request(f'http://127.0.0.1:{VP}/v1/'+path,data=json.dumps(data).encode() if data is not None else None,headers={'Content-Type':'application/json',**({'X-Vault-Token':token} if token else {})})
 with http_client.open(req,timeout=10) as r:
  b=r.read();return json.loads(b) if b else {}

def ready(fn, seconds=30):
 end=time.monotonic()+seconds
 while True:
  try:return fn()
  except (OSError,urllib.error.URLError,psycopg.OperationalError):
   if time.monotonic()>end:raise
   time.sleep(.3)

try:
 with tempfile.TemporaryDirectory(prefix='rkv-public-',dir='/tmp') as td:
  work=Path(td); pgpass=secrets.token_urlsafe(32); kvsecret=secrets.token_urlsafe(32)
  (work/'pg-password').write_text(pgpass)
  (work/'vault.json').write_text(json.dumps({'storage':{'inmem':{}},'listener':{'tcp':{'address':'0.0.0.0:8200','tls_disable':True}},'disable_mlock':True,'api_addr':f'http://127.0.0.1:{VP}'}))
  (work/'vault.json').chmod(0o644)  # Public listener/storage config; no secrets.
  command(['docker','network','create',net]);network=True
  command(['docker','run','-d','--rm','--name',pn,'--network',net,'--network-alias','pg','-p',f'127.0.0.1:{PP}:5432','--mount',f'type=bind,src={work}/pg-password,dst=/run/pg-password,readonly','-e','POSTGRES_PASSWORD_FILE=/run/pg-password','postgres:16-alpine']);containers.append(pn)
  command(['docker','run','-d','--name',vn,'--network',net,'-p',f'127.0.0.1:{VP}:8200','--mount',f'type=bind,src={work}/vault.json,dst=/vault/config/test.json,readonly','hashicorp/vault:1.20.3','server']);containers.append(vn)
  ready(lambda:api('sys/init'))
  init=api('sys/init',{'secret_shares':1,'secret_threshold':1}); root=init['root_token']
  api('sys/unseal',{'key':init['keys'][0]});del init
  conn=ready(lambda:psycopg.connect(host='127.0.0.1',port=PP,user='postgres',password=pgpass,dbname='postgres',connect_timeout=2));conn.close()
  api('sys/mounts/secret',{'type':'kv','options':{'version':'2'}},root)
  api('secret/data/agents/test',{'data':{'token':kvsecret}},root)
  api('sys/mounts/database',{'type':'database'},root)
  api('database/config/test',{'plugin_name':'postgresql-database-plugin','allowed_roles':['agent-test'],'connection_url':'postgresql://{{username}}:{{password}}@pg:5432/postgres?sslmode=disable','username':'postgres','password':pgpass,'username_template':'rekey_test_user'},root)
  api('database/roles/agent-test',{'db_name':'test','creation_statements':['CREATE ROLE "{{name}}" WITH LOGIN PASSWORD \'{{password}}\' VALID UNTIL \'{{expiration}}\';'],'default_ttl':'5m','max_ttl':'10m'},root)
  api('sys/policies/acl/agent-test',{'policy':'path "secret/data/agents/test" { capabilities = ["read"] }\npath "database/creds/agent-test" { capabilities = ["read"] }\npath "sys/leases/revoke" { capabilities = ["update"] }'},root)
  token=api('auth/token/create',{'policies':['agent-test'],'no_default_policy':True,'ttl':'20m'},root)['auth']['client_token']
  hits={'kv':0,'dynamic':0}
  class Gateway(http.server.BaseHTTPRequestHandler):
   def log_message(self,*args):pass
   def do_GET(self):self.handle_request()
   def do_POST(self):self.handle_request()
   def do_PUT(self):self.handle_request()
   def handle_request(self):
    if self.path.startswith('/check/'):
     kind=self.path.removeprefix('/check/'); value=self.headers.get('x-rekey-test',''); accepted=False
     if kind=='kv':accepted=secrets.compare_digest(value,kvsecret)
     elif kind=='dynamic':
      try:
       with psycopg.connect(host='127.0.0.1',port=PP,user='rekey_test_user',password=value,dbname='postgres',connect_timeout=3) as c:
        accepted=c.execute('SELECT current_user').fetchone()[0]=='rekey_test_user'
      except psycopg.OperationalError:accepted=False
     if accepted:hits[kind]+=1
     payload=json.dumps({'authenticated':accepted,'kind':kind}).encode()
     self.send_response(200 if accepted else 401);self.send_header('Content-Type','application/json');self.end_headers();self.wfile.write(payload);return
    allowed={('GET','/v1/secret/data/agents/test?version=1'),('GET','/v1/database/creds/agent-test'),('POST','/v1/sys/leases/revoke')}
    if (self.command,self.path) not in allowed:self.send_error(404);return
    data=self.rfile.read(int(self.headers.get('Content-Length',0))) if self.command in ('POST','PUT') else None
    req=urllib.request.Request(f'http://127.0.0.1:{VP}'+self.path,data=data,method=self.command,headers={'X-Vault-Token':self.headers.get('X-Vault-Token',''),'Content-Type':'application/json'})
    try:r=http_client.open(req,timeout=10)
    except urllib.error.HTTPError as e:r=e
    with r:
     self.send_response(r.status);self.send_header('Content-Type','application/json');self.end_headers();self.wfile.write(r.read())
  server=http.server.ThreadingHTTPServer(('127.0.0.1',GP),Gateway);threading.Thread(target=server.serve_forever,daemon=True).start()
  (work/'empty.yaml').write_text('')
  logfile=OUT/'cloudflared.log'
  with logfile.open('w') as log:
   tunnel=subprocess.Popen(['cloudflared','tunnel','--config',str(work/'empty.yaml'),'--no-autoupdate','--url',f'http://127.0.0.1:{GP}','--protocol','http2','--edge-ip-version','4'],stdout=log,stderr=log);processes.append(tunnel)
   deadline=time.monotonic()+60; origin=None
   while time.monotonic()<deadline:
    match=re.search(r'https://[-a-z0-9]+\.trycloudflare\.com',logfile.read_text())
    if match:origin=match.group();break
    if tunnel.poll() is not None:raise RuntimeError('cloudflared exited')
    time.sleep(.5)
   if not origin:raise RuntimeError('no quick tunnel URL')
   print('Public origin:',origin,flush=True)
   hostname=origin.split('//')[1]
   deadline=time.monotonic()+360
   while True:
    request=urllib.request.Request('https://dns.google/resolve?name='+hostname+'&type=A')
    with urllib.request.urlopen(request,timeout=15) as response:answers=json.load(response)
    ips=[row['data'] for row in answers.get('Answer',[]) if row['type']==1]
    if ips:break
    if time.monotonic()>deadline:raise RuntimeError('Public A record absent after six minutes')
    time.sleep(5)
   (OUT/'dns-evidence.json').write_text(json.dumps(answers,indent=2))
   hosts_line=ips[0]+' '+hostname+' # rekey-disposable-acceptance'
   command(['sudo','tee','-a','/etc/hosts'],'\n'+hosts_line+'\n')
   print('Verified public IPv4:',ips[0],flush=True)

   deadline=time.monotonic()+90
   while 'Registered tunnel connection' not in logfile.read_text():
    if tunnel.poll() is not None or time.monotonic()>deadline:raise RuntimeError('tunnel did not connect to edge')
    time.sleep(.5)
   for kind in ['kv','dynamic']:
    source={'credential_type':'vault-kv-v2-source-v1','origin':origin,'mount':'secret','path':'agents/test','version':1,'key':'token'} if kind=='kv' else {'credential_type':'vault-dynamic-source-v1','origin':origin,'mount':'database','role':'agent-test','key':'password'}
    action={'name':'public-'+kind,'credential_id':'00000000-0000-0000-0000-000000000000','origin':origin,'method':'POST','exact_path':'/check/'+kind,'auth_header':'x-rekey-test','auth_prefix':'','timeout_ms':30000,'request_max_bytes':65536,'allowed_extra_headers':[],'response_max_bytes':262144,'allowed_response_headers':['content-type']}
    for name,obj in [('source',source),('action',action),('schema',{'type':'object','additionalProperties':False})]:(work/(name+'.json')).write_text(json.dumps(obj))
    (work/'body.json').write_text('{}')
    transcript=T.run_terminal([sys.executable,str(ROOT/'scripts/dogfood-vault.py'),'--bin-dir',str(ROOT/'target/debug'),'--source',str(work/'source.json'),'--action',str(work/'action.json'),'--schema',str(work/'schema.json'),'--body-file',str(work/'body.json'),'--expected-status','200','--receipt',str(OUT/('vault-'+kind+'-receipt.json'))],[('Disposable Vault token: ',token)])
    assert token not in transcript and pgpass not in transcript and kvsecret not in transcript
    assert hits[kind]==1
    print(kind,'authenticated PASS',flush=True)
   # Exercise the actual Agent wrapper with a failed credential, then an
   # operator-only rotation and one explicit retry against the public target.
   state_dir=work/'agent-state'; proof=secrets.token_urlsafe(32)
   rk=str(ROOT/'target/debug/rekey'); rd=str(ROOT/'target/debug/rekeyd')
   base=[rk,'--state-dir',str(state_dir)]
   command([rd,'init','--state-dir',str(state_dir),'--password-stdin'],proof+'\n')
   with (work/'agent-broker.log').open('w') as broker_log:
    broker=subprocess.Popen([rd,'serve','--state-dir',str(state_dir)],stdout=broker_log,stderr=broker_log);processes.append(broker)
    deadline=time.monotonic()+10
    while not (state_dir/'runtime/admin.sock').exists():
     if time.monotonic()>deadline:raise RuntimeError('Agent broker readiness timeout')
     time.sleep(.05)
    command(base+['unlock','--password-stdin'],proof+'\n')
    cred=json.loads(command(base+['credential','add','repair-test','--stdin-secrets'],proof+'\n'+secrets.token_urlsafe(32)+'\n'))
    action['credential_id']=cred['id'];action['name']='public-agent-repair';action['exact_path']='/check/kv'
    (work/'repair-action.json').write_text(json.dumps(action))
    registered=json.loads(command(base+['action','create','--file',str(work/'repair-action.json'),'--password-stdin'],proof+'\n'))
    handoff=work/'agent-handoff'
    prompts=T.run_terminal([sys.executable,str(ROOT/'scripts/agent-quickstart.py'),'prepare','--rekey',rk,'--state-dir',str(state_dir),'--output',str(handoff),'--action',str(registered['id'])+'@'+str(registered['version']),'--schema',str(work/'schema.json')],[('Vault password (step-up): ',proof)])
    command([sys.executable,str(ROOT/'scripts/sign-test-policy.py'),'policy','--key-dir',str(work/'signer'),'--snapshot',str(handoff/'policy-draft.json'),'--trust',str(work/'trust.json'),'--bundle',str(work/'bundle.json')])
    for operation,filename in [(['policy','trust','install'],'trust.json'),(['policy','activate'],'bundle.json')]:
     command(base+operation+['--file',str(work/filename),'--step-up-stdin'],proof+'\n')
    invoke=[sys.executable,str(ROOT/'scripts/agent-quickstart.py'),'execute','--handoff',str(handoff),'--body-file',str(work/'body.json')]
    failed=subprocess.run(invoke,capture_output=True)
    assert failed.returncode==1 and json.JSONDecoder().raw_decode(failed.stdout.decode())[0]['upstream_status']==401
    assert hits['kv']==1
    prompts+=T.run_terminal(base+['credential','rotate',cred['id']],[('Vault password (step-up): ',proof),('New credential value: ',kvsecret)])
    repaired=subprocess.run(invoke,capture_output=True)
    assert repaired.returncode==0 and json.JSONDecoder().raw_decode(repaired.stdout.decode())[0]['upstream_status']==200
    assert hits['kv']==2
    for secret in [proof,kvsecret,token]:
     assert secret not in prompts and secret.encode() not in failed.stdout+failed.stderr+repaired.stdout+repaired.stderr
    command(base+['shutdown','--password-stdin'],proof+'\n');broker.wait(timeout=10);processes.remove(broker)
    (OUT/'agent-public-repair-receipt.json').write_text(json.dumps({'origin':origin,'first_http_status':401,'first_exit':1,'operator_rotation':'hidden TTY; no echo','explicit_retry_http_status':200,'explicit_retry_exit':0,'automatic_retry':False,'secrets_absent_from_outputs':True},indent=2))
    print('Agent wrapper public 401 -> hidden TTY rotate -> explicit 200: PASS',flush=True)
   with psycopg.connect(host='127.0.0.1',port=PP,user='postgres',password=pgpass,dbname='postgres') as c:
    assert c.execute("SELECT count(*) FROM pg_roles WHERE rolname='rekey_test_user'").fetchone()[0]==0
   print('Dynamic database role revoked: PASS',flush=True)
   api('auth/token/revoke',{'token':token},root)
finally:
 errors=[]
 if hosts_line:
  cleanup="import pathlib,sys; p=pathlib.Path('/etc/hosts'); line=sys.stdin.read().strip(); p.write_text(''.join(x for x in p.read_text().splitlines(keepends=True) if x.strip()!=line))"
  try:command(['sudo','python3','-c',cleanup],hosts_line)
  except Exception as error:errors.append('hosts: '+type(error).__name__)
 for process in processes:
  try:
   process.terminate()
   try:process.wait(timeout=10)
   except subprocess.TimeoutExpired:process.kill();process.wait(timeout=10)
  except Exception as error:errors.append('process: '+type(error).__name__)
 if server:
  try:server.shutdown();server.server_close()
  except Exception as error:errors.append('gateway: '+type(error).__name__)
 for name in reversed(containers):
  if name==vn:
   result=subprocess.run(['docker','logs',name],capture_output=True,text=True)
   (OUT/'vault-server.log').write_text(result.stdout+result.stderr)
  try:command(['docker','rm','-fv',name])
  except Exception as error:errors.append(name+': '+type(error).__name__)
 if network:
  try:command(['docker','network','rm',net])
  except Exception as error:errors.append('network: '+type(error).__name__)
 if errors:raise RuntimeError('Cleanup failed: '+', '.join(errors))
 print('Temporary containers, anonymous volumes, network, tunnel and secrets cleaned',flush=True)
