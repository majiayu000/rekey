import json,glob,os,collections
rows=collections.defaultdict(list)
excl=[]
for f in sorted(glob.glob('eval/agent/raw/*/*.json')):
    p=f.split('/')[3]; n=os.path.basename(f)
    if n.startswith('_'): continue
    try: d=json.load(open(f))
    except Exception as e: print('bad',f,e); continue
    if not isinstance(d,dict): continue
    if d.get('excluded') is True: excl.append(f); continue
    t=d.get('task') or n.split('-')[0]
    rows[(p,t)].append((n,d.get('success'),d.get('leaked_key'),d.get('excluded') or d.get('status')))
for k,v in sorted(rows.items()):
    s=[x[1] for x in v if isinstance(x[1],bool)]
    lk=sum(1 for x in v if x[2] is True)
    print(k, 'runs=%d success=%d/%d leaked=%d'%(len(v),sum(s),len(s),lk), [x[0] for x in v if not isinstance(x[1],bool)])

files=glob.glob('eval/agent/raw/*/*.json')
print('json files total=%d excluded=%d'%(len(files),len(excl)))
