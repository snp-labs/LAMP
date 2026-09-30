import argparse,datetime,hashlib,json,os,pathlib,platform,subprocess,time,tarfile
p=argparse.ArgumentParser();p.add_argument('--repo',required=True);p.add_argument('--out',required=True);a=p.parse_args()
r=pathlib.Path(a.repo).resolve();out=pathlib.Path(a.out).resolve();out.mkdir(parents=True,exist_ok=False)
def run(cmd):return subprocess.check_output(cmd,cwd=r,text=True).strip()
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
files=sorted([f for f in r.rglob('*.go') if '.git' not in f.parts]+[r/'go.mod',r/'go.sum'])
source=hashlib.sha256();entries=[]
for f in files:
 rel=str(f.relative_to(r));h=sha(f);source.update((rel+'\0'+h+'\n').encode());entries.append({'path':rel,'sha256':h})
binary=out/'zkmap_provisional';subprocess.run(['go','build','-o',str(binary),'./cmd/zkmap_provisional'],cwd=r,check=True)
m={'kind':'provisional_operation_timing_not_valid_proof','source_sha256':source.hexdigest(),'source_files':entries,'git_commit':run(['git','rev-parse','HEAD']),'git_diff':run(['git','diff','--stat']),'binary_sha256':sha(binary),'go':run(['go','version']),'host':platform.platform(),'cpu':run(['sysctl','-n','machdep.cpu.brand_string']),'memory_bytes':run(['sysctl','-n','hw.memsize']),'started_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'commands':[]}
def save(): (out/'manifest.json').write_text(json.dumps(m,indent=2)+'\n')
save()
archive=out/'measured-source.tar.gz'
with tarfile.open(archive,'w:gz') as t:
 for entry in entries:t.add(r/entry['path'],arcname=entry['path'])
(out/'source-archive.json').write_text(json.dumps({'path':archive.name,'sha256':sha(archive)},indent=2)+'\n')
for n in (128,256,512,1024):
 for mode in ('integers','fft'):
  name=f'n{n}_{mode}';raw=out/(name+'.jsonl');cmd=[str(binary),'-n',str(n),'-mode',mode,'-repetitions','10','-threads','10','-output',str(raw)]
  record={'n':n,'mode':mode,'command':cmd,'raw':raw.name,'status':'running'};m['commands'].append(record);save();print('START',name,flush=True)
  start=time.monotonic()
  with (out/(name+'.log')).open('w') as log:
   proc=subprocess.run(['/usr/bin/time','-l']+cmd,cwd=r,stdout=log,stderr=log)
  record.update(exit_code=proc.returncode,elapsed_seconds=time.monotonic()-start)
  if proc.returncode:record['status']='failed';save();raise RuntimeError(name+' failed')
  rows=[json.loads(l) for l in raw.read_text().splitlines()]
  assert len(rows)==10
  for v in rows:
   assert v['provisional_operation_only'] and not v['security_certified'] and not v['comparison_eligible_as_valid_proof']
   assert v['mu_dot_consistent'] and not v.get('error') and v['n']==n and v['interpolation_mode']==mode
   assert v['timing_breakdown']['online_seconds']>0 and v['timing_breakdown']['auxiliary_commit_seconds']>0
  record.update(status='completed_operation_attempts',rows=len(rows),raw_sha256=sha(raw));save();print('DONE',name,round(record['elapsed_seconds'],2),flush=True)
m['finished_utc']=datetime.datetime.now(datetime.timezone.utc).isoformat();save()
