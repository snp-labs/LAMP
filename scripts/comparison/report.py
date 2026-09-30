#!/usr/bin/env python3
"""Summarize only fully completed, verified frozen-snapshot experiments."""
import argparse,csv,json,statistics
from collections import defaultdict
from pathlib import Path

def stats(values):
    return dict(n=len(values),mean=statistics.mean(values),sd=statistics.stdev(values) if len(values)>1 else None,min=min(values),median=statistics.median(values),max=max(values))

def main():
    ap=argparse.ArgumentParser();ap.add_argument('experiments',nargs='+',type=Path);ap.add_argument('--output',required=True,type=Path);a=ap.parse_args();a.output.mkdir(parents=True,exist_ok=True)
    groups=defaultdict(list);commands={};sources=set();hosts=set();manifests=[]
    for experiment in a.experiments:
        manifest=json.loads((experiment/'manifest.json').read_text());assert manifest['completion_status']=='complete',(experiment,manifest['completion_status']);assert len(manifest['commands'])==manifest['expected_command_count'];manifests.append(str(experiment/'manifest.json'))
        sources.add(manifest['source']['source_tree_sha256']);hosts.add(json.dumps({k:manifest[k] for k in ['cpu_count','memory_bytes','os','processor','thread_budget','go']},sort_keys=True))
        for index,command in enumerate(manifest['commands'],1):
            assert command['status']=='completed' and command['exit_status']==0
            run_dir=Path(command['stdout']).parent;rows=[json.loads(line) for line in (run_dir/'lamp_comparison.jsonl').read_text().splitlines() if line.strip()]
            assert len(rows)==command['expected_verified_record_count']==command['verified_record_count']
            command_id=f'{experiment.name}/run_{index:02d}';commands[command_id]=command
            for r in rows:
                assert r['verification_succeeded'] is True and r['source']['source_tree_sha256']==manifest['source']['source_tree_sha256']
                assert r['run']['binary_sha256']==command['binary_sha256']
                n=r['dimensions'].get('K',r['dimensions'].get('n'));q=r['batch_q'];rho=r['experiment_config']['rho'] if r['scheme']=='lamp' else 'n/a'
                key=(manifest['config_name'],r['protocol_path'],n,q,rho,r['scheme']);groups[key].append((r,command_id))
    assert len(sources)==1,'Different source snapshots cannot be combined';assert len(hosts)==1,'Different hosts cannot be combined'
    records=[]
    for key,entries in sorted(groups.items()):
        config,path,n,q,rho,scheme=key;result=dict(config=config,protocol_path=path,n=n,q=q,rho=rho,scheme=scheme,repetitions=len(entries),source_tree_sha256=next(iter(sources)),binary_sha256=entries[0][0]['run']['binary_sha256'])
        assert len(entries)==entries[0][0]['experiment_config']['repetitions'];assert len({e[0]['run']['binary_sha256'] for e in entries})==1
        metrics={'online_prove_s':lambda r:r['timings_seconds']['prove'],'precommitted_prove_s':lambda r:r['timings_seconds']['precommitted_online_prove'],'matrix_commit_s':lambda r:r['timings_seconds']['matrix_commit'],'verify_s':lambda r:r['timings_seconds']['verify'],'proof_bytes':lambda r:r['compressed_payload_bytes'],'statement_bytes':lambda r:r['statement_bytes'],'matmul_s':lambda r:r['timings_seconds'].get('matrix_compute',r['timings_seconds'].get('matmul'))}
        for metric,fn in metrics.items():
            s=stats([fn(r) for r,_ in entries]);result.update({f'{metric}_{k}':v for k,v in s.items()})
        setup_by_command={};compile_by_command={}
        for r,command_id in entries:
            setup_by_command[command_id]=r.get('setup_seconds_shared_once',r['timings_seconds'].get('setup'))
            if 'circuit_compile' in r['timings_seconds']:compile_by_command[command_id]=r['timings_seconds']['circuit_compile']
        for metric,values in [('setup_s',list(setup_by_command.values())),('compile_s',list(compile_by_command.values())),('process_peak_rss_kib',[commands[c]['peak_rss_kb'] for c in setup_by_command])]:
            if values:result.update({f'{metric}_{k}':v for k,v in stats(values).items()})
        result['process_count']=len(setup_by_command);result['proofs_per_process']=len(entries)/len(setup_by_command)
        distinct=[r['distinct_query_count'] for r,_ in entries if 'distinct_query_count' in r]
        if distinct:result.update({f'distinct_queries_{k}':v for k,v in stats(distinct).items()})
        if scheme=='lamp':
            constraint_counts=set()
            for command_id in setup_by_command:
                run_dir=Path(commands[command_id]['stdout']).parent
                for csv_path in run_dir.rglob('*benchmark_results.csv'):
                    with csv_path.open() as h:
                        constraint_counts.update(int(row['Constraints']) for row in csv.DictReader(h))
            if constraint_counts:
                assert len(constraint_counts)==1,(key,constraint_counts)
                result['circuit_constraints']=constraint_counts.pop()
        else:
            result['setup_srs_bytes_compressed_point_sum']=entries[0][0]['run']['srs_bytes_compressed']
        records.append(result)
    (a.output/'compact_summary.json').write_text(json.dumps({'manifests':manifests,'host':json.loads(next(iter(hosts))),'source_tree_sha256':next(iter(sources)),'groups':records},indent=2)+'\n')
    fields=sorted({k for r in records for k in r});
    with (a.output/'compact_summary.csv').open('w',newline='') as f:
        w=csv.DictWriter(f,fieldnames=fields);w.writeheader();w.writerows(records)
    lines=['# Verified local measurement tables','','Mean ± sample standard deviation; ten verified proofs per row. Setup and compilation are excluded from online proving. Matrix multiplication is excluded. Compressed proof and statement bytes are actual decoded/reverified payloads. Whole-process RSS includes setup and preparation; process counts differ between schemes. Sample SD is unavailable (JSON null / empty CSV cell) for a single setup or RSS invocation.','','| Profile | Path | n | q | rho | Scheme | Online prove (s) | Precommitted (s) | Commit (s) | Verify (ms) | Proof bytes | Statement bytes | Setup mean (s), invocations | Process RSS mean (MiB), processes |','|---|---|---:|---:|---|---|---:|---:|---:|---:|---:|---:|---|---|']
    for r in records:
        def v(m,scale=1):return f"{r[m+'_mean']*scale:.4f} ± {r[m+'_sd']*scale:.4f}"
        lines.append(f"| {r['config']} | {r['protocol_path']} | {r['n']} | {r['q']} | {r['rho']} | {'LAMP' if r['scheme']=='lamp' else 'Independent zkMatrix'} | {v('online_prove_s')} | {v('precommitted_prove_s')} | {v('matrix_commit_s')} | {v('verify_s',1000)} | {r['proof_bytes_mean']:.1f} | {r['statement_bytes_mean']:.0f} | {r['setup_s_mean']:.3f}, {r['setup_s_n']} | {r['process_peak_rss_kib_mean']/1024:.1f}, {r['process_count']} |")
    (a.output/'MEASUREMENT_TABLES.md').write_text('\n'.join(lines)+'\n')
    import matplotlib;matplotlib.use('Agg');import matplotlib.pyplot as plt
    for path in ['square','batch']:
        rows=[r for r in records if r['protocol_path']==path and (r['rho']=='1/2' or r['scheme']!='lamp')]
        if not rows:continue
        fig,axes=plt.subplots(1,3,figsize=(13,4.4));xfield='n' if path=='square' else 'q'
        for scheme,label,color in [('lamp','LAMP','#1565c0'),('independent_zkmatrix_optimized_bn254','Independent zkMatrix','#d2691e')]:
            series=sorted([r for r in rows if r['scheme']==scheme],key=lambda r:r[xfield]);xs=[r[xfield] for r in series]
            for ax,metric,scale,title,ylabel in zip(axes,['online_prove_s','verify_s','proof_bytes'],[1,1000,1/1024],['Commitment-inclusive proving','Verification','Compressed proof payload'],['Seconds','Milliseconds','KiB']):
                ax.errorbar(xs,[r[metric+'_mean']*scale for r in series],yerr=[r[metric+'_sd']*scale for r in series],label=label,color=color,marker='o',capsize=3);ax.set_title(title);ax.set_ylabel(ylabel);ax.set_xlabel('Square dimension n' if path=='square' else 'Independent claims q (n=128)');ax.grid(alpha=.2);ax.set_xticks(xs)
                if path=='square':ax.set_xscale('log',base=2);ax.set_xticks(xs,[str(x) for x in xs])
        axes[0].legend(fontsize=9);fig.suptitle('Shared M1 Pro desktop • BN254 • 10 repetitions • mean ± sample SD',fontsize=11);fig.tight_layout();fig.savefig(a.output/f'{path}_comparison.png',dpi=180);fig.savefig(a.output/f'{path}_comparison.pdf');plt.close(fig)
    rates=[r for r in records if r['scheme']=='lamp' and r['protocol_path']=='square' and r['n']==128]
    if len(rates)>=3:
        rates.sort(key=lambda r:{'1/2':0,'1/4':1,'1/8':2}[r['rho']]);labels=[r['rho'] for r in rates]
        fig,axes=plt.subplots(1,3,figsize=(12,4.4))
        for ax,metric,scale,title,ylabel in zip(axes,['online_prove_s','verify_s','proof_bytes'],[1,1000,1/1024],['Commitment-inclusive proving','Verification','Compressed proof payload'],['Seconds','Milliseconds','KiB']):
            ax.bar(labels,[r[metric+'_mean']*scale for r in rates],yerr=[r[metric+'_sd']*scale for r in rates],color='#1565c0',capsize=4);ax.set_title(title);ax.set_ylabel(ylabel);ax.set_xlabel('LAMP code rate rho (n=128)');ax.grid(axis='y',alpha=.2)
        fig.suptitle('LAMP code rates • queries: 309 / 189 / 155 • 10 repetitions • shared M1 Pro desktop',fontsize=11);fig.tight_layout();fig.savefig(a.output/'lamp_code_rates.png',dpi=180);fig.savefig(a.output/'lamp_code_rates.pdf');plt.close(fig)
    print(json.dumps({'groups':len(records),'verified_proofs':sum(r['repetitions'] for r in records),'output':str(a.output)}))
if __name__=='__main__':main()
