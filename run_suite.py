#!/usr/bin/env python3
"""Stream WAF payload manifests and execute them through k6 in configurable batches."""
from __future__ import annotations
import argparse, gzip, hashlib, json, os, re, shutil, signal, subprocess, sys, tempfile, uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

def utc_now(): return datetime.now(timezone.utc).isoformat()
def append_jsonl(path, record):
    with path.open('a', encoding='utf-8') as h: h.write(json.dumps(record, ensure_ascii=False, separators=(',', ':'))+'\n'); h.flush()
def atomic_write_json(path, value):
    tmp=path.with_suffix(path.suffix+'.tmp'); tmp.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding='utf-8'); tmp.replace(path)
def archive_manifest(source,dest):
    tmp=dest.with_suffix(dest.suffix+'.tmp')
    with source.open('rb') as i,tmp.open('wb') as raw:
        with gzip.GzipFile(fileobj=raw,mode='wb',compresslevel=6,mtime=0) as o: shutil.copyfileobj(i,o)
    tmp.replace(dest)
def file_sha256(path):
    d=hashlib.sha256()
    with path.open('rb') as h:
        for chunk in iter(lambda:h.read(1024*1024),b''): d.update(chunk)
    return d.hexdigest()
def parse_args():
    p=argparse.ArgumentParser(description='Run streamed WAF payload cases with k6')
    p.add_argument('--target', required=True); p.add_argument('--payload-file', default='payloads.jsonl'); p.add_argument('--k6-script', default='k6_run_payloads.js')
    p.add_argument('--rps', type=int, default=10); p.add_argument('--duration', default='30s'); p.add_argument('--cooldown', type=float, default=5.0)
    p.add_argument('--graceful-stop', default='1s'); p.add_argument('--threshold-mode', choices=['disabled','strict'], default='disabled')
    p.add_argument('--batch-size', type=int, default=25, help='Cases per k6 process; use 1 for isolated mode')
    p.add_argument('--batch-max-duration', default='24h')
    p.add_argument('--start-index', type=int, default=0); p.add_argument('--limit', type=int); p.add_argument('--case-id')
    p.add_argument('--format', dest='formats', action='append'); p.add_argument('--structure', dest='structures', action='append')
    p.add_argument('--value-encoding', dest='value_encodings', action='append'); p.add_argument('--charset', dest='charsets', action='append')
    p.add_argument('--compression', dest='compressions', action='append'); p.add_argument('--validity', dest='validities', action='append', choices=['valid','invalid','invalid-compression'])
    p.add_argument('--list', action='store_true'); p.add_argument('--results-dir', default='results'); p.add_argument('--preallocated-vus', type=int); p.add_argument('--max-vus', type=int)
    p.add_argument('--terminate-timeout', type=float, default=10.0)
    return p.parse_args()
def detect_manifest_format(path):
    with path.open('r',encoding='utf-8') as h:
        while True:
            c=h.read(1)
            if not c: raise ValueError('payload manifest is empty')
            if not c.isspace(): return 'json' if c=='[' else 'jsonl'
def iter_manifest(path, fmt):
    if fmt=='jsonl':
        with path.open('r',encoding='utf-8') as h:
            idx=0
            for ln,line in enumerate(h,1):
                if not line.strip(): continue
                try: case=json.loads(line)
                except json.JSONDecodeError as e: raise ValueError(f'invalid JSONL at line {ln}: {e}') from e
                if not isinstance(case,dict): raise ValueError(f'JSONL line {ln} is not an object')
                yield idx,case; idx+=1
    else:
        data=json.loads(path.read_text(encoding='utf-8'))
        if not isinstance(data,list): raise ValueError('legacy JSON manifest must be an array')
        for idx,case in enumerate(data):
            if not isinstance(case,dict): raise ValueError(f'JSON array item {idx} is not an object')
            yield idx,case
def matches(v, allowed): return allowed is None or str(v) in allowed
def case_matches(case,args):
    if args.case_id and case.get('id')!=args.case_id: return False
    m=case.get('metadata') or {}
    return all((matches(m.get('format'),args.formats),matches(m.get('structure'),args.structures),matches(m.get('value_encoding'),args.value_encodings),matches(m.get('charset'),args.charsets),matches(m.get('compression'),args.compressions),matches(m.get('validity'),args.validities)))
def selected_cases(path,fmt,args):
    count=0
    for idx,case in iter_manifest(path,fmt):
        if idx<args.start_index or not case_matches(case,args): continue
        yield idx,case; count+=1
        if args.limit is not None and count>=args.limit: return
def batched(iterator,size):
    batch=[]
    for item in iterator:
        batch.append(item)
        if len(batch)>=size: yield batch; batch=[]
    if batch: yield batch
def terminate_process(proc,timeout):
    if proc.poll() is not None:return
    proc.send_signal(signal.SIGINT)
    try: proc.wait(timeout=max(.1,timeout))
    except subprocess.TimeoutExpired:
        proc.terminate()
        try: proc.wait(timeout=3)
        except subprocess.TimeoutExpired: proc.kill(); proc.wait()
def parse_k6_event(line):
    line=line.strip(); candidates=[line]
    m=re.search(r'msg="(\{.*\})"(?:\s|$)',line)
    if m:
        try: candidates.append(bytes(m.group(1),'utf-8').decode('unicode_escape'))
        except UnicodeDecodeError: pass
    a=line.find('{'); b=line.rfind('}')
    if a>=0 and b>a: candidates.append(line[a:b+1])
    for text in candidates:
        try:
            obj=json.loads(text)
            if isinstance(obj,dict) and isinstance(obj.get('event'),str): return obj
        except json.JSONDecodeError: pass
    return None
def metric_lookup(summary,metric,field):
    node=(summary.get('metrics') or {}).get(metric) if isinstance(summary,dict) else None
    if not isinstance(node,dict): return None
    for container in (node.get('values'),node):
        if isinstance(container,dict):
            value=container.get(field)
            if isinstance(value,(int,float)): return float(value)
    return None
def compact_summary(path):
    if not path.exists(): return {}
    try: s=json.loads(path.read_text(encoding='utf-8'))
    except (OSError,json.JSONDecodeError): return {}
    return {'http_reqs':metric_lookup(s,'http_reqs','count'),'http_req_failed_rate':metric_lookup(s,'http_req_failed','rate'),'http_req_duration_p95_ms':metric_lookup(s,'http_req_duration','p(95)'),'http_req_duration_max_ms':metric_lookup(s,'http_req_duration','max'),'dropped_iterations':metric_lookup(s,'dropped_iterations','count'),'checks_rate':metric_lookup(s,'checks','rate'),'data_sent_bytes':metric_lookup(s,'data_sent','count'),'data_received_bytes':metric_lookup(s,'data_received','count')}
def main():
    a=parse_args()
    if a.start_index<0 or (a.limit is not None and a.limit<1) or a.batch_size<1 or a.rps<1 or a.cooldown<0:
        print('ERROR: invalid numeric option',file=sys.stderr); return 2
    payload=Path(a.payload_file).resolve(); script=Path(a.k6_script).resolve()
    if not payload.is_file() or not script.is_file(): print('ERROR: payload file or k6 script does not exist',file=sys.stderr); return 2
    try: fmt=detect_manifest_format(payload)
    except ValueError as e: print(f'ERROR: {e}',file=sys.stderr); return 2
    if a.list:
        n=0
        try:
            for idx,case in selected_cases(payload,fmt,a): print(json.dumps({'index':idx,'case_id':case.get('id'),'wire_body_size':case.get('wire_body_size'),'metadata':case.get('metadata')},ensure_ascii=False)); n+=1
        except ValueError as e: print(f'ERROR: {e}',file=sys.stderr); return 2
        print(f'Matched cases: {n}',file=sys.stderr); return 0 if n else 3
    if shutil.which('k6') is None: print('ERROR: k6 executable was not found in PATH',file=sys.stderr); return 2
    run_id=f"{datetime.now(timezone.utc):%Y%m%dT%H%M%SZ}-{uuid.uuid4().hex[:8]}"; results=Path(a.results_dir)/run_id; results.mkdir(parents=True)
    journal=results/'run.jsonl'; active=results/'active_case.json'; archive=results/('payloads.jsonl.gz' if fmt=='jsonl' else 'payloads.json.gz'); archive_manifest(payload,archive)
    config={'run_id':run_id,'target':a.target,'rps':a.rps,'duration':a.duration,'cooldown':a.cooldown,'graceful_stop':a.graceful_stop,'threshold_mode':a.threshold_mode,'batch_size':a.batch_size,'batch_max_duration':a.batch_max_duration,'start_index':a.start_index,'limit':a.limit,'case_id':a.case_id,'filters':{'format':a.formats,'structure':a.structures,'value_encoding':a.value_encodings,'charset':a.charsets,'compression':a.compressions,'validity':a.validities},'payload_file':str(payload),'payload_manifest_format':fmt,'archived_payload_file':str(archive),'payload_manifest_sha256':file_sha256(payload),'k6_script':str(script),'storage_mode':'compact-streaming-batched'}
    atomic_write_json(results/'run_config.json',config); append_jsonl(journal,{'event':'RUN_START','timestamp':utc_now(),**config})
    completed=0; nonzero=0; proc=None; current=None; temp_paths=None
    try:
        with tempfile.TemporaryDirectory(prefix=f'waf-payload-{run_id}-') as td:
            t=Path(td)
            for batch_no,batch in enumerate(batched(selected_cases(payload,fmt,a),a.batch_size),1):
                payloads=[]
                for idx,case in batch:
                    c=dict(case); c['_source_index']=idx; payloads.append(c)
                case_file=t/'batch.json'; atomic_write_json(case_file,payloads[0] if len(payloads)==1 else payloads)
                summary=t/'summary.json'; stdout_log=t/'stdout.log'; stderr_log=t/'stderr.log'; temp_paths=(summary,stdout_log,stderr_log)
                for p in temp_paths:p.unlink(missing_ok=True)
                env=os.environ.copy(); env.update({'TARGET_URL':a.target,'CASE_FILE':str(case_file),'CASE_INDEX':str(batch[0][0]),'RUN_ID':run_id,'RPS':str(a.rps),'DURATION':a.duration,'COOLDOWN':str(a.cooldown),'GRACEFUL_STOP':a.graceful_stop,'THRESHOLD_MODE':a.threshold_mode,'BATCH_MAX_DURATION':a.batch_max_duration})
                if a.preallocated_vus is not None: env['PREALLOCATED_VUS']=str(a.preallocated_vus)
                if a.max_vus is not None: env['MAX_VUS']=str(a.max_vus)
                append_jsonl(journal,{'event':'BATCH_START','timestamp':utc_now(),'run_id':run_id,'batch':batch_no,'cases':len(batch),'first_index':batch[0][0],'last_index':batch[-1][0]})
                with stdout_log.open('w',encoding='utf-8') as out, stderr_log.open('w',encoding='utf-8') as err:
                    proc=subprocess.Popen(['k6','run','--summary-export',str(summary),str(script)],env=env,stdout=subprocess.PIPE,stderr=err,text=True,bufsize=1)
                    assert proc.stdout is not None
                    for line in proc.stdout:
                        out.write(line); out.flush(); event=parse_k6_event(line)
                        if not event: continue
                        et=event.get('event')
                        if et=='CASE_START':
                            current=event
                            rec={'event':'CASE_START','timestamp':utc_now(),'run_id':run_id,'index':event.get('payload_index'),'case_id':event.get('payload_id'),'sha256':event.get('sha256'),'wire_body_size':event.get('wire_body_size'),'metadata':event.get('metadata')}
                            atomic_write_json(active,{'run_id':run_id,'active':rec,'completed':False}); append_jsonl(journal,rec); print(json.dumps(rec,ensure_ascii=False),flush=True)
                        elif et=='CASE_END':
                            rec={'event':'CASE_END','timestamp':utc_now(),'run_id':run_id,'index':event.get('payload_index'),'case_id':event.get('payload_id'),'requests':event.get('requests'),'elapsed_seconds':event.get('elapsed_seconds')}
                            append_jsonl(journal,rec); print(json.dumps(rec,ensure_ascii=False),flush=True); completed+=1; current=None; atomic_write_json(active,{'run_id':run_id,'active':None,'last_completed':rec,'completed':False})
                    code=proc.wait(); proc=None
                nonzero+=int(code!=0); metrics=compact_summary(summary)
                append_jsonl(journal,{'event':'BATCH_END','timestamp':utc_now(),'run_id':run_id,'batch':batch_no,'exit_code':code,'metrics':metrics})
                if code!=0: print(json.dumps({'event':'BATCH_END','batch':batch_no,'exit_code':code,'metrics':metrics}),flush=True)
    except KeyboardInterrupt:
        if proc is not None: terminate_process(proc,a.terminate_timeout)
        rec={'event':'RUN_INTERRUPTED','timestamp':utc_now(),'run_id':run_id,'reason':'SIGINT','active_index':current.get('payload_index') if current else None,'active_case_id':current.get('payload_id') if current else None}
        append_jsonl(journal,rec); atomic_write_json(active,{'run_id':run_id,'active':current,'interrupted_at':rec['timestamp'],'completed':False})
        if temp_paths:
            intr=results/'interrupted'; intr.mkdir(exist_ok=True)
            for src,name in zip(temp_paths,('k6-summary.json','stdout.log','stderr.log')):
                if src.exists(): shutil.copy2(src,intr/name)
        print(json.dumps(rec,ensure_ascii=False),flush=True); print(f'Interrupted results: {results}'); return 130
    except (ValueError,OSError) as e:
        append_jsonl(journal,{'event':'RUN_ERROR','timestamp':utc_now(),'run_id':run_id,'error':str(e)}); print(f'ERROR: {e}',file=sys.stderr); return 2
    if completed==0:
        atomic_write_json(active,{'run_id':run_id,'active':None,'completed':True,'no_matches':True}); append_jsonl(journal,{'event':'RUN_END','timestamp':utc_now(),'run_id':run_id,'completed_cases':0,'no_matches':True}); return 3
    atomic_write_json(active,{'run_id':run_id,'active':None,'completed':True,'completed_at':utc_now()}); append_jsonl(journal,{'event':'RUN_END','timestamp':utc_now(),'run_id':run_id,'completed_cases':completed,'nonzero_exit_codes':nonzero}); print(f'Results: {results}'); return 0
if __name__=='__main__': raise SystemExit(main())
