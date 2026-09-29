#!/usr/bin/env python3
"""Reproducible LAMP / independent zkMatrix experiment runner and aggregator."""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import platform
import shutil
import statistics
import subprocess
import sys
import time
import csv
import warnings
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CONFIGS = ROOT / "scripts/comparison/configs.json"
RAW = "lamp_comparison.jsonl"
RHO_N = {"1/2": 2, "1/4": 4, "1/8": 8}
SERVER_USABLE_MEMORY_FLOOR = 240 * (1 << 30)  # usable-memory estimate for nominal 256 GiB hosts


def load_config(name: str) -> dict:
    data = json.loads(CONFIGS.read_text())
    if name not in data:
        raise ValueError(f"unknown config {name!r}; choose {', '.join(data)}")
    cfg = data[name]
    if cfg.get("gated"):
        raise ValueError(f"configuration {name!r} is gated: {cfg['reason']}")
    validate_config(name, cfg)
    _validate_query_capacity(cfg)
    return cfg


def _validate_query_capacity(cfg: dict) -> None:
    # Official GenerateIndices samples with replacement, so L may exceed N.
    return


def validate_config(name: str, cfg: dict) -> None:
    for key in ("log_k", "queries", "repetitions", "threads", "timeout_seconds"):
        if type(cfg.get(key)) is not int or cfg[key] <= 0:
            raise ValueError(f"{name}: {key} must be a positive integer")
    if cfg["log_k"] < 1 or cfg["log_k"] > 15:
        raise ValueError(f"{name}: log_k must be in [1,15]")
    if cfg.get("rho") not in RHO_N:
        raise ValueError(f"{name}: unsupported rho {cfg.get('rho')!r}; supported rates: {', '.join(RHO_N)}")
    for key in ("zkmatrix_batch_q", "lamp_batch_q"):
        values = cfg.get(key, [])
        if not isinstance(values, list) or any(type(v) is not int or v <= 0 for v in values):
            raise ValueError(f"{name}: {key} must contain positive integers")
    cap=cfg.get("max_matrix_elements",1<<20)
    if type(cap) is not int or cap <= 0:
        raise ValueError(f"{name}: max_matrix_elements must be a positive integer")
    if "include_square" in cfg and type(cfg["include_square"]) is not bool:
        raise ValueError(f"{name}: include_square must be a boolean")
    if "log_k_range" in cfg:
        bounds=cfg["log_k_range"]
        if not isinstance(bounds,list) or len(bounds)!=2 or any(type(v) is not int or v<=0 for v in bounds) or bounds[0]>bounds[1] or bounds[1]>15:
            raise ValueError(f"{name}: log_k_range must be an ordered pair in [1,15]")


def source_manifest() -> dict:
    digest = hashlib.sha256()
    count = 0
    excluded = {".git", "vendor", "node_modules", "__pycache__", ".venv", "results", "result"}
    for path in sorted(ROOT.rglob("*")):
        if not path.is_file() or any(part in excluded for part in path.relative_to(ROOT).parts):
            continue
        rel = path.relative_to(ROOT).as_posix()
        if rel.startswith("benchmark/comparison/"):
            continue
        # Hash executable/source inputs only. In particular, never walk arbitrary
        # docs, env files, benchmark outputs, or local configuration secrets.
        source = path.suffix == ".go"
        source = source or path.name in {"go.mod", "go.sum", "go.work", "go.work.sum"}
        source = source or rel in {"scripts/comparison/run.py", "scripts/comparison/test_run.py", "scripts/comparison/configs.json"}
        if not source:
            continue
        try:
            content = path.read_bytes()
        except OSError:
            continue
        digest.update(rel.encode()+b"\0"+hashlib.sha256(content).digest())
        count += 1
    git = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True, capture_output=True)
    status = subprocess.run(["git", "status", "--short"], cwd=ROOT, text=True, capture_output=True)
    diff = subprocess.run(["git", "diff", "--binary", "HEAD"], cwd=ROOT, capture_output=True)
    return {"head": git.stdout.strip() if git.returncode == 0 else "unknown", "tracked_diff_sha256": hashlib.sha256(diff.stdout).hexdigest(), "source_tree_sha256": digest.hexdigest(), "source_files_hashed": count, "working_tree_status": status.stdout.splitlines(), "scope": "Go source and Go module files, including lib/gnark, plus comparison runner/config; no docs, env files, or outputs"}


def _commands_for_case(cfg: dict, binaries: Path) -> list[list[str]]:
    k, l, rho, threads = cfg["log_k"], cfg["queries"], cfg["rho"], cfg["threads"]
    cap=str(cfg.get("max_matrix_elements",1<<20))
    out = []
    if cfg.get("include_square",True):
        out.append([str(binaries/"zkmatrix"), "-K", str(k), "-repetitions", str(cfg["repetitions"]), "-threads", str(threads), "-batch", "0", "-variant", "accelerated", "-max-matrix-elements", cap])
    for q in cfg.get("zkmatrix_batch_q", []):
        out.append([str(binaries/"zkmatrix"), "-K", str(k), "-repetitions", str(cfg["repetitions"]), "-threads", str(threads), "-batch", str(q), "-variant", "accelerated", "-max-matrix-elements", cap])
    if cfg.get("include_square",True):
        lamp_cmd=[str(binaries/"lamp"), "-K", str(k), "-rho", rho, "-L", str(l), "-all=false", "-compile=false", "-OnlyCompile=false"]
        out.extend([lamp_cmd[:] for _ in range(cfg["repetitions"])])
    for q in cfg.get("lamp_batch_q", []):
        batch_cmd=[str(binaries/"lamp_batch"), "-K", str(k), "-rho", rho, "-L", str(l), "-batch", str(q), "-all=false", "-compile=false", "-OnlyCompile=false", "-batch-range=false"]
        out.extend([batch_cmd[:] for _ in range(cfg["repetitions"])])
    return out


def commands(cfg: dict, binaries: Path) -> list[list[str]]:
    if "log_k_range" not in cfg:
        return _commands_for_case(cfg,binaries)
    out=[]
    for k in range(cfg["log_k_range"][0],cfg["log_k_range"][1]+1):
        case={**cfg,"log_k":k}
        case.pop("log_k_range",None)
        out.extend(_commands_for_case(case,binaries))
    return out


def filter_commands(cmds: list[list[str]], scheme: str) -> list[list[str]]:
    if scheme == "lamp":
        return [c for c in cmds if Path(c[0]).name.startswith("lamp")]
    if scheme == "zkmatrix":
        return [c for c in cmds if Path(c[0]).name == "zkmatrix"]
    return cmds


def plan_commands(cfg: dict, binaries: Path, scheme: str) -> list[list[str]]:
    return filter_commands(commands(cfg,binaries),scheme)


def aggregate(path: Path | list[Path], manifest: dict | None, config_name: str) -> list[dict]:
    if manifest is None:
        raise ValueError("aggregation requires the experiment manifest")
    groups: dict[tuple, list[dict]] = {}
    paths = path if isinstance(path, list) else [path]
    for source in paths:
        for lineno, line in enumerate(source.read_text().splitlines(), 1):
            if not line.strip():
                continue
            try:
                r = json.loads(line)
            except json.JSONDecodeError as e:
                raise ValueError(f"{source}:{lineno}: malformed JSON: {e}") from e
            if r.get("verification_succeeded") is not True:
                raise ValueError(f"{source}:{lineno}: unverified record is not aggregatable")
            required=("schema_version","scheme","variant","workload","protocol_path","sampling_profile","protocol_fidelity","dimensions","query_count","timings_seconds","proof_size_definition","statement_bytes","statement_size_definition","timing_accounting_profile","experiment_config")
            missing=[k for k in required if k not in r or r[k] in (None,"")]
            if missing:raise ValueError(f"{source}:{lineno}: missing required fields {missing}")
            if not isinstance(r["dimensions"],dict) or not r["dimensions"] or any(type(v) is not int or v <= 0 for v in r["dimensions"].values()):raise ValueError(f"{source}:{lineno}: invalid dimensions")
            if type(r["query_count"]) is not int or r["query_count"] < 0 or (r["query_count"] == 0 and not r.get("query_count_not_applicable")):raise ValueError(f"{source}:{lineno}: invalid query_count")
            distinct=r.get("distinct_query_count")
            if distinct is not None and (type(distinct) is not int or distinct < 0 or distinct > r["query_count"]):raise ValueError(f"{source}:{lineno}: invalid distinct_query_count")
            if not isinstance(r["timings_seconds"],dict) or not {"prove","verify"}.issubset(r["timings_seconds"]):raise ValueError(f"{source}:{lineno}: prove and verify timings are required")
            for name, value in r.get("timings_seconds", {}).items():
                if type(value) not in (int, float) or not math.isfinite(value) or value < 0:
                    raise ValueError(f"{source}:{lineno}: invalid timing {name}={value!r}")
            if any(k not in r["timings_seconds"] or not r["timings_seconds"][k] for k in ("prove", "verify")):
                raise ValueError(f"{source}:{lineno}: empty prove/verify timing")
            if not isinstance(r.get("host"), dict) or not r["host"]:
                raise ValueError(f"{source}:{lineno}: recorded host provenance is required")
            if not isinstance(r.get("source"), dict) or not r["source"].get("head") or not r["source"].get("source_tree_sha256"):
                raise ValueError(f"{source}:{lineno}: recorded source provenance is required")
            manifest_source=manifest.get("source",{})
            if manifest_source and any(r["source"].get(k)!=manifest_source.get(k) for k in ("head","source_tree_sha256")):
                raise ValueError(f"{source}:{lineno}: record source provenance disagrees with manifest")
            if manifest.get("config_name") and r["experiment_config"].get("name")!=manifest["config_name"]:
                raise ValueError(f"{source}:{lineno}: record config disagrees with manifest")
            for name in ("original_reported_proof_bytes", "compressed_payload_bytes", "statement_bytes"):
                value = r.get(name)
                if value is not None and (type(value) is not int or value < 0):
                    raise ValueError(f"{source}:{lineno}: invalid {name}")
            host=json.dumps(r["host"],sort_keys=True)
            provenance=r["source"]
            key = (r.get("scheme"), r.get("variant"), r.get("workload"), json.dumps(r.get("dimensions", {}), sort_keys=True), r.get("batch_q", 1), r.get("query_count"), r.get("sampling_profile"),r["protocol_fidelity"],r.get("proof_size_definition"),r.get("statement_size_definition"),r.get("timing_accounting_profile"),r.get("protocol_path"),host,provenance.get("head"),provenance.get("source_tree_sha256"),r.get("run",{}).get("binary_sha256"),json.dumps(r["experiment_config"],sort_keys=True))
            groups.setdefault(key, []).append(r)
    result = []
    for key, rows in groups.items():
        times = sorted(x["timings_seconds"]["prove"] for x in rows)
        verify = [x["timings_seconds"]["verify"] for x in rows]
        sizes = [x["original_reported_proof_bytes"] for x in rows if x.get("original_reported_proof_bytes") is not None]
        compressed = [x["compressed_payload_bytes"] for x in rows if x.get("compressed_payload_bytes") is not None]
        timing_names=sorted(set().union(*(r["timings_seconds"].keys() for r in rows)))
        metric_stats={name:(stats([r["timings_seconds"][name] for r in rows]) if all(name in r["timings_seconds"] for r in rows) else None) for name in timing_names}
        setups={r["setup_invocation_id"]:r["setup_seconds_shared_once"] for r in rows if r.get("setup_invocation_id") and r.get("setup_seconds_shared_once") is not None}
        statement_sizes=[r["statement_bytes"] for r in rows if type(r.get("statement_bytes")) is int]
        distinct_counts=[r["distinct_query_count"] for r in rows if type(r.get("distinct_query_count")) is int]
        result.append({"key": list(key), "n": len(rows), "prove_seconds": stats(times), "verify_seconds": stats(verify), "timings_seconds":metric_stats,"setup_seconds_shared_once": stats(list(setups.values())) if setups else None,"shared_setup_invocations":len(setups),"statement_bytes":stats(statement_sizes) if statement_sizes else None,"distinct_query_count":stats(distinct_counts) if distinct_counts else None, "original_reported_proof_bytes": stats(sizes) if sizes else None, "compressed_payload_bytes": stats(compressed) if compressed else None, "proof_size_accounting": rows[0].get("proof_size_definition")})
    return result


def stats(values: list[float]) -> dict:
    return {"n":len(values),"mean": statistics.mean(values), "sample_sd": statistics.stdev(values) if len(values)>1 else None, "min": min(values), "median": statistics.median(values), "max": max(values)}


def peak_rss_kb(stderr: str) -> int | None:
    for line in stderr.splitlines():
        if "Maximum resident set size" in line:
            try: return int(line.split(":",1)[1].strip())
            except ValueError: pass
        if "maximum resident set size" in line.lower():
            try: return int(line.split()[0])//1024
            except (ValueError, IndexError): pass
    return None


def host_hardware() -> dict:
    cpu=os.cpu_count(); memory=None
    platform_processor=platform.processor()
    processor=platform_processor
    if platform.system()=="Darwin":
        for key,target in (("hw.ncpu","cpu"),("hw.memsize","memory")):
            p=subprocess.run(["sysctl","-n",key],text=True,capture_output=True)
            if p.returncode==0:
                try:
                    value=int(p.stdout.strip())
                    if target=="cpu":cpu=value
                    else:memory=value
                except ValueError:pass
        p=subprocess.run(["sysctl","-n","machdep.cpu.brand_string"],text=True,capture_output=True)
        if p.returncode==0 and p.stdout.strip():processor=p.stdout.strip()
    elif Path("/proc/meminfo").exists():
        for line in Path("/proc/meminfo").read_text().splitlines():
            if line.startswith("MemTotal:"):
                memory=int(line.split()[1])*1024;break
        try:
            for line in Path("/proc/cpuinfo").read_text().splitlines():
                if line.lower().startswith(("model name", "hardware")):
                    processor=line.split(":",1)[1].strip();break
        except OSError:pass
    return {"cpu_count":cpu,"memory_bytes":memory,"os":platform.platform(),"processor":processor or "unknown","platform_processor":platform_processor or "unknown"}


def server_resource_error(cfg: dict, hardware: dict) -> str | None:
    max_k=max(cfg.get("log_k_range",[cfg["log_k"]]))
    if max_k>=11 and ((hardware.get("cpu_count") or 0)<32 or (hardware.get("memory_bytes") or 0)<SERVER_USABLE_MEMORY_FLOOR):
        return "K>=11 server runs require at least 32 logical CPUs and usable memory near the 240 GiB floor for a nominal 256 GiB host; current host does not meet that resource floor"
    if cfg.get("threads",0)>10 and (hardware.get("cpu_count") or 0)<cfg["threads"]:
        return f"thread budget {cfg['threads']} exceeds current host logical CPU count {hardware.get('cpu_count')}"
    return None


def numeric_csv_records(csv_path: Path, config_name: str, config: dict, source: dict, host: dict, run_dir: Path, binary: Path, protocol_path: str) -> list[dict]:
    records=[]
    with csv_path.open(newline="") as f:
        for row in csv.DictReader(f):
            if row.get("verified") != "true":
                raise ValueError(f"{csv_path}: zkMatrix CSV row is not verified")
            q=int(row["batch_q"]);batch=q if q > 0 else 1
            timings={"setup":float(row["setup_seconds"]),"matmul":float(row["matmul_seconds"]),"commit":float(row["commit_seconds"]),"prove":float(row["totalprove_seconds"]),"verify":float(row["verify_seconds"])}
            record={"schema_version":1,"scheme":"independent_zkmatrix_optimized_bn254","variant":row["variant"],"workload":"square" if row["m"]==row["inner"]==row["n"] else "rectangular","sampling_profile":"deterministic_pseudorandom_field_matrices","protocol_fidelity":"independent_zkmatrix_implementation","experiment_config":{"name":config_name,**config},"dimensions":{"m":int(row["m"]),"inner":int(row["inner"]),"n":int(row["n"])},"batch_q":batch,"protocol_path":protocol_path,"query_count":0,"query_count_not_applicable":True,"verification_succeeded":True,"timings_seconds":{"prove":timings["prove"],"verify":timings["verify"],"matrix_commit":timings["commit"],"precommitted_online_prove":timings["prove"]-timings["commit"],"matmul":timings["matmul"]},"setup_seconds_shared_once":timings["setup"],"original_reported_proof_bytes":None,"compressed_payload_bytes":int(row["proof_bytes"]),"proof_size_definition":"zkMatrix canonical serialized proof bytes, including codec framing; statement/commitment bytes separate","statement_bytes":int(row["commit_bytes"]),"statement_size_definition":"zkMatrix canonical serialized statement codec bytes, including codec framing","setup_invocation_id":run_dir.parent.name+"/"+run_dir.name,"timing_accounting_profile":"commit-inclusive online prove; setup shared once, matmul excluded","host":{**host,"runtime_num_cpu":int(row["runtime_num_cpu"]),"thread_budget":int(row["threads"]),"gomaxprocs":int(row["threads"])},"source":source,"run":{"seed_base":int(row["seed_base"]),"effective_seed":int(row["effective_seed"]),"threads":int(row["threads"]),"runtime_num_cpu":int(row["runtime_num_cpu"]),"curve":row["curve"],"setup_mode":row["setup_mode"],"srs_points":int(row["setup_srs_g1_points"]),"srs_bytes_compressed":int(row["setup_srs_bytes_compressed"]),"statement_bytes":int(row["commit_bytes"]),"total_bytes":int(row["total_bytes"]),"binary_sha256":file_sha256(binary)}}
            records.append(record)
    if len(records) != config["repetitions"]:
        raise ValueError(f"{csv_path}: expected {config['repetitions']} verified rows, found {len(records)}")
    raw=run_dir/RAW
    raw.write_text("".join(json.dumps(r,allow_nan=False)+"\n" for r in records))
    return records


def file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def require_verified_records(records: list[dict], expected: int, context: str) -> None:
    if len(records) != expected:
        raise ValueError(f"{context}: expected {expected} verified raw records, found {len(records)}")
    if any(r.get("verification_succeeded") is not True for r in records):
        raise ValueError(f"{context}: found a raw record without successful verification")


def completed_command_count(entries: list[dict]) -> int:
    return sum(1 for e in entries if e.get("status")=="completed" and
               type(e.get("verified_record_count")) is int and
               e["verified_record_count"]==e.get("expected_verified_record_count"))


def manifest_raw_paths(output_dir: Path, manifest: dict) -> list[Path]:
    """Return outputs from completed commands with the expected verified rows."""
    paths=[]
    for entry in manifest.get("commands",[]):
        expected=entry.get("expected_verified_record_count")
        if (entry.get("status")!="completed" or type(expected) is not int or expected < 0 or
                type(entry.get("verified_record_count")) is not int or
                entry["verified_record_count"]!=expected):
            continue
        stdout=entry.get("stdout")
        if not stdout:
            continue
        raw=Path(stdout).parent/RAW
        if not raw.is_file():
            continue
        try:
            rows=[json.loads(line) for line in raw.read_text().splitlines() if line.strip()]
        except (OSError,json.JSONDecodeError):
            continue
        if len(rows)!=expected or any(row.get("verification_succeeded") is not True for row in rows):
            continue
        paths.append(raw)
    return paths


def enrich_lamp_records(raw: Path, source: dict, host: dict, binary_hash: str, config_name: str, config: dict) -> None:
    if not raw.exists():return
    rows=[]
    for line in raw.read_text().splitlines():
        if not line.strip():continue
        r=json.loads(line);r["source"]=source;r["host"]={**host,**r.get("host",{})};r["run"]={"binary_sha256":binary_hash};r.setdefault("protocol_fidelity", "official_revision_e2d1cae");r["experiment_config"]={"name":config_name,**config}
        if type(r.get("batch_q")) is not int:r["batch_q"]=1
        r.setdefault("protocol_path", "batch" if r.get("workload")=="batch" else "square")
        rows.append(json.dumps(r,allow_nan=False))
    raw.write_text("\n".join(rows)+("\n" if rows else ""))


def write_manifest(output_dir: Path, manifest: dict) -> None:
    temporary=output_dir/"manifest.json.tmp"
    temporary.write_text(json.dumps(manifest,indent=2)+"\n")
    temporary.replace(output_dir/"manifest.json")


def main() -> int:
    ap=argparse.ArgumentParser();ap.add_argument("--config",default="development");ap.add_argument("--output",type=Path);ap.add_argument("--dry-run",action="store_true");ap.add_argument("--plan",action="store_true",help="print a gated server resource plan without executing it");ap.add_argument("--aggregate",type=Path);ap.add_argument("--manifest",type=Path,help="manifest for historical --aggregate input; otherwise an adjacent manifest.json is required");ap.add_argument("--scheme",choices=("both","lamp","zkmatrix","zkmap"),default="both");args=ap.parse_args()
    if args.scheme=="zkmap":raise ValueError("No resolved zkMaP proof scheme is available; see docs/comparison/ZKMAP_SPEC_GAPS.md. The audit command is diagnostic only.")
    if args.aggregate:
        mp=args.manifest or (args.aggregate.parent/"manifest.json")
        if not mp.is_file():raise ValueError("historical --aggregate requires adjacent manifest.json or --manifest")
        historical=json.loads(mp.read_text())
        print(json.dumps(aggregate(args.aggregate,historical,args.config),indent=2));return 0
    if args.plan:
        data=json.loads(CONFIGS.read_text())
        if args.config not in data:raise ValueError(f"unknown config {args.config!r}")
        cfg=dict(data[args.config]);cfg.pop("gated",None);cfg.pop("reason",None)
        validate_config(args.config,cfg)
        planned=plan_commands(cfg,Path("<binary-dir>"),args.scheme)
        print(json.dumps({"mode":"plan_only","config":args.config,"resource_plan":cfg.get("resource_plan"),"commands":planned,"expected_commands":len(planned),"execution":"not started"},indent=2));return 0
    cfg=load_config(args.config)
    hardware=host_hardware()
    if cfg.get("resource_plan") and not args.dry_run:
        issue=server_resource_error(cfg,hardware)
        if issue:raise SystemExit(f"resource guard: {issue}; use --plan to inspect the full command grid")
    out=args.output or ROOT/"benchmark/comparison"/(args.config+"_"+str(int(time.time())))
    if out.exists(): raise SystemExit(f"refusing to overwrite existing experiment directory: {out}")
    cmds=filter_commands(commands(cfg,out/"bin"),args.scheme)
    if args.dry_run:
        print(json.dumps({"config":cfg,"output":str(out),"commands":cmds},indent=2));return 0
    out.mkdir(parents=True)
    (out/"bin").mkdir()
    source=source_manifest()
    manifest={"config_name":args.config,"config":cfg,"protocol_fidelity":"official revision e2d1cae; per-record square and batch paths retained","source":source,"python":sys.version,"go":subprocess.run(["go","version"],text=True,capture_output=True).stdout.strip(),**hardware,"gomaxprocs":cfg["threads"],"thread_budget":cfg["threads"],"started_unix":time.time(),"commands":[],"expected_command_count":len(cmds),"selected_scheme":args.scheme}
    manifest["completion_status"]="incomplete"
    manifest["run_state"]="preparing"
    write_manifest(out,manifest)
    try:
        import psutil  # optional, metadata only
        manifest["memory_bytes"]=psutil.virtual_memory().total
    except ImportError:
        if Path("/proc/meminfo").exists():
            for line in Path("/proc/meminfo").read_text().splitlines():
                if line.startswith("MemTotal:"):manifest["memory_bytes"]=int(line.split()[1])*1024;break
    write_manifest(out,manifest)
    build_names=sorted({Path(c[0]).name for c in cmds})
    for name in build_names:
        manifest["run_state"]="building"
        manifest["active_build"]=name
        write_manifest(out,manifest)
        build=["go","build","-o",str(out/"bin"/name),f"./cmd/{name}"]
        try:
            p=subprocess.run(build,cwd=ROOT,text=True,capture_output=True)
        except KeyboardInterrupt:
            manifest["run_state"]="interrupted";manifest["interruption_stage"]="build";manifest["finished_unix"]=time.time();write_manifest(out,manifest);return 130
        (out/f"build_{name}.stdout.txt").write_text(p.stdout);(out/f"build_{name}.stderr.txt").write_text(p.stderr)
        if p.returncode: manifest["build_failed"]=name;manifest["build_exit_status"]=p.returncode;manifest["run_state"]="build_failed";write_manifest(out,manifest);break
        manifest.pop("active_build",None);manifest["run_state"]="built";write_manifest(out,manifest)
    if "build_failed" not in manifest:
        host={**host_hardware(),"gomaxprocs":cfg["threads"],"thread_budget":cfg["threads"],"go":manifest["go"]}
        binary_hashes={name:file_sha256(out/"bin"/name) for name in build_names}
        for i,cmd in enumerate(cmds):
            run_dir=out/f"run_{i+1:02d}";run_dir.mkdir();env=os.environ.copy();env["GOMAXPROCS"]=str(cfg["threads"]);env["LAMP_COMPARISON_RAW_JSONL"]=str(run_dir/RAW)
            env["LAMP_OUTPUT_DIR"]=str(run_dir/"lamp");env["LAMP_BATCH_OUTPUT_DIR"]=str(run_dir/"lamp_batch");env["LAMP_GPT2_OUTPUT_DIR"]=str(run_dir/"lamp_gpt2")
            if Path(cmd[0]).name=="zkmatrix":cmd=cmd+["-output",str(run_dir/"zkmatrix.csv")]
            timer=["/usr/bin/time","-v"] if platform.system()=="Linux" else (["/usr/bin/time","-l"] if platform.system()=="Darwin" else [])
            start=time.time()
            expected_rows=cfg["repetitions"] if Path(cmd[0]).name=="zkmatrix" else 1
            entry={"argv":cmd,"cwd":str(ROOT),"stdout":str(run_dir/"stdout.txt"),"stderr":str(run_dir/"stderr.txt"),"exit_status":None,"status":"started","started_unix":start,"binary_sha256":binary_hashes[Path(cmd[0]).name],"expected_verified_record_count":expected_rows}
            manifest["commands"].append(entry);manifest["run_state"]="running_command";manifest["active_command_index"]=i;write_manifest(out,manifest)
            try:p=subprocess.run(timer+cmd,cwd=ROOT,env=env,text=True,capture_output=True,timeout=cfg["timeout_seconds"])
            except subprocess.TimeoutExpired as e:
                stdout=e.stdout or "";stderr=e.stderr or ""
                if isinstance(stdout,bytes):stdout=stdout.decode(errors="replace")
                if isinstance(stderr,bytes):stderr=stderr.decode(errors="replace")
                (run_dir/"stdout.txt").write_text(stdout);(run_dir/"stderr.txt").write_text(stderr);status="timeout";code=None
            except KeyboardInterrupt:
                entry["status"]="interrupted";entry["elapsed_seconds"]=time.time()-start;entry["finished_unix"]=time.time();manifest["run_state"]="interrupted";manifest["interruption_stage"]="command";manifest["finished_unix"]=time.time();write_manifest(out,manifest);return 130
            else:
                (run_dir/"stdout.txt").write_text(p.stdout);(run_dir/"stderr.txt").write_text(p.stderr);status="completed" if p.returncode==0 else "failed";code=p.returncode;stderr=p.stderr
            entry.update({"exit_status":code,"status":status,"elapsed_seconds":time.time()-start,"finished_unix":time.time(),"peak_rss_kb":peak_rss_kb(stderr)})
            manifest["run_state"]="postprocessing" if status=="completed" else "command_failed";write_manifest(out,manifest)
            if status=="completed":
                try:
                    if Path(cmd[0]).name=="zkmatrix":
                        rows=numeric_csv_records(run_dir/"zkmatrix.csv",args.config,cfg,source,host,run_dir,Path(cmd[0]),"batch" if "-batch" in cmd and cmd[cmd.index("-batch")+1] != "0" else "square")
                        expected=cfg["repetitions"]
                    else:
                        enrich_lamp_records(run_dir/RAW,source,host,binary_hashes[Path(cmd[0]).name],args.config,cfg)
                        expected=1
                        rows=[json.loads(x) for x in (run_dir/RAW).read_text().splitlines() if x.strip()] if (run_dir/RAW).exists() else []
                    require_verified_records(rows,expected,"command raw output")
                    entry["verified_record_count"]=len(rows)
                except KeyboardInterrupt:
                    entry["status"]="interrupted";manifest["run_state"]="interrupted";manifest["interruption_stage"]="postprocessing";manifest["finished_unix"]=time.time();write_manifest(out,manifest);return 130
                except Exception as e:
                    entry["status"]="postprocessing_failed";entry["postprocessing_error"]=str(e)
                    manifest["postprocessing_failed"]=True
            write_manifest(out,manifest)
    completed=completed_command_count(manifest["commands"])
    manifest["completion_status"]="complete" if completed==manifest["expected_command_count"] and "build_failed" not in manifest else "incomplete"
    manifest["run_state"]="finished";manifest["finished_unix"]=time.time();write_manifest(out,manifest)
    records=[]
    try:
        raw_paths=manifest_raw_paths(out,manifest)
        records=aggregate(raw_paths,manifest,args.config) if raw_paths else []
    except KeyboardInterrupt:
        manifest["completion_status"]="incomplete";manifest["run_state"]="interrupted";manifest["interruption_stage"]="aggregation";manifest["finished_unix"]=time.time();write_manifest(out,manifest);return 130
    except Exception as e:
        manifest["completion_status"]="incomplete";manifest["aggregation_error"]=str(e)
        write_manifest(out,manifest)
        return 1
    write_manifest(out,manifest)
    (out/"summary.json").write_text(json.dumps(records,indent=2)+"\n")
    lines=["# Experiment summary", "", f"Completion status: **{manifest['completion_status']}**. Any rows below are partial when this is incomplete.", "", "Prove means full commitment-inclusive online time when available; setup and compilation are excluded. LAMP's historical reported phase sum is shown separately. Statement bytes are shown apart from proof bytes.", "", f"Profile: `{cfg['label']}`. Results are grouped only within exact scheme, variant, shape, batch, protocol path, fidelity, proof and statement accounting, timing accounting, host, source, binary, and recorded config keys.", "", "| Group key | n | Prove mean ± sample SD (s) | Full online (s) | LAMP historical reported prove (s) | Matrix commit (s) | Precommitted online (s) | Setup (s) | Circuit compile (s) | Matrix multiply (s) | Verify mean ± sample SD (s) | Statement bytes | Original reported proof bytes | Normalized compressed proof bytes |", "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|"]
    for r in records:
        ts=r.get("timings_seconds",{})
        setup=fmtstat(ts.get('setup')) if ts.get('setup') else fmtstat(r.get('setup_seconds_shared_once'))
        lines.append(f"| `{r['key']}` | {r['n']} | {fmtstat(r['prove_seconds'])} | {fmtstat(ts.get('full_online_prove'))} | {fmtstat(ts.get('original_reported_totalprove'))} | {fmtstat(ts.get('matrix_commit'))} | {fmtstat(ts.get('precommitted_online_prove'))} | {setup} ({r.get('shared_setup_invocations',r['n'])} setup invocations) | {fmtstat(ts.get('circuit_compile'))} | {fmtstat(ts.get('matrix_compute'))} | {fmtstat(r['verify_seconds'])} | {fmtstat(r.get('statement_bytes'))} | {fmtstat(r['original_reported_proof_bytes'])} | {fmtstat(r['compressed_payload_bytes'])} |")
    (out/"summary.md").write_text("\n".join(lines)+"\n")
    print(out);return 0 if manifest["completion_status"]=="complete" and not manifest.get("postprocessing_failed") else 1


def fmtstat(s):
    if not s:return "unavailable"
    return f"{s['mean']:.6g} ± {s['sample_sd'] if s['sample_sd'] is not None else 'n/a'}"

def fmtseconds(v):
    return "unavailable" if v is None else f"{v:.6g} (one shared setup)"

if __name__=="__main__":
    try: raise SystemExit(main())
    except (ValueError,KeyError,json.JSONDecodeError) as e: raise SystemExit(str(e))
