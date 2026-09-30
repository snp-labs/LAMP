import importlib.util
import json
import math
import tempfile
import unittest
from unittest import mock
from pathlib import Path

SPEC=importlib.util.spec_from_file_location("comparison_run",Path(__file__).with_name("run.py"))
run=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(run)

class ComparisonRunnerTests(unittest.TestCase):
    def test_official_paper_parameter_profile_and_original_exact_gate(self):
        cfg=run.load_config("official_paper_parameters")
        self.assertEqual(cfg["queries"],309)
        with self.assertRaisesRegex(ValueError,"Original author revision"):
            run.load_config("original_exact")

    def test_aggregates_real_numeric_records(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/"x.jsonl";rows=[]
            for x in (1.0,3.0):rows.append({"schema_version":1,"verification_succeeded":True,"scheme":"lamp","variant":"qa/multi","workload":"square","protocol_path":"square","protocol_fidelity":"official_revision_e2d1cae_public_protocol","experiment_config":{"name":"fixture","threads":2},"dimensions":{"K":128},"batch_q":1,"query_count":128,"distinct_query_count":100,"sampling_profile":"official","timing_accounting_profile":"full-online","timings_seconds":{"prove":x,"verify":x/2},"original_reported_proof_bytes":100,"compressed_payload_bytes":None,"statement_bytes":64,"statement_size_definition":"two roots","proof_size_definition":"original bytes","host":{"host":"fixture","goos":"darwin"},"source":{"head":"abc","source_tree_sha256":"tree"}})
            p.write_text("\n".join(json.dumps(x) for x in rows)+"\n")
            result=run.aggregate(p,{"head":"abc"},"development")[0]
            self.assertEqual(result["n"],2);self.assertEqual(result["prove_seconds"]["n"],2);self.assertEqual(result["prove_seconds"]["mean"],2);self.assertEqual(result["prove_seconds"]["sample_sd"],math.sqrt(2))
            self.assertIsNone(result["compressed_payload_bytes"])

    def test_setup_summary_counts_invocations_not_repetition_rows(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/"setup.jsonl"
            row={"schema_version":1,"verification_succeeded":True,"scheme":"independent_zkmatrix","variant":"accelerated","workload":"square","protocol_path":"square","protocol_fidelity":"independent","experiment_config":{"name":"fixture"},"dimensions":{"K":4},"batch_q":1,"query_count":0,"query_count_not_applicable":True,"sampling_profile":"fixed","timing_accounting_profile":"online","timings_seconds":{"prove":1.0,"verify":0.1},"setup_seconds_shared_once":2.0,"setup_invocation_id":"case-a","statement_bytes":20,"statement_size_definition":"fixture statement","original_reported_proof_bytes":None,"compressed_payload_bytes":80,"proof_size_definition":"fixture","host":{"host":"fixture"},"source":{"head":"abc","source_tree_sha256":"tree"}}
            rows=[]
            for i in range(10): rows.append({**row,"run":{"binary_sha256":"bin"},"setup_invocation_id":"case-a"})
            rows.append({**row,"run":{"binary_sha256":"bin"},"setup_invocation_id":"case-b","setup_seconds_shared_once":3.0})
            p.write_text("\n".join(json.dumps(x) for x in rows)+"\n")
            result=run.aggregate(p,{"config_name":"fixture"},"fixture")[0]
            self.assertEqual(result["n"],11)
            self.assertEqual(result["shared_setup_invocations"],2)
            self.assertEqual(result["setup_seconds_shared_once"]["n"],2)
            self.assertEqual(result["setup_seconds_shared_once"]["mean"],2.5)

    def test_rejects_malformed_or_unverified_records(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/"bad.jsonl";p.write_text("{bad\n")
            with self.assertRaisesRegex(ValueError,"malformed JSON"):run.aggregate(p,{},"development")
            p.write_text(json.dumps({"schema_version":1,"verification_succeeded":False,"timings_seconds":{}})+"\n")
            with self.assertRaisesRegex(ValueError,"unverified"):run.aggregate(p,{},"development")
            p.write_text(json.dumps({"schema_version":1,"verification_succeeded":True,"scheme":"lamp","variant":"v","workload":"w","protocol_path":"square","protocol_fidelity":"snapshot","experiment_config":{"name":"fixture"},"sampling_profile":"official","dimensions":{"K":1},"query_count":1,"timings_seconds":{"prove":float("nan"),"verify":0},"proof_size_definition":"x","statement_bytes":1,"statement_size_definition":"x","timing_accounting_profile":"x","host":{"host":"fixture"},"source":{"head":"abc","source_tree_sha256":"tree"}})+"\n")
            with self.assertRaisesRegex(ValueError,"invalid timing"):run.aggregate(p,{},"development")

    def test_rejects_absent_empty_and_boolean_numeric_values(self):
        base={"schema_version":1,"verification_succeeded":True,"scheme":"lamp","variant":"v","workload":"w","protocol_path":"square","protocol_fidelity":"snapshot","experiment_config":{"name":"fixture"},"sampling_profile":"official","dimensions":{"K":1},"query_count":1,"timings_seconds":{"prove":1.0,"verify":2.0},"proof_size_definition":"x","statement_bytes":1,"statement_size_definition":"x","timing_accounting_profile":"fixture","host":{"host":"fixture"},"source":{"head":"abc","source_tree_sha256":"tree"}}
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/"bad.jsonl"
            for edit, message in (({"dimensions":{}},"invalid dimensions"),({"query_count":0},"invalid query_count"),({"timings_seconds":{"prove":1,"verify":0}},"empty prove/verify"),({"timings_seconds":{"prove":True,"verify":1}},"invalid timing"),({"host":{}},"recorded host")):
                row={**base,**edit};p.write_text(json.dumps(row)+"\n")
                with self.assertRaisesRegex(ValueError,message):run.aggregate(p,{},"development")

    def test_missing_raw_and_failed_command_records_are_rejected(self):
        with self.assertRaisesRegex(ValueError,"expected 1 verified raw records"):
            run.require_verified_records([],1,"fixture")
        with self.assertRaisesRegex(ValueError,"without successful verification"):
            run.require_verified_records([{"verification_succeeded":False}],1,"fixture")
        # The runner records nonzero exit statuses as failures and cannot count
        # those commands toward completion.
        command={"status":"failed","exit_status":7}
        self.assertNotEqual(command["status"],"completed")
        zkmatrix_command={"status":"completed","verified_record_count":10,"expected_verified_record_count":10}
        self.assertEqual(run.completed_command_count([zkmatrix_command]),1)
        lamp_commands=[{"status":"completed","verified_record_count":1,"expected_verified_record_count":1} for _ in range(10)]
        self.assertEqual(run.completed_command_count(lamp_commands),10)

    def test_failed_command_with_valid_late_raw_row_is_excluded_from_manifest_aggregation(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);failed=root/"run_01";failed.mkdir();done=root/"run_02";done.mkdir()
            row={"verification_succeeded":True,"value":1}
            (failed/run.RAW).write_text(json.dumps(row)+"\n")
            (done/run.RAW).write_text(json.dumps(row)+"\n")
            manifest={"commands":[
                {"status":"failed","exit_status":9,"verified_record_count":1,"expected_verified_record_count":1,"stdout":str(failed/"stdout.txt")},
                {"status":"completed","exit_status":0,"verified_record_count":1,"expected_verified_record_count":1,"stdout":str(done/"stdout.txt")},
                {"status":"completed","verified_record_count":0,"expected_verified_record_count":1,"stdout":str(failed/"stdout.txt")},
            ]}
            self.assertEqual(run.manifest_raw_paths(root,manifest),[done/run.RAW])

    def test_darwin_cpu_brand_overrides_generic_arm_processor(self):
        def fake_run(cmd,**kwargs):
            value={"hw.ncpu":"10\n","hw.memsize":str(32*(1<<30))+"\n","machdep.cpu.brand_string":"Apple M1 Pro\n"}[cmd[-1]]
            return __import__("subprocess").CompletedProcess(cmd,0,stdout=value,stderr="")
        with mock.patch.object(run.platform,"system",return_value="Darwin"), \
             mock.patch.object(run.platform,"processor",return_value="arm"), \
             mock.patch.object(run.platform,"platform",return_value="fixture Darwin arm64"), \
             mock.patch.object(run.os,"cpu_count",return_value=10), \
             mock.patch.object(run.subprocess,"run",side_effect=fake_run):
            hardware=run.host_hardware()
        self.assertEqual(hardware["processor"],"Apple M1 Pro")
        self.assertEqual(hardware["platform_processor"],"arm")

    def test_server_guard_accepts_240_gib_usable_for_nominal_256_gib_host(self):
        cfg={"log_k":11,"repetitions":1,"threads":10}
        self.assertIsNotNone(run.server_resource_error(cfg,{"cpu_count":32,"memory_bytes":239*(1<<30)}))
        self.assertIsNone(run.server_resource_error(cfg,{"cpu_count":32,"memory_bytes":240*(1<<30)}))

    def test_config_validation_and_unique_query_gate(self):
        with self.assertRaisesRegex(ValueError,"unsupported rho"):
            run.validate_config("bad",{"log_k":7,"queries":10,"repetitions":1,"threads":1,"timeout_seconds":1,"rho":"1/3","sampling":"unique"})
        with self.assertRaisesRegex(ValueError,"positive integer"):
            run.validate_config("bad",{"log_k":7,"queries":10,"repetitions":True,"threads":1,"timeout_seconds":1,"rho":"1/2","sampling":"unique"})
        # Official GenerateIndices uses replacement, so 309 draws over N=256 are valid.
        run._validate_query_capacity({"log_k":7,"rho":"1/2","queries":309})

    def test_scheme_filter_is_applied_to_actual_command_list(self):
        cfg=run.load_config("development")
        with tempfile.TemporaryDirectory() as d:
            cmds=run.commands(cfg,Path(d))
            lamp=run.filter_commands(cmds,"lamp")
            zkm=run.filter_commands(cmds,"zkmatrix")
            self.assertEqual(len(lamp),cfg["repetitions"]*(1+len(cfg["lamp_batch_q"])))
            self.assertEqual(len(zkm),1+len(cfg["zkmatrix_batch_q"]))
            self.assertTrue(all(Path(c[0]).name.startswith("lamp") for c in lamp))
            self.assertTrue(all(Path(c[0]).name=="zkmatrix" for c in zkm))
            self.assertFalse(any(c in run.filter_commands(cmds,"lamp") for c in run.filter_commands(cmds,"zkmatrix")))

    def test_local_profiles_and_server_plans_expand_to_actual_execution_grid(self):
        with tempfile.TemporaryDirectory() as d:
            binaries=Path(d)
            squares=run.load_config("official_squares_local")
            square_cmds=run.commands(squares,binaries)
            self.assertEqual(len(run.filter_commands(square_cmds,"lamp")),10)
            self.assertEqual(len(run.filter_commands(square_cmds,"zkmatrix")),1)
            batches=run.load_config("official_batch_local")
            batch_cmds=run.commands(batches,binaries)
            qvals=[int(c[c.index("-batch")+1]) for c in run.filter_commands(batch_cmds,"zkmatrix")]
            self.assertEqual(qvals,list(range(1,11)))
            self.assertFalse(any(Path(c[0]).name=="lamp" for c in batch_cmds))
            server=json.loads(run.CONFIGS.read_text())["server_square_k7_k13"]
            planned=run.plan_commands(server,binaries,"both")
            actual=run.filter_commands(run.commands(server,binaries),"both")
            self.assertEqual(planned,actual)
            self.assertEqual(sorted({int(c[c.index("-K")+1]) for c in actual}),list(range(7,14)))
            self.assertIsNotNone(run.server_resource_error(server,{"cpu_count":10,"memory_bytes":32*(1<<30)}))
            self.assertIsNone(run.server_resource_error(server,{"cpu_count":32,"memory_bytes":256*(1<<30)}))
            self.assertEqual(run.load_config("official_batch_local")["max_matrix_elements"],1<<20)
            expanded=run.commands(run.load_config("official_squares_k7_k10_local"),binaries)
            self.assertEqual(len(run.filter_commands(expanded,"zkmatrix")),4)
            self.assertEqual(len(run.filter_commands(expanded,"lamp")),40)
            batch_grid=run.commands(run.load_config("official_batch_q1_q10_local"),binaries)
            self.assertEqual(len(run.filter_commands(batch_grid,"zkmatrix")),10)
            self.assertEqual(len(run.filter_commands(batch_grid,"lamp")),100)
            self.assertEqual(run.load_config("official_square_rho_1_4_local")["queries"],189)
            self.assertEqual(run.load_config("official_square_rho_1_8_local")["queries"],155)
            server_batch=json.loads(run.CONFIGS.read_text())["server_batch_q1_q10"]
            batch_plan=run.plan_commands(server_batch,binaries,"both")
            batch_actual=run.filter_commands(run.commands(server_batch,binaries),"both")
            self.assertEqual(batch_plan,batch_actual)
            self.assertEqual(len(batch_actual),110)
            zk_q=[int(c[c.index("-batch")+1]) for c in batch_actual if Path(c[0]).name=="zkmatrix"]
            lamp_q=[int(c[c.index("-batch")+1]) for c in batch_actual if Path(c[0]).name=="lamp_batch"]
            self.assertEqual(zk_q,list(range(1,11)))
            self.assertEqual(lamp_q,[q for q in range(1,11) for _ in range(10)])

    def test_zkmatrix_csv_adapter_keeps_numeric_proof_records(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);binary=root/"zkmatrix";binary.write_bytes(b"binary")
            p=root/"zkmatrix.csv"
            header=["run","variant","batch_q","m","inner","n","threads","runtime_num_cpu","seed_base","effective_seed","setup_seconds","setup_srs_g1_points","setup_srs_bytes_compressed","matmul_seconds","commit_seconds","prove_seconds","totalprove_seconds","verify_seconds","proof_bytes","commit_bytes","total_bytes","verified","setup_mode","curve","goos","goarch","go_version","cpu","git_commit"]
            values=["1","accelerated","2","4","4","4","3","10","11","7930","1.25","10","320","0.1","0.2","0.3","0.5","0.04","99","200","299","true","single_party_experimental","BN254","darwin","arm64","go1.x","fixture","abc"]
            p.write_text(",".join(header)+"\n"+",".join(values)+"\n")
            records=run.numeric_csv_records(p,"fixture",{"threads":3,"repetitions":1},{"head":"abc"},{"host":"fixture"},root,binary,"batch")
            self.assertEqual(len(records),1)
            row=records[0]
            self.assertEqual(row["timings_seconds"]["prove"],0.5)
            self.assertEqual(row["setup_seconds_shared_once"],1.25)
            self.assertEqual(row["run"]["effective_seed"],7930)
            self.assertEqual(row["compressed_payload_bytes"],99)
            self.assertNotIn("setup",row["timings_seconds"])
            self.assertEqual(row["query_count"],0)
            self.assertTrue(row["query_count_not_applicable"])
            self.assertEqual(row["protocol_path"],"batch")
            self.assertEqual(row["statement_bytes"],200)
            self.assertEqual(row["host"]["runtime_num_cpu"],10)

    def test_q1_square_and_batch_paths_remain_distinct(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);binary=root/"zkmatrix";binary.write_bytes(b"binary")
            p=root/"zkmatrix.csv"
            header="run,variant,batch_q,m,inner,n,threads,runtime_num_cpu,seed_base,effective_seed,setup_seconds,setup_srs_g1_points,setup_srs_bytes_compressed,matmul_seconds,commit_seconds,prove_seconds,totalprove_seconds,verify_seconds,proof_bytes,commit_bytes,total_bytes,verified,setup_mode,curve,goos,goarch,go_version,cpu,git_commit\n"
            row="1,accelerated,1,4,4,4,3,10,11,11,1,10,320,0.1,0.2,0.3,0.5,0.04,99,200,299,true,single_party_experimental,BN254,darwin,arm64,go1.x,fixture,abc\n"
            p.write_text(header+row)
            square=run.numeric_csv_records(p,"fixture",{"threads":3,"repetitions":1},{"head":"abc","source_tree_sha256":"tree"},{"host":"fixture"},root,binary,"square")[0]
            square_path=root/"square.jsonl";square_path.write_text(json.dumps(square)+"\n")
            batch=run.numeric_csv_records(p,"fixture",{"threads":3,"repetitions":1},{"head":"abc","source_tree_sha256":"tree"},{"host":"fixture"},root,binary,"batch")[0]
            self.assertNotEqual(square["protocol_path"],batch["protocol_path"])
            p.write_text("\n".join(json.dumps(x) for x in (square,batch))+"\n")
            groups=run.aggregate(p,{"config_name":"fixture"},"fixture")
            self.assertEqual(len(groups),2)

    def test_source_manifest_tracks_untracked_go_but_not_docs_or_env(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);(root/"lib/gnark").mkdir(parents=True);(root/"lib/gnark/go.mod").write_text("module fixture\n");(root/"lib/gnark/go.sum").write_text("sum one\n")
            (root/"config").mkdir();(root/"config/unlisted.go").write_text("package config\n")
            (root/"new.go").write_text("package fixture\n")
            (root/"notes.md").write_text("one\n");(root/".env").write_text("SECRET=x\n")
            original=run.ROOT;run.ROOT=root
            try:
                first=run.source_manifest()["source_tree_sha256"]
                (root/"new.go").write_text("package fixture\n// changed\n")
                second=run.source_manifest()["source_tree_sha256"]
                self.assertNotEqual(first,second)
                (root/"new.go").write_text("package fixture\n// changed\n")
                first=run.source_manifest()["source_tree_sha256"]
                (root/"notes.md").write_text("two\n");(root/".env").write_text("SECRET=y\n")
                self.assertEqual(first,run.source_manifest()["source_tree_sha256"])
                (root/"lib/gnark/go.sum").write_text("sum two\n")
                self.assertNotEqual(first,run.source_manifest()["source_tree_sha256"])
                current=run.source_manifest()["source_tree_sha256"]
                (root/"config/unlisted.go").write_text("package config\n// changed\n")
                self.assertNotEqual(current,run.source_manifest()["source_tree_sha256"])
                current=run.source_manifest()["source_tree_sha256"]
                (root/"benchmark/comparison").mkdir(parents=True);(root/"benchmark/comparison/result.go").write_text("package result\n")
                self.assertEqual(current,run.source_manifest()["source_tree_sha256"])
            finally:run.ROOT=original

    def test_main_executes_filtered_list_and_persists_missing_or_failed_output(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);script_dir=root/"scripts/comparison";script_dir.mkdir(parents=True)
            config_path=script_dir/"configs.json"
            config_path.write_text(json.dumps({"tiny":{"label":"fixture","log_k":2,"rho":"1/2","queries":2,"repetitions":1,"threads":1,"zkmatrix_batch_q":[],"lamp_batch_q":[],"timeout_seconds":1}}))
            old_root,old_configs=run.ROOT,run.CONFIGS
            try:
                run.ROOT=root;run.CONFIGS=config_path
                for mode in ("success","missing","failed","interrupted"):
                    out=root/f"out_{mode}"
                    args=["run.py","--config","tiny","--scheme","lamp","--output",str(out)]
                    record={"schema_version":1,"scheme":"lamp","variant":"qa/multi","workload":"square","protocol_path":"square","protocol_fidelity":"official_revision_e2d1cae_public_protocol","sampling_profile":"official","dimensions":{"K":4},"query_count":2,"verification_succeeded":True,"timings_seconds":{"prove":1.0,"verify":0.1,"setup":0.2},"original_reported_proof_bytes":100,"compressed_payload_bytes":80,"statement_bytes":64,"proof_size_definition":"fixture proof","statement_size_definition":"fixture statement","timing_accounting_profile":"fixture","host":{"runtime_num_cpu":1}}
                    def fake_run(cmd, **kwargs):
                        if cmd[0]=="git":
                            stdout="abc\n" if "rev-parse" in cmd else ("?? fixture.go\n" if "status" in cmd else b"")
                            return __import__("subprocess").CompletedProcess(cmd,0,stdout=stdout,stderr="" if kwargs.get("text") else b"")
                        if cmd[0]=="sysctl":
                            return __import__("subprocess").CompletedProcess(cmd,0,stdout="10\n" if cmd[-1]=="hw.ncpu" else str(32*(1<<30))+"\n",stderr="")
                        if cmd[0]=="go" and "build" in cmd:
                            binary=Path(cmd[cmd.index("-o")+1]);binary.parent.mkdir(parents=True,exist_ok=True);binary.write_bytes(b"fixture binary")
                            return __import__("subprocess").CompletedProcess(cmd,0,stdout="",stderr="")
                        if kwargs.get("env") is not None and "LAMP_COMPARISON_RAW_JSONL" in kwargs["env"]:
                            if mode=="interrupted":raise KeyboardInterrupt()
                            if mode=="failed":
                                raw=Path(kwargs["env"]["LAMP_COMPARISON_RAW_JSONL"]);raw.parent.mkdir(parents=True,exist_ok=True);raw.write_text(json.dumps(record)+"\n")
                                return __import__("subprocess").CompletedProcess(cmd,7,stdout="",stderr="failed after writing a valid raw row")
                            if mode=="success":
                                raw=Path(kwargs["env"]["LAMP_COMPARISON_RAW_JSONL"]);raw.parent.mkdir(parents=True,exist_ok=True);raw.write_text(json.dumps(record)+"\n")
                            return __import__("subprocess").CompletedProcess(cmd,0,stdout="ok",stderr="")
                        if cmd[:2]==["go","version"]:
                            return __import__("subprocess").CompletedProcess(cmd,0,stdout="go version fixture",stderr="")
                        return __import__("subprocess").CompletedProcess(cmd,0,stdout="",stderr="")
                    checkpoints=[]
                    original_write=run.write_manifest
                    def capture_checkpoint(directory,manifest):
                        checkpoints.append(json.loads(json.dumps(manifest)))
                        original_write(directory,manifest)
                    with mock.patch.object(run.sys,"argv",args),mock.patch.object(run.platform,"platform",return_value="fixture darwin"),mock.patch.object(run.platform,"processor",return_value="fixture cpu"),mock.patch.object(run.subprocess,"run",side_effect=fake_run),mock.patch.object(run,"write_manifest",side_effect=capture_checkpoint):
                        rc=run.main()
                    manifest=json.loads((out/"manifest.json").read_text())
                    self.assertEqual(manifest["expected_command_count"],1)
                    self.assertEqual(Path(manifest["commands"][0]["argv"][0]).name,"lamp")
                    if mode=="success":
                        self.assertEqual(rc,0);self.assertEqual(manifest["completion_status"],"complete")
                    elif mode=="interrupted":
                        self.assertEqual(rc,130);self.assertEqual(manifest["completion_status"],"incomplete")
                        self.assertEqual(manifest["run_state"],"interrupted")
                        self.assertEqual(manifest["commands"][0]["status"],"interrupted")
                        self.assertEqual(checkpoints[0]["completion_status"],"incomplete")
                        self.assertEqual(checkpoints[0]["run_state"],"preparing")
                        self.assertTrue(any(x.get("commands") and x["commands"][0]["status"]=="started" for x in checkpoints))
                    else:
                        self.assertEqual(rc,1);self.assertEqual(manifest["completion_status"],"incomplete")
                        if mode=="failed":
                            self.assertTrue((out/"run_01"/run.RAW).is_file())
                            self.assertEqual(json.loads((out/"summary.json").read_text()),[])
            finally:
                run.ROOT=old_root;run.CONFIGS=old_configs

if __name__=="__main__":unittest.main()
