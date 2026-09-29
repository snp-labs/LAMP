package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"example.com/lamp/crypto/zkmatrix"
)

// The certificate intentionally proves only the matrix products represented
// by the official GPT-2 tensor generator. It does not prove graph wiring or
// public input/output binding across the independently committed claims.
const gpt2BaselineScope = "official_gpt2_graph_matmul_claims_only"

func gpt2SequenceLength(seqLog int) (int, error) {
	if seqLog < 0 || seqLog > 10 {
		return 0, fmt.Errorf("GPT-2 sequence log must be in [0,10], got %d", seqLog)
	}
	return 1 << seqLog, nil
}

type matrixClaimGroup struct {
	m, inner, n int
	claims      []claimSpec
}

type gpt2BaselineGroupResult struct {
	Rows                 int      `json:"rows"`
	Inner                int      `json:"inner"`
	Columns              int      `json:"columns"`
	Claims               int      `json:"claims"`
	ClaimIDs             []int    `json:"claim_ids,omitempty"`
	ClaimTags            []string `json:"claim_tags,omitempty"`
	SetupSeconds         float64  `json:"setup_seconds_shared_once,omitempty"`
	SRSPoints            int      `json:"srs_g1_points,omitempty"`
	SRSCompressedBytes   int      `json:"srs_compressed_bytes,omitempty"`
	CommitSeconds        float64  `json:"commit_seconds,omitempty"`
	ProveSeconds         float64  `json:"prove_seconds,omitempty"`
	FullOnlineSeconds    float64  `json:"full_online_seconds_commit_plus_prove,omitempty"`
	PrecommittedSeconds  float64  `json:"precommitted_online_seconds,omitempty"`
	VerifySeconds        float64  `json:"verify_seconds,omitempty"`
	SerializedProofBytes int      `json:"serialized_proof_bytes,omitempty"`
	StatementBytes       int      `json:"statement_bytes,omitempty"`
	Verified             bool     `json:"verified,omitempty"`
}

type gpt2BaselineReport struct {
	ExecutionStatus        string                    `json:"execution_status"`
	Scope                  string                    `json:"workload"`
	Certificate            string                    `json:"certificate"`
	GraphWiringCertified   bool                      `json:"graph_wiring_certified"`
	InputOutputBinding     bool                      `json:"public_input_output_binding_certified"`
	SequenceLength         int                       `json:"sequence_length"`
	Repetitions            int                       `json:"repetitions,omitempty"`
	Threads                int                       `json:"threads,omitempty"`
	Claims                 int                       `json:"claims"`
	VerifiedClaims         int                       `json:"verified_claims"`
	Groups                 []gpt2BaselineGroupResult `json:"groups"`
	Runs                   []gpt2BaselineRun         `json:"runs,omitempty"`
	MatrixComputeSeconds   float64                   `json:"matrix_compute_seconds_excluded_from_prover"`
	GraphGenerationSeconds float64                   `json:"graph_generation_seconds,omitempty"`
	SetupSecondsTotal      float64                   `json:"setup_seconds_total_shared_once"`
	Host                   map[string]any            `json:"host,omitempty"`
	Source                 map[string]string         `json:"source,omitempty"`
	BinarySHA256           string                    `json:"binary_sha256,omitempty"`
	DataProvenance         string                    `json:"data_provenance"`
	SRSSizeDefinition      string                    `json:"srs_size_definition"`
	ResourceGuard          string                    `json:"resource_guard,omitempty"`
}

type gpt2BaselineRun struct {
	Repetition int                       `json:"repetition"`
	Groups     []gpt2BaselineGroupResult `json:"groups"`
}

func groupMatrixClaims(specs []claimSpec) ([]matrixClaimGroup, error) {
	byShape := make(map[[3]int][]claimSpec)
	for _, spec := range specs {
		if spec.A == nil || spec.B == nil || spec.C == nil {
			return nil, fmt.Errorf("claim %q has nil tensor", spec.name)
		}
		if spec.A.rows != spec.C.rows || spec.A.cols != spec.B.rows || spec.B.cols != spec.C.cols {
			return nil, fmt.Errorf("claim %q tensor dimensions do not align", spec.name)
		}
		key := [3]int{spec.A.rows, spec.A.cols, spec.B.cols}
		byShape[key] = append(byShape[key], spec)
	}
	keys := make([][3]int, 0, len(byShape))
	for key := range byShape {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		for k := 0; k < 3; k++ {
			if keys[i][k] != keys[j][k] {
				return keys[i][k] < keys[j][k]
			}
		}
		return false
	})
	groups := make([]matrixClaimGroup, 0, len(keys))
	for _, key := range keys {
		groups = append(groups, matrixClaimGroup{m: key[0], inner: key[1], n: key[2], claims: byShape[key]})
	}
	return groups, nil
}

func planGPT2ZKMatrixBaseline(seqLen int) (gpt2BaselineReport, error) {
	if seqLen <= 0 || seqLen&(seqLen-1) != 0 {
		return gpt2BaselineReport{}, errors.New("sequence length must be a positive power of two")
	}
	_, specs := buildGPT2MediumTensorShapes(seqLen)
	groups, err := groupMatrixClaims(specs)
	if err != nil {
		return gpt2BaselineReport{}, err
	}
	report := gpt2BaselineReport{ExecutionStatus: "planned_only", Scope: gpt2BaselineScope, Certificate: "grouped_zkmatrix_matmul_claims_only", GraphWiringCertified: false, InputOutputBinding: false, SequenceLength: seqLen, Claims: len(specs), DataProvenance: "official GPT-2 medium shape generator; no matrix values generated and no SRS setup performed", SRSSizeDefinition: "compressed point bytes for 2 G1 power arrays plus 3 G2 anchors; excludes the fixed hiding point and codec/framing bytes"}
	for _, group := range groups {
		planned := gpt2BaselineGroupResult{Rows: group.m, Inner: group.inner, Columns: group.n, Claims: len(group.claims)}
		for _, claim := range group.claims {
			planned.ClaimIDs = append(planned.ClaimIDs, claim.id)
			planned.ClaimTags = append(planned.ClaimTags, claim.name)
		}
		report.Groups = append(report.Groups, planned)
	}
	return report, nil
}

func proveGPT2ClaimGroup(group matrixClaimGroup, pp *zkmatrix.PublicParams, setupSeconds float64) (gpt2BaselineGroupResult, error) {
	result := gpt2BaselineGroupResult{Rows: group.m, Inner: group.inner, Columns: group.n, Claims: len(group.claims), SetupSeconds: setupSeconds}
	result.SRSPoints, result.SRSCompressedBytes = pp.SetupSRSInfo()
	statements := make(zkmatrix.BatchStatement, len(group.claims))
	witnesses := make(zkmatrix.BatchWitness, len(group.claims))
	start := time.Now()
	for i, claim := range group.claims {
		s, ra, rb, err := zkmatrix.CommitInputs(pp, claim.A.data, claim.B.data)
		if err != nil {
			return result, fmt.Errorf("%s input commitment: %w", claim.name, err)
		}
		sc, rc, err := zkmatrix.CommitOutput(pp, claim.C.data)
		if err != nil {
			return result, fmt.Errorf("%s output commitment: %w", claim.name, err)
		}
		s.Cc = sc.Cc
		statements[i] = s
		witnesses[i] = zkmatrix.Witness{A: claim.A.data, B: claim.B.data, C: claim.C.data, RA: ra, RB: rb, RC: rc}
	}
	result.CommitSeconds = time.Since(start).Seconds()
	var proofBytes []byte
	start = time.Now()
	if len(group.claims) == 1 {
		proof, err := zkmatrix.ProveOptimized(pp, statements[0], witnesses[0])
		result.ProveSeconds = time.Since(start).Seconds()
		if err != nil {
			return result, err
		}
		proofBytes, err = proof.MarshalBinaryFor(pp)
		if err != nil {
			return result, err
		}
		statementBytes, err := zkmatrix.MarshalStatement(pp, statements[0])
		if err != nil {
			return result, err
		}
		decodedStatement, err := zkmatrix.UnmarshalStatement(pp, statementBytes)
		if err != nil {
			return result, err
		}
		decodedProof, err := zkmatrix.UnmarshalOptimizedProof(pp, proofBytes)
		if err != nil {
			return result, err
		}
		start = time.Now()
		err = zkmatrix.VerifyOptimized(pp, decodedStatement, decodedProof)
		result.VerifySeconds = time.Since(start).Seconds()
		if err != nil {
			return result, err
		}
		result.StatementBytes = len(statementBytes)
	} else {
		proof, err := zkmatrix.ProveBatch(pp, statements, witnesses)
		result.ProveSeconds = time.Since(start).Seconds()
		if err != nil {
			return result, err
		}
		proofBytes, err = proof.MarshalBinaryFor(pp)
		if err != nil {
			return result, err
		}
		decodedProof, err := zkmatrix.UnmarshalBatchProof(pp, proofBytes)
		if err != nil {
			return result, err
		}
		decodedStatements := make(zkmatrix.BatchStatement, len(statements))
		for i, statement := range statements {
			encoded, err := zkmatrix.MarshalStatement(pp, statement)
			if err != nil {
				return result, err
			}
			decodedStatements[i], err = zkmatrix.UnmarshalStatement(pp, encoded)
			if err != nil {
				return result, err
			}
			result.StatementBytes += len(encoded)
		}
		start = time.Now()
		err = zkmatrix.VerifyBatch(pp, decodedStatements, decodedProof)
		result.VerifySeconds = time.Since(start).Seconds()
		if err != nil {
			return result, err
		}
	}
	result.SerializedProofBytes = len(proofBytes)
	result.PrecommittedSeconds = result.ProveSeconds
	result.FullOnlineSeconds = result.CommitSeconds + result.ProveSeconds
	result.Verified = true
	return result, nil
}

func runGPT2ZKMatrixBaseline(seqLen, repetitions, threads int) (gpt2BaselineReport, error) {
	if seqLen <= 0 || seqLen&(seqLen-1) != 0 {
		return gpt2BaselineReport{}, errors.New("sequence length must be a positive power of two")
	}
	if repetitions <= 0 || threads <= 0 {
		return gpt2BaselineReport{}, errors.New("repetitions and threads must be positive")
	}
	host := baselineHostInfo()
	if err := baselineResourceGuard(host); err != nil {
		return gpt2BaselineReport{}, err
	}
	runtime.GOMAXPROCS(threads)
	generationStart := time.Now()
	tensors, specs, matrixCompute := buildGPT2MediumTensors(seqLen)
	_ = tensors // the claim specs retain every tensor needed by the certificate
	generationSeconds := time.Since(generationStart).Seconds()
	groups, err := groupMatrixClaims(specs)
	if err != nil {
		return gpt2BaselineReport{}, err
	}
	report := gpt2BaselineReport{ExecutionStatus: "completed", Scope: gpt2BaselineScope, Certificate: "grouped_zkmatrix_matmul_claims_only", GraphWiringCertified: false, InputOutputBinding: false, SequenceLength: seqLen, Repetitions: repetitions, Threads: threads, Claims: len(specs), MatrixComputeSeconds: matrixCompute, GraphGenerationSeconds: generationSeconds, Host: host, Source: baselineSourceInfo(), BinarySHA256: baselineBinaryHash(), DataProvenance: "official buildGPT2MediumTensors using field SetRandom; one generated graph is reused across repetitions and commitments use fresh blindings", SRSSizeDefinition: "compressed point bytes for 2 G1 power arrays plus 3 G2 anchors; excludes the fixed hiding point and codec/framing bytes", ResourceGuard: "execution requires at least 32 logical CPUs and 240 GiB usable memory for a nominal 256 GiB host; --baseline-plan is resource-free"}
	for _, group := range groups {
		planGroup := gpt2BaselineGroupResult{Rows: group.m, Inner: group.inner, Columns: group.n, Claims: len(group.claims)}
		for _, claim := range group.claims {
			planGroup.ClaimIDs = append(planGroup.ClaimIDs, claim.id)
			planGroup.ClaimTags = append(planGroup.ClaimTags, claim.name)
		}
		report.Groups = append(report.Groups, planGroup)
		start := time.Now()
		pp, err := zkmatrix.SetupWithLimit(group.m, group.inner, group.n, 1<<24)
		setupSeconds := time.Since(start).Seconds()
		if err != nil {
			return report, fmt.Errorf("setup %dx%dx%d: %w", group.m, group.inner, group.n, err)
		}
		report.SetupSecondsTotal += setupSeconds
		for rep := 1; rep <= repetitions; rep++ {
			result, err := proveGPT2ClaimGroup(group, pp, 0)
			if err != nil {
				return report, fmt.Errorf("repetition %d group %dx%dx%d: %w", rep, group.m, group.inner, group.n, err)
			}
			if rep == 1 {
				result.SetupSeconds = setupSeconds
			}
			runIdx := rep - 1
			if len(report.Runs) <= runIdx {
				report.Runs = append(report.Runs, gpt2BaselineRun{Repetition: rep})
			}
			report.Runs[runIdx].Groups = append(report.Runs[runIdx].Groups, result)
			report.VerifiedClaims += result.Claims
		}
	}
	return report, nil
}

func baselineResourceGuard(host map[string]any) error {
	cpu, _ := host["cpu_count"].(int)
	memory, _ := host["memory_bytes"].(uint64)
	if cpu < 32 || memory < 240*(uint64(1)<<30) {
		return fmt.Errorf("resource guard: GPT-2 graph execution requires at least 32 logical CPUs and usable memory near the 240 GiB floor for a nominal 256 GiB host (detected CPUs=%d memory_bytes=%d); use --baseline-plan", cpu, memory)
	}
	return nil
}

func baselineHostInfo() map[string]any {
	info := map[string]any{"cpu_count": runtime.NumCPU(), "goos": runtime.GOOS, "goarch": runtime.GOARCH, "go_version": runtime.Version()}
	if runtime.GOOS == "darwin" {
		if generic, err := exec.Command("uname", "-m").Output(); err == nil {
			info["platform_processor"] = strings.TrimSpace(string(generic))
		}
		for _, key := range []string{"hw.memsize", "machdep.cpu.brand_string"} {
			out, err := exec.Command("sysctl", "-n", key).Output()
			if err != nil {
				continue
			}
			value := strings.TrimSpace(string(out))
			if key == "hw.memsize" {
				var bytes uint64
				_, _ = fmt.Sscan(value, &bytes)
				info["memory_bytes"] = bytes
			} else {
				info["processor"] = value
			}
		}
	} else if b, err := os.ReadFile("/proc/meminfo"); err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			if strings.HasPrefix(line, "MemTotal:") {
				var kib uint64
				_, _ = fmt.Sscanf(line, "MemTotal: %d kB", &kib)
				info["memory_bytes"] = kib * 1024
				break
			}
		}
		if b, err = os.ReadFile("/proc/cpuinfo"); err == nil {
			for _, line := range strings.Split(string(b), "\n") {
				if strings.HasPrefix(strings.ToLower(line), "model name") {
					info["processor"] = strings.TrimSpace(strings.SplitN(line, ":", 2)[1])
					break
				}
			}
		}
	}
	if _, ok := info["memory_bytes"]; !ok {
		info["memory_bytes"] = uint64(0)
	}
	if _, ok := info["processor"]; !ok {
		info["processor"] = "unknown"
	}
	return info
}

func baselineSourceInfo() map[string]string {
	root, _ := os.Getwd()
	head, _ := exec.Command("git", "-C", root, "rev-parse", "HEAD").Output()
	digest, count, err := baselineSourceFingerprint(root)
	if err != nil {
		digest = "unavailable"
	}
	return map[string]string{"head": strings.TrimSpace(string(head)), "source_hash": digest, "source_files_hashed": fmt.Sprint(count), "source_hash_scope": "all project Go files, nested go.mod/go.sum/go.work files, and comparison runner/config; excludes docs, env files, and benchmark/comparison results"}
}

func baselineSourceFingerprint(root string) (string, int, error) {
	var files []string
	excluded := map[string]bool{".git": true, "vendor": true, "node_modules": true, "__pycache__": true, ".venv": true, "docs": true, "results": true, "result": true}
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		if entry.IsDir() {
			if rel != "." {
				for _, part := range strings.Split(rel, string(filepath.Separator)) {
					if excluded[part] {
						return filepath.SkipDir
					}
				}
				if rel == filepath.Join("benchmark", "comparison") {
					return filepath.SkipDir
				}
			}
			return nil
		}
		if !entry.Type().IsRegular() {
			return nil
		}
		name := entry.Name()
		include := filepath.Ext(name) == ".go" || name == "go.mod" || name == "go.sum" || name == "go.work" || name == "go.work.sum"
		relSlash := filepath.ToSlash(rel)
		include = include || relSlash == "scripts/comparison/run.py" || relSlash == "scripts/comparison/test_run.py" || relSlash == "scripts/comparison/configs.json"
		if include {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		return "", 0, err
	}
	sort.Strings(files)
	h := sha256.New()
	for _, path := range files {
		rel, _ := filepath.Rel(root, path)
		data, err := os.ReadFile(path)
		if err != nil {
			return "", len(files), err
		}
		_, _ = h.Write([]byte(filepath.ToSlash(rel) + "\x00"))
		fileHash := sha256.Sum256(data)
		_, _ = h.Write(fileHash[:])
	}
	return hex.EncodeToString(h.Sum(nil)), len(files), nil
}

func baselineBinaryHash() string {
	path, err := os.Executable()
	if err != nil {
		return "unknown"
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "unknown"
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
