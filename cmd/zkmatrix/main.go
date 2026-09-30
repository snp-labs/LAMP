package main

import (
	"encoding/csv"
	"flag"
	"fmt"
	"math/rand"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"

	"example.com/lamp/crypto/zkmatrix"
	"example.com/lamp/matrix"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

func main() {
	k := flag.Int("K", 2, "log2 of square matrix dimension")
	reps := flag.Int("repetitions", 1, "number of measured proofs")
	warmups := flag.Int("warmups", 0, "full proof/verification warmups excluded from output")
	threads := flag.Int("threads", runtime.NumCPU(), "GOMAXPROCS value")
	seed := flag.Int64("seed", 1, "deterministic input-data seed; proof randomness remains cryptographic")
	output := flag.String("output", "", "new CSV output path; existing files are never overwritten")
	variant := flag.String("variant", "accelerated", "verifier variant: accelerated or direct")
	batchSize := flag.Int("batch", 0, "Algorithm 6 batch claim count; 0 runs optimized single-proof mode")
	mFlag := flag.Int("m", 0, "optional rectangular output rows")
	innerFlag := flag.Int("inner", 0, "optional rectangular inner dimension")
	nFlag := flag.Int("n", 0, "optional rectangular output columns")
	maxElements := flag.Int("max-matrix-elements", 1<<20, "explicit per-matrix field-element limit; raise only with sufficient server memory")
	flag.Parse()
	if *variant != "accelerated" && *variant != "direct" {
		fatal("--variant must be accelerated or direct")
	}
	if *k < 1 || *k > 15 || *reps < 1 || *threads < 1 || *warmups < 0 || *batchSize < 0 || *batchSize > 10000 {
		fatal("K, repetitions and threads must be positive, K <= 15, and warmups nonnegative")
	}
	if *maxElements < 1 {
		fatal("--max-matrix-elements must be positive")
	}
	runtime.GOMAXPROCS(*threads)
	base := 1 << *k
	m, inner, n := base, base, base
	if *mFlag > 0 {
		m = *mFlag
	}
	if *innerFlag > 0 {
		inner = *innerFlag
	}
	if *nFlag > 0 {
		n = *nFlag
	}
	if m > 1<<15 || inner > 1<<15 || n > 1<<15 || int64(m)*int64(inner) > int64(*maxElements) || int64(inner)*int64(n) > int64(*maxElements) || int64(m)*int64(n) > int64(*maxElements) {
		fatal("dimensions exceed --max-matrix-elements or the dimension bound")
	}
	path := *output
	if path == "" {
		path = fmt.Sprintf("zkmatrix_optimized_%dx%dx%d_%d.csv", m, inner, n, time.Now().UnixNano())
	}
	f, e := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
	if e != nil {
		fatal("create CSV without overwrite: %v", e)
	}
	defer f.Close()
	cw := csv.NewWriter(f)
	header := []string{"run", "variant", "batch_q", "m", "inner", "n", "threads", "runtime_num_cpu", "seed_base", "effective_seed", "setup_seconds", "setup_srs_g1_points", "setup_srs_bytes_compressed", "matmul_seconds", "commit_seconds", "prove_seconds", "totalprove_seconds", "verify_seconds", "proof_bytes", "commit_bytes", "total_bytes", "verified", "setup_mode", "curve", "goos", "goarch", "go_version", "cpu", "git_commit"}
	if e = cw.Write(header); e != nil {
		fatal("CSV header: %v", e)
	}
	setupStart := time.Now()
	pp, e := zkmatrix.SetupWithLimit(m, inner, n, *maxElements)
	setupSeconds := time.Since(setupStart).Seconds()
	if e != nil {
		fatal("setup: %v", e)
	}
	srsPoints, srsBytes := pp.SetupSRSInfo()
	// Warmups are complete proofs over the same setup and are omitted from output.
	for w := 0; w < *warmups; w++ {
		effective := *seed + int64(w-*warmups)*7919
		if *batchSize == 0 {
			_, e = runOne(pp, m, inner, n, effective, *variant)
		} else {
			_, e = runBatch(pp, m, inner, n, effective, *variant, *batchSize)
		}
		if e != nil {
			fatal("warmup %d: %v", w+1, e)
		}
	}
	for run := 1; run <= *reps; run++ {
		effective := *seed + int64(run-1)*7919
		var r runResult
		if *batchSize == 0 {
			r, e = runOne(pp, m, inner, n, effective, *variant)
		} else {
			r, e = runBatch(pp, m, inner, n, effective, *variant, *batchSize)
		}
		if e != nil {
			fatal("run %d: %v", run, e)
		}
		total := r.commit + r.prove
		q := *batchSize
		if q == 0 {
			q = 1
		}
		values := []string{strconv.Itoa(run), "independent_zkmatrix_optimized_bn254_" + *variant, strconv.Itoa(q), strconv.Itoa(m), strconv.Itoa(inner), strconv.Itoa(n), strconv.Itoa(*threads), strconv.Itoa(runtime.NumCPU()), strconv.FormatInt(*seed, 10), strconv.FormatInt(effective, 10), num(setupSeconds), strconv.Itoa(srsPoints), strconv.Itoa(srsBytes), num(r.matmul), num(r.commit), num(r.prove), num(total), num(r.verify), strconv.Itoa(r.proofBytes), strconv.Itoa(r.commitBytes), strconv.Itoa(r.proofBytes + r.commitBytes), "true", "single_party_experimental", "BN254", runtime.GOOS, runtime.GOARCH, runtime.Version(), cpuName(), gitCommit()}
		if e = cw.Write(values); e != nil {
			fatal("CSV row: %v", e)
		}
		cw.Flush()
		if e = cw.Error(); e != nil {
			fatal("CSV write: %v", e)
		}
		fmt.Printf("run %d/%d: %dx%dx%d q=%d verified, proof=%d bytes, totalprove=%.6fs\n", run, *reps, m, inner, n, q, r.proofBytes, total)
	}
	cw.Flush()
	if e = cw.Error(); e != nil {
		fatal("CSV flush: %v", e)
	}
	fmt.Println("CSV:", path)
}

type runResult struct {
	matmul, commit, prove, verify float64
	proofBytes, commitBytes       int
}

func runOne(pp *zkmatrix.PublicParams, m, k, n int, seed int64, variant string) (runResult, error) {
	var out runResult
	r := rand.New(rand.NewSource(seed))
	a, b := randMatrix(r, m, k), randMatrix(r, k, n)
	start := time.Now()
	c, e := multiply(a, b)
	out.matmul = time.Since(start).Seconds()
	if e != nil {
		return out, e
	}
	start = time.Now()
	s, ra, rb, e := zkmatrix.CommitInputs(pp, a, b)
	if e != nil {
		return out, e
	}
	sc, rc, e := zkmatrix.CommitOutput(pp, c)
	if e != nil {
		return out, e
	}
	s.Cc = sc.Cc
	out.commit = time.Since(start).Seconds()
	w := zkmatrix.Witness{A: a, B: b, C: c, RA: ra, RB: rb, RC: rc}
	start = time.Now()
	proof, e := zkmatrix.ProveOptimized(pp, s, w)
	out.prove = time.Since(start).Seconds()
	if e != nil {
		return out, e
	}
	encoded, e := proof.MarshalBinaryFor(pp)
	if e != nil {
		return out, e
	}
	statement, e := zkmatrix.MarshalStatement(pp, s)
	if e != nil {
		return out, e
	}
	decodedStatement, e := zkmatrix.UnmarshalStatement(pp, statement)
	if e != nil {
		return out, fmt.Errorf("decode statement payload: %w", e)
	}
	decodedProof, e := zkmatrix.UnmarshalOptimizedProof(pp, encoded)
	if e != nil {
		return out, fmt.Errorf("decode proof payload: %w", e)
	}
	out.proofBytes = len(encoded)
	out.commitBytes = len(statement)
	start = time.Now()
	if variant == "accelerated" {
		e = zkmatrix.VerifyOptimized(pp, s, proof)
	} else {
		e = zkmatrix.VerifyOptimizedDirect(pp, s, proof)
	}
	out.verify = time.Since(start).Seconds()
	if e != nil {
		return out, fmt.Errorf("verification failed: %w", e)
	}
	// Verify the exact canonical payloads outside the timed verifier interval.
	if variant == "direct" {
		e = zkmatrix.VerifyOptimizedDirect(pp, decodedStatement, decodedProof)
	} else {
		e = zkmatrix.VerifyOptimized(pp, decodedStatement, decodedProof)
	}
	if e != nil {
		return out, fmt.Errorf("decoded payload verification failed: %w", e)
	}
	return out, nil
}

func runBatch(pp *zkmatrix.PublicParams, m, k, n int, seed int64, variant string, q int) (runResult, error) {
	var out runResult
	r := rand.New(rand.NewSource(seed))
	ss := make(zkmatrix.BatchStatement, q)
	ws := make(zkmatrix.BatchWitness, q)
	for i := 0; i < q; i++ {
		a, b := randMatrix(r, m, k), randMatrix(r, k, n)
		mulStart := time.Now()
		c, e := multiply(a, b)
		out.matmul += time.Since(mulStart).Seconds()
		if e != nil {
			return out, e
		}
		cmStart := time.Now()
		s, ra, rb, e := zkmatrix.CommitInputs(pp, a, b)
		if e != nil {
			return out, e
		}
		sc, rc, e := zkmatrix.CommitOutput(pp, c)
		if e != nil {
			return out, e
		}
		s.Cc = sc.Cc
		out.commit += time.Since(cmStart).Seconds()
		ss[i] = s
		ws[i] = zkmatrix.Witness{A: a, B: b, C: c, RA: ra, RB: rb, RC: rc}
	}
	proveStart := time.Now()
	proof, e := zkmatrix.ProveBatch(pp, ss, ws)
	out.prove = time.Since(proveStart).Seconds()
	if e != nil {
		return out, e
	}
	encoded, e := proof.MarshalBinaryFor(pp)
	if e != nil {
		return out, e
	}
	decodedProof, e := zkmatrix.UnmarshalBatchProof(pp, encoded)
	if e != nil {
		return out, fmt.Errorf("decode batch proof payload: %w", e)
	}
	out.proofBytes = len(encoded)
	decodedStatements := make(zkmatrix.BatchStatement, len(ss))
	for i, s := range ss {
		b, e := zkmatrix.MarshalStatement(pp, s)
		if e != nil {
			return out, e
		}
		out.commitBytes += len(b)
		decoded, e := zkmatrix.UnmarshalStatement(pp, b)
		if e != nil {
			return out, fmt.Errorf("decode batch statement payload: %w", e)
		}
		decodedStatements[i] = decoded
	}
	verifyStart := time.Now()
	if variant == "direct" {
		e = zkmatrix.VerifyBatchDirect(pp, ss, proof)
	} else {
		e = zkmatrix.VerifyBatch(pp, ss, proof)
	}
	out.verify = time.Since(verifyStart).Seconds()
	if e != nil {
		return out, fmt.Errorf("batch verification failed: %w", e)
	}
	// Verify the exact canonical statement and proof payloads outside the timed interval.
	if variant == "direct" {
		e = zkmatrix.VerifyBatchDirect(pp, decodedStatements, decodedProof)
	} else {
		e = zkmatrix.VerifyBatch(pp, decodedStatements, decodedProof)
	}
	if e != nil {
		return out, fmt.Errorf("decoded batch payload verification failed: %w", e)
	}
	return out, nil
}

func randMatrix(r *rand.Rand, rows, cols int) [][]fr.Element {
	m := make([][]fr.Element, rows)
	var raw [32]byte
	for i := range m {
		m[i] = make([]fr.Element, cols)
		for j := range m[i] {
			for k := 0; k < 4; k++ {
				v := r.Uint64()
				for q := 0; q < 8; q++ {
					raw[k*8+q] = byte(v >> (56 - 8*q))
				}
			}
			for m[i][j].SetBytesCanonical(raw[:]) != nil {
				for k := 0; k < 4; k++ {
					v := r.Uint64()
					for q := 0; q < 8; q++ {
						raw[k*8+q] = byte(v >> (56 - 8*q))
					}
				}
			}
		}
	}
	return m
}
func multiply(a, b [][]fr.Element) ([][]fr.Element, error) {
	if len(a) == 0 || len(b) == 0 {
		return nil, fmt.Errorf("invalid matrix dimensions")
	}
	inner, cols := len(a[0]), len(b[0])
	if inner == 0 || cols == 0 || inner != len(b) {
		return nil, fmt.Errorf("invalid matrix dimensions")
	}
	for i := range a {
		if len(a[i]) != inner {
			return nil, fmt.Errorf("invalid matrix dimensions: A row %d has length %d, want %d", i, len(a[i]), inner)
		}
	}
	for i := range b {
		if len(b[i]) != cols {
			return nil, fmt.Errorf("invalid matrix dimensions: B row %d has length %d, want %d", i, len(b[i]), cols)
		}
	}
	return matrix.MatMulRect(a, b, len(a), inner, cols), nil
}
func num(v float64) string { return strconv.FormatFloat(v, 'f', 9, 64) }
func cpuName() string {
	if runtime.GOOS == "darwin" {
		if b, e := exec.Command("sysctl", "-n", "machdep.cpu.brand_string").Output(); e == nil {
			return strings.TrimSpace(string(b))
		}
	}
	if runtime.GOOS == "linux" {
		if b, e := os.ReadFile("/proc/cpuinfo"); e == nil {
			for _, line := range strings.Split(string(b), "\n") {
				if strings.HasPrefix(line, "model name") || strings.HasPrefix(line, "Hardware") {
					parts := strings.SplitN(line, ":", 2)
					if len(parts) == 2 {
						return strings.TrimSpace(parts[1])
					}
				}
			}
		}
	}
	return runtime.GOARCH + " (" + strconv.Itoa(runtime.NumCPU()) + " logical CPUs)"
}
func gitCommit() string {
	if b, e := exec.Command("git", "rev-parse", "HEAD").Output(); e == nil {
		return strings.TrimSpace(string(b))
	}
	return "unknown"
}
func fatal(f string, a ...any) { fmt.Fprintf(os.Stderr, "zkmatrix: "+f+"\n", a...); os.Exit(1) }
