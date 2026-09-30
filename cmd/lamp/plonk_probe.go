package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"math"
	"runtime"
	"sync"
	"time"

	"example.com/lamp/benchmark"
	"example.com/lamp/circuit"
	"example.com/lamp/crypto"
	"example.com/lamp/matrix"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/fft"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/test/unsafekzg"
)

// PLONKProbeResult holds timing and proof data from a PLONK backend probe
type PLONKProbeResult struct {
	LogK              int
	Rho               string
	N                 int
	NumQueries        int
	DistinctQueries   int
	Constraints       int
	CompileTime       float64
	MatrixComputeTime float64
	DataCommitTime    float64
	EncodingTime      float64
	KZGSRSTime        float64
	SetupTime         float64
	ProveTime         float64
	VerifyTime        float64
	ProofSizeBytes    int
	VerificationOK    bool
	PeakMemoryBytes   uint64
	HostGoOS          string
	HostGoArch        string
	HostGoVersion     string
	HostNumCPU        int
}

// runPLONKProbe executes a single PLONK backend probe experiment.
func runPLONKProbe(logK int, rhoStr string, L int) PLONKProbeResult {
	K := 1 << logK
	var N int
	switch rhoStr {
	case "1/2":
		N = K << 1
	case "1/4":
		N = K << 2
	case "1/8":
		N = K << 3
	default:
		log.Fatalf("unsupported rho %q; use 1/2, 1/4, or 1/8", rhoStr)
	}
	depth := int(math.Log2(float64(N)))
	field := ecc.BN254.ScalarField()

	fmt.Printf("\n🔍 [PLONK Probe] logK=%d, K=%d, N=%d, L=%d\n", logK, K, N, L)
	fmt.Println("  ⚠️  COMPONENT-ONLY PROBE — not a production or full LAMP replacement")

	// =========================================================================
	// 0. Precompute domains and roots
	// =========================================================================
	domainN := fft.NewDomain(uint64(N))
	rootsN := crypto.GetDomainRoots(domainN, N)
	weightsN := crypto.PrecomputeBarycentricWeights(rootsN)

	domainK := fft.NewDomain(uint64(K))
	rootsK := crypto.GetDomainRoots(domainK, K)
	weightsK := crypto.PrecomputeBarycentricWeights(rootsK)

	// =========================================================================
	// 1. Compute Matrices A, B, C (shared with Groth16)
	// =========================================================================
	fmt.Println("  Matrix computation and encoding...")
	startMatCompute := time.Now()
	matA := matrix.GenerateRandomMatrix(K, K)
	matB := matrix.GenerateRandomMatrix(K, K)
	matC := matrix.MatMul(matA, matB, K)
	matrixComputeTime := time.Since(startMatCompute).Seconds()

	// =========================================================================
	// 2. Encode & prepare vectors (shared with Groth16)
	// =========================================================================
	startMatCommit := time.Now()

	var colsEncA, colsEncB, colsEncC [][]fr.Element
	var errA, errB, errC error
	var rootABC fr.Element
	var leavesABC []bn254.G1Affine

	var wg sync.WaitGroup
	wg.Add(3)
	startMatrixEncoding := time.Now()

	go func() {
		defer wg.Done()
		encoder := crypto.NewEncoder(K, N)
		colsEncA, errA = encoder.EncodeRowsToColumns(matA)
	}()

	go func() {
		defer wg.Done()
		encoder := crypto.NewEncoder(K, N)
		colsEncB, errB = encoder.EncodeRowsToColumns(matB)
	}()

	go func() {
		defer wg.Done()
		encoder := crypto.NewEncoder(K, N)
		colsEncC, errC = encoder.EncodeRowsToColumns(matC)
	}()

	wg.Wait()
	matrixEncodingTime := time.Since(startMatrixEncoding).Seconds()
	if errA != nil || errB != nil || errC != nil {
		log.Fatalf("❌ Matrix encoding failed: A=%v B=%v C=%v", errA, errB, errC)
	}

	ckABC := crypto.SetupCommitKey(3 * K)
	leavesABC, _ = crypto.BatchPedersenCommitABCBlinded(colsEncA, colsEncB, colsEncC, ckABC)
	_, rootABC = crypto.BuildMerkleTreeFromGroupElements(leavesABC, depth)

	CmABC := crypto.HashElementsMiMC(rootABC)
	ChallengeR := crypto.HashElements(CmABC)
	ChallengeRPowers := matrix.Powers(ChallengeR, K)
	ChallengeB := crypto.HashElements(CmABC, uint64Element(challengeBLabel))
	ChallengeBPowers := matrix.Powers(ChallengeB, K)

	encoder := crypto.NewEncoder(K, N)
	vecX := matrix.VecMatMul(ChallengeRPowers, matA, K)
	vecYZ := matrix.VecMatMul(vecX, matB, K)
	vecBTest := matrix.VecMatMul(ChallengeBPowers, matB, K)

	startVectorEncoding := time.Now()
	_, encX, _ := encoder.Encode(vecX)
	_, encYZ, _ := encoder.Encode(vecYZ)
	_, encBTest, err := encoder.Encode(vecBTest)
	vectorEncodingTime := time.Since(startVectorEncoding).Seconds()
	if err != nil {
		log.Fatalf("❌ Vector encoding failed: %v", err)
	}

	colsXYZ := combineXYZScalars(encX, encYZ, encBTest)
	ckXYZ := crypto.SetupCommitKey(3)
	leavesXYZ, _ := crypto.BatchPedersenCommitBlinded(colsXYZ, ckXYZ)
	_, rootXYZ := crypto.BuildMerkleTreeFromGroupElements(leavesXYZ, depth)

	CmXYZ := crypto.HashElementsMiMC(rootXYZ)
	indices, err := crypto.GenerateIndices(CmXYZ, N, L)
	if err != nil {
		log.Fatalf("❌ Query index derivation failed: %v", err)
	}
	unique := make(map[int]struct{}, len(indices))
	for _, index := range indices {
		unique[index] = struct{}{}
	}
	fmt.Printf("  Distinct query indices: %d/%d\n", len(unique), L)

	encodingTime := matrixEncodingTime + vectorEncodingTime
	dataCommitTime := time.Since(startMatCommit).Seconds()

	// =========================================================================
	// 3. Create empty circuit for compilation
	// =========================================================================
	fmt.Println("  Circuit compilation...")
	compileStart := time.Now()

	emptyCircuit := &circuit.LAMPCircuit{
		K: K, N: N, Depth: depth,
		DomainK: rootsK, WeightsK: weightsK,
		DomainN: rootsN, WeightsN: weightsN,
		ColsEncABC: make([][]frontend.Variable, L),
		Indices:    make([]frontend.Variable, L),
		VecX:       make([]frontend.Variable, K), VecYZ: make([]frontend.Variable, K),
		VecBTest: make([]frontend.Variable, K),
		EncX:     make([]frontend.Variable, N), EncYZ: make([]frontend.Variable, N),
		EncBTest:         make([]frontend.Variable, N),
		QueriedEncValues: make([][]frontend.Variable, L),
	}
	for i := 0; i < L; i++ {
		emptyCircuit.ColsEncABC[i] = make([]frontend.Variable, 3*K)
		emptyCircuit.QueriedEncValues[i] = make([]frontend.Variable, 3)
	}

	ccs, err := frontend.Compile(field, scs.NewBuilder, emptyCircuit)
	if err != nil {
		log.Fatalf("❌ PLONK Compilation failed: %v", err)
	}
	compileTime := time.Since(compileStart).Seconds()
	nbConstraints := ccs.GetNbConstraints()

	// =========================================================================
	// 4. Setup KZG SRS (test-only, unsafe)
	// =========================================================================
	fmt.Println("  KZG SRS setup (test-only)...")
	kzgStart := time.Now()
	srs, srsLagrange, err := unsafekzg.NewSRS(ccs)
	if err != nil {
		log.Fatalf("❌ KZG SRS generation failed: %v", err)
	}
	kzgTime := time.Since(kzgStart).Seconds()

	// =========================================================================
	// 5. PLONK Setup
	// =========================================================================
	fmt.Println("  PLONK setup...")
	setupStart := time.Now()
	pk, vk, err := plonk.Setup(ccs, srs, srsLagrange)
	if err != nil {
		log.Fatalf("❌ PLONK Setup failed: %v", err)
	}
	setupTime := time.Since(setupStart).Seconds()

	// =========================================================================
	// 6. Create assignment and witness
	// =========================================================================
	assignment := &circuit.LAMPCircuit{
		K: K, N: N, Depth: depth,
		DomainK: rootsK, WeightsK: weightsK,
		DomainN: rootsN, WeightsN: weightsN,
		RootABC: rootABC, RootXYZ: rootXYZ, CmABC: CmABC, CmXYZ: CmXYZ,
		ChallengeR: ChallengeR, ChallengeB: ChallengeB,
		ColsEncABC: make([][]frontend.Variable, L),
		Indices:    make([]frontend.Variable, L),
		VecX:       make([]frontend.Variable, K), VecYZ: make([]frontend.Variable, K),
		VecBTest: make([]frontend.Variable, K),
		EncX:     make([]frontend.Variable, N), EncYZ: make([]frontend.Variable, N),
		EncBTest:         make([]frontend.Variable, N),
		QueriedEncValues: make([][]frontend.Variable, L),
	}

	for i := 0; i < K; i++ {
		assignment.VecX[i] = vecX[i]
		assignment.VecYZ[i] = vecYZ[i]
		assignment.VecBTest[i] = vecBTest[i]
	}
	for i := 0; i < N; i++ {
		assignment.EncX[i] = encX[i]
		assignment.EncYZ[i] = encYZ[i]
		assignment.EncBTest[i] = encBTest[i]
	}

	for i, idx := range indices {
		assignment.Indices[i] = idx
		assignment.QueriedEncValues[i] = []frontend.Variable{encX[idx], encYZ[idx], encBTest[idx]}
		assignment.ColsEncABC[i] = make([]frontend.Variable, 3*K)
		for j := 0; j < K; j++ {
			assignment.ColsEncABC[i][j] = colsEncA[idx][j]
			assignment.ColsEncABC[i][K+j] = colsEncB[idx][j]
			assignment.ColsEncABC[i][2*K+j] = colsEncC[idx][j]
		}
	}

	fmt.Println("  Proving...")
	witness, err := frontend.NewWitness(assignment, field)
	if err != nil {
		log.Fatalf("❌ Failed to create witness: %v", err)
	}

	publicWitness, err := witness.Public()
	if err != nil {
		log.Fatalf("❌ Failed to extract public witness: %v", err)
	}

	// =========================================================================
	// 7. PLONK Prove
	// =========================================================================
	proveStart := time.Now()
	proof, err := plonk.Prove(ccs, pk, witness)
	if err != nil {
		log.Fatalf("❌ PLONK Prove failed: %v", err)
	}
	proveTime := time.Since(proveStart).Seconds()

	// =========================================================================
	// 8. PLONK Verify
	// =========================================================================
	fmt.Println("  Verifying...")
	verifyStart := time.Now()
	err = plonk.Verify(proof, vk, publicWitness)
	verifyTime := time.Since(verifyStart).Seconds()

	verifyOK := err == nil
	if !verifyOK {
		log.Fatalf("PLONK probe proof verification failed: %v", err)
	}
	fmt.Println("  ✅ Verification passed")

	// =========================================================================
	// 9. Measure proof size
	// =========================================================================
	var buf bytes.Buffer
	if _, err := proof.WriteTo(&buf); err != nil {
		log.Fatalf("PLONK proof serialization failed: %v", err)
	}
	proofSize := buf.Len()

	fmt.Printf("\n  📊 PLONK Probe Results:\n")
	fmt.Printf("    Constraints: %d\n", nbConstraints)
	fmt.Printf("    Compile: %.3f s\n", compileTime)
	fmt.Printf("    KZG SRS: %.3f s\n", kzgTime)
	fmt.Printf("    Setup: %.3f s\n", setupTime)
	fmt.Printf("    Prove: %.3f s\n", proveTime)
	fmt.Printf("    Verify: %.3f s\n", verifyTime)
	fmt.Printf("    Proof size: %d B\n", proofSize)
	fmt.Printf("    Verification: %v\n", verifyOK)

	result := PLONKProbeResult{
		LogK:              logK,
		Rho:               rhoStr,
		N:                 N,
		NumQueries:        L,
		DistinctQueries:   len(unique),
		Constraints:       nbConstraints,
		CompileTime:       compileTime,
		MatrixComputeTime: matrixComputeTime,
		DataCommitTime:    dataCommitTime,
		EncodingTime:      encodingTime,
		KZGSRSTime:        kzgTime,
		SetupTime:         setupTime,
		ProveTime:         proveTime,
		VerifyTime:        verifyTime,
		ProofSizeBytes:    proofSize,
		VerificationOK:    verifyOK,
		PeakMemoryBytes:   benchmark.PeakRSSBytes(),
		HostGoOS:          runtime.GOOS,
		HostGoArch:        runtime.GOARCH,
		HostGoVersion:     runtime.Version(),
		HostNumCPU:        runtime.NumCPU(),
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		log.Fatalf("PLONK probe result serialization failed: %v", err)
	}
	fmt.Printf("PLONK_PROBE_JSON=%s\n", encoded)
	return result
}
