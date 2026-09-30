// Command lamp_sparse_fri_probe is a research-only A/C sparse-opening hybrid.
// It retains a full private B column for the generic x^T B inner product.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"runtime"
	"sync"
	"time"

	"example.com/lamp/circuit"
	"example.com/lamp/crypto"
	"example.com/lamp/matrix"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/fft"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/fri"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

type instance struct {
	k, n, t, l                                                          int
	a, b, c                                                             [][]fr.Element
	colsA, colsB, colsC                                                 [][]fr.Element
	aFRI, cFRI                                                          []*crypto.FRIColumn
	aRoots, cRoots                                                      [][32]byte
	bHashes, xyzHashes                                                  []fr.Element
	abcRoot, xyzRoot                                                    [32]byte
	rowIndices, indices                                                 []int
	challengeB                                                          fr.Element
	x, yz                                                               [][]fr.Element
	encX, encYZ                                                         [][]fr.Element
	bTest, encBTest                                                     []fr.Element
	aOpen, cOpen                                                        [][]fr.Element
	friCommitSeconds, bHashSeconds, openingSeconds, nativeVerifySeconds float64
	onlinePreparationSeconds                                            float64
	friProofBytes                                                       int
}

func deterministicMatrix(k int, selector uint64) [][]fr.Element {
	out := make([][]fr.Element, k)
	for i := range out {
		out[i] = make([]fr.Element, k)
		for j := range out[i] {
			out[i][j].SetUint64(selector + uint64(11*i+17*j+3*i*j+2*i*i+j*j))
		}
	}
	return out
}

func hashStatement(aRoots, cRoots [][32]byte, bHashes []fr.Element) [32]byte {
	h := sha256.New()
	_, _ = h.Write([]byte("LAMP-sparse-FRI-ABC-research-v1"))
	var size [8]byte
	binary.BigEndian.PutUint64(size[:], uint64(len(bHashes)))
	_, _ = h.Write(size[:])
	for j := range aRoots {
		_, _ = h.Write(aRoots[j][:])
		_, _ = h.Write(cRoots[j][:])
		b := bHashes[j].Bytes()
		_, _ = h.Write(b[:])
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

func hashXYZ(hashes []fr.Element) [32]byte {
	h := sha256.New()
	_, _ = h.Write([]byte("LAMP-sparse-FRI-XYZ-research-v1"))
	for _, value := range hashes {
		b := value.Bytes()
		_, _ = h.Write(b[:])
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

func challenge(root [32]byte, label string, counter int) [32]byte {
	h := sha256.New()
	_, _ = h.Write([]byte("LAMP-sparse-FRI-challenge-v1"))
	_, _ = h.Write(root[:])
	_, _ = h.Write([]byte(label))
	var count [8]byte
	binary.BigEndian.PutUint64(count[:], uint64(counter))
	_, _ = h.Write(count[:])
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

func challengeIndex(root [32]byte, label string, counter, limit int) int {
	c := challenge(root, label, counter)
	return int(binary.BigEndian.Uint64(c[:8]) % uint64(limit))
}

func build(k, repetitions, queries, workers int, tamperC bool) (*instance, error) {
	n := 2 * k
	in := &instance{k: k, n: n, t: repetitions, l: queries}
	in.a, in.b = deterministicMatrix(k, 29), deterministicMatrix(k, 61)
	in.c = matrix.MatMul(in.a, in.b, k)
	if tamperC {
		var one fr.Element
		one.SetOne()
		// A constant error across row 0 survives horizontal RS encoding
		// at every sampled column, unlike a one-cell error at tiny L.
		for j := 0; j < k; j++ {
			in.c[0][j].Add(&in.c[0][j], &one)
		}
	}
	onlineStart := time.Now()
	encoder := crypto.NewEncoder(k, n)
	var err error
	in.colsA, err = encoder.EncodeRowsToColumns(in.a)
	if err != nil {
		return nil, err
	}
	in.colsB, err = encoder.EncodeRowsToColumns(in.b)
	if err != nil {
		return nil, err
	}
	in.colsC, err = encoder.EncodeRowsToColumns(in.c)
	if err != nil {
		return nil, err
	}
	in.aFRI, in.cFRI = make([]*crypto.FRIColumn, n), make([]*crypto.FRIColumn, n)
	in.aRoots, in.cRoots = make([][32]byte, n), make([][32]byte, n)
	in.bHashes = make([]fr.Element, n)
	start := time.Now()
	jobs := make(chan int)
	var wg sync.WaitGroup
	var firstErr error
	var errMu sync.Mutex
	if workers > n {
		workers = n
	}
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				aColumn, e := crypto.CommitFRIColumn(in.colsA[j])
				if e != nil {
					errMu.Lock()
					if firstErr == nil {
						firstErr = e
					}
					errMu.Unlock()
					continue
				}
				cColumn, e := crypto.CommitFRIColumn(in.colsC[j])
				if e != nil {
					errMu.Lock()
					if firstErr == nil {
						firstErr = e
					}
					errMu.Unlock()
					continue
				}
				in.aFRI[j], in.cFRI[j] = aColumn, cColumn
				in.aRoots[j], in.cRoots[j] = aColumn.Root(), cColumn.Root()
			}
		}()
	}
	for j := 0; j < n; j++ {
		jobs <- j
	}
	close(jobs)
	wg.Wait()
	if firstErr != nil {
		return nil, firstErr
	}
	in.friCommitSeconds = time.Since(start).Seconds()
	start = time.Now()
	jobs = make(chan int)
	wg = sync.WaitGroup{}
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				in.bHashes[j] = crypto.HashElementsMiMC(in.colsB[j]...)
			}
		}()
	}
	for j := 0; j < n; j++ {
		jobs <- j
	}
	close(jobs)
	wg.Wait()
	in.bHashSeconds = time.Since(start).Seconds()
	in.abcRoot = hashStatement(in.aRoots, in.cRoots, in.bHashes)
	in.rowIndices = make([]int, repetitions)
	for t := range in.rowIndices {
		in.rowIndices[t] = challengeIndex(in.abcRoot, "vertical-row", t, fri.GetRho()*k)
	}
	bChallenge := challenge(in.abcRoot, "B-proximity", 0)
	in.challengeB.SetBytes(bChallenge[:])
	in.x, in.yz, in.encX, in.encYZ = make([][]fr.Element, repetitions), make([][]fr.Element, repetitions),
		make([][]fr.Element, repetitions), make([][]fr.Element, repetitions)
	vertical, err := crypto.NewColumnCoefficientEncoder(k, fri.GetRho()*k)
	if err != nil {
		return nil, err
	}
	verticalRoots := vertical.Roots()
	for t, row := range in.rowIndices {
		powers := matrix.Powers(verticalRoots[row], k)
		in.x[t] = matrix.VecMatMul(powers, in.a, k)
		in.yz[t] = matrix.VecMatMul(in.x[t], in.b, k)
		_, in.encX[t], err = encoder.Encode(in.x[t])
		if err != nil {
			return nil, err
		}
		_, in.encYZ[t], err = encoder.Encode(in.yz[t])
		if err != nil {
			return nil, err
		}
	}
	in.bTest = matrix.VecMatMul(matrix.Powers(in.challengeB, k), in.b, k)
	_, in.encBTest, err = encoder.Encode(in.bTest)
	if err != nil {
		return nil, err
	}
	in.xyzHashes = make([]fr.Element, n)
	for j := 0; j < n; j++ {
		values := make([]fr.Element, 2*repetitions+1)
		for t := 0; t < repetitions; t++ {
			values[2*t], values[2*t+1] = in.encX[t][j], in.encYZ[t][j]
		}
		values[2*repetitions] = in.encBTest[j]
		in.xyzHashes[j] = crypto.HashElementsMiMC(values...)
	}
	in.xyzRoot = hashXYZ(in.xyzHashes)
	in.indices = make([]int, queries)
	for i := range in.indices {
		in.indices[i] = challengeIndex(in.xyzRoot, "horizontal-column", i, n)
	}
	in.aOpen, in.cOpen = make([][]fr.Element, repetitions), make([][]fr.Element, repetitions)
	for t := 0; t < repetitions; t++ {
		in.aOpen[t], in.cOpen[t] = make([]fr.Element, queries), make([]fr.Element, queries)
	}
	start = time.Now()
	for i, j := range in.indices {
		for t, row := range in.rowIndices {
			openingA, err := in.aFRI[j].Open(uint64(row))
			if err != nil {
				return nil, err
			}
			openingC, err := in.cFRI[j].Open(uint64(row))
			if err != nil {
				return nil, err
			}
			in.aOpen[t][i], in.cOpen[t][i] = openingA.ClaimedValue, openingC.ClaimedValue
			verifyStart := time.Now()
			if err := crypto.VerifyFRIColumn(k, in.aRoots[j], uint64(row), in.aFRI[j].ProximityProof(), openingA); err != nil {
				return nil, err
			}
			if err := crypto.VerifyFRIColumn(k, in.cRoots[j], uint64(row), in.cFRI[j].ProximityProof(), openingC); err != nil {
				return nil, err
			}
			in.nativeVerifySeconds += time.Since(verifyStart).Seconds()
			in.friProofBytes += friOpeningBytes(openingA) + friOpeningBytes(openingC)
		}
		in.friProofBytes += friProximityBytes(in.aFRI[j].ProximityProof()) + friProximityBytes(in.cFRI[j].ProximityProof())
	}
	in.openingSeconds = time.Since(start).Seconds() - in.nativeVerifySeconds
	in.onlinePreparationSeconds = time.Since(onlineStart).Seconds()
	return in, nil
}

func friOpeningBytes(p fri.OpeningProof) int {
	size := 0
	for _, part := range p.ProofSet {
		size += len(part)
	}
	return size
}

func friProximityBytes(p fri.ProofOfProximity) int {
	size := 0
	for _, round := range p.Rounds {
		size += 32
		for _, interaction := range round.Interactions {
			for _, path := range interaction {
				size += len(path.MerkleRoot)
				for _, part := range path.ProofSet {
					size += len(part)
				}
			}
		}
	}
	return size
}

func circuitShape(in *instance) *circuit.SparseFRILAMPCircuit {
	k, n, T, L := in.k, in.n, in.t, in.l
	domainK, domainN := fft.NewDomain(uint64(k)), fft.NewDomain(uint64(n))
	rootsK, rootsN := crypto.GetDomainRoots(domainK, k), crypto.GetDomainRoots(domainN, n)
	c := &circuit.SparseFRILAMPCircuit{
		K: k, N: n, Repetitions: T,
		DomainK: rootsK, WeightsK: crypto.PrecomputeBarycentricWeights(rootsK),
		DomainN: rootsN, WeightsN: crypto.PrecomputeBarycentricWeights(rootsN),
		Indices: make([]frontend.Variable, L), AOpen: make([][]frontend.Variable, T), COpen: make([][]frontend.Variable, T),
		BColumnHashes: make([]frontend.Variable, L), XYZHashes: make([]frontend.Variable, L),
		BColumns: make([][]frontend.Variable, L), QueriedValues: make([][]frontend.Variable, L),
		VecX: make([][]frontend.Variable, T), VecYZ: make([][]frontend.Variable, T),
		EncX: make([][]frontend.Variable, T), EncYZ: make([][]frontend.Variable, T),
		VecBTest: make([]frontend.Variable, k), EncBTest: make([]frontend.Variable, n),
	}
	for t := 0; t < T; t++ {
		c.AOpen[t], c.COpen[t] = make([]frontend.Variable, L), make([]frontend.Variable, L)
		c.VecX[t], c.VecYZ[t] = make([]frontend.Variable, k), make([]frontend.Variable, k)
		c.EncX[t], c.EncYZ[t] = make([]frontend.Variable, n), make([]frontend.Variable, n)
	}
	for i := 0; i < L; i++ {
		c.BColumns[i], c.QueriedValues[i] = make([]frontend.Variable, k), make([]frontend.Variable, 2*T+1)
	}
	return c
}

func fillWitness(c *circuit.SparseFRILAMPCircuit, in *instance, publicOnly bool) {
	c.ChallengeB = in.challengeB
	for i, j := range in.indices {
		c.Indices[i] = j
		c.BColumnHashes[i], c.XYZHashes[i] = in.bHashes[j], in.xyzHashes[j]
		if !publicOnly {
			for h, v := range in.colsB[j] {
				c.BColumns[i][h] = v
			}
			for t := 0; t < in.t; t++ {
				c.QueriedValues[i][2*t], c.QueriedValues[i][2*t+1] = in.encX[t][j], in.encYZ[t][j]
			}
			c.QueriedValues[i][2*in.t] = in.encBTest[j]
		}
	}
	for t := 0; t < in.t; t++ {
		for i := range in.indices {
			c.AOpen[t][i], c.COpen[t][i] = in.aOpen[t][i], in.cOpen[t][i]
		}
		if !publicOnly {
			for h, v := range in.x[t] {
				c.VecX[t][h] = v
			}
			for h, v := range in.yz[t] {
				c.VecYZ[t][h] = v
			}
			for j, v := range in.encX[t] {
				c.EncX[t][j] = v
			}
			for j, v := range in.encYZ[t] {
				c.EncYZ[t][j] = v
			}
		}
	}
	if !publicOnly {
		for h, v := range in.bTest {
			c.VecBTest[h] = v
		}
		for j, v := range in.encBTest {
			c.EncBTest[j] = v
		}
	}
}

func run(k, repetitions, queries, workers int, tamperC bool) (map[string]any, error) {
	in, err := build(k, repetitions, queries, workers, tamperC)
	if err != nil {
		return nil, err
	}
	shape := circuitShape(in)
	start := time.Now()
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, shape)
	if err != nil {
		return nil, err
	}
	compileSeconds := time.Since(start).Seconds()
	start = time.Now()
	pk, vk, err := groth16.Setup(cs)
	if err != nil {
		return nil, err
	}
	setupSeconds := time.Since(start).Seconds()
	witnessAssignment := circuitShape(in)
	fillWitness(witnessAssignment, in, false)
	start = time.Now()
	witness, err := frontend.NewWitness(witnessAssignment, ecc.BN254.ScalarField())
	if err != nil {
		return nil, err
	}
	proof, err := groth16.Prove(cs, pk, witness)
	if tamperC {
		if err == nil {
			return nil, fmt.Errorf("incorrect C matrix unexpectedly proved")
		}
		return map[string]any{
			"schema": "lamp_sparse_fri_full_B_research_v1", "scope": "research_only_not_main_lamp",
			"K": k, "N": 2 * k, "repetitions": repetitions, "queries": queries,
			"tampered_c_rejected": true, "constraints": cs.GetNbConstraints(),
		}, nil
	}
	if err != nil {
		return nil, err
	}
	proveSeconds := time.Since(start).Seconds()
	publicAssignment := circuitShape(in)
	fillWitness(publicAssignment, in, true)
	publicWitness, err := frontend.NewWitness(publicAssignment, ecc.BN254.ScalarField(), frontend.PublicOnly())
	if err != nil {
		return nil, err
	}
	start = time.Now()
	if err := groth16.Verify(proof, vk, publicWitness); err != nil {
		return nil, err
	}
	verifySeconds := time.Since(start).Seconds()
	var proofBuffer bytes.Buffer
	if _, err := proof.WriteTo(&proofBuffer); err != nil {
		return nil, err
	}
	return map[string]any{
		"schema": "lamp_sparse_fri_full_B_research_v1", "scope": "research_only_not_main_lamp",
		"K": k, "N": 2 * k, "vertical_M": fri.GetRho() * k, "repetitions": repetitions, "queries": queries,
		"workers":     workers,
		"constraints": cs.GetNbConstraints(), "verified": true, "row_indices": in.rowIndices, "column_indices": in.indices,
		"groth16_proof_bytes": proofBuffer.Len(), "fri_payload_estimate_bytes": in.friProofBytes,
		"statement_bytes": 4 * in.n * 32, "statement_definition": "A/C FRI roots plus B/XYZ leaf hashes; excludes dimensions",
		"go_version": runtime.Version(), "goos": runtime.GOOS, "goarch": runtime.GOARCH,
		"timings_seconds": map[string]float64{
			"online_preparation_including_native_checks":  in.onlinePreparationSeconds,
			"pilot_online_prover_excluding_native_checks": in.onlinePreparationSeconds - in.nativeVerifySeconds + proveSeconds,
			"fri_proximity_commit_all_columns":            in.friCommitSeconds,
			"b_column_hash_all_columns":                   in.bHashSeconds,
			"fri_sparse_openings":                         in.openingSeconds,
			"fri_native_verify":                           in.nativeVerifySeconds,
			"circuit_compile":                             compileSeconds,
			"groth16_setup":                               setupSeconds,
			"groth16_witness_and_prove":                   proveSeconds,
			"groth16_verify":                              verifySeconds,
		},
	}, nil
}

func main() {
	logK := flag.Int("logK", 2, "base-two log of K (research pilot: 2..10)")
	repetitions := flag.Int("repetitions", 3, "independent vertical row challenges")
	queries := flag.Int("queries", 1, "sampled horizontal columns")
	workers := flag.Int("workers", 10, "parallel FRI column commitment workers")
	tamperC := flag.Bool("tamper-c", false, "change one C row and require Groth16 rejection")
	flag.Parse()
	if *logK < 2 || *logK > 10 || *repetitions < 1 || *repetitions > 43 || *queries < 1 || *queries > 4 || *workers < 1 || (*logK > 3 && (*repetitions != 1 || *queries != 1)) {
		log.Fatal("research pilot requires logK 2..10; above logK=3, only repetitions=1 and queries=1 are allowed")
	}
	result, err := run(1<<*logK, *repetitions, *queries, *workers, *tamperC)
	if err != nil {
		log.Fatal(err)
	}
	if err := json.NewEncoder(os.Stdout).Encode(result); err != nil {
		log.Fatal(err)
	}
}
