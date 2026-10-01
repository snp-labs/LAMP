// Command lamp_backend_probe compares two research-only LAMP-inspired paths.
// Neither path is the paper's zero-knowledge protocol or its security claim.
package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	mathrand "math/rand"
	"os"
	"runtime"
	"sync"
	"time"

	"example.com/lamp/crypto"
	"example.com/lamp/matrix"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/fft"
	"github.com/consensys/gnark-crypto/ecc/bn254/kzg"
	"github.com/consensys/gnark-crypto/utils"
)

type matrices struct{ a, b, c [][]fr.Element }

func makeMatrices(k int, seed int64) matrices {
	rng := mathrand.New(mathrand.NewSource(seed))
	makeOne := func() [][]fr.Element {
		out := make([][]fr.Element, k)
		var raw [32]byte
		for i := range out {
			out[i] = make([]fr.Element, k)
			for j := range out[i] {
				_, _ = rng.Read(raw[:])
				out[i][j].SetBytes(raw[:])
			}
		}
		return out
	}
	a, b := makeOne(), makeOne()
	return matrices{a: a, b: b, c: matrix.MatMul(a, b, k)}
}

func transcriptHash(label string, dimensions []int, data ...[]byte) [32]byte {
	h := sha256.New()
	_, _ = h.Write([]byte(label))
	var b [8]byte
	for _, dimension := range dimensions {
		binary.BigEndian.PutUint64(b[:], uint64(dimension))
		_, _ = h.Write(b[:])
	}
	for _, part := range data {
		binary.BigEndian.PutUint64(b[:], uint64(len(part)))
		_, _ = h.Write(b[:])
		_, _ = h.Write(part)
	}
	var digest [32]byte
	copy(digest[:], h.Sum(nil))
	return digest
}

func hashVectors(label string, vectors ...[]fr.Element) [32]byte {
	h := sha256.New()
	_, _ = h.Write([]byte(label))
	var b [8]byte
	for _, vector := range vectors {
		binary.BigEndian.PutUint64(b[:], uint64(len(vector)))
		_, _ = h.Write(b[:])
		for _, value := range vector {
			encoded := value.Bytes()
			_, _ = h.Write(encoded[:])
		}
	}
	var digest [32]byte
	copy(digest[:], h.Sum(nil))
	return digest
}

func challenge(root [32]byte, label string) fr.Element {
	digest := transcriptHash("LAMP-backend-challenge-v1", nil, root[:], []byte(label))
	var value fr.Element
	value.SetBytes(digest[:])
	return value
}

func queryIndices(root, folds [32]byte, n, count int) []int {
	indices := make([]int, count)
	for i := range indices {
		var counter [8]byte
		binary.BigEndian.PutUint64(counter[:], uint64(i))
		digest := transcriptHash("LAMP-backend-column-query-v1", []int{n}, root[:], folds[:], counter[:])
		indices[i] = int(binary.BigEndian.Uint64(digest[:8]) % uint64(n))
	}
	return indices
}

func equal(a, b fr.Element) bool { return a.Equal(&b) }

func dot(a, b []fr.Element) fr.Element {
	var sum, product fr.Element
	for i := range a {
		product.Mul(&a[i], &b[i])
		sum.Add(&sum, &product)
	}
	return sum
}

type directProof struct {
	x, yz, bTest []fr.Element
	opening      crypto.HashABCOpening
	a, b, c      [][]fr.Element // sorted unique opened columns
}

func verifyDirect(k, n, queries int, root [32]byte, proof directProof) error {
	if len(proof.x) != k || len(proof.yz) != k || len(proof.bTest) != k {
		return errors.New("fold vector length mismatch")
	}
	r, b := challenge(root, "r"), challenge(root, "b")
	rPowers, bPowers := matrix.Powers(r, k), matrix.Powers(b, k)
	encoder := crypto.NewEncoder(k, n)
	_, encX, err := encoder.Encode(proof.x)
	if err != nil {
		return err
	}
	_, encYZ, err := encoder.Encode(proof.yz)
	if err != nil {
		return err
	}
	_, encBTest, err := encoder.Encode(proof.bTest)
	if err != nil {
		return err
	}
	folds := hashVectors("LAMP-direct-folds-v1", proof.x, proof.yz, proof.bTest)
	expected := queryIndices(root, folds, n, queries)
	unique := make(map[int]struct{}, len(expected))
	for _, idx := range expected {
		unique[idx] = struct{}{}
	}
	if len(proof.opening.Indices) != len(unique) {
		return errors.New("queried column count mismatch")
	}
	for _, idx := range proof.opening.Indices {
		if _, ok := unique[idx]; !ok {
			return errors.New("queried column index mismatch")
		}
	}
	if !crypto.VerifyHashABCOpening(root, n, proof.opening, proof.a, proof.b, proof.c) {
		return errors.New("ABC column authentication failed")
	}
	for i, j := range proof.opening.Indices {
		if len(proof.a[i]) != k || len(proof.b[i]) != k || len(proof.c[i]) != k {
			return errors.New("opened column length mismatch")
		}
		if !equal(dot(rPowers, proof.a[i]), encX[j]) ||
			!equal(dot(proof.x, proof.b[i]), encYZ[j]) ||
			!equal(dot(rPowers, proof.c[i]), encYZ[j]) ||
			!equal(dot(bPowers, proof.b[i]), encBTest[j]) {
			return fmt.Errorf("LAMP fold rejected at column %d", j)
		}
	}
	return nil
}

func runDirect(data matrices, n, queries int) (map[string]any, error) {
	k := len(data.a)
	start := time.Now()
	encoder := crypto.NewEncoder(k, n)
	a, err := encoder.EncodeRowsToColumns(data.a)
	if err != nil {
		return nil, err
	}
	b, err := encoder.EncodeRowsToColumns(data.b)
	if err != nil {
		return nil, err
	}
	c, err := encoder.EncodeRowsToColumns(data.c)
	if err != nil {
		return nil, err
	}
	encodingSeconds := time.Since(start).Seconds()
	start = time.Now()
	oracle, err := crypto.BuildHashABCOracle(a, b, c)
	if err != nil {
		return nil, err
	}
	commitSeconds := time.Since(start).Seconds()
	root := oracle.Root()
	start = time.Now()
	r, challengeB := challenge(root, "r"), challenge(root, "b")
	x := matrix.VecMatMul(matrix.Powers(r, k), data.a, k)
	yz := matrix.VecMatMul(x, data.b, k)
	bTest := matrix.VecMatMul(matrix.Powers(challengeB, k), data.b, k)
	proof := directProof{x: x, yz: yz, bTest: bTest}
	folds := hashVectors("LAMP-direct-folds-v1", x, yz, bTest)
	indices := queryIndices(root, folds, n, queries)
	proof.opening, err = oracle.Open(indices)
	if err != nil {
		return nil, err
	}
	for _, j := range proof.opening.Indices {
		proof.a = append(proof.a, a[j])
		proof.b = append(proof.b, b[j])
		proof.c = append(proof.c, c[j])
	}
	postCommitSeconds := time.Since(start).Seconds()
	start = time.Now()
	if err := verifyDirect(k, n, queries, root, proof); err != nil {
		return nil, err
	}
	verifySeconds := time.Since(start).Seconds()
	return map[string]any{
		"scheme": "research_hash_direct", "verified": true, "K": k, "N": n,
		"queries": queries, "distinct_queries": len(proof.opening.Indices),
		"proof_payload_estimate_bytes": proof.opening.OpeningBytes(k) + 3*k*32 + 4*len(proof.opening.Indices),
		"statement_bytes":              32, "timings_seconds": map[string]float64{
			"matrix_encoding": encodingSeconds, "matrix_commit": commitSeconds,
			"fold_and_open": postCommitSeconds, "online_prove": encodingSeconds + commitSeconds + postCommitSeconds,
			"verify": verifySeconds,
		},
	}, nil
}

func matrixCoefficients(rows [][]fr.Element) [][]fr.Element {
	out := make([][]fr.Element, len(rows))
	for i, row := range rows {
		out[i] = interpolate(row)
	}
	return out
}

func commitRows(rows [][]fr.Element, srs *kzg.SRS) ([]kzg.Digest, error) {
	out := make([]kzg.Digest, len(rows))
	jobs := make(chan int)
	var wg sync.WaitGroup
	var firstErr error
	var mu sync.Mutex
	workers := runtime.NumCPU()
	if workers > len(rows) {
		workers = len(rows)
	}
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				commitment, err := kzg.Commit(rows[i], srs.Pk, 1)
				if err != nil {
					mu.Lock()
					if firstErr == nil {
						firstErr = err
					}
					mu.Unlock()
					continue
				}
				out[i] = commitment
			}
		}()
	}
	for i := range rows {
		jobs <- i
	}
	close(jobs)
	wg.Wait()
	return out, firstErr
}

func hashCommitments(k, n int, groups ...[]kzg.Digest) [32]byte {
	h := sha256.New()
	_, _ = h.Write([]byte("LAMP-KZG-row-commitments-v1"))
	var size [8]byte
	for _, value := range []int{k, n} {
		binary.BigEndian.PutUint64(size[:], uint64(value))
		_, _ = h.Write(size[:])
	}
	for _, group := range groups {
		binary.BigEndian.PutUint64(size[:], uint64(len(group)))
		_, _ = h.Write(size[:])
		for _, point := range group {
			encoded := point.Bytes()
			_, _ = h.Write(encoded[:])
		}
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

func foldCoefficients(rows [][]fr.Element, weights []fr.Element) []fr.Element {
	out := make([]fr.Element, len(rows[0]))
	var product fr.Element
	for i, row := range rows {
		for j := range row {
			product.Mul(&weights[i], &row[j])
			out[j].Add(&out[j], &product)
		}
	}
	return out
}

func foldCommitments(commits []kzg.Digest, weights []fr.Element) (kzg.Digest, error) {
	var out kzg.Digest
	_, err := out.MultiExp(commits, weights, ecc.MultiExpConfig{})
	return out, err
}

func interpolate(values []fr.Element) []fr.Element {
	coeffs := append([]fr.Element(nil), values...)
	domain := fft.NewDomain(uint64(len(coeffs)))
	domain.FFTInverse(coeffs, fft.DIF)
	utils.BitReverse(coeffs)
	return coeffs
}

func evaluate(coeffs []fr.Element, point fr.Element) fr.Element {
	var result fr.Element
	for i := len(coeffs) - 1; i >= 0; i-- {
		result.Mul(&result, &point).Add(&result, &coeffs[i])
	}
	return result
}

type kzgProof struct {
	x, yz, bTest []fr.Element
	opening      kzg.BatchOpeningProof
}

func verifyKZG(k, n int, srs *kzg.SRS, commitments [3][]kzg.Digest, proof kzgProof) error {
	if len(proof.x) != k || len(proof.yz) != k || len(proof.bTest) != k || len(proof.opening.ClaimedValues) != 4 {
		return errors.New("KZG proof shape mismatch")
	}
	for _, group := range commitments {
		if len(group) != k {
			return errors.New("KZG statement shape mismatch")
		}
		for _, commitment := range group {
			if !commitment.IsInSubGroup() {
				return errors.New("KZG statement contains a point outside the subgroup")
			}
		}
	}
	root := hashCommitments(k, n, commitments[:]...)
	r, challengeB := challenge(root, "r"), challenge(root, "b")
	rPowers, bPowers := matrix.Powers(r, k), matrix.Powers(challengeB, k)
	folds := hashVectors("LAMP-KZG-folds-v1", proof.x, proof.yz, proof.bTest)
	point := challenge(transcriptHash("LAMP-KZG-opening-point-v1", []int{k, n}, root[:], folds[:]), "evaluation")
	want := []fr.Element{evaluate(interpolate(proof.x), point), evaluate(interpolate(proof.yz), point),
		evaluate(interpolate(proof.yz), point), evaluate(interpolate(proof.bTest), point)}
	for i := range want {
		if !proof.opening.ClaimedValues[i].Equal(&want[i]) {
			return fmt.Errorf("KZG folded value %d differs from claimed vector", i)
		}
	}
	aggregates := make([]kzg.Digest, 4)
	var err error
	for i, request := range []struct {
		group   []kzg.Digest
		weights []fr.Element
	}{{commitments[0], rPowers}, {commitments[1], proof.x}, {commitments[2], rPowers}, {commitments[1], bPowers}} {
		aggregates[i], err = foldCommitments(request.group, request.weights)
		if err != nil {
			return err
		}
	}
	if err := kzg.BatchVerifySinglePoint(aggregates, &proof.opening, point, sha256.New(), srs.Vk, root[:]); err != nil {
		return fmt.Errorf("KZG fold opening: %w", err)
	}
	return nil
}

func runKZG(data matrices, n int) (map[string]any, error) {
	k := len(data.a)
	// Benchmark-local SRS generation only. Production needs an MPC SRS whose
	// trapdoor was discarded; this pilot does not claim a secure deployment.
	setupStart := time.Now()
	alpha, err := rand.Int(rand.Reader, fr.Modulus())
	if err != nil {
		return nil, err
	}
	srs, err := kzg.NewSRS(uint64(k), alpha)
	if err != nil {
		return nil, err
	}
	setupSeconds := time.Since(setupStart).Seconds()
	start := time.Now()
	a := matrixCoefficients(data.a)
	b := matrixCoefficients(data.b)
	c := matrixCoefficients(data.c)
	encodingSeconds := time.Since(start).Seconds()
	start = time.Now()
	var commitments [3][]kzg.Digest
	for i, rows := range [][][]fr.Element{a, b, c} {
		commitments[i], err = commitRows(rows, srs)
		if err != nil {
			return nil, err
		}
	}
	root := hashCommitments(k, n, commitments[:]...)
	commitSeconds := time.Since(start).Seconds()
	start = time.Now()
	r, challengeB := challenge(root, "r"), challenge(root, "b")
	rPowers, bPowers := matrix.Powers(r, k), matrix.Powers(challengeB, k)
	x := matrix.VecMatMul(rPowers, data.a, k)
	yz := matrix.VecMatMul(x, data.b, k)
	bTest := matrix.VecMatMul(bPowers, data.b, k)
	proof := kzgProof{x: x, yz: yz, bTest: bTest}
	folds := hashVectors("LAMP-KZG-folds-v1", x, yz, bTest)
	point := challenge(transcriptHash("LAMP-KZG-opening-point-v1", []int{k, n}, root[:], folds[:]), "evaluation")
	polynomials := [][]fr.Element{foldCoefficients(a, rPowers), foldCoefficients(b, x),
		foldCoefficients(c, rPowers), foldCoefficients(b, bPowers)}
	aggregates := make([]kzg.Digest, 4)
	for i, request := range []struct {
		group   []kzg.Digest
		weights []fr.Element
	}{{commitments[0], rPowers}, {commitments[1], x}, {commitments[2], rPowers}, {commitments[1], bPowers}} {
		aggregates[i], err = foldCommitments(request.group, request.weights)
		if err != nil {
			return nil, err
		}
	}
	proof.opening, err = kzg.BatchOpenSinglePoint(polynomials, aggregates, point, sha256.New(), srs.Pk, root[:])
	if err != nil {
		return nil, err
	}
	postCommitSeconds := time.Since(start).Seconds()
	start = time.Now()
	if err := verifyKZG(k, n, srs, commitments, proof); err != nil {
		return nil, err
	}
	verifySeconds := time.Since(start).Seconds()
	var buf bytes.Buffer
	if _, err := proof.opening.WriteTo(&buf); err != nil {
		return nil, err
	}
	statementBytes := 3 * k * bn254.SizeOfG1AffineCompressed
	proofBytes := 3*k*32 + buf.Len()
	return map[string]any{
		"scheme": "research_kzg_row_fold", "verified": true, "K": k, "N": n,
		"proof_payload_bytes": proofBytes, "statement_bytes": statementBytes,
		"total_communication_bytes": proofBytes + statementBytes,
		"timings_seconds": map[string]float64{
			"local_srs_setup": setupSeconds, "row_interpolation": encodingSeconds,
			"matrix_commit": commitSeconds, "fold_and_open": postCommitSeconds,
			"online_prove": encodingSeconds + commitSeconds + postCommitSeconds,
			"verify":       verifySeconds,
		},
	}, nil
}

func main() {
	logK := flag.Int("logK", 5, "base-two log of square matrix dimension")
	queryCount := flag.Int("queries", 309, "direct protocol's sampled encoded columns")
	seed := flag.Int64("seed", 7, "deterministic input seed")
	mode := flag.String("mode", "both", "direct, kzg, or both")
	flag.Parse()
	if *logK < 2 || *logK > 12 || *queryCount < 1 || (*mode != "direct" && *mode != "kzg" && *mode != "both") {
		log.Fatal("requires logK 2..12, queries >= 1, mode direct|kzg|both")
	}
	k, n := 1<<*logK, 2<<*logK
	data := makeMatrices(k, *seed)
	results := make([]map[string]any, 0, 2)
	if *mode == "direct" || *mode == "both" {
		result, err := runDirect(data, n, *queryCount)
		if err != nil {
			log.Fatal(err)
		}
		results = append(results, result)
	}
	if *mode == "kzg" || *mode == "both" {
		result, err := runKZG(data, n)
		if err != nil {
			log.Fatal(err)
		}
		results = append(results, result)
	}
	for _, result := range results {
		result["schema"] = "lamp_backend_research_probe_v1"
		result["scope"] = "research_only_not_original_lamp_or_paper_security"
		result["input_seed"] = *seed
		result["go_version"] = runtime.Version()
		result["goos"] = runtime.GOOS
		result["goarch"] = runtime.GOARCH
		if err := json.NewEncoder(os.Stdout).Encode(result); err != nil {
			log.Fatal(err)
		}
	}
}
