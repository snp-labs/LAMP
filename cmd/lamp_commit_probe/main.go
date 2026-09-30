// Command lamp_commit_probe compares commitment components on the same
// Reed–Solomon encoded matrix data. It does not construct a LAMP proof.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math/rand"
	"os"
	"runtime"
	"time"

	"example.com/lamp/crypto"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

type timings struct {
	EncodingSeconds       float64 `json:"encoding_seconds"`
	PedersenMerkleSeconds float64 `json:"pedersen_merkle_seconds"`
	PedersenOpenSeconds   float64 `json:"pedersen_open_seconds"`
	PedersenVerifySeconds float64 `json:"pedersen_verify_seconds"`
	HashMerkleSeconds     float64 `json:"hash_merkle_seconds"`
	HashOpenSeconds       float64 `json:"hash_open_seconds"`
	HashVerifySeconds     float64 `json:"hash_verify_seconds"`
}

type result struct {
	Schema              string  `json:"schema"`
	Scope               string  `json:"scope"`
	K                   int     `json:"K"`
	N                   int     `json:"N"`
	Rho                 string  `json:"rho"`
	Seed                int64   `json:"seed"`
	Queries             int     `json:"queries"`
	DistinctQueries     int     `json:"distinct_queries"`
	GoVersion           string  `json:"go_version"`
	OS                  string  `json:"os"`
	Arch                string  `json:"arch"`
	PedersenRoot        string  `json:"pedersen_root"`
	HashRoot            string  `json:"hash_root"`
	HashStoredBytes     int     `json:"hash_stored_bytes"`
	HashDisclosedBytes  int     `json:"hash_disclosed_bytes"`
	HashOpeningVerified bool    `json:"hash_opening_verified"`
	Timings             timings `json:"timings"`
}

func main() {
	logK := flag.Int("logK", 10, "base-2 logarithm of square matrix dimension")
	rho := flag.String("rho", "1/2", "code rate: 1/2, 1/4, or 1/8")
	seed := flag.Int64("seed", 1, "deterministic input seed")
	queries := flag.Int("queries", 309, "number of sampled column indices")
	jsonOut := flag.Bool("json", true, "print one JSON result")
	flag.Parse()
	if *logK < 1 || *logK > 12 || *queries < 1 {
		log.Fatal("logK must be in [1,12], queries must be positive")
	}
	k := 1 << *logK
	var n int
	switch *rho {
	case "1/2":
		n = 2 * k
	case "1/4":
		n = 4 * k
	case "1/8":
		n = 8 * k
	default:
		log.Fatal("unsupported rho")
	}
	r, err := run(k, n, *rho, *seed, *queries)
	if err != nil {
		log.Fatal(err)
	}
	if *jsonOut {
		if err := json.NewEncoder(os.Stdout).Encode(r); err != nil {
			log.Fatal(err)
		}
	} else {
		fmt.Printf("K=%d N=%d, Pedersen+Merkle %.3fs, hash+Merkle %.3fs, hash public opening %d bytes\n",
			r.K, r.N, r.Timings.PedersenMerkleSeconds, r.Timings.HashMerkleSeconds, r.HashDisclosedBytes)
	}
}

func deterministicMatrix(k int, rng *rand.Rand) [][]fr.Element {
	m := make([][]fr.Element, k)
	var raw [32]byte
	for i := range m {
		m[i] = make([]fr.Element, k)
		for j := range m[i] {
			_, _ = rng.Read(raw[:])
			m[i][j].SetBytes(raw[:])
		}
	}
	return m
}

func run(k, n int, rho string, seed int64, queryCount int) (result, error) {
	r := result{
		Schema: "lamp_commit_probe_v1", Scope: "component_only_not_zero_knowledge",
		K: k, N: n, Rho: rho, Seed: seed, Queries: queryCount,
		GoVersion: runtime.Version(), OS: runtime.GOOS, Arch: runtime.GOARCH,
	}
	rng := rand.New(rand.NewSource(seed))
	encoder := crypto.NewEncoder(k, n)
	matA := deterministicMatrix(k, rng)
	start := time.Now()
	a, err := encoder.EncodeRowsToColumns(matA)
	if err != nil {
		return r, err
	}
	r.Timings.EncodingSeconds += time.Since(start).Seconds()
	matA = nil
	matB := deterministicMatrix(k, rng)
	start = time.Now()
	b, err := encoder.EncodeRowsToColumns(matB)
	if err != nil {
		return r, err
	}
	r.Timings.EncodingSeconds += time.Since(start).Seconds()
	matB = nil
	matC := deterministicMatrix(k, rng)
	start = time.Now()
	c, err := encoder.EncodeRowsToColumns(matC)
	if err != nil {
		return r, err
	}
	r.Timings.EncodingSeconds += time.Since(start).Seconds()
	matC = nil
	runtime.GC()

	indices := make([]int, queryCount)
	for i := range indices {
		indices[i] = rng.Intn(n)
	}
	distinct := make(map[int]bool)
	for _, idx := range indices {
		distinct[idx] = true
	}
	r.DistinctQueries = len(distinct)

	ck := crypto.SetupCommitKey(3 * k) // one-time key setup, outside both timings
	start = time.Now()
	leaves, _ := crypto.BatchPedersenCommitABCBlinded(a, b, c, ck)
	depth := log2(n)
	tree, pedersenRoot := crypto.BuildMerkleTreeFromGroupElements(leaves, depth)
	r.Timings.PedersenMerkleSeconds = time.Since(start).Seconds()
	r.PedersenRoot = pedersenRoot.String()
	start = time.Now()
	pedersenProof := crypto.GetMerkleMultiProof(tree, indices, depth)
	r.Timings.PedersenOpenSeconds = time.Since(start).Seconds()
	start = time.Now()
	queriedCommitments := make([]bn254.G1Affine, len(indices))
	for i, idx := range indices {
		queriedCommitments[i] = leaves[idx]
	}
	if !verifyPedersen(pedersenRoot, queriedCommitments, indices, pedersenProof, depth) {
		return r, fmt.Errorf("Pedersen Merkle multiproof rejected")
	}
	r.Timings.PedersenVerifySeconds = time.Since(start).Seconds()

	runtime.GC()
	start = time.Now()
	hashTree, err := crypto.BuildHashABCOracle(a, b, c)
	if err != nil {
		return r, err
	}
	r.Timings.HashMerkleSeconds = time.Since(start).Seconds()
	r.HashRoot = fmt.Sprintf("%x", hashTree.Root())
	r.HashStoredBytes = hashTree.StoredBytes()
	start = time.Now()
	opening, err := hashTree.Open(indices)
	if err != nil {
		return r, err
	}
	r.Timings.HashOpenSeconds = time.Since(start).Seconds()
	r.HashDisclosedBytes = opening.DisclosedBytes(k)
	openA, openB, openC := selectABC(a, b, c, opening.Indices)
	start = time.Now()
	r.HashOpeningVerified = crypto.VerifyHashABCOpening(hashTree.Root(), n, opening, openA, openB, openC)
	r.Timings.HashVerifySeconds = time.Since(start).Seconds()
	if !r.HashOpeningVerified {
		return r, fmt.Errorf("hash Merkle multiproof rejected")
	}
	return r, nil
}

func selectABC(a, b, c [][]fr.Element, indices []int) ([][]fr.Element, [][]fr.Element, [][]fr.Element) {
	x, y, z := make([][]fr.Element, len(indices)), make([][]fr.Element, len(indices)), make([][]fr.Element, len(indices))
	for i, idx := range indices {
		x[i], y[i], z[i] = a[idx], b[idx], c[idx]
	}
	return x, y, z
}

func log2(n int) int {
	depth := 0
	for n > 1 {
		n >>= 1
		depth++
	}
	return depth
}

func verifyPedersen(root fr.Element, leaves []bn254.G1Affine, indices []int, proof crypto.MerkleMultiProof, depth int) bool {
	hashes := make([]fr.Element, len(leaves))
	for i, leaf := range leaves {
		hashes[i] = crypto.HashPoint(leaf)
	}
	return crypto.VerifyMerkleMultiProof(root, hashes, indices, proof, depth)
}
