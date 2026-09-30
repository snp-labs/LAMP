// Command lamp_kzg_row_probe benchmarks a complete non-ZK matrix-product
// relation over row KZG commitments. It is a distinct row-KZG/Freivalds variant,
// not the current LAMP sampled-column protocol or an outer ZK proof.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math/big"
	"math/rand"
	"os"
	"runtime"
	"time"

	"example.com/lamp/crypto/kzgrow"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/kzg"
)

type timings struct {
	MatrixGenerateSeconds float64 `json:"matrix_generate_seconds"`
	SRSSetupSeconds       float64 `json:"srs_setup_seconds"`
	RowInterpolateSeconds float64 `json:"row_interpolate_seconds"`
	RowCommitSeconds      float64 `json:"row_commit_seconds"`
	InnerProveSeconds     float64 `json:"inner_prove_seconds"`
	InnerVerifySeconds    float64 `json:"inner_verify_seconds"`
	FullOnlineProve       float64 `json:"full_online_prove_seconds"`
	DirectProveSeconds    float64 `json:"direct_prove_seconds"`
	DirectVerifySeconds   float64 `json:"direct_verify_seconds"`
	DirectOnlineProve     float64 `json:"direct_online_prove_seconds"`
}

type result struct {
	Schema                string  `json:"schema"`
	Protocol              string  `json:"protocol"`
	K                     int     `json:"K"`
	Workers               int     `json:"workers"`
	Seed                  int64   `json:"seed"`
	StatementRoot         string  `json:"statement_root"`
	ProofBytes            int     `json:"proof_bytes"`
	StatementBytes        int     `json:"statement_bytes"`
	Verified              bool    `json:"verified"`
	DecodedVerified       bool    `json:"decoded_verified"`
	DirectProofBytes      int     `json:"direct_proof_bytes"`
	DirectVerified        bool    `json:"direct_verified"`
	DirectDecodedVerified bool    `json:"direct_decoded_verified"`
	GoVersion             string  `json:"go_version"`
	OS                    string  `json:"os"`
	Arch                  string  `json:"arch"`
	Timings               timings `json:"timings_seconds"`
}

func randomField(rng *rand.Rand) fr.Element {
	var raw [32]byte
	_, _ = rng.Read(raw[:])
	var out fr.Element
	out.SetBytes(raw[:])
	return out
}

// A = I + u v^T and C = A B. All three matrices are dense; the structured A
// lets the benchmark construct an honest large instance in O(K²) time.
func honestMatrices(k int, rng *rand.Rand) ([][]fr.Element, [][]fr.Element, [][]fr.Element) {
	u, v, w := make([]fr.Element, k), make([]fr.Element, k), make([]fr.Element, k)
	for i := 0; i < k; i++ {
		u[i], v[i] = randomField(rng), randomField(rng)
	}
	b := make([][]fr.Element, k)
	for i := 0; i < k; i++ {
		b[i] = make([]fr.Element, k)
		for j := 0; j < k; j++ {
			b[i][j] = randomField(rng)
			var term fr.Element
			term.Mul(&v[i], &b[i][j])
			w[j].Add(&w[j], &term)
		}
	}
	a, c := make([][]fr.Element, k), make([][]fr.Element, k)
	var one fr.Element
	one.SetOne()
	for i := 0; i < k; i++ {
		a[i], c[i] = make([]fr.Element, k), make([]fr.Element, k)
		for j := 0; j < k; j++ {
			a[i][j].Mul(&u[i], &v[j])
			if i == j {
				a[i][j].Add(&a[i][j], &one)
			}
			var term fr.Element
			term.Mul(&u[i], &w[j])
			c[i][j].Add(&b[i][j], &term)
		}
	}
	return a, b, c
}

func run(k, workers int, seed int64) (result, error) {
	r := result{Schema: "row_kzg_freivalds_probe_v1", Protocol: "full_field_row_kzg_non_zk_not_original_lamp",
		K: k, Seed: seed, GoVersion: runtime.Version(), OS: runtime.GOOS, Arch: runtime.GOARCH}
	rng := rand.New(rand.NewSource(seed))
	start := time.Now()
	a, b, c := honestMatrices(k, rng)
	r.Timings.MatrixGenerateSeconds = time.Since(start).Seconds()
	var alpha fr.Element
	if _, err := alpha.SetRandom(); err != nil {
		return r, err
	}
	var alphaBig big.Int
	alpha.BigInt(&alphaBig)
	start = time.Now()
	srs, err := kzg.NewSRS(uint64(k), &alphaBig)
	if err != nil {
		return r, err
	}
	r.Timings.SRSSetupSeconds = time.Since(start).Seconds()
	alpha.SetZero()
	alphaBig.SetUint64(0)
	witness, commitTimes, err := kzgrow.Commit(a, b, c, srs, workers)
	if err != nil {
		return r, err
	}
	r.Workers = commitTimes.Workers
	r.Timings.RowInterpolateSeconds = commitTimes.Interpolate.Seconds()
	r.Timings.RowCommitSeconds = commitTimes.KZGCommit.Seconds()
	start = time.Now()
	proof, err := kzgrow.Prove(witness, srs)
	if err != nil {
		return r, err
	}
	r.Timings.InnerProveSeconds = time.Since(start).Seconds()
	r.Timings.FullOnlineProve = r.Timings.RowInterpolateSeconds + r.Timings.RowCommitSeconds + r.Timings.InnerProveSeconds
	root, err := witness.S.Root()
	if err != nil {
		return r, err
	}
	r.StatementRoot = fmt.Sprintf("%x", root)
	start = time.Now()
	if err := kzgrow.VerifyWithRoot(root, witness.S, proof, srs); err != nil {
		return r, err
	}
	r.Timings.InnerVerifySeconds = time.Since(start).Seconds()
	r.Verified = true
	proofWire, err := proof.MarshalBinary()
	if err != nil {
		return r, err
	}
	statementWire, err := witness.S.MarshalBinary()
	if err != nil {
		return r, err
	}
	r.ProofBytes, r.StatementBytes = len(proofWire), len(statementWire)
	decodedProof, err := kzgrow.UnmarshalProof(proofWire)
	if err != nil {
		return r, err
	}
	decodedStatement, err := kzgrow.UnmarshalStatement(statementWire)
	if err != nil {
		return r, err
	}
	if err := kzgrow.VerifyWithRoot(root, decodedStatement, decodedProof, srs); err != nil {
		return r, err
	}
	r.DecodedVerified = true
	start = time.Now()
	direct, err := kzgrow.ProveDirect(witness)
	if err != nil {
		return r, err
	}
	r.Timings.DirectProveSeconds = time.Since(start).Seconds()
	r.Timings.DirectOnlineProve = r.Timings.RowInterpolateSeconds + r.Timings.RowCommitSeconds + r.Timings.DirectProveSeconds
	start = time.Now()
	if err := kzgrow.VerifyDirectWithRoot(root, witness.S, direct, srs); err != nil {
		return r, err
	}
	r.Timings.DirectVerifySeconds = time.Since(start).Seconds()
	r.DirectVerified = true
	directWire, err := direct.MarshalBinary()
	if err != nil {
		return r, err
	}
	r.DirectProofBytes = len(directWire)
	decodedDirect, err := kzgrow.UnmarshalDirectProof(directWire)
	if err != nil {
		return r, err
	}
	if err := kzgrow.VerifyDirectWithRoot(root, decodedStatement, decodedDirect, srs); err != nil {
		return r, err
	}
	r.DirectDecodedVerified = true
	return r, nil
}

func main() {
	logK := flag.Int("logK", 8, "base-2 log of square matrix dimension")
	workers := flag.Int("workers", runtime.GOMAXPROCS(0), "parallel row commitment workers")
	seed := flag.Int64("seed", 20260930, "deterministic matrix seed")
	flag.Parse()
	if *logK < 2 || *logK > 12 || *workers < 1 {
		log.Fatal("logK must be in [2,12] and workers positive")
	}
	r, err := run(1<<*logK, *workers, *seed)
	if err != nil {
		log.Fatal(err)
	}
	if err := json.NewEncoder(os.Stdout).Encode(r); err != nil {
		log.Fatal(err)
	}
}
