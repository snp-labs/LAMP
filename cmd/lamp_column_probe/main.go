// Command lamp_column_probe measures a column-extended, authenticated-opening
// component. It is not a complete or sound LAMP proof: low-degree testing of
// committed columns and the x^T B relation are still absent.
package main

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math/rand"
	"os"
	"runtime"
	"sort"
	"time"

	"example.com/lamp/crypto"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

type timings struct {
	HorizontalEncodeSeconds float64 `json:"horizontal_encode_seconds"`
	VerticalEncodeSeconds   float64 `json:"vertical_encode_seconds"`
	GridHashSeconds         float64 `json:"grid_hash_seconds"`
	SparseOpenSeconds       float64 `json:"sparse_open_seconds"`
	SparseVerifySeconds     float64 `json:"sparse_verify_seconds"`
	ThreeDirectFoldsSeconds float64 `json:"three_direct_folds_seconds"`
	RemainingDotSeconds     float64 `json:"remaining_xB_dot_seconds"`
}

type result struct {
	Schema           string  `json:"schema"`
	Scope            string  `json:"scope"`
	K                int     `json:"K"`
	N                int     `json:"N"`
	M                int     `json:"M"`
	Seed             int64   `json:"seed"`
	Queries          int     `json:"queries"`
	Workers          int     `json:"workers"`
	DistinctQueries  int     `json:"distinct_queries"`
	RowR             int     `json:"row_r"`
	RowB             int     `json:"row_b"`
	Root             string  `json:"root"`
	OpeningBytes     int     `json:"opening_bytes"`
	OpeningsVerified bool    `json:"openings_verified"`
	FoldChecksPassed bool    `json:"fold_checks_passed"`
	RemainingDotSum  string  `json:"remaining_xB_dot_sum"`
	GoVersion        string  `json:"go_version"`
	OS               string  `json:"os"`
	Arch             string  `json:"arch"`
	Timings          timings `json:"timings_seconds"`
}

func randomMatrix(k int, rng *rand.Rand) [][]fr.Element {
	matrix := make([][]fr.Element, k)
	var raw [32]byte
	for row := range matrix {
		matrix[row] = make([]fr.Element, k)
		for col := range matrix[row] {
			_, _ = rng.Read(raw[:])
			matrix[row][col].SetBytes(raw[:])
		}
	}
	return matrix
}

func transcriptIndex(root [32]byte, label string, counter, limit int) int {
	h := sha256.New()
	_, _ = h.Write([]byte("LAMP-column-grid-probe-challenge-v1"))
	_, _ = h.Write(root[:])
	_, _ = h.Write([]byte(label))
	var index [8]byte
	binary.BigEndian.PutUint64(index[:], uint64(counter))
	_, _ = h.Write(index[:])
	sum := h.Sum(nil)
	return int(binary.BigEndian.Uint64(sum[:8]) % uint64(limit))
}

func run(k, n, m, queries int, seed int64, workers int) (result, error) {
	r := result{Schema: "lamp_column_grid_probe_v1", Scope: "component_only_missing_low_degree_and_xB_proofs",
		K: k, N: n, M: m, Seed: seed, Queries: queries,
		GoVersion: runtime.Version(), OS: runtime.GOOS, Arch: runtime.GOARCH}
	if queries < 1 || n < 1 || m < 1 {
		return r, fmt.Errorf("invalid probe dimensions or query count")
	}
	rng := rand.New(rand.NewSource(seed))
	horizontal := crypto.NewEncoder(k, n)
	var columns [3][][]fr.Element
	for matrix := range columns {
		input := randomMatrix(k, rng)
		start := time.Now()
		encoded, err := horizontal.EncodeRowsToColumns(input)
		if err != nil {
			return r, err
		}
		r.Timings.HorizontalEncodeSeconds += time.Since(start).Seconds()
		columns[matrix] = encoded
	}
	oracle, gridTimes, err := crypto.BuildColumnGridOracle(columns[0], columns[1], columns[2], k, m, workers)
	if err != nil {
		return r, err
	}
	r.Timings.VerticalEncodeSeconds = gridTimes.Encode.Seconds()
	r.Timings.GridHashSeconds = gridTimes.Hash.Seconds()
	r.Workers = gridTimes.Workers
	root := oracle.Root()
	r.Root = fmt.Sprintf("%x", root)
	r.RowR = transcriptIndex(root, "row-r", 0, m)
	r.RowB = transcriptIndex(root, "row-b", 0, m)
	for retry := 1; r.RowB == r.RowR; retry++ {
		r.RowB = transcriptIndex(root, "row-b", retry, m)
	}
	indices := make(map[int]struct{}, queries)
	for i := 0; i < queries; i++ {
		indices[transcriptIndex(root, "horizontal-column", i, n)] = struct{}{}
	}
	sorted := make([]int, 0, len(indices))
	for index := range indices {
		sorted = append(sorted, index)
	}
	sort.Ints(sorted)
	r.DistinctQueries = len(sorted)
	roots, err := crypto.NewColumnCoefficientEncoder(k, m)
	if err != nil {
		return r, err
	}
	points := roots.Roots()
	x := make([]fr.Element, k)
	for i := range x {
		x[i].SetUint64(uint64(i + 1))
	}
	r.OpeningsVerified, r.FoldChecksPassed = true, true
	var dotSum fr.Element
	for _, index := range sorted {
		start := time.Now()
		opening, err := oracle.Open(index, r.RowR, r.RowB)
		if err != nil {
			return r, err
		}
		r.Timings.SparseOpenSeconds += time.Since(start).Seconds()
		r.OpeningBytes += opening.Bytes()
		start = time.Now()
		r.OpeningsVerified = r.OpeningsVerified && crypto.VerifyColumnGridOpening(root, n, m, opening)
		r.Timings.SparseVerifySeconds += time.Since(start).Seconds()
		start = time.Now()
		foldA := crypto.FoldPowers(columns[0][index], points[r.RowR])
		foldC := crypto.FoldPowers(columns[2][index], points[r.RowR])
		foldBTest := crypto.FoldPowers(columns[1][index], points[r.RowB])
		r.FoldChecksPassed = r.FoldChecksPassed &&
			foldA.Equal(&opening.AtR[0]) && foldC.Equal(&opening.AtR[2]) && foldBTest.Equal(&opening.AtB[1])
		r.Timings.ThreeDirectFoldsSeconds += time.Since(start).Seconds()
		start = time.Now()
		var dot, term fr.Element
		for i := 0; i < k; i++ {
			term.Mul(&x[i], &columns[1][index][i])
			dot.Add(&dot, &term)
		}
		r.Timings.RemainingDotSeconds += time.Since(start).Seconds()
		dotSum.Add(&dotSum, &dot)
	}
	r.RemainingDotSum = dotSum.String()
	return r, nil
}

func main() {
	logK := flag.Int("logK", 10, "base-2 log of K")
	queries := flag.Int("queries", 309, "number of sampled horizontal positions")
	workers := flag.Int("workers", runtime.GOMAXPROCS(0), "parallel workers for vertical encoding and grid hashing")
	seed := flag.Int64("seed", 20260930, "deterministic input seed")
	jsonOutput := flag.Bool("json", true, "print JSON")
	flag.Parse()
	if *logK < 2 || *logK > 12 {
		log.Fatal("logK must be in [2,12]")
	}
	k := 1 << *logK
	r, err := run(k, 2*k, 2*k, *queries, *seed, *workers)
	if err != nil {
		log.Fatal(err)
	}
	if !r.OpeningsVerified || !r.FoldChecksPassed {
		log.Fatal("opening or fold check failed")
	}
	if *jsonOutput {
		if err := json.NewEncoder(os.Stdout).Encode(r); err != nil {
			log.Fatal(err)
		}
	} else {
		fmt.Printf("K=%d N=%d M=%d: grid commit %.3fs, openings %.3fs, opening data %d B\n",
			r.K, r.N, r.M, r.Timings.VerticalEncodeSeconds+r.Timings.GridHashSeconds,
			r.Timings.SparseOpenSeconds, r.OpeningBytes)
	}
}
