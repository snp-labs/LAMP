// Command public_freivalds measures direct verification when A, B, and C are
// all disclosed to the verifier. This is deliberately not a ZK protocol.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"runtime"
	"time"

	"example.com/lamp/benchmark"
	"example.com/lamp/matrix"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

type result struct {
	Dimension        int     `json:"dimension"`
	BatchQ           int     `json:"batch_q"`
	GenerationS      float64 `json:"generation_seconds"`
	ProductS         float64 `json:"product_seconds"`
	VerificationS    float64 `json:"verification_seconds"`
	TamperRejected   bool    `json:"tamper_rejected"`
	PublicInputBytes uint64  `json:"public_input_bytes"`
	PeakMemoryBytes  uint64  `json:"peak_memory_bytes"`
	GoVersion        string  `json:"go_version"`
}

// verifyPublicProduct checks rᵀAB = rᵀC with a fresh private verifier challenge.
// For a false product, one round accepts with probability at most 1/|Fr|.
func verifyPublicProduct(a, b, c [][]fr.Element, r []fr.Element) bool {
	n := len(r)
	if len(a) != n || len(b) != n || len(c) != n {
		return false
	}
	for i := 0; i < n; i++ {
		if len(a[i]) != n || len(b[i]) != n || len(c[i]) != n {
			return false
		}
	}
	ra := matrix.VecMatMul(r, a, n)
	rAB := matrix.VecMatMul(ra, b, n)
	rC := matrix.VecMatMul(r, c, n)
	for i := 0; i < n; i++ {
		if !rAB[i].Equal(&rC[i]) {
			return false
		}
	}
	return true
}

func main() {
	n := flag.Int("n", 1024, "square matrix dimension")
	q := flag.Int("q", 1, "number of independent public products")
	flag.Parse()
	if *n <= 0 || *n > 4096 {
		log.Fatal("n must be between 1 and 4096")
	}
	if *q <= 0 || *q > 16 {
		log.Fatal("q must be between 1 and 16")
	}
	var generation, product, verification float64
	tamperRejected := true
	for claim := 0; claim < *q; claim++ {
		start := time.Now()
		a := matrix.GenerateRandomMatrix(*n, *n)
		b := matrix.GenerateRandomMatrix(*n, *n)
		generation += time.Since(start).Seconds()
		start = time.Now()
		c := matrix.MatMul(a, b, *n)
		product += time.Since(start).Seconds()
		r := matrix.GenerateRandomVector(*n)
		start = time.Now()
		if !verifyPublicProduct(a, b, c, r) {
			log.Fatal("honest public product rejected")
		}
		verification += time.Since(start).Seconds()
		if claim == 0 {
			var one fr.Element
			one.SetOne()
			c[0][0].Add(&c[0][0], &one)
			// Use a guaranteed nonzero first coefficient for the negative test.
			r[0].SetOne()
			tamperRejected = !verifyPublicProduct(a, b, c, r)
			if !tamperRejected {
				log.Fatal("modified public product accepted")
			}
		}
	}
	res := result{
		Dimension: *n, BatchQ: *q, GenerationS: generation, ProductS: product,
		VerificationS: verification, TamperRejected: tamperRejected,
		PublicInputBytes: uint64(3) * uint64(*n) * uint64(*n) * uint64(*q) * 32,
		PeakMemoryBytes:  benchmark.PeakRSSBytes(), GoVersion: runtime.Version(),
	}
	out, err := json.Marshal(res)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("PUBLIC_CHECK_JSON=%s\n", out)
}
