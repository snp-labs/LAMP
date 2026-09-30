package main

import (
	"math/big"
	"math/rand"
	"testing"

	"example.com/lamp/crypto/zkmatrix"
)

func TestRandMatrixDeterministicFullWidthFieldSamples(t *testing.T) {
	a := randMatrix(rand.New(rand.NewSource(99)), 8, 8)
	b := randMatrix(rand.New(rand.NewSource(99)), 8, 8)
	maxBits := 0
	for i := range a {
		for j := range a[i] {
			if !a[i][j].Equal(&b[i][j]) {
				t.Fatal("same seed generated different data")
			}
			bits := a[i][j].BigInt(new(big.Int)).BitLen()
			if bits > maxBits {
				maxBits = bits
			}
		}
	}
	if maxBits < 220 {
		t.Fatalf("data appear small-domain: max bit length %d", maxBits)
	}
}

func TestRunOneAndBatchVerifyDecodedCanonicalPayloads(t *testing.T) {
	pp, err := zkmatrix.Setup(2, 2, 2)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runOne(pp, 2, 2, 2, 17, "accelerated"); err != nil {
		t.Fatalf("decoded single run failed: %v", err)
	}
	if _, err := runBatch(pp, 2, 2, 2, 23, "accelerated", 2); err != nil {
		t.Fatalf("decoded batch run failed: %v", err)
	}
}
