package main

import (
	"math/rand"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

func TestStructuredMatricesMultiplyExactly(t *testing.T) {
	const k = 4
	a, b, c := honestMatrices(k, rand.New(rand.NewSource(42)))
	for i := 0; i < k; i++ {
		for j := 0; j < k; j++ {
			var want fr.Element
			for h := 0; h < k; h++ {
				var term fr.Element
				term.Mul(&a[i][h], &b[h][j])
				want.Add(&want, &term)
			}
			if !want.Equal(&c[i][j]) {
				t.Fatalf("C[%d,%d] differs from A*B", i, j)
			}
		}
	}
}

func TestRowKZGProbeVerifiesSerializedProof(t *testing.T) {
	r, err := run(4, 2, 42)
	if err != nil {
		t.Fatal(err)
	}
	if !r.Verified || !r.DecodedVerified || !r.DirectVerified || !r.DirectDecodedVerified ||
		r.ProofBytes == 0 || r.DirectProofBytes == 0 || r.StatementBytes == 0 {
		t.Fatalf("incomplete row-KZG result: %+v", r)
	}
}
