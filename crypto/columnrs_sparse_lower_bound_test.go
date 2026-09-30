package crypto

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

// Even perfectly verified vertical RS degree bounds do not make a generic
// x^T B column inner product recoverable from fewer than K evaluations.
func TestSparseColumnOpeningsDoNotBindGenericInnerProduct(t *testing.T) {
	const k, m = 8, 16
	encoder, err := NewColumnCoefficientEncoder(k, m)
	if err != nil {
		t.Fatal(err)
	}
	roots := encoder.Roots()
	for sampled := 1; sampled < k; sampled++ {
		// h(T) = T^(K-1-sampled) * product_{i<sampled}(T-root_i).
		// It has degree K-1, vanishes at every opened point, but its
		// leading coefficient is one. Let x=e_{K-1}; then x^T h=1.
		poly := []fr.Element{{}}
		poly[0].SetOne()
		for i := 0; i < sampled; i++ {
			next := make([]fr.Element, len(poly)+1)
			for j := range poly {
				var term fr.Element
				term.Mul(&poly[j], &roots[i])
				next[j].Sub(&next[j], &term)
				next[j+1].Add(&next[j+1], &poly[j])
			}
			poly = next
		}
		column := make([]fr.Element, k)
		copy(column[k-1-sampled:], poly)
		encoded, err := encoder.Encode(column)
		if err != nil {
			t.Fatal(err)
		}
		for i := 0; i < sampled; i++ {
			if !encoded[i].IsZero() {
				t.Fatalf("sampled=%d: difference visible at opened row %d", sampled, i)
			}
		}
		var one fr.Element
		one.SetOne()
		if !column[k-1].Equal(&one) {
			t.Fatalf("sampled=%d: inner product did not change", sampled)
		}
	}
}
