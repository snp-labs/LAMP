package crypto

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/fft"
)

func TestColumnCoefficientEncodingMatchesFolds(t *testing.T) {
	for _, k := range []int{4, 8} {
		m := 2 * k
		column := make([]fr.Element, k)
		for i := range column {
			column[i].SetUint64(uint64(i*i + 7))
		}
		encoded, err := EncodeColumnCoefficients(column, m)
		if err != nil {
			t.Fatal(err)
		}
		roots := GetDomainRoots(fft.NewDomain(uint64(m)), m)
		for i, root := range roots {
			want := FoldPowers(column, root)
			if !encoded[i].Equal(&want) {
				t.Fatalf("K=%d position=%d: FFT and fold differ", k, i)
			}
		}
	}
}

func TestColumnEncodingIsLinearAndDetectsChangedCoefficient(t *testing.T) {
	a := make([]fr.Element, 4)
	b := make([]fr.Element, 4)
	for i := range a {
		a[i].SetUint64(uint64(i + 1))
		b[i].SetUint64(uint64(10 + i))
	}
	ea, _ := EncodeColumnCoefficients(a, 8)
	eb, _ := EncodeColumnCoefficients(b, 8)
	sum := make([]fr.Element, 4)
	for i := range sum {
		sum[i].Add(&a[i], &b[i])
	}
	esum, _ := EncodeColumnCoefficients(sum, 8)
	for i := range esum {
		var want fr.Element
		want.Add(&ea[i], &eb[i])
		if !esum[i].Equal(&want) {
			t.Fatalf("linearity failed at %d", i)
		}
	}
	a[0].SetUint64(99)
	changed, _ := EncodeColumnCoefficients(a, 8)
	for i := range ea {
		if ea[i].Equal(&changed[i]) {
			t.Fatalf("changed constant coefficient was not detected at %d", i)
		}
	}
}

func TestColumnEncodingRejectsInvalidShapes(t *testing.T) {
	for _, tc := range []struct{ k, m int }{{0, 8}, {3, 8}, {4, 7}, {8, 8}, {8, 4}} {
		if _, err := EncodeColumnCoefficients(make([]fr.Element, tc.k), tc.m); err == nil {
			t.Fatalf("accepted K=%d M=%d", tc.k, tc.m)
		}
	}
}

// At rate 1/2, a nonzero degree-(K-1) error may vanish at K-1 of M=2K
// permitted row challenges. Many horizontal column queries do not repair a
// bad shared row challenge. This is why the component is not a LAMP proof.
func TestSingleVerticalRowChallengeCanMissAlmostHalfTheDomain(t *testing.T) {
	const k, m = 8, 16
	roots := GetDomainRoots(fft.NewDomain(m), m)
	coefficients := []fr.Element{{}}
	coefficients[0].SetOne()
	for i := 0; i < k-1; i++ {
		next := make([]fr.Element, len(coefficients)+1)
		for degree, coefficient := range coefficients {
			var term fr.Element
			term.Mul(&coefficient, &roots[i])
			next[degree].Sub(&next[degree], &term)
			next[degree+1].Add(&next[degree+1], &coefficient)
		}
		coefficients = next
	}
	encoded, err := EncodeColumnCoefficients(coefficients, m)
	if err != nil {
		t.Fatal(err)
	}
	zeros := 0
	var zero fr.Element
	for _, value := range encoded {
		if value.Equal(&zero) {
			zeros++
		}
	}
	if zeros != k-1 {
		t.Fatalf("expected %d missed row challenges out of %d, found %d", k-1, m, zeros)
	}
}
