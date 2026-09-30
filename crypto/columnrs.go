package crypto

import (
	"fmt"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/fft"
	"github.com/consensys/gnark-crypto/utils"
)

// ColumnCoefficientEncoder reuses one FFT domain across columns. Its inputs
// are coefficients, unlike Encoder.Encode, whose inputs are K-domain values.
type ColumnCoefficientEncoder struct {
	k, m   int
	domain *fft.Domain
}

func NewColumnCoefficientEncoder(k, m int) (*ColumnCoefficientEncoder, error) {
	if !isPowerOfTwo(k) || !isPowerOfTwo(m) || m <= k {
		return nil, fmt.Errorf("require power-of-two K and M with 0 < K < M; got K=%d M=%d", k, m)
	}
	return &ColumnCoefficientEncoder{k: k, m: m, domain: fft.NewDomain(uint64(m))}, nil
}

func (e *ColumnCoefficientEncoder) Encode(column []fr.Element) ([]fr.Element, error) {
	if len(column) != e.k {
		return nil, fmt.Errorf("expected %d column coefficients, got %d", e.k, len(column))
	}
	values := make([]fr.Element, e.m)
	copy(values, column)
	e.domain.FFT(values, fft.DIF)
	utils.BitReverse(values)
	return values, nil
}

func (e *ColumnCoefficientEncoder) Roots() []fr.Element {
	return GetDomainRoots(e.domain, e.m)
}

// EncodeColumnCoefficients encodes a column of K monomial coefficients to domainSize codeword points.
// Input: column has K elements representing coefficients c0, c1, ..., c_{K-1} of polynomial
//
//	sum_i column[i] * x^i
//
// Output: encoded array of domainSize elements where encoded[e] = sum_i column[i] * root[e]^i
// Requires: K and domainSize are powers of two, domainSize > K
func EncodeColumnCoefficients(column []fr.Element, domainSize int) ([]fr.Element, error) {
	e, err := NewColumnCoefficientEncoder(len(column), domainSize)
	if err != nil {
		return nil, err
	}
	return e.Encode(column)
}

// FoldPowers evaluates the polynomial with given coefficients at point r using Horner's method.
// Input: column has K elements representing coefficients c0, c1, ..., c_{K-1}
//
//	r is the evaluation point
//
// Output: polynomial(r) = c0 + r*(c1 + r*(c2 + ... + r*c_{K-1}))
func FoldPowers(column []fr.Element, r fr.Element) fr.Element {
	if len(column) == 0 {
		var zero fr.Element
		return zero
	}

	// Horner's method: start from the highest degree coefficient
	result := column[len(column)-1]
	for i := len(column) - 2; i >= 0; i-- {
		result.Mul(&result, &r)
		result.Add(&result, &column[i])
	}

	return result
}

// Helper function to check if a number is a power of two
func isPowerOfTwo(n int) bool {
	return n > 0 && (n&(n-1)) == 0
}
