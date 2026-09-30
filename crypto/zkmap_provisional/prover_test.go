package zkmap_provisional

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/fft"
)

func TestInterpolationIntegerNodesSmall(t *testing.T) {
	basis, _, err := preprocessIntegerBasis(2)
	if err != nil {
		t.Fatalf("preprocess basis: %v", err)
	}

	var v0, v1 fr.Element
	v0.SetUint64(10)
	v1.SetUint64(20)
	values := []fr.Element{v0, v1}

	coeffs := interpolateFromBasis(basis, values)

	if len(coeffs) != 2 {
		t.Errorf("expected 2 coefficients, got %d", len(coeffs))
	}

	var x0, x1 fr.Element
	x0.SetUint64(0)
	x1.SetUint64(1)

	e0 := evalPolynomial(coeffs, x0)
	e1 := evalPolynomial(coeffs, x1)
	if !e0.Equal(&values[0]) {
		t.Errorf("eval at 0: got %v, want %v", e0, values[0])
	}
	if !e1.Equal(&values[1]) {
		t.Errorf("eval at 1: got %v, want %v", e1, values[1])
	}
}

func TestPolynomialProduct(t *testing.T) {
	var a0, a1, b0, b1 fr.Element
	a0.SetUint64(1)
	a1.SetUint64(2)
	b0.SetUint64(3)
	b1.SetUint64(4)

	a := []fr.Element{a0, a1}
	b := []fr.Element{b0, b1}

	prod := polynomialProduct(a, b)

	if len(prod) != 3 {
		t.Errorf("expected 3 coefficients, got %d", len(prod))
	}

	var expected0, expected1, expected2 fr.Element
	expected0.SetUint64(3)
	expected1.SetUint64(10)
	expected2.SetUint64(8)

	if !prod[0].Equal(&expected0) || !prod[1].Equal(&expected1) || !prod[2].Equal(&expected2) {
		t.Errorf("product coefficients incorrect")
	}
}

func TestDivideByXMinusY(t *testing.T) {
	var y fr.Element
	y.SetUint64(2)

	var c0, c1, c2 fr.Element
	c0.SetUint64(5)
	c1.SetUint64(7)
	c2.SetUint64(3)

	poly := []fr.Element{c0, c1, c2}

	q, r := divideByXMinusY(poly, y)

	if len(q) != 2 {
		t.Errorf("expected quotient of length 2, got %d", len(q))
	}

	reconstructed := polynomialProduct(q, []fr.Element{fr.Element{}, fr.Element{}})
	_ = reconstructed

	pAtY := evalPolynomial(poly, y)
	if !pAtY.Equal(&r) {
		t.Errorf("division check: p(y) not equal remainder. p(y)=%v, rem=%v", pAtY, r)
	}
}

func TestProverSmallN(t *testing.T) {
	config := ProverConfig{
		N:                 8,
		Mode:              IntegerNodes,
		NumThreads:        1,
		MaxMatrixElements: 1 << 20,
	}

	result, err := ProveBN254(config)
	if err != nil {
		t.Fatalf("prover failed: %v", err)
	}

	if result == nil {
		t.Fatal("prover returned nil result")
	}

	if result.Error != "" {
		t.Errorf("prover error: %s", result.Error)
	}

	if result.Dimensions != 8 {
		t.Errorf("expected n=8, got %d", result.Dimensions)
	}

	if !result.ProvisionalOperationOnly {
		t.Error("not marked provisional")
	}

	if result.SecurityCertified {
		t.Error("should not be security certified")
	}

	if result.ComparisonEligibleAsValidProof {
		t.Error("should not be eligible as valid proof")
	}

	if result.MuDotConsistent != true {
		t.Error("mu dot product should match mu")
	}
}

func TestProverSmallNFFT(t *testing.T) {
	config := ProverConfig{
		N:                 8,
		Mode:              FFTRoots,
		NumThreads:        1,
		MaxMatrixElements: 1 << 20,
	}

	result, err := ProveBN254(config)
	if err != nil {
		t.Fatalf("prover FFT failed: %v", err)
	}

	if result == nil {
		t.Fatal("prover returned nil result")
	}

	if result.Error != "" {
		t.Errorf("prover error: %s", result.Error)
	}

	if result.InterpolationMode != "fft" {
		t.Errorf("expected fft mode, got %s", result.InterpolationMode)
	}
}

func TestProjectionAndMuConsistency(t *testing.T) {
	config := ProverConfig{
		N:                 4,
		Mode:              IntegerNodes,
		NumThreads:        1,
		MaxMatrixElements: 1 << 20,
	}

	result, err := ProveBN254(config)
	if err != nil {
		t.Fatalf("prover failed: %v", err)
	}

	if !result.MuDotConsistent {
		t.Error("mu and dot product should match for honest C")
	}
}

func TestRemainderPreservation(t *testing.T) {
	config := ProverConfig{
		N:                 8,
		Mode:              IntegerNodes,
		NumThreads:        1,
		MaxMatrixElements: 1 << 20,
	}

	result, err := ProveBN254(config)
	if err != nil {
		t.Fatalf("prover failed: %v", err)
	}

	if result.ActualRemainder == "" {
		t.Error("remainder not recorded")
	}

	if result.RemainderIsZero != result.WitnessPolynomialExists {
		t.Error("remainder zero status should match witness existence")
	}
}

func TestIntegerRecoveryAllNodes(t *testing.T) {
	n := 8
	basis, _, err := preprocessIntegerBasis(n)
	if err != nil {
		t.Fatalf("preprocess basis: %v", err)
	}

	values := make([]fr.Element, n)
	for i := 0; i < n; i++ {
		values[i].SetUint64(uint64(i + 1))
	}

	coeffs := interpolateFromBasis(basis, values)

	for i := 0; i < n; i++ {
		var xi fr.Element
		xi.SetUint64(uint64(i))
		eval := evalPolynomial(coeffs, xi)
		if !eval.Equal(&values[i]) {
			t.Errorf("integer recovery failed at node %d: got %v, want %v", i, eval, values[i])
		}
	}
}

func TestFFTRecoveryAllNodes(t *testing.T) {
	n := 8
	domain := fft.NewDomain(uint64(n))

	values := make([]fr.Element, n)
	for i := 1; i <= n; i++ {
		values[i-1].SetUint64(uint64(i))
	}

	coeffs := make([]fr.Element, n)
	copy(coeffs, values)
	domain.FFTInverse(coeffs, fft.DIF, fft.WithNbTasks(1))
	fft.BitReverse(coeffs)

	gen, err := fft.Generator(uint64(n))
	if err != nil {
		t.Fatalf("get generator: %v", err)
	}

	var power fr.Element
	power.SetOne()
	for i := 0; i < n; i++ {
		eval := evalPolynomial(coeffs, power)
		if !eval.Equal(&values[i]) {
			t.Errorf("FFT recovery failed at root^%d: got %v, want %v", i, eval, values[i])
		}
		power.Mul(&power, &gen)
	}

	var genN fr.Element
	genN.SetOne()
	for i := 0; i < n; i++ {
		genN.Mul(&genN, &gen)
	}
	if !genN.IsOne() {
		t.Error("generator order != n")
	}

	var genHalf fr.Element
	genHalf.SetOne()
	for i := 0; i < n/2; i++ {
		genHalf.Mul(&genHalf, &gen)
	}
	if genHalf.IsOne() {
		t.Error("generator^(n/2) should not be 1")
	}
}

func TestConfigValidationOverflow(t *testing.T) {
	config := ProverConfig{
		N:                 2000,
		Mode:              IntegerNodes,
		NumThreads:        1,
		MaxMatrixElements: 1 << 20,
	}

	if err := config.Validate(); err == nil {
		t.Error("n=2000 should be rejected with default 1<<20 cap")
	}
}

func TestConfigN1024Accepts(t *testing.T) {
	config := ProverConfig{
		N:                 1024,
		Mode:              IntegerNodes,
		NumThreads:        1,
		MaxMatrixElements: 1 << 20,
	}

	if err := config.Validate(); err != nil {
		t.Errorf("n=1024 should be accepted with cap 1<<20: %v", err)
	}
}

func TestPreparedProverReuse(t *testing.T) {
	config := ProverConfig{
		N:                 8,
		Mode:              IntegerNodes,
		NumThreads:        1,
		MaxMatrixElements: 1 << 20,
	}

	prover, err := NewPreparedProver(config)
	if err != nil {
		t.Fatalf("prepare prover: %v", err)
	}

	result1, err := prover.Prove()
	if err != nil {
		t.Fatalf("first prove: %v", err)
	}

	result2, err := prover.Prove()
	if err != nil {
		t.Fatalf("second prove: %v", err)
	}

	if result1.SetupInvocationCount != 1 || result2.SetupInvocationCount != 1 {
		t.Error("both calls should report setup_invocation_count=1")
	}

	if result1.TimingBreakdown.SetupSeconds <= 0 {
		t.Error("setup_seconds should be positive")
	}
	if result1.TimingBreakdown.PreprocessingSeconds <= 0 {
		t.Error("preprocessing_seconds should be positive")
	}
	if result1.TimingBreakdown.AuxiliarySeconds <= 0 {
		t.Error("auxiliary_seconds should be positive")
	}

	if result1.ChallengeYHex == result2.ChallengeYHex {
		t.Error("challenges should differ for different random matrices")
	}
}
