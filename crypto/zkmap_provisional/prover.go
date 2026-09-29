package zkmap_provisional

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"
	"runtime"
	"time"

	"example.com/lamp/matrix"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/fft"
	"github.com/consensys/gnark-crypto/ecc/bn254/kzg"
)

type OperationTiming struct {
	InputGenerationSeconds float64 `json:"input_generation_seconds"`
	MatmulSeconds          float64 `json:"matmul_seconds"`
	SetupSeconds           float64 `json:"setup_seconds"`
	PreprocessingSeconds   float64 `json:"preprocessing_seconds"`
	InputCommitSeconds     float64 `json:"input_commit_seconds"`
	ChallengeSeconds       float64 `json:"challenge_seconds"`
	ProjectionsSeconds     float64 `json:"projections_seconds"`
	InterpolationSeconds   float64 `json:"interpolation_seconds"`
	ProductSeconds         float64 `json:"polynomial_product_seconds"`
	DivisionSeconds        float64 `json:"polynomial_division_seconds"`
	AuxiliarySeconds       float64 `json:"auxiliary_commit_seconds"`
	OnlineSeconds          float64 `json:"online_seconds"`
	TotalSeconds           float64 `json:"total_seconds"`
}

type ProverResult struct {
	ProvisionalOperationOnly       bool            `json:"provisional_operation_only"`
	SecurityCertified              bool            `json:"security_certified"`
	ComparisonEligibleAsValidProof bool            `json:"comparison_eligible_as_valid_proof"`
	Dimensions                     int             `json:"n"`
	DenseElements                  int             `json:"dense_elements"`
	SRSCompressedBytes             int             `json:"srs_compressed_bytes"`
	G1ProofAttemptBytes            int             `json:"g1_proof_attempt_bytes"`
	IntegerBasisBytes              int             `json:"integer_basis_bytes"`
	SetupInvocationCount           int             `json:"setup_invocation_count"`
	ActualGOMPAXPROCS              int             `json:"actual_gomaxprocs"`
	ConfiguredThreads              int             `json:"configured_threads"`
	TimingBreakdown                OperationTiming `json:"timing_breakdown"`
	ChallengeYHex                  string          `json:"challenge_y_hex"`
	ActualRemainder                string          `json:"actual_remainder"`
	RemainderIsZero                bool            `json:"remainder_is_zero"`
	WitnessPolynomialExists        bool            `json:"witness_polynomial_exists"`
	LiteralPairingAccepted         bool            `json:"literal_pairing_accepted"`
	MuDotConsistent                bool            `json:"mu_dot_consistent"`
	InterpolationMode              string          `json:"interpolation_mode"`
	GoVersion                      string          `json:"go_version"`
	Error                          string          `json:"error,omitempty"`
}

const domain = "zkmap-provisional/prover/v1"

type InterpolationMode int

const (
	IntegerNodes InterpolationMode = iota
	FFTRoots
)

type ProverConfig struct {
	N                 int
	Mode              InterpolationMode
	NumThreads        int
	MaxMatrixElements int
}

func (c *ProverConfig) Validate() error {
	if c.N < 2 || c.N > 32768 {
		return fmt.Errorf("n must be in [2, 32768], got %d", c.N)
	}
	if c.NumThreads < 1 {
		return fmt.Errorf("threads must be >= 1, got %d", c.NumThreads)
	}
	if c.MaxMatrixElements < 1 {
		return fmt.Errorf("max elements must be >= 1, got %d", c.MaxMatrixElements)
	}
	// Per-matrix cap: each matrix is N*N elements
	if c.N > c.MaxMatrixElements/c.N {
		return fmt.Errorf("n=%d exceeds per-matrix cap %d (n > maxElements/n)", c.N, c.MaxMatrixElements)
	}
	if c.Mode == FFTRoots {
		if c.N&(c.N-1) != 0 {
			return fmt.Errorf("FFT mode requires n to be power of two, got %d", c.N)
		}
	} else if c.Mode != IntegerNodes {
		return fmt.Errorf("unknown interpolation mode: %d", c.Mode)
	}
	return nil
}

type PreparedProver struct {
	config               ProverConfig
	srs                  *kzg.SRS
	srsCompressedBytes   int
	srsFingerprint       [32]byte
	integerBasis         [][]fr.Element
	integerBasisBytes    int
	fftDomain            *fft.Domain
	setupSeconds         float64
	preprocessingSeconds float64
}

func NewPreparedProver(cfg ProverConfig) (*PreparedProver, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	runtime.GOMAXPROCS(cfg.NumThreads)

	tSetup := time.Now()
	srs, err := setupPublicSRS(uint64(cfg.N))
	if err != nil {
		return nil, fmt.Errorf("setup SRS: %w", err)
	}
	setupSeconds := time.Since(tSetup).Seconds()

	tPrep := time.Now()
	srsFingerprint, err := computeSRSFingerprint(srs)
	if err != nil {
		return nil, err
	}

	srsCompressed, err := computeSRSCompressedBytes(srs)
	if err != nil {
		return nil, err
	}
	var intBasis [][]fr.Element
	var intBasisBytes int
	var fftDom *fft.Domain

	if cfg.Mode == IntegerNodes {
		intBasis, intBasisBytes, err = preprocessIntegerBasis(cfg.N)
		if err != nil {
			return nil, fmt.Errorf("preprocess integer basis: %w", err)
		}
	} else if cfg.Mode == FFTRoots {
		fftDom = fft.NewDomain(uint64(cfg.N))
	}
	preprocessingSeconds := time.Since(tPrep).Seconds()

	return &PreparedProver{
		config:               cfg,
		srs:                  srs,
		srsCompressedBytes:   srsCompressed,
		srsFingerprint:       srsFingerprint,
		integerBasis:         intBasis,
		integerBasisBytes:    intBasisBytes,
		fftDomain:            fftDom,
		setupSeconds:         setupSeconds,
		preprocessingSeconds: preprocessingSeconds,
	}, nil
}

func (p *PreparedProver) Prove() (*ProverResult, error) {
	return p.prove()
}

func setupPublicSRS(n uint64) (*kzg.SRS, error) {
	alpha, err := randNonzeroScalar()
	if err != nil {
		return nil, err
	}
	alphaBig := alpha.BigInt(new(big.Int))
	return kzg.NewSRS(n*n, alphaBig)
}

func randNonzeroScalar() (fr.Element, error) {
	for {
		var s fr.Element
		if _, err := s.SetRandom(); err != nil {
			return fr.Element{}, err
		}
		if !s.IsZero() {
			return s, nil
		}
	}
}

func computeSRSFingerprint(srs *kzg.SRS) ([32]byte, error) {
	var buf bytes.Buffer
	if _, err := srs.WriteTo(&buf); err != nil {
		return [32]byte{}, fmt.Errorf("serialize SRS: %w", err)
	}
	return sha256.Sum256(buf.Bytes()), nil
}

func computeSRSCompressedBytes(srs *kzg.SRS) (int, error) {
	var buf bytes.Buffer
	if _, err := srs.WriteTo(&buf); err != nil {
		return 0, fmt.Errorf("serialize SRS: %w", err)
	}
	return buf.Len(), nil
}

func preprocessIntegerBasis(n int) ([][]fr.Element, int, error) {
	basis := make([][]fr.Element, n)
	for i := 0; i < n; i++ {
		basis[i] = make([]fr.Element, n)
	}

	var one fr.Element
	one.SetOne()
	commonPoly := []fr.Element{one}
	for j := 0; j < n; j++ {
		var root fr.Element
		root.SetUint64(uint64(j))
		negRoot := new(fr.Element)
		negRoot.Neg(&root)

		newPoly := make([]fr.Element, len(commonPoly)+1)
		for k := 0; k < len(commonPoly); k++ {
			var term fr.Element
			term.Mul(&commonPoly[k], negRoot)
			newPoly[k].Add(&newPoly[k], &term)
			newPoly[k+1].Add(&newPoly[k+1], &commonPoly[k])
		}
		commonPoly = newPoly
	}

	for i := 0; i < n; i++ {
		var xi fr.Element
		xi.SetUint64(uint64(i))
		q, r := divideByXMinusY(commonPoly, xi)

		var denom fr.Element
		denom.SetOne()
		for j := 0; j < n; j++ {
			if i == j {
				continue
			}
			var xi, xj, diff fr.Element
			xi.SetUint64(uint64(i))
			xj.SetUint64(uint64(j))
			diff.Sub(&xi, &xj)
			denom.Mul(&denom, &diff)
		}

		if !r.IsZero() {
			return nil, 0, fmt.Errorf("quotient remainder nonzero at i=%d", i)
		}

		denomInv := new(fr.Element).Inverse(&denom)
		for k := 0; k < len(q); k++ {
			basis[i][k].Mul(&q[k], denomInv)
		}
	}

	basisBytes := n * n * 32
	return basis, basisBytes, nil
}

func challengeDerivation(n int, mode InterpolationMode, fingerprint [32]byte, va, vb, vc bn254.G1Affine) (fr.Element, string) {
	h := sha256.New()
	h.Write([]byte(domain))

	var dims [8]byte
	binary.BigEndian.PutUint64(dims[:], uint64(n))
	h.Write(dims[:])

	h.Write(fingerprint[:])

	var modeBytes [1]byte
	if mode == FFTRoots {
		modeBytes[0] = 1
	}
	h.Write(modeBytes[:])

	h.Write(va.Marshal())
	h.Write(vb.Marshal())
	h.Write(vc.Marshal())

	digest := h.Sum(nil)
	var y fr.Element
	y.SetBigInt(new(big.Int).SetBytes(digest))

	return y, hex.EncodeToString(digest)
}

func divideByXMinusY(p []fr.Element, y fr.Element) ([]fr.Element, fr.Element) {
	if len(p) == 0 {
		return []fr.Element{}, fr.Element{}
	}
	if len(p) == 1 {
		var zero fr.Element
		return []fr.Element{zero}, p[0]
	}

	q := make([]fr.Element, len(p)-1)
	q[len(q)-1] = p[len(p)-1]
	for i := len(q) - 2; i >= 0; i-- {
		q[i].Mul(&q[i+1], &y)
		q[i].Add(&q[i], &p[i+1])
	}

	var r fr.Element
	r.Mul(&q[0], &y)
	r.Add(&r, &p[0])

	return q, r
}

func polynomialProduct(a, b []fr.Element) []fr.Element {
	out := make([]fr.Element, len(a)+len(b)-1)
	for i := 0; i < len(a); i++ {
		for j := 0; j < len(b); j++ {
			var term fr.Element
			term.Mul(&a[i], &b[j])
			out[i+j].Add(&out[i+j], &term)
		}
	}
	return out
}

func evalPolynomial(coeffs []fr.Element, x fr.Element) fr.Element {
	var v fr.Element
	for i := len(coeffs) - 1; i >= 0; i-- {
		v.Mul(&v, &x)
		v.Add(&v, &coeffs[i])
	}
	return v
}

func mulG1(p bn254.G1Affine, s fr.Element) bn254.G1Affine {
	var out bn254.G1Affine
	out.ScalarMultiplication(&p, s.BigInt(new(big.Int)))
	return out
}

func mulG2(p bn254.G2Affine, s fr.Element) bn254.G2Affine {
	var out bn254.G2Affine
	out.ScalarMultiplication(&p, s.BigInt(new(big.Int)))
	return out
}

func addG1(a, b bn254.G1Affine) bn254.G1Affine {
	var out bn254.G1Affine
	out.Add(&a, &b)
	return out
}

func subG1(a, b bn254.G1Affine) bn254.G1Affine {
	var neg bn254.G1Affine
	neg.Neg(&b)
	return addG1(a, neg)
}

func subG2(a, b bn254.G2Affine) bn254.G2Affine {
	var neg bn254.G2Affine
	neg.Neg(&b)
	var out bn254.G2Affine
	out.Add(&a, &neg)
	return out
}

func scalarPairing(lhsVW, rhsG1 bn254.G1Affine, d2, g2 bn254.G2Affine) (bool, error) {
	negRHS := rhsG1
	negRHS.Neg(&rhsG1)
	return bn254.PairingCheck([]bn254.G1Affine{lhsVW, negRHS}, []bn254.G2Affine{d2, g2})
}

func (p *PreparedProver) prove() (*ProverResult, error) {
	result := &ProverResult{
		ProvisionalOperationOnly:       true,
		SecurityCertified:              false,
		ComparisonEligibleAsValidProof: false,
		Dimensions:                     p.config.N,
		DenseElements:                  p.config.N * p.config.N * 3,
		SRSCompressedBytes:             p.srsCompressedBytes,
		IntegerBasisBytes:              p.integerBasisBytes,
		G1ProofAttemptBytes:            7 * 32,
		SetupInvocationCount:           1,
		ActualGOMPAXPROCS:              runtime.GOMAXPROCS(-1),
		ConfiguredThreads:              p.config.NumThreads,
		InterpolationMode:              "integers",
		GoVersion:                      runtime.Version(),
	}

	if p.config.Mode == FFTRoots {
		result.InterpolationMode = "fft"
	}

	result.TimingBreakdown.SetupSeconds = p.setupSeconds
	result.TimingBreakdown.PreprocessingSeconds = p.preprocessingSeconds

	startTotal := time.Now()

	tInputGen := time.Now()
	a := make([]fr.Element, p.config.N*p.config.N)
	b := make([]fr.Element, p.config.N*p.config.N)
	for i := 0; i < len(a); i++ {
		if _, err := a[i].SetRandom(); err != nil {
			result.Error = fmt.Sprintf("random A[%d]: %v", i, err)
			return result, err
		}
		if _, err := b[i].SetRandom(); err != nil {
			result.Error = fmt.Sprintf("random B[%d]: %v", i, err)
			return result, err
		}
	}
	result.TimingBreakdown.InputGenerationSeconds = time.Since(tInputGen).Seconds()

	tMatmul := time.Now()
	a2d := make([][]fr.Element, p.config.N)
	b2d := make([][]fr.Element, p.config.N)
	for i := 0; i < p.config.N; i++ {
		a2d[i] = a[i*p.config.N : (i+1)*p.config.N]
		b2d[i] = b[i*p.config.N : (i+1)*p.config.N]
	}

	c2d := matrix.MatMulRect(a2d, b2d, p.config.N, p.config.N, p.config.N)
	c := make([]fr.Element, p.config.N*p.config.N)
	for i := 0; i < p.config.N; i++ {
		copy(c[i*p.config.N:(i+1)*p.config.N], c2d[i])
	}
	result.TimingBreakdown.MatmulSeconds = time.Since(tMatmul).Seconds()

	startOnline := time.Now()

	tCommit := time.Now()
	va, err := kzg.Commit(a, p.srs.Pk, p.config.NumThreads)
	if err != nil {
		result.Error = fmt.Sprintf("commit A: %v", err)
		return result, err
	}
	vb, err := kzg.Commit(b, p.srs.Pk, p.config.NumThreads)
	if err != nil {
		result.Error = fmt.Sprintf("commit B: %v", err)
		return result, err
	}
	vc, err := kzg.Commit(c, p.srs.Pk, p.config.NumThreads)
	if err != nil {
		result.Error = fmt.Sprintf("commit C: %v", err)
		return result, err
	}
	result.TimingBreakdown.InputCommitSeconds = time.Since(tCommit).Seconds()

	tChall := time.Now()
	y, yHex := challengeDerivation(p.config.N, p.config.Mode, p.srsFingerprint, va, vb, vc)
	result.ChallengeYHex = yHex
	result.TimingBreakdown.ChallengeSeconds = time.Since(tChall).Seconds()

	tProj := time.Now()
	var yPow, power fr.Element
	yPow.SetOne()
	yL := make([]fr.Element, p.config.N)
	for i := 0; i < p.config.N; i++ {
		yL[i] = yPow
		for k := 0; k < p.config.N; k++ {
			yPow.Mul(&yPow, &y)
		}
	}

	power.SetOne()
	yR := make([]fr.Element, p.config.N)
	for i := 0; i < p.config.N; i++ {
		yR[i] = power
		power.Mul(&power, &y)
	}

	ay := make([]fr.Element, p.config.N)
	by := make([]fr.Element, p.config.N)
	for j := 0; j < p.config.N; j++ {
		for i := 0; i < p.config.N; i++ {
			var term fr.Element
			term.Mul(&yL[i], &a[i*p.config.N+j])
			ay[j].Add(&ay[j], &term)
		}
	}
	for i := 0; i < p.config.N; i++ {
		for j := 0; j < p.config.N; j++ {
			var term fr.Element
			term.Mul(&b[i*p.config.N+j], &yR[j])
			by[i].Add(&by[i], &term)
		}
	}

	var mu fr.Element
	for i := 0; i < p.config.N; i++ {
		for j := 0; j < p.config.N; j++ {
			var term fr.Element
			term.Mul(&yL[i], &c[i*p.config.N+j])
			term.Mul(&term, &yR[j])
			mu.Add(&mu, &term)
		}
	}

	result.TimingBreakdown.ProjectionsSeconds = time.Since(tProj).Seconds()

	tInterp := time.Now()
	var pay, pby []fr.Element
	if p.config.Mode == IntegerNodes {
		pay = interpolateFromBasis(p.integerBasis, ay)
		pby = interpolateFromBasis(p.integerBasis, by)
	} else {
		pay = make([]fr.Element, p.config.N)
		copy(pay, ay)
		p.fftDomain.FFTInverse(pay, fft.DIF, fft.WithNbTasks(p.config.NumThreads))
		fft.BitReverse(pay)

		pby = make([]fr.Element, p.config.N)
		copy(pby, by)
		p.fftDomain.FFTInverse(pby, fft.DIF, fft.WithNbTasks(p.config.NumThreads))
		fft.BitReverse(pby)
	}
	result.TimingBreakdown.InterpolationSeconds = time.Since(tInterp).Seconds()

	tProd := time.Now()
	prod := polynomialProduct(pay, pby)
	result.TimingBreakdown.ProductSeconds = time.Since(tProd).Seconds()

	tDiv := time.Now()
	numerator := make([]fr.Element, len(prod))
	for i := 0; i < len(prod); i++ {
		numerator[i].Neg(&prod[i])
	}
	numerator[0].Add(&numerator[0], &mu)
	q, rem := divideByXMinusY(numerator, y)
	result.TimingBreakdown.DivisionSeconds = time.Since(tDiv).Seconds()

	result.ActualRemainder = fieldToHex(rem)
	result.RemainderIsZero = rem.IsZero()
	result.WitnessPolynomialExists = rem.IsZero()

	tAux := time.Now()
	vw, errVW := kzg.Commit(q, p.srs.Pk, p.config.NumThreads)
	if errVW != nil {
		result.Error = fmt.Sprintf("commit quotient: %v", errVW)
		return result, errVW
	}
	vay, errAy := kzg.Commit(pay, p.srs.Pk, p.config.NumThreads)
	if errAy != nil {
		result.Error = fmt.Sprintf("commit pay: %v", errAy)
		return result, errAy
	}
	vby, errBy := kzg.Commit(pby, p.srs.Pk, p.config.NumThreads)
	if errBy != nil {
		result.Error = fmt.Sprintf("commit pby: %v", errBy)
		return result, errBy
	}
	vmu := mulG1(p.srs.Pk.G1[0], mu)
	result.TimingBreakdown.AuxiliarySeconds = time.Since(tAux).Seconds()

	result.TimingBreakdown.OnlineSeconds = time.Since(startOnline).Seconds()

	var muDot fr.Element
	for i := 0; i < p.config.N; i++ {
		var term fr.Element
		term.Mul(&ay[i], &by[i])
		muDot.Add(&muDot, &term)
	}
	result.MuDotConsistent = mu.Equal(&muDot)
	if !result.MuDotConsistent {
		result.Error = "honest C failed: mu != dot(ay,by)"
		return result, fmt.Errorf("consistency check failed")
	}

	result.G1ProofAttemptBytes = len(va.Bytes()) + len(vb.Bytes()) + len(vc.Bytes()) + len(vw.Bytes()) +
		len(vay.Bytes()) + len(vby.Bytes()) + len(vmu.Bytes())

	d2 := subG2(p.srs.Vk.G2[1], mulG2(p.srs.Vk.G2[0], y))
	rhs := subG1(subG1(vmu, vay), vby)
	accepted, errPairing := scalarPairing(vw, rhs, d2, p.srs.Vk.G2[0])
	if errPairing != nil {
		result.Error = fmt.Sprintf("pairing check: %v", errPairing)
		return result, errPairing
	}
	result.LiteralPairingAccepted = accepted

	result.TimingBreakdown.TotalSeconds = time.Since(startTotal).Seconds()

	return result, nil
}

func interpolateFromBasis(basis [][]fr.Element, values []fr.Element) []fr.Element {
	n := len(values)
	out := make([]fr.Element, n)
	for i := 0; i < n; i++ {
		for j := 0; j < n; j++ {
			var term fr.Element
			term.Mul(&basis[i][j], &values[i])
			out[j].Add(&out[j], &term)
		}
	}
	return out
}

func fieldToHex(f fr.Element) string {
	b := f.Bytes()
	return hex.EncodeToString(b[:])
}

func ProveBN254(config ProverConfig) (*ProverResult, error) {
	prover, err := NewPreparedProver(config)
	if err != nil {
		return nil, err
	}
	return prover.Prove()
}
