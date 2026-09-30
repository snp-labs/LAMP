// Package zkmap_audit contains executable, diagnostic-only reproductions of
// selected zkMaP paper equations. It is not a zkMaP implementation or benchmark.
package zkmap_audit

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"time"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/kzg"
)

type AuditResult struct {
	Name      string            `json:"name"`
	Category  string            `json:"category"`
	Passed    bool              `json:"passed"`
	Details   map[string]string `json:"details"`
	Code      string            `json:"code"`
	Assertion string            `json:"assertion"`
}

type AuditSummary struct {
	Timestamp     string         `json:"timestamp"`
	Results       []*AuditResult `json:"results"`
	CriticalCount int            `json:"critical_count"`
	DefiniteCount int            `json:"definite_count"`
	AllPassed     bool           `json:"all_passed"`
	Summary       string         `json:"summary"`
}

// rectangularConvolution computes the first four coefficients directly.
func RectangularConvolutionMismatch() *AuditResult {
	a := [6]uint64{2, 3, 5, 7, 11, 13}
	b := [6]uint64{17, 19, 23, 29, 31, 37}
	c := [4]uint64{
		2*17 + 3*23 + 5*31,
		2*19 + 3*29 + 5*37,
		7*17 + 11*23 + 13*31,
		7*19 + 11*29 + 13*37,
	}
	var conv [4]uint64
	for i := range a {
		for j := range b {
			if i+j < len(conv) {
				conv[i+j] += a[i] * b[j]
			}
		}
	}
	d := map[string]string{
		"matrix_product_row_major":    fmt.Sprint(c),
		"truncated_convolution":       fmt.Sprint(conv),
		"exact_convolution_assertion": fmt.Sprintf("[%d %d %d %d]", conv[0], conv[1], conv[2], conv[3]),
	}
	return &AuditResult{Name: "Rectangular convolution differs from matrix multiplication", Category: "DEFINITE", Code: "Section 4.1, p.13", Assertion: "Direct integer arithmetic gives matrix product [258 310 775 933] and truncated row-major convolution [34 89 188 341].", Passed: c == [4]uint64{258, 310, 775, 933} && conv == [4]uint64{34, 89, 188, 341}, Details: d}
}

// setupPublicSRS samples alpha privately, constructs a KZG SRS, then discards
// alpha. Only the public SRS is returned to callers.
func setupPublicSRS(n uint64) (*kzg.SRS, error) {
	modulus := fr.Modulus()
	var alpha *big.Int
	for alpha == nil || alpha.Sign() == 0 {
		v, err := rand.Int(rand.Reader, modulus)
		if err != nil {
			return nil, err
		}
		if v.Sign() != 0 {
			alpha = v
		}
	}
	return kzg.NewSRS(n*n, alpha)
}

func commit(coeffs []fr.Element, srs *kzg.SRS) (bn254.G1Affine, error) {
	return kzg.Commit(coeffs, srs.Pk)
}

func scalarBig(v fr.Element) *big.Int { return v.BigInt(new(big.Int)) }

func mulG1(p bn254.G1Affine, s fr.Element) bn254.G1Affine {
	var out bn254.G1Affine
	out.ScalarMultiplication(&p, scalarBig(s))
	return out
}

func mulG2(p bn254.G2Affine, s fr.Element) bn254.G2Affine {
	var out bn254.G2Affine
	out.ScalarMultiplication(&p, scalarBig(s))
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

func addG2(a, b bn254.G2Affine) bn254.G2Affine {
	var out bn254.G2Affine
	out.Add(&a, &b)
	return out
}

func subG2(a, b bn254.G2Affine) bn254.G2Affine {
	var neg bn254.G2Affine
	neg.Neg(&b)
	return addG2(a, neg)
}

func serializeG1(p bn254.G1Affine) []byte { return p.Marshal() }

func challenge(n int, srs *kzg.SRS, va, vb, vc bn254.G1Affine) (fr.Element, string, string, error) {
	var serialized bytes.Buffer
	if _, err := srs.WriteTo(&serialized); err != nil {
		return fr.Element{}, "", "", err
	}
	srsDigest := sha256.Sum256(serialized.Bytes())
	h := sha256.New()
	h.Write([]byte("zkmap-audit/challenge/v1"))
	var dims [8]byte
	binary.BigEndian.PutUint64(dims[:], uint64(n))
	h.Write(dims[:])
	h.Write(srsDigest[:])
	h.Write(serializeG1(va))
	h.Write(serializeG1(vb))
	h.Write(serializeG1(vc))
	digest := h.Sum(nil)
	var y fr.Element
	y.SetBigInt(new(big.Int).SetBytes(digest))
	return y, hex.EncodeToString(digest), hex.EncodeToString(srsDigest[:]), nil
}

func denseMatrices(n int) (a, b, c []fr.Element, invalid bool) {
	a = make([]fr.Element, n*n)
	b = make([]fr.Element, n*n)
	c = make([]fr.Element, n*n)
	for i := range a {
		a[i].SetUint64(uint64(i + 2))
		b[i].SetUint64(uint64(i + 5))
		c[i].SetUint64(uint64(i + 100))
	}
	product := make([]fr.Element, n*n)
	for i := 0; i < n; i++ {
		for j := 0; j < n; j++ {
			for k := 0; k < n; k++ {
				var term fr.Element
				term.Mul(&a[i*n+k], &b[k*n+j])
				product[i*n+j].Add(&product[i*n+j], &term)
			}
		}
	}
	invalid = false
	for i := range c {
		if !c[i].Equal(&product[i]) {
			invalid = true
		}
	}
	return
}

func scalarPairing(lhsVW, rhsG1 bn254.G1Affine, d2, g2 bn254.G2Affine) (bool, error) {
	negRHS := rhsG1
	negRHS.Neg(&rhsG1)
	return bn254.PairingCheck([]bn254.G1Affine{lhsVW, negRHS}, []bn254.G2Affine{d2, g2})
}

func runPairingAttacks(n int, srs *kzg.SRS, y fr.Element) (scalarAccepted, scalarTampered, appendixAccepted, appendixTampered bool, err error) {
	g1, g2 := srs.Pk.G1[0], srs.Vk.G2[0]
	sG1, sG2 := srs.Pk.G1[1], srs.Vk.G2[1]
	d1 := subG1(sG1, mulG1(g1, y))
	d2 := subG2(sG2, mulG2(g2, y))
	var aeval, beval, w, t fr.Element
	aeval.SetUint64(3)
	beval.SetUint64(5)
	w.SetUint64(7)
	t.Mul(&aeval, &beval)
	vw := mulG1(g1, w)
	tG1 := mulG1(g1, t)
	vmu := addG1(tG1, mulG1(d1, w))
	rhs := subG1(vmu, tG1)
	scalarAccepted, err = scalarPairing(vw, rhs, d2, g2)
	if err != nil {
		return
	}
	scalarTampered, err = scalarPairing(vw, addG1(rhs, g1), d2, g2)
	if err != nil {
		return
	}

	// Appendix E Algorithm 2 literally verifies e(VW,D2)=e(Vmu,G2)/e(Vay,G2)/e(Vby,G2).
	// Its attacker chooses all three proof commitments using public SRS points only.
	var av, bv fr.Element
	av.SetUint64(uint64(n + 3))
	bv.SetUint64(uint64(n + 7))
	vay, vby := mulG1(g1, av), mulG1(g1, bv)
	appendixVW := mulG1(g1, w)
	vmuAppendix := addG1(addG1(vay, vby), mulG1(d1, w))
	appendixRHS := subG1(subG1(vmuAppendix, vay), vby)
	appendixAccepted, err = scalarPairing(appendixVW, appendixRHS, d2, g2)
	if err != nil {
		return
	}
	appendixTampered, err = scalarPairing(appendixVW, addG1(appendixRHS, g1), d2, g2)
	return
}

// PairingAttackDiagnostic executes both the Section 4.4 scalar-evaluation
// reading and Appendix E Algorithm 2 against nonzero KZG commitments to a
// directly checked false matrix statement. No trapdoor is passed to the attack.
func PairingAttackDiagnostic(n int) *AuditResult {
	result := &AuditResult{Name: fmt.Sprintf("Public-SRS pairing attack, n=%d", n), Category: "CRITICAL", Code: "Section 4.4 p.16 unnumbered pairing equation; Appendix E Algorithm 2 p.37", Assertion: "Both published check forms accept a false dense matrix statement using public commitments and reject a one-generator Vmu mutation.", Details: map[string]string{"n": fmt.Sprint(n), "dimensions": fmt.Sprintf("%d x %d", n, n), "attack_trapdoor_input": "false"}}
	fail := func(err error) *AuditResult {
		result.Details["error"] = err.Error()
		result.Passed = false
		return result
	}
	if n < 1 {
		return fail(fmt.Errorf("n must be positive"))
	}
	srs, err := setupPublicSRS(uint64(n))
	if err != nil {
		return fail(err)
	}
	a, b, c, invalid := denseMatrices(n)
	va, err := commit(a, srs)
	if err != nil {
		return fail(fmt.Errorf("commit A: %w", err))
	}
	vb, err := commit(b, srs)
	if err != nil {
		return fail(fmt.Errorf("commit B: %w", err))
	}
	vc, err := commit(c, srs)
	if err != nil {
		return fail(fmt.Errorf("commit C: %w", err))
	}
	y, digest, srsDigest, err := challenge(n, srs, va, vb, vc)
	if err != nil {
		return fail(err)
	}
	scalarOK, scalarBad, appOK, appBad, err := runPairingAttacks(n, srs, y)
	if err != nil {
		return fail(fmt.Errorf("pairing check: %w", err))
	}
	result.Details["invalid_C_neq_AB"] = fmt.Sprint(invalid)
	result.Details["A_commitment_nonzero"] = fmt.Sprint(!va.IsInfinity())
	result.Details["B_commitment_nonzero"] = fmt.Sprint(!vb.IsInfinity())
	result.Details["C_commitment_nonzero"] = fmt.Sprint(!vc.IsInfinity())
	result.Details["challenge_sha256"] = digest
	result.Details["serialized_public_srs_sha256"] = srsDigest
	result.Details["challenge_y"] = y.String()
	result.Details["scalar_aeval"] = "3"
	result.Details["scalar_beval"] = "5"
	result.Details["scalar_w"] = "7"
	result.Details["scalar_t"] = "15"
	result.Details["appendix_Vay_scalar"] = fmt.Sprint(n + 3)
	result.Details["appendix_Vby_scalar"] = fmt.Sprint(n + 7)
	result.Details["appendix_VW_scalar"] = "7"
	result.Details["scalar_pairing_accepted"] = fmt.Sprint(scalarOK)
	result.Details["scalar_pairing_tampered_accepted"] = fmt.Sprint(scalarBad)
	result.Details["appendix_e_algorithm2_accepted"] = fmt.Sprint(appOK)
	result.Details["appendix_e_algorithm2_tampered_accepted"] = fmt.Sprint(appBad)
	result.Details["attack_scope"] = "algebraic exploit of stated equation only; not a full author implementation"
	result.Details["appendix_projection_relation"] = "Vay and Vby are attacker-chosen public points, not proven projections"
	result.Passed = invalid && !va.IsInfinity() && !vb.IsInfinity() && !vc.IsInfinity() && scalarOK && !scalarBad && appOK && !appBad
	return result
}

// interpolateAtIntegerNodes uses Lagrange interpolation over fr at 0..n-1.
func interpolateAtIntegerNodes(values []fr.Element) []fr.Element {
	out := make([]fr.Element, len(values))
	for i, yi := range values {
		var one fr.Element
		one.SetOne()
		basis := []fr.Element{one}
		denom := new(fr.Element).SetOne()
		for j := range values {
			if j == i {
				continue
			}
			var root fr.Element
			root.SetUint64(uint64(j))
			next := make([]fr.Element, len(basis)+1)
			for k := range basis {
				var negTerm fr.Element
				negTerm.Mul(&basis[k], &root)
				negTerm.Neg(&negTerm)
				next[k].Add(&next[k], &negTerm)
				next[k+1].Add(&next[k+1], &basis[k])
			}
			basis = next
			var xi, xj, diff fr.Element
			xi.SetUint64(uint64(i))
			xj.SetUint64(uint64(j))
			diff.Sub(&xi, &xj)
			denom.Mul(denom, &diff)
		}
		inv := new(fr.Element).Inverse(denom)
		for k := range basis {
			var term fr.Element
			term.Mul(&basis[k], &yi)
			term.Mul(&term, inv)
			out[k].Add(&out[k], &term)
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

func polynomialProduct(a, b []fr.Element) []fr.Element {
	out := make([]fr.Element, len(a)+len(b)-1)
	for i := range a {
		for j := range b {
			var term fr.Element
			term.Mul(&a[i], &b[j])
			out[i+j].Add(&out[i+j], &term)
		}
	}
	return out
}

// divideByXMinusY performs synthetic division and returns quotient and remainder.
func divideByXMinusY(p []fr.Element, y fr.Element) ([]fr.Element, fr.Element) {
	if len(p) <= 1 {
		r := p[0]
		return []fr.Element{{}}, r
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

// AppendixInterpolationDiagnostic documents one explicit interpretation of
// Algorithm 2's unspecified interpolation nodes: 0,1,...,n-1.
func AppendixInterpolationDiagnostic(n int) *AuditResult {
	result := &AuditResult{Name: fmt.Sprintf("Appendix E interpolation reproduction, n=%d", n), Category: "DIAGNOSTIC", Code: "Appendix E Algorithm 2 lines 11-18, p.37", Assertion: "Using nodes 0..n-1 and ordinary coefficient commitments, report the exact quotient remainder and execute the literal pairing check when a polynomial quotient exists.", Details: map[string]string{"n": fmt.Sprint(n), "interpolation_nodes": "0..n-1", "interpretation": "documented diagnostic choice; paper does not specify interpolation nodes"}}
	fail := func(err error) *AuditResult { result.Details["error"] = err.Error(); return result }
	if n < 1 {
		return fail(fmt.Errorf("n must be positive"))
	}
	srs, err := setupPublicSRS(uint64(n))
	if err != nil {
		return fail(err)
	}
	a, b, c, _ := denseMatrices(n)
	// Replace C by the independently computed honest A*B.
	for i := range c {
		c[i].SetZero()
	}
	for i := 0; i < n; i++ {
		for j := 0; j < n; j++ {
			for k := 0; k < n; k++ {
				var term fr.Element
				term.Mul(&a[i*n+k], &b[k*n+j])
				c[i*n+j].Add(&c[i*n+j], &term)
			}
		}
	}
	honestProduct := true
	for i := 0; i < n; i++ {
		for j := 0; j < n; j++ {
			var expected fr.Element
			for k := 0; k < n; k++ {
				var term fr.Element
				term.Mul(&a[i*n+k], &b[k*n+j])
				expected.Add(&expected, &term)
			}
			if !expected.Equal(&c[i*n+j]) {
				honestProduct = false
			}
		}
	}
	va, err := commit(a, srs)
	if err != nil {
		return fail(err)
	}
	vb, err := commit(b, srs)
	if err != nil {
		return fail(err)
	}
	vc, err := commit(c, srs)
	if err != nil {
		return fail(err)
	}
	y, _, _, err := challenge(n, srs, va, vb, vc)
	if err != nil {
		return fail(err)
	}
	var yl, yr []fr.Element
	yl, yr = make([]fr.Element, n), make([]fr.Element, n)
	var yToN fr.Element
	yToN.SetOne()
	for i := 0; i < n; i++ {
		yl[i] = yToN
		for k := 0; k < n; k++ {
			yToN.Mul(&yToN, &y)
		}
	}
	var power fr.Element
	power.SetOne()
	for i := 0; i < n; i++ {
		yr[i] = power
		power.Mul(&power, &y)
	}
	ay, by := make([]fr.Element, n), make([]fr.Element, n)
	for j := 0; j < n; j++ {
		for i := 0; i < n; i++ {
			var term fr.Element
			term.Mul(&yl[i], &a[i*n+j])
			ay[j].Add(&ay[j], &term)
		}
	}
	for i := 0; i < n; i++ {
		for j := 0; j < n; j++ {
			var term fr.Element
			term.Mul(&b[i*n+j], &yr[j])
			by[i].Add(&by[i], &term)
		}
	}
	var mu fr.Element
	// mu = yL^T C yR.
	for i := 0; i < n; i++ {
		for j := 0; j < n; j++ {
			var term fr.Element
			term.Mul(&yl[i], &c[i*n+j])
			term.Mul(&term, &yr[j])
			mu.Add(&mu, &term)
		}
	}
	pay, pby := interpolateAtIntegerNodes(ay), interpolateAtIntegerNodes(by)
	prod := polynomialProduct(pay, pby)
	numerator := make([]fr.Element, len(prod))
	for i := range prod {
		numerator[i].Neg(&prod[i])
	}
	numerator[0].Add(&numerator[0], &mu)
	q, rem := divideByXMinusY(numerator, y)
	reconstructed := make([]fr.Element, len(numerator))
	for i := range q {
		var negYQ fr.Element
		negYQ.Mul(&y, &q[i]).Neg(&negYQ)
		reconstructed[i].Add(&reconstructed[i], &negYQ)
		reconstructed[i+1].Add(&reconstructed[i+1], &q[i])
	}
	reconstructed[0].Add(&reconstructed[0], &rem)
	divisionConsistent := true
	for i := range numerator {
		if !numerator[i].Equal(&reconstructed[i]) {
			divisionConsistent = false
		}
	}
	result.Details["mu"] = mu.String()
	result.Details["remainder_zero"] = fmt.Sprint(rem.IsZero())
	result.Details["remainder"] = rem.String()
	result.Details["honest_C_equals_AB"] = fmt.Sprint(honestProduct)
	result.Details["synthetic_division_identity_holds"] = fmt.Sprint(divisionConsistent)
	result.Details["quotient_degree"] = fmt.Sprint(len(q) - 1)
	result.Details["witness_polynomial_exists"] = fmt.Sprint(rem.IsZero())
	if rem.IsZero() {
		vw, err := commit(q, srs)
		if err != nil {
			return fail(err)
		}
		vay, err := commit(pay, srs)
		if err != nil {
			return fail(err)
		}
		vby, err := commit(pby, srs)
		if err != nil {
			return fail(err)
		}
		vmu := mulG1(srs.Pk.G1[0], mu)
		d2 := subG2(srs.Vk.G2[1], mulG2(srs.Vk.G2[0], y))
		rhs := subG1(subG1(vmu, vay), vby)
		accepted, err := scalarPairing(vw, rhs, d2, srs.Vk.G2[0])
		if err != nil {
			return fail(err)
		}
		result.Details["appendix_pairing_accepted"] = fmt.Sprint(accepted)
	} else {
		result.Details["appendix_pairing_accepted"] = "not-run: no polynomial witness for selected interpolation"
	}
	result.Passed = honestProduct && divisionConsistent
	result.Details["passed_semantics"] = "computation completed; not a protocol acceptance claim"
	return result
}

func RunFullAudit() []*AuditResult {
	return []*AuditResult{
		RectangularConvolutionMismatch(),
		PairingAttackDiagnostic(2),
		PairingAttackDiagnostic(4),
		AppendixInterpolationDiagnostic(2),
	}
}

func GenerateSummary() *AuditSummary {
	results := RunFullAudit()
	summary := &AuditSummary{Timestamp: time.Now().UTC().Format(time.RFC3339), Results: results, AllPassed: true}
	for _, r := range results {
		if !r.Passed {
			summary.AllPassed = false
		}
		if r.Category == "CRITICAL" {
			summary.CriticalCount++
		} else if r.Category == "DEFINITE" {
			summary.DefiniteCount++
		}
	}
	summary.Summary = fmt.Sprintf("%d CRITICAL findings; %d DEFINITE arithmetic findings; all diagnostics passed=%t", summary.CriticalCount, summary.DefiniteCount, summary.AllPassed)
	return summary
}

func PrintAuditSummary() string {
	b, err := ExportJSON()
	if err != nil {
		return "zkMaP diagnostic failed: " + err.Error()
	}
	return string(b)
}

func ExportJSON() ([]byte, error) { return json.MarshalIndent(GenerateSummary(), "", "  ") }
