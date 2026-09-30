package zkmatrix

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

type BatchStatement []Statement
type BatchWitness []Witness
type BatchIntermediate struct{ Cay, Cby, Cd bn254.G1Affine }
type BatchFinalProof struct {
	Alpha, Beta, Gamma, Delta bn254.G1Affine
	ZA, ZB, ZC                fr.Element
	IPA                       IPAProof
}

// VerifyBatch checks the shared projections and all per-claim final IPAs, then
// verifies one Eq.21 pairing aggregation for the complete set of residuals.
func VerifyBatch(p *PublicParams, statements BatchStatement, proof BatchProof) error {
	return verifyBatch(p, statements, proof, false)
}

// VerifyBatchDirect independently folds the IPA equations before checking the
// same aggregate accelerator transcript and pairing equation.
func VerifyBatchDirect(p *PublicParams, statements BatchStatement, proof BatchProof) error {
	return verifyBatch(p, statements, proof, true)
}

func verifyBatch(p *PublicParams, statements BatchStatement, proof BatchProof, direct bool) error {
	if err := validateBatchProof(p, statements, proof); err != nil {
		return err
	}
	t := initBatchTranscript(p, statements)
	y := t.challenge("matrix/y")
	t.point("batch/intermediate/Cd", proof.Intermediate[0].Cd)
	t.point("batch/intermediate/Cay", proof.Intermediate[0].Cay)
	t.point("batch/intermediate/Cby", proof.Intermediate[0].Cby)
	for i := 1; i < len(proof.Intermediate); i++ {
		t.point("batch/intermediate/Cd", proof.Intermediate[i].Cd)
		t.point("batch/intermediate/Cay", proof.Intermediate[i].Cay)
		t.point("batch/intermediate/Cby", proof.Intermediate[i].Cby)
	}
	rho := t.challenge("batch/matrix-rho")
	powers := rhoPowers(rho, len(statements))
	barS := aggregateStatements(statements, powers)
	barCd := aggregateIntermediates(proof.Intermediate, powers, 2)
	barCaY := aggregateIntermediates(proof.Intermediate, powers, 0)
	barCbY := aggregateIntermediates(proof.Intermediate, powers, 1)
	var yL, yR, flatY []fr.Element
	if direct {
		yL, yR = projectionPowers(y, p.m, p.inner, p.n)
		flatY = flatWeights(yL, yR)
	}
	Ps := make([]bn254.G1Affine, 3+len(statements))
	ipas := make([]IPAProof, len(Ps))
	ds := []accelDescriptor{{kind: accelC, y: y}, {kind: accelAHD, y: y}, {kind: accelBHD, y: y}}
	chs := make([][]fr.Element, len(Ps))
	var err error
	inputs := []bn254.G1Affine{barS.Cc, barS.Ca, barS.Cb}
	outputs := []bn254.G1Affine{barCd, barCaY, barCbY}
	for i := 0; i < 3; i++ {
		pr := proof.Projections[i]
		t.point("projection/mask-in", pr.In)
		t.point("projection/mask-out", pr.Out)
		tau := t.challenge("projection/mask-t")
		t.scalar("projection/z-in", pr.ZIn)
		t.scalar("projection/z-out", pr.ZOut)
		pin := sumPoint(sumPoint(pr.In, mulPoint(inputs[i], tau)), mulPoint(p.hide, neg(pr.ZIn)))
		pout := sumPoint(sumPoint(pr.Out, mulPoint(outputs[i], tau)), mulPoint(p.hide, neg(pr.ZOut)))
		label := "projection/hd-x"
		if i == 0 {
			label = "projection/ipa-x"
		}
		xx := t.challenge(label)
		P := sumPoint(pin, mulPoint(pout, xx))
		Ps[i] = P
		ipas[i] = pr.IPA
		if direct {
			var G, H []bn254.G1Affine
			var U bn254.G1Affine
			var pub []fr.Element
			if i == 0 {
				ds[i].x = xx
				U = mulPoint(p.u, xx)
				G = p.c
				H = zeroBases(len(G))
				pub = flatY
			} else {
				ds[i].xHD = xx
				U = p.u
				outer := yL
				inBases := p.a
				outBases := p.g
				if i == 2 {
					outer = yR
					inBases = make([]bn254.G1Affine, p.inner*p.n)
					for j := 0; j < p.n; j++ {
						for k := 0; k < p.inner; k++ {
							inBases[j*p.inner+k] = p.b[k*p.n+j]
						}
					}
					outBases = p.h
				}
				G = make([]bn254.G1Affine, len(inBases))
				for k := range G {
					oi, ki := k/p.inner, k%p.inner
					G[k] = sumPoint(inBases[k], mulPoint(outBases[ki], mul(xx, outer[oi])))
				}
				H = zeroBases(len(G))
				pub = make([]fr.Element, len(G))
			}
			chs[i], err = directOptimizedIPA(t, P, U, G, H, pr.IPA, pub, i == 0)
			if err != nil {
				return fmt.Errorf("batch projection %d: %w", i, err)
			}
		} else {
			if i == 0 {
				ds[i].x = xx
			} else {
				ds[i].xHD = xx
			}
			var pub *fr.Element
			if i == 0 {
				pub = &y
			} else {
				z := fr.Element{}
				pub = &z
			}
			chs[i], err = acceleratedIPATranscript(t, p, &ipas[i], ds[i], pub)
			if err != nil {
				return fmt.Errorf("batch projection %d: %w", i, err)
			}
		}
	}
	// Final claims have distinct transcript frames so reordering proofs changes
	// every downstream challenge.
	for i, fp := range proof.Finals {
		t.point("batch/final/alpha", fp.Alpha)
		t.point("batch/final/beta", fp.Beta)
		t.point("batch/final/gamma", fp.Gamma)
		t.point("batch/final/delta", fp.Delta)
		x := t.challenge("batch/final/x")
		t.scalar("batch/final/za", fp.ZA)
		t.scalar("batch/final/zb", fp.ZB)
		t.scalar("batch/final/zc", fp.ZC)
		inter := proof.Intermediate[i]
		pa := mulPoint(sumPoint(sumPoint(fp.Alpha, mulPoint(inter.Cay, x)), mulPoint(p.hide, fp.ZA)), x)
		pb := mulPoint(sumPoint(sumPoint(fp.Beta, mulPoint(inter.Cby, x)), mulPoint(p.hide, fp.ZB)), x)
		pc := mulPoint(sumPoint(sumPoint(sumPoint(fp.Gamma, mulPoint(fp.Delta, x)), mulPoint(inter.Cd, mul(x, x))), mulPoint(p.hide, fp.ZC)), mul(x, x))
		Ps[3+i] = sumPoint(sumPoint(pa, pb), pc)
		ipas[3+i] = fp.IPA
		ds = append(ds, accelDescriptor{kind: accelDot})
		if direct {
			chs[3+i], err = directOptimizedIPA(t, Ps[3+i], p.u, p.g, p.h, fp.IPA, nil, false)
		} else {
			chs[3+i], err = acceleratedIPATranscript(t, p, &ipas[3+i], ds[3+i], nil)
		}
		if err != nil {
			return fmt.Errorf("batch final %d IPA: %w", i, err)
		}
	}
	// Eq.21 challenge is sampled only after all q+3 IPA transcripts.
	residualRho := t.challenge("batch/projection-residual-rho")
	sigma := t.challenge("batch/final-residual-rho")
	weights := append(aggregateWeights(residualRho)[:3], rhoPowers(sigma, len(statements))...)
	z, err := evalChallenge(t, p)
	if err != nil {
		return err
	}
	t.point("batch/aggregate/Vprime", proof.VPrime)
	t.point("batch/aggregate/W", proof.W)
	pairTheta := t.challenge("batch/aggregate/pairing-theta")
	if direct {
		return nil
	}
	return verifyBatchPairing(p, ipas, Ps, ds, chs, weights, z, pairTheta, proof.VPrime, proof.W)
}

func verifyBatchPairing(p *PublicParams, ipas []IPAProof, Ps []bn254.G1Affine, ds []accelDescriptor, chs [][]fr.Element, weights []fr.Element, z, theta fr.Element, vprime, w bn254.G1Affine) error {
	var vSum bn254.G1Affine
	var phi fr.Element
	for i := range ipas {
		v, e := ipaCommitment(Ps[i], ipas[i], chs[i])
		if e != nil {
			return e
		}
		vSum = sumPoint(vSum, mulPoint(v, weights[i]))
		f, e := factorizedPhi(p, ds[i], ipas[i], chs[i], z)
		if e != nil {
			return e
		}
		phi.Add(&phi, new(fr.Element).Mul(&f, &weights[i]))
	}
	phiG := mulPoint(p.srs[0], phi)
	var nv, nw bn254.G1Affine
	nv.Neg(&vSum)
	nw.Neg(&w)
	first := sumPoint(sumPoint(phiG, nv), mulPoint(vprime, theta))
	negThetaV := negPoint(vSum, theta)
	var zg2, q2 bn254.G2Affine
	zg2.ScalarMultiplication(&p.g2, z.BigInt(new(big.Int)))
	q2.Sub(&zg2, &p.tauG2)
	ok, e := bn254.PairingCheck([]bn254.G1Affine{first, nw, negThetaV}, []bn254.G2Affine{p.g2, q2, p.nuG2})
	if e != nil {
		return e
	}
	if !ok {
		return errors.New("batch aggregate pairing check rejected")
	}
	return nil
}

func validateBatchProof(p *PublicParams, s BatchStatement, proof BatchProof) error {
	if err := checkPP(p); err != nil {
		return err
	}
	q := len(s)
	if q == 0 || q > 10000 || len(proof.Intermediate) != q || len(proof.Finals) != q {
		return errors.New("batch proof claim count mismatch")
	}
	rounds := []int{log2(p.m * p.n), log2(p.m * p.inner), log2(p.inner * p.n)}
	for i, pr := range proof.Projections {
		if len(pr.IPA.L) != rounds[i] || len(pr.IPA.R) != rounds[i] {
			return errors.New("batch projection IPA shape mismatch")
		}
	}
	for _, f := range proof.Finals {
		if len(f.IPA.L) != log2(p.inner) || len(f.IPA.R) != log2(p.inner) {
			return errors.New("batch final IPA shape mismatch")
		}
	}
	pts := []bn254.G1Affine{proof.VPrime, proof.W}
	for _, v := range proof.Intermediate {
		pts = append(pts, v.Cay, v.Cby, v.Cd)
	}
	for i, pr := range proof.Projections {
		pts = append(pts, pr.In, pr.Out)
		pts = append(pts, pr.IPA.L...)
		pts = append(pts, pr.IPA.R...)
		_ = i
	}
	for _, f := range proof.Finals {
		pts = append(pts, f.Alpha, f.Beta, f.Gamma, f.Delta)
		pts = append(pts, f.IPA.L...)
		pts = append(pts, f.IPA.R...)
	}
	for i, pt := range append(pts, statementPoints(s)...) {
		if !pt.IsOnCurve() || !pt.IsInSubGroup() {
			return fmt.Errorf("invalid batch point %d", i)
		}
	}
	return nil
}
func statementPoints(s BatchStatement) []bn254.G1Affine {
	v := make([]bn254.G1Affine, 0, 3*len(s))
	for _, x := range s {
		v = append(v, x.Ca, x.Cb, x.Cc)
	}
	return v
}

type BatchProof struct {
	Intermediate []BatchIntermediate
	Projections  [3]OptimizedProjection
	Finals       []BatchFinalProof
	VPrime, W    bn254.G1Affine
}
type batchClaimData struct {
	ay, by       []fr.Element
	d            fr.Element
	ray, rby, rd fr.Element
}

// ProveBatch implements Algorithm 6: three shared relaxed projections and one
// final masked dot-product IPA per multiplication, followed by one accelerator.
func ProveBatch(p *PublicParams, statements BatchStatement, witnesses BatchWitness) (BatchProof, error) {
	var proof BatchProof
	if e := checkPP(p); e != nil {
		return proof, e
	}
	q := len(statements)
	if q == 0 || len(witnesses) != q {
		return proof, errors.New("batch must contain equally many nonempty statements and witnesses")
	}
	for i := range witnesses {
		if e := checkWitness(p, witnesses[i]); e != nil {
			return proof, fmt.Errorf("witness %d: %w", i, e)
		}
	}
	t := initBatchTranscript(p, statements)
	y := t.challenge("matrix/y")
	yL, yR := projectionPowers(y, p.m, p.inner, p.n)
	flatY := flatWeights(yL, yR)
	proof.Intermediate = make([]BatchIntermediate, q)
	data := make([]batchClaimData, q)
	aVectors := make([][]fr.Element, q)
	bVectors := make([][]fr.Element, q)
	cVectors := make([][]fr.Element, q)
	for i := 0; i < q; i++ {
		w := witnesses[i]
		aVectors[i], _ = flatten(w.A, p.m, p.inner)
		bVectors[i], _ = flatten(w.B, p.inner, p.n)
		cVectors[i], _ = flatten(w.C, p.m, p.n)
		data[i].ay = weightedA(w.A, yL)
		data[i].by = weightedB(w.B, yR)
		data[i].d = dot(cVectors[i], flatY)
		var e error
		data[i].ray, e = randScalar()
		if e != nil {
			return proof, e
		}
		data[i].rby, e = randScalar()
		if e != nil {
			return proof, e
		}
		data[i].rd, e = randScalar()
		if e != nil {
			return proof, e
		}
		proof.Intermediate[i].Cay, e = commit(data[i].ay, p.g, p.hide, data[i].ray)
		if e != nil {
			return proof, e
		}
		proof.Intermediate[i].Cby, e = commit(data[i].by, p.h, p.hide, data[i].rby)
		if e != nil {
			return proof, e
		}
		proof.Intermediate[i].Cd, e = commit([]fr.Element{data[i].d}, []bn254.G1Affine{p.u}, p.hide, data[i].rd)
		if e != nil {
			return proof, e
		}
		t.point("batch/intermediate/Cd", proof.Intermediate[i].Cd)
		t.point("batch/intermediate/Cay", proof.Intermediate[i].Cay)
		t.point("batch/intermediate/Cby", proof.Intermediate[i].Cby)
	}
	rho := t.challenge("batch/matrix-rho")
	powers := rhoPowers(rho, q)
	barStatements := aggregateStatements(statements, powers)
	barCaY := aggregateIntermediates(proof.Intermediate, powers, 0)
	barCbY := aggregateIntermediates(proof.Intermediate, powers, 1)
	barCd := aggregateIntermediates(proof.Intermediate, powers, 2)
	abar := aggregateVectors(aVectors, powers)
	bbar := aggregateVectors(bVectors, powers)
	cbar := aggregateVectors(cVectors, powers)
	aybar := weightedA(unflatten(abar, p.m, p.inner), yL)
	bybar := weightedB(unflatten(bbar, p.inner, p.n), yR)
	dbar := dot(cbar, flatY)
	raBar := aggregateBlindings(witnesses, powers, 0)
	rbBar := aggregateBlindings(witnesses, powers, 1)
	rcBar := aggregateBlindings(witnesses, powers, 2)
	rayBar := aggregateClaimBlinds(data, powers, 0)
	rbyBar := aggregateClaimBlinds(data, powers, 1)
	rdBar := aggregateClaimBlinds(data, powers, 2)
	var e error
	proof.Projections[0], e = proveOptimizedLinear(t, p, cbar, []fr.Element{dbar}, flatY, barStatements.Cc, barCd, rcBar, rdBar, 0, y)
	if e != nil {
		return proof, fmt.Errorf("batch C projection: %w", e)
	}
	proof.Projections[1], e = proveOptimizedLinear(t, p, abar, aybar, yL, barStatements.Ca, barCaY, raBar, rayBar, 1, y)
	if e != nil {
		return proof, fmt.Errorf("batch A projection: %w", e)
	}
	proof.Projections[2], e = proveOptimizedLinear(t, p, bbar, bybar, yR, barStatements.Cb, barCbY, rbBar, rbyBar, 2, y)
	if e != nil {
		return proof, fmt.Errorf("batch B projection: %w", e)
	}
	proof.Finals = make([]BatchFinalProof, q)
	for i := 0; i < q; i++ {
		fp, err := proveBatchFinal(t, p, data[i], witnesses[i], proof.Intermediate[i])
		if err != nil {
			return proof, fmt.Errorf("batch final %d: %w", i, err)
		}
		proof.Finals[i] = fp
	}
	ipas := batchIPAs(proof)
	descs := batchDescriptors(proof, y)
	residualRho := t.challenge("batch/projection-residual-rho")
	sigma := t.challenge("batch/final-residual-rho")
	coeff, e := buildBatchCoefficients(p, ipas, descs, residualRho, sigma, q)
	if e != nil {
		return proof, e
	}
	z, e := evalChallenge(t, p)
	if e != nil {
		return proof, e
	}
	proof.VPrime, e = msm(p.shifted, coeff)
	if e != nil {
		return proof, e
	}
	proof.W, e = msm(p.srs, quotientCoefficients(coeff, z))
	if e != nil {
		return proof, e
	}
	t.point("batch/aggregate/Vprime", proof.VPrime)
	t.point("batch/aggregate/W", proof.W)
	t.challenge("batch/aggregate/pairing-theta")
	return proof, nil
}
func proveBatchFinal(t *transcript, p *PublicParams, d batchClaimData, w Witness, inter BatchIntermediate) (BatchFinalProof, error) {
	var f BatchFinalProof
	alpha, e := randVec(p.inner)
	if e != nil {
		return f, e
	}
	beta, e := randVec(p.inner)
	if e != nil {
		return f, e
	}
	ra0, e := randScalar()
	if e != nil {
		return f, e
	}
	rb0, e := randScalar()
	if e != nil {
		return f, e
	}
	rg0, e := randScalar()
	if e != nil {
		return f, e
	}
	rd0, e := randScalar()
	if e != nil {
		return f, e
	}
	f.Alpha, e = commit(alpha, p.g, p.hide, ra0)
	if e != nil {
		return f, e
	}
	f.Beta, e = commit(beta, p.h, p.hide, rb0)
	if e != nil {
		return f, e
	}
	f.Gamma, e = commit([]fr.Element{dot(alpha, beta)}, []bn254.G1Affine{p.u}, p.hide, rg0)
	if e != nil {
		return f, e
	}
	cross := add(dot(alpha, d.by), dot(d.ay, beta))
	f.Delta, e = commit([]fr.Element{cross}, []bn254.G1Affine{p.u}, p.hide, rd0)
	if e != nil {
		return f, e
	}
	t.point("batch/final/alpha", f.Alpha)
	t.point("batch/final/beta", f.Beta)
	t.point("batch/final/gamma", f.Gamma)
	t.point("batch/final/delta", f.Delta)
	x := t.challenge("batch/final/x")
	f.ZA = neg(add(ra0, mul(x, d.ray)))
	f.ZB = neg(add(rb0, mul(x, d.rby)))
	f.ZC = neg(add(add(rg0, mul(x, rd0)), mul(mul(x, x), d.rd)))
	t.scalar("batch/final/za", f.ZA)
	t.scalar("batch/final/zb", f.ZB)
	t.scalar("batch/final/zc", f.ZC)
	pa := mulPoint(sumPoint(sumPoint(f.Alpha, mulPoint(inter.Cay, x)), mulPoint(p.hide, f.ZA)), x)
	pb := mulPoint(sumPoint(sumPoint(f.Beta, mulPoint(inter.Cby, x)), mulPoint(p.hide, f.ZB)), x)
	pc := mulPoint(sumPoint(sumPoint(sumPoint(f.Gamma, mulPoint(f.Delta, x)), mulPoint(inter.Cd, mul(x, x))), mulPoint(p.hide, f.ZC)), mul(x, x))
	P := sumPoint(sumPoint(pa, pb), pc)
	aPrime := scaleVec(plusVec(alpha, scaleVec(d.ay, x)), x)
	bPrime := scaleVec(plusVec(beta, scaleVec(d.by, x)), x)
	f.IPA, e = IPAProve(t, P, p.u, p.g, p.h, aPrime, bPrime)
	_ = w
	return f, e
}
func initBatchTranscript(p *PublicParams, s BatchStatement) *transcript {
	t := &transcript{}
	t.raw("domain", []byte(domain+"/batch"))
	t.raw("dimensions", encodeDims([3]int{p.m, p.inner, p.n}))
	t.raw("parameter-fingerprint", p.fingerprint[:])
	var count [4]byte
	binary.BigEndian.PutUint32(count[:], uint32(len(s)))
	t.raw("claim-count", count[:])
	for i := range s {
		t.point("statement/Ca", s[i].Ca)
		t.point("statement/Cb", s[i].Cb)
		t.point("statement/Cc", s[i].Cc)
	}
	return t
}
func rhoPowers(rho fr.Element, q int) []fr.Element {
	p := make([]fr.Element, q)
	if q == 0 {
		return p
	}
	p[0] = fr.One()
	for i := 1; i < q; i++ {
		p[i].Mul(&p[i-1], &rho)
	}
	return p
}
func aggregateVectors(v [][]fr.Element, powers []fr.Element) []fr.Element {
	z := make([]fr.Element, len(v[0]))
	for i := range v {
		for j := range z {
			z[j].Add(&z[j], new(fr.Element).Mul(&v[i][j], &powers[i]))
		}
	}
	return z
}
func aggregateStatements(s BatchStatement, powers []fr.Element) Statement {
	var z Statement
	for i := range s {
		z.Ca = sumPoint(z.Ca, mulPoint(s[i].Ca, powers[i]))
		z.Cb = sumPoint(z.Cb, mulPoint(s[i].Cb, powers[i]))
		z.Cc = sumPoint(z.Cc, mulPoint(s[i].Cc, powers[i]))
	}
	return z
}
func aggregateIntermediates(v []BatchIntermediate, p []fr.Element, which int) bn254.G1Affine {
	var z bn254.G1Affine
	for i := range v {
		q := v[i].Cay
		if which == 1 {
			q = v[i].Cby
		} else if which == 2 {
			q = v[i].Cd
		}
		z = sumPoint(z, mulPoint(q, p[i]))
	}
	return z
}
func unflatten(v []fr.Element, rows, cols int) [][]fr.Element {
	m := make([][]fr.Element, rows)
	for i := range m {
		m[i] = append([]fr.Element(nil), v[i*cols:(i+1)*cols]...)
	}
	return m
}
func aggregateBlindings(w []Witness, p []fr.Element, which int) fr.Element {
	var z fr.Element
	for i := range w {
		v := w[i].RA
		if which == 1 {
			v = w[i].RB
		} else if which == 2 {
			v = w[i].RC
		}
		z.Add(&z, new(fr.Element).Mul(&v, &p[i]))
	}
	return z
}
func aggregateClaimBlinds(d []batchClaimData, p []fr.Element, which int) fr.Element {
	var z fr.Element
	for i := range d {
		v := d[i].ray
		if which == 1 {
			v = d[i].rby
		} else if which == 2 {
			v = d[i].rd
		}
		z.Add(&z, new(fr.Element).Mul(&v, &p[i]))
	}
	return z
}
func batchIPAs(p BatchProof) []IPAProof {
	v := []IPAProof{p.Projections[0].IPA, p.Projections[1].IPA, p.Projections[2].IPA}
	for i := range p.Finals {
		v = append(v, p.Finals[i].IPA)
	}
	return v
}
func batchDescriptors(p BatchProof, y fr.Element) []accelDescriptor {
	v := []accelDescriptor{{kind: accelC, y: y, x: p.Projections[0].x}, {kind: accelAHD, y: y, xHD: p.Projections[1].x}, {kind: accelBHD, y: y, xHD: p.Projections[2].x}}
	for range p.Finals {
		v = append(v, accelDescriptor{kind: accelDot})
	}
	return v
}
func buildBatchCoefficients(p *PublicParams, ipas []IPAProof, ds []accelDescriptor, rho, sigma fr.Element, q int) ([]fr.Element, error) {
	if len(ipas) != q+3 || len(ds) != q+3 {
		return nil, errors.New("batch residual count mismatch")
	}
	weights := append(aggregateWeights(rho)[:3], rhoPowers(sigma, q)...)
	sum := make([]fr.Element, p.q+1)
	for i := range ipas {
		c, e := proverCoefficients(p, ipas[i], ds[i])
		if e != nil {
			return nil, e
		}
		for j := range sum {
			sum[j].Add(&sum[j], new(fr.Element).Mul(&c[j], &weights[i]))
		}
	}
	return sum, nil
}

// MarshalBinaryFor emits the complete canonical Algorithm 6 proof. Folded
// public scalars for the three shared projections are omitted and recomputed.
func (p BatchProof) MarshalBinaryFor(pp *PublicParams) ([]byte, error) {
	if err := checkPP(pp); err != nil {
		return nil, err
	}
	q := len(p.Intermediate)
	if q == 0 || q>10000 || len(p.Finals) != q {
		return nil, errors.New("batch claim count mismatch")
	}
	var b bytes.Buffer
	b.WriteString("ZKB1")
	_ = binary.Write(&b, binary.BigEndian, uint32(pp.m))
	_ = binary.Write(&b, binary.BigEndian, uint32(pp.inner))
	_ = binary.Write(&b, binary.BigEndian, uint32(pp.n))
	_ = binary.Write(&b, binary.BigEndian, uint32(q))
	for _, x := range p.Intermediate {
		for _, pt := range []bn254.G1Affine{x.Cd, x.Cay, x.Cby} {
			if e := writePoint(&b, pt); e != nil {
				return nil, e
			}
		}
	}
	for i, x := range p.Projections {
		for _, pt := range []bn254.G1Affine{x.In, x.Out} {
			if e := writePoint(&b, pt); e != nil {
				return nil, e
			}
		}
		for _, s := range []fr.Element{x.ZIn, x.ZOut} {
			if e := writeScalar(&b, s); e != nil {
				return nil, e
			}
		}
		r := []int{log2(pp.m * pp.n), log2(pp.m * pp.inner), log2(pp.inner * pp.n)}[i]
		if e := writeOptimizedIPA(&b, x.IPA, r, true); e != nil {
			return nil, e
		}
	}
	for _, x := range p.Finals {
		for _, pt := range []bn254.G1Affine{x.Alpha, x.Beta, x.Gamma, x.Delta} {
			if e := writePoint(&b, pt); e != nil {
				return nil, e
			}
		}
		for _, s := range []fr.Element{x.ZA, x.ZB, x.ZC} {
			if e := writeScalar(&b, s); e != nil {
				return nil, e
			}
		}
		if e := writeOptimizedIPA(&b, x.IPA, log2(pp.inner), false); e != nil {
			return nil, e
		}
	}
	for _, pt := range []bn254.G1Affine{p.VPrime, p.W} {
		if e := writePoint(&b, pt); e != nil {
			return nil, e
		}
	}
	return b.Bytes(), nil
}

// UnmarshalBatchProof rejects oversized claims before allocation and rejects
// trailing, noncanonical, wrong-dimension, off-curve and wrong-subgroup data.
func UnmarshalBatchProof(pp *PublicParams, data []byte) (BatchProof, error) {
	var p BatchProof
	if e := checkPP(pp); e != nil {
		return p, e
	}
	if len(data) < 20 || len(data) > 256<<20 {
		return p, errors.New("invalid batch proof size")
	}
	r := bytes.NewReader(data)
	head := make([]byte, 20)
	if _, e := io.ReadFull(r, head); e != nil {
		return p, e
	}
	if string(head[:4]) != "ZKB1" || binary.BigEndian.Uint32(head[4:8]) != uint32(pp.m) || binary.BigEndian.Uint32(head[8:12]) != uint32(pp.inner) || binary.BigEndian.Uint32(head[12:16]) != uint32(pp.n) {
		return p, errors.New("batch header/dimensions mismatch")
	}
	q := binary.BigEndian.Uint32(head[16:20])
	if q == 0 || q > 10000 {
		return p, errors.New("batch claim count outside serialization limit")
	}
	p.Intermediate = make([]BatchIntermediate, int(q))
	p.Finals = make([]BatchFinalProof, int(q))
	var e error
	for i := range p.Intermediate {
		p.Intermediate[i].Cd, e = readPoint(r)
		if e != nil {
			return p, e
		}
		p.Intermediate[i].Cay, e = readPoint(r)
		if e != nil {
			return p, e
		}
		p.Intermediate[i].Cby, e = readPoint(r)
		if e != nil {
			return p, e
		}
	}
	for i := range p.Projections {
		x := &p.Projections[i]
		x.In, e = readPoint(r)
		if e != nil {
			return p, e
		}
		x.Out, e = readPoint(r)
		if e != nil {
			return p, e
		}
		x.ZIn, e = readScalar(r)
		if e != nil {
			return p, e
		}
		x.ZOut, e = readScalar(r)
		if e != nil {
			return p, e
		}
		rounds := []int{log2(pp.m * pp.n), log2(pp.m * pp.inner), log2(pp.inner * pp.n)}[i]
		x.IPA, e = readOptimizedIPA(r, rounds, true)
		if e != nil {
			return p, e
		}
	}
	for i := range p.Finals {
		x := &p.Finals[i]
		x.Alpha, e = readPoint(r)
		if e != nil {
			return p, e
		}
		x.Beta, e = readPoint(r)
		if e != nil {
			return p, e
		}
		x.Gamma, e = readPoint(r)
		if e != nil {
			return p, e
		}
		x.Delta, e = readPoint(r)
		if e != nil {
			return p, e
		}
		x.ZA, e = readScalar(r)
		if e != nil {
			return p, e
		}
		x.ZB, e = readScalar(r)
		if e != nil {
			return p, e
		}
		x.ZC, e = readScalar(r)
		if e != nil {
			return p, e
		}
		x.IPA, e = readOptimizedIPA(r, log2(pp.inner), false)
		if e != nil {
			return p, e
		}
	}
	p.VPrime, e = readPoint(r)
	if e != nil {
		return p, e
	}
	p.W, e = readPoint(r)
	if e != nil {
		return p, e
	}
	if r.Len() != 0 {
		return p, errors.New("trailing batch proof bytes")
	}
	return p, nil
}
