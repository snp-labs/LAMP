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

type OptimizedProjection struct {
	In, Out   bn254.G1Affine
	ZIn, ZOut fr.Element
	IPA       IPAProof
	x         fr.Element
	P         bn254.G1Affine
}
type OptimizedProof struct {
	Cay, Cby, Cd              bn254.G1Affine
	Projections               [3]OptimizedProjection
	Alpha, Beta, Gamma, Delta bn254.G1Affine
	ZA, ZB, ZC                fr.Element
	Final                     IPAProof
	VPrime, W                 bn254.G1Affine
}

// ProveOptimized implements the paper's relaxed four-IPA composition. Matrix
// multiplication is data preparation and is never performed by this function.
func ProveOptimized(p *PublicParams, s Statement, w Witness) (OptimizedProof, error) {
	var proof OptimizedProof
	if e := checkPP(p); e != nil {
		return proof, e
	}
	if e := checkWitness(p, w); e != nil {
		return proof, e
	}
	cv, _ := flatten(w.C, p.m, p.n)
	t := initTranscript(p, s)
	y := t.challenge("matrix/y")
	yL, yR := projectionPowers(y, p.m, p.inner, p.n)
	flatY := flatWeights(yL, yR)
	ay := weightedA(w.A, yL)
	by := weightedB(w.B, yR)
	d := dot(cv, flatY)
	ray, e := randScalar()
	if e != nil {
		return proof, e
	}
	rby, e := randScalar()
	if e != nil {
		return proof, e
	}
	rd, e := randScalar()
	if e != nil {
		return proof, e
	}
	proof.Cay, e = commit(ay, p.g, p.hide, ray)
	if e != nil {
		return proof, e
	}
	proof.Cby, e = commit(by, p.h, p.hide, rby)
	if e != nil {
		return proof, e
	}
	proof.Cd, e = commit([]fr.Element{d}, []bn254.G1Affine{p.u}, p.hide, rd)
	if e != nil {
		return proof, e
	}
	t.point("projection/Cay", proof.Cay)
	t.point("projection/Cby", proof.Cby)
	t.point("projection/Cd", proof.Cd)
	av, _ := flatten(w.A, p.m, p.inner)
	bv, _ := flatten(w.B, p.inner, p.n)
	proof.Projections[0], e = proveOptimizedLinear(t, p, cv, []fr.Element{d}, flatY, s.Cc, proof.Cd, w.RC, rd, 0, y)
	if e != nil {
		return proof, fmt.Errorf("C projection: %w", e)
	}
	proof.Projections[1], e = proveOptimizedLinear(t, p, av, ay, yL, s.Ca, proof.Cay, w.RA, ray, 1, y)
	if e != nil {
		return proof, fmt.Errorf("A projection: %w", e)
	}
	proof.Projections[2], e = proveOptimizedLinear(t, p, bv, by, yR, s.Cb, proof.Cby, w.RB, rby, 2, y)
	if e != nil {
		return proof, fmt.Errorf("B projection: %w", e)
	}
	alpha, e := randVec(p.inner)
	if e != nil {
		return proof, e
	}
	beta, e := randVec(p.inner)
	if e != nil {
		return proof, e
	}
	ra0, e := randScalar()
	if e != nil {
		return proof, e
	}
	rb0, e := randScalar()
	if e != nil {
		return proof, e
	}
	rg0, e := randScalar()
	if e != nil {
		return proof, e
	}
	rd0, e := randScalar()
	if e != nil {
		return proof, e
	}
	proof.Alpha, e = commit(alpha, p.g, p.hide, ra0)
	if e != nil {
		return proof, e
	}
	proof.Beta, e = commit(beta, p.h, p.hide, rb0)
	if e != nil {
		return proof, e
	}
	proof.Gamma, e = commit([]fr.Element{dot(alpha, beta)}, []bn254.G1Affine{p.u}, p.hide, rg0)
	if e != nil {
		return proof, e
	}
	cross := add(dot(alpha, by), dot(ay, beta))
	proof.Delta, e = commit([]fr.Element{cross}, []bn254.G1Affine{p.u}, p.hide, rd0)
	if e != nil {
		return proof, e
	}
	t.point("final/alpha", proof.Alpha)
	t.point("final/beta", proof.Beta)
	t.point("final/gamma", proof.Gamma)
	t.point("final/delta", proof.Delta)
	x := t.challenge("final/x")
	proof.ZA = neg(add(ra0, mul(x, ray)))
	proof.ZB = neg(add(rb0, mul(x, rby)))
	proof.ZC = neg(add(add(rg0, mul(x, rd0)), mul(mul(x, x), rd)))
	t.scalar("final/za", proof.ZA)
	t.scalar("final/zb", proof.ZB)
	t.scalar("final/zc", proof.ZC)
	pa := mulPoint(sumPoint(sumPoint(proof.Alpha, mulPoint(proof.Cay, x)), mulPoint(p.hide, proof.ZA)), x)
	pb := mulPoint(sumPoint(sumPoint(proof.Beta, mulPoint(proof.Cby, x)), mulPoint(p.hide, proof.ZB)), x)
	pc := mulPoint(sumPoint(sumPoint(sumPoint(proof.Gamma, mulPoint(proof.Delta, x)), mulPoint(proof.Cd, mul(x, x))), mulPoint(p.hide, proof.ZC)), mul(x, x))
	Pdot := sumPoint(sumPoint(pa, pb), pc)
	aPrime := scaleVec(plusVec(alpha, scaleVec(ay, x)), x)
	bPrime := scaleVec(plusVec(beta, scaleVec(by, x)), x)
	proof.Final, e = IPAProve(t, Pdot, p.u, p.g, p.h, aPrime, bPrime)
	if e != nil {
		return proof, e
	}
	descs := []accelDescriptor{{kind: accelC, y: y, x: proof.Projections[0].x}, {kind: accelAHD, y: y, xHD: proof.Projections[1].x}, {kind: accelBHD, y: y, xHD: proof.Projections[2].x}, {kind: accelDot}}
	ipas := []IPAProof{proof.Projections[0].IPA, proof.Projections[1].IPA, proof.Projections[2].IPA, proof.Final}
	if e = attachAggregate(t, p, &proof.VPrime, &proof.W, ipas, descs); e != nil {
		return proof, e
	}
	return proof, nil
}

func proveOptimizedLinear(t *transcript, p *PublicParams, v, out, weights []fr.Element, Cin, Cout bn254.G1Affine, rin, rout fr.Element, kind int, y fr.Element) (OptimizedProjection, error) {
	var pr OptimizedProjection
	v0, e := randVec(len(v))
	if e != nil {
		return pr, e
	}
	ri0, e := randScalar()
	if e != nil {
		return pr, e
	}
	ro0, e := randScalar()
	if e != nil {
		return pr, e
	}
	lv0 := applyLinear(v0, kind, p.inner, weights)
	pr.In, e = commit(v0, linearBases(p, kind), p.hide, ri0)
	if e != nil {
		return pr, e
	}
	pr.Out, e = commit(lv0, outputBases(p, kind), p.hide, ro0)
	if e != nil {
		return pr, e
	}
	t.point("projection/mask-in", pr.In)
	t.point("projection/mask-out", pr.Out)
	tau := t.challenge("projection/mask-t")
	pr.ZIn = add(ri0, mul(tau, rin))
	pr.ZOut = add(ro0, mul(tau, rout))
	t.scalar("projection/z-in", pr.ZIn)
	t.scalar("projection/z-out", pr.ZOut)
	pin := sumPoint(sumPoint(pr.In, mulPoint(Cin, tau)), mulPoint(p.hide, neg(pr.ZIn)))
	pout := sumPoint(sumPoint(pr.Out, mulPoint(Cout, tau)), mulPoint(p.hide, neg(pr.ZOut)))
	vm := plusVec(v0, scaleVec(v, tau))
	label := "projection/hd-x"
	if kind == 0 {
		label = "projection/ipa-x"
	}
	pr.x = t.challenge(label)
	pr.P = sumPoint(pin, mulPoint(pout, pr.x))
	if kind == 0 {
		pr.IPA, e = IPAProve(t, pr.P, mulPoint(p.u, pr.x), p.c, zeroBases(len(v)), vm, weights)
		return pr, e
	}
	bases := linearBases(p, kind)
	var transV []fr.Element
	var transBases []bn254.G1Affine
	outBases := p.g
	outer := weights
	if kind == 1 {
		transV = vm
		transBases = bases
	} else {
		transV = make([]fr.Element, len(vm))
		transBases = make([]bn254.G1Affine, len(vm))
		for j := 0; j < p.n; j++ {
			for k := 0; k < p.inner; k++ {
				i := j*p.inner + k
				transV[i] = vm[k*p.n+j]
				transBases[i] = p.b[k*p.n+j]
			}
		}
		outBases = p.h
	}
	W := make([]bn254.G1Affine, len(transBases))
	parallelPoints(len(W), func(i int) {
		oi, ki := i/p.inner, i%p.inner
		W[i] = sumPoint(transBases[i], mulPoint(outBases[ki], mul(pr.x, outer[oi])))
	})
	pr.IPA, e = IPAProve(t, pr.P, p.u, W, zeroBases(len(W)), transV, make([]fr.Element, len(W)))
	_ = y
	return pr, e
}

func aggregateWeights(rho fr.Element) []fr.Element {
	r2 := mul(rho, rho)
	return []fr.Element{rho, r2, mul(r2, rho), fr.One()}
}
func aggregateCoefficients(p *PublicParams, ipas []IPAProof, descs []accelDescriptor, weights []fr.Element) ([]fr.Element, error) {
	if len(ipas) != 4 || len(descs) != 4 || len(weights) != 4 {
		return nil, errors.New("aggregate requires four IPA residuals")
	}
	sum := make([]fr.Element, p.q+1)
	for j := range ipas {
		c, e := proverCoefficients(p, ipas[j], descs[j])
		if e != nil {
			return nil, e
		}
		for i := range sum {
			sum[i].Add(&sum[i], new(fr.Element).Mul(&c[i], &weights[j]))
		}
	}
	return sum, nil
}
func attachAggregate(t *transcript, p *PublicParams, vprime, w *bn254.G1Affine, ipas []IPAProof, descs []accelDescriptor) error {
	rho := t.challenge("aggregate/projection-rho")
	coeff, e := aggregateCoefficients(p, ipas, descs, aggregateWeights(rho))
	if e != nil {
		return e
	}
	z, e := evalChallenge(t, p)
	if e != nil {
		return e
	}
	*vprime, e = msm(p.shifted, coeff)
	if e != nil {
		return e
	}
	*w, e = msm(p.srs, quotientCoefficients(coeff, z))
	if e != nil {
		return e
	}
	t.point("aggregate/Vprime", *vprime)
	t.point("aggregate/W", *w)
	t.challenge("aggregate/pairing-theta")
	return nil
}

func aggregatePhiFactorized(p *PublicParams, ipas []IPAProof, descs []accelDescriptor, challenges [][]fr.Element, rho, z fr.Element) (fr.Element, error) {
	weights := aggregateWeights(rho)
	var sum fr.Element
	for i := 0; i < 4; i++ {
		v, e := factorizedPhi(p, descs[i], ipas[i], challenges[i], z)
		if e != nil {
			return fr.Element{}, e
		}
		sum.Add(&sum, new(fr.Element).Mul(&v, &weights[i]))
	}
	return sum, nil
}
func consumeAggregateTranscript(t *transcript, p *PublicParams, proof OptimizedProof) error {
	if _, e := evalChallenge(t, p); e != nil {
		return e
	}
	t.point("aggregate/Vprime", proof.VPrime)
	t.point("aggregate/W", proof.W)
	t.challenge("aggregate/pairing-theta")
	return nil
}
func optimizedPairingVerify(t *transcript, p *PublicParams, ipas []IPAProof, Ps []bn254.G1Affine, descs []accelDescriptor, challenges [][]fr.Element, rho fr.Element, VPrime, W bn254.G1Affine) error {
	z, e := evalChallenge(t, p)
	if e != nil {
		return e
	}
	t.point("aggregate/Vprime", VPrime)
	t.point("aggregate/W", W)
	theta := t.challenge("aggregate/pairing-theta")
	weights := aggregateWeights(rho)
	var vSum bn254.G1Affine
	for i := range ipas {
		v, e := ipaCommitment(Ps[i], ipas[i], challenges[i])
		if e != nil {
			return e
		}
		vSum = sumPoint(vSum, mulPoint(v, weights[i]))
	}
	phi, e := aggregatePhiFactorized(p, ipas, descs, challenges, rho, z)
	if e != nil {
		return e
	}
	phiG := mulPoint(p.srs[0], phi)
	var negV bn254.G1Affine
	negV.Neg(&vSum)
	first := sumPoint(sumPoint(phiG, negV), mulPoint(VPrime, theta))
	var negW bn254.G1Affine
	negW.Neg(&W)
	negThetaV := negPoint(vSum, theta)
	var zG2, q2 bn254.G2Affine
	zG2.ScalarMultiplication(&p.g2, z.BigInt(new(big.Int)))
	q2.Sub(&zG2, &p.tauG2)
	ok, e := bn254.PairingCheck([]bn254.G1Affine{first, negW, negThetaV}, []bn254.G2Affine{p.g2, q2, p.nuG2})
	if e != nil {
		return e
	}
	if !ok {
		return errors.New("aggregated accelerated IPA pairing check rejected")
	}
	return nil
}

func VerifyOptimized(p *PublicParams, s Statement, proof OptimizedProof) error {
	if e := validateOptimizedProof(p, s, proof); e != nil {
		return e
	}
	t := initTranscript(p, s)
	y := t.challenge("matrix/y")
	t.point("projection/Cay", proof.Cay)
	t.point("projection/Cby", proof.Cby)
	t.point("projection/Cd", proof.Cd)
	descs := []accelDescriptor{{kind: accelC, y: y}, {kind: accelAHD, y: y}, {kind: accelBHD, y: y}}
	Ps := make([]bn254.G1Affine, 4)
	ipas := make([]IPAProof, 4)
	ch := make([][]fr.Element, 4)
	var e error
	for i := 0; i < 3; i++ {
		d := proof.Projections[i]
		kind := i
		Cin := []bn254.G1Affine{s.Cc, s.Ca, s.Cb}[i]
		Cout := []bn254.G1Affine{proof.Cd, proof.Cay, proof.Cby}[i]
		t.point("projection/mask-in", d.In)
		t.point("projection/mask-out", d.Out)
		tau := t.challenge("projection/mask-t")
		t.scalar("projection/z-in", d.ZIn)
		t.scalar("projection/z-out", d.ZOut)
		pin := sumPoint(sumPoint(d.In, mulPoint(Cin, tau)), mulPoint(p.hide, neg(d.ZIn)))
		pout := sumPoint(sumPoint(d.Out, mulPoint(Cout, tau)), mulPoint(p.hide, neg(d.ZOut)))
		if kind == 0 {
			d.x = t.challenge("projection/ipa-x")
			Ps[i] = sumPoint(pin, mulPoint(pout, d.x))
			descs[i].x = d.x
		} else {
			d.x = t.challenge("projection/hd-x")
			Ps[i] = sumPoint(pin, mulPoint(pout, d.x))
			descs[i].xHD = d.x
		}
		ipas[i] = d.IPA
		var publicB *fr.Element
		if i < 3 {
			if i == 0 {
				publicB = &y
			} else {
				zero := fr.Element{}
				publicB = &zero
			}
		}
		ch[i], e = acceleratedIPATranscript(t, p, &ipas[i], descs[i], publicB)
		if e != nil {
			return fmt.Errorf("projection %d IPA: %w", i, e)
		}
	}
	t.point("final/alpha", proof.Alpha)
	t.point("final/beta", proof.Beta)
	t.point("final/gamma", proof.Gamma)
	t.point("final/delta", proof.Delta)
	x := t.challenge("final/x")
	t.scalar("final/za", proof.ZA)
	t.scalar("final/zb", proof.ZB)
	t.scalar("final/zc", proof.ZC)
	pa := mulPoint(sumPoint(sumPoint(proof.Alpha, mulPoint(proof.Cay, x)), mulPoint(p.hide, proof.ZA)), x)
	pb := mulPoint(sumPoint(sumPoint(proof.Beta, mulPoint(proof.Cby, x)), mulPoint(p.hide, proof.ZB)), x)
	pc := mulPoint(sumPoint(sumPoint(sumPoint(proof.Gamma, mulPoint(proof.Delta, x)), mulPoint(proof.Cd, mul(x, x))), mulPoint(p.hide, proof.ZC)), mul(x, x))
	Ps[3] = sumPoint(sumPoint(pa, pb), pc)
	ipas[3] = proof.Final
	descs = append(descs, accelDescriptor{kind: accelDot})
	ch[3], e = acceleratedIPATranscript(t, p, &ipas[3], descs[3], nil)
	if e != nil {
		return e
	}
	rho := t.challenge("aggregate/projection-rho")
	return optimizedPairingVerify(t, p, ipas, Ps, descs, ch, rho, proof.VPrime, proof.W)
}

func acceleratedIPATranscript(t *transcript, p *PublicParams, ipa *IPAProof, d accelDescriptor, publicB *fr.Element) ([]fr.Element, error) {
	rounds := 0
	switch d.kind {
	case accelC:
		rounds = log2(p.m * p.n)
	case accelAHD:
		rounds = log2(p.m) + log2(p.inner)
	case accelBHD:
		rounds = log2(p.n) + log2(p.inner)
	case accelDot:
		rounds = log2(p.inner)
	default:
		return nil, errors.New("bad optimized IPA kind")
	}
	if rounds > 64 || len(ipa.L) != rounds || len(ipa.R) != rounds {
		return nil, errors.New("bad optimized IPA round count")
	}
	ch := make([]fr.Element, rounds)
	for i := range ch {
		t.point("ipa/L", ipa.L[i])
		t.point("ipa/R", ipa.R[i])
		ch[i] = t.challenge("ipa/x")
	}
	t.scalar("ipa/a", ipa.A)
	if d.kind == accelC {
		b := evalX(ch, d.y, 1)
		ipa.B = b
		t.scalar("ipa/b", b)
	} else if d.kind == accelDot {
		t.scalar("ipa/b", ipa.B)
	} else {
		if !ipa.B.IsZero() {
			return nil, errors.New("HD folded public scalar is not zero")
		}
		t.scalar("ipa/b", fr.Element{})
	}
	_ = p
	_ = publicB
	return ch, nil
}

func VerifyOptimizedDirect(p *PublicParams, s Statement, proof OptimizedProof) error {
	if e := validateOptimizedProof(p, s, proof); e != nil {
		return e
	}
	t := initTranscript(p, s)
	y := t.challenge("matrix/y")
	yL, yR := projectionPowers(y, p.m, p.inner, p.n)
	flatY := flatWeights(yL, yR)
	t.point("projection/Cay", proof.Cay)
	t.point("projection/Cby", proof.Cby)
	t.point("projection/Cd", proof.Cd)
	Ps := make([]bn254.G1Affine, 4)
	ipas := make([]IPAProof, 4)
	descs := []accelDescriptor{{kind: accelC, y: y}, {kind: accelAHD, y: y}, {kind: accelBHD, y: y}, {kind: accelDot}}
	ch := make([][]fr.Element, 4)
	var e error
	for i := 0; i < 3; i++ {
		pr := proof.Projections[i]
		Cin := []bn254.G1Affine{s.Cc, s.Ca, s.Cb}[i]
		Cout := []bn254.G1Affine{proof.Cd, proof.Cay, proof.Cby}[i]
		t.point("projection/mask-in", pr.In)
		t.point("projection/mask-out", pr.Out)
		tau := t.challenge("projection/mask-t")
		t.scalar("projection/z-in", pr.ZIn)
		t.scalar("projection/z-out", pr.ZOut)
		pin := sumPoint(sumPoint(pr.In, mulPoint(Cin, tau)), mulPoint(p.hide, neg(pr.ZIn)))
		pout := sumPoint(sumPoint(pr.Out, mulPoint(Cout, tau)), mulPoint(p.hide, neg(pr.ZOut)))
		label := "projection/hd-x"
		if i == 0 {
			label = "projection/ipa-x"
		}
		xx := t.challenge(label)
		P := sumPoint(pin, mulPoint(pout, xx))
		ipa := pr.IPA
		var G, H []bn254.G1Affine
		var U bn254.G1Affine
		var public []fr.Element
		if i == 0 {
			descs[i].x = xx
			U = mulPoint(p.u, xx)
			G = p.c
			H = zeroBases(len(G))
			public = flatY
		} else {
			descs[i].xHD = xx
			U = p.u
			outer := yL
			inBases := p.a
			outBases := p.g
			if i == 2 {
				outer = yR
				inBases = make([]bn254.G1Affine, len(p.b))
				idx := 0
				for j := 0; j < p.n; j++ {
					for k := 0; k < p.inner; k++ {
						inBases[idx] = p.b[k*p.n+j]
						idx++
					}
				}
				outBases = p.h
			}
			G = make([]bn254.G1Affine, len(inBases))
			for q := range G {
				oi, ki := q/p.inner, q%p.inner
				G[q] = sumPoint(inBases[q], mulPoint(outBases[ki], mul(xx, outer[oi])))
			}
			H = zeroBases(len(G))
			public = make([]fr.Element, len(G))
		}
		ch[i], e = directOptimizedIPA(t, P, U, G, H, ipa, public, i == 0)
		if e != nil {
			return fmt.Errorf("projection %d direct IPA: %w", i, e)
		}
		Ps[i] = P
		ipas[i] = ipa
	}
	t.point("final/alpha", proof.Alpha)
	t.point("final/beta", proof.Beta)
	t.point("final/gamma", proof.Gamma)
	t.point("final/delta", proof.Delta)
	x := t.challenge("final/x")
	t.scalar("final/za", proof.ZA)
	t.scalar("final/zb", proof.ZB)
	t.scalar("final/zc", proof.ZC)
	pa := mulPoint(sumPoint(sumPoint(proof.Alpha, mulPoint(proof.Cay, x)), mulPoint(p.hide, proof.ZA)), x)
	pb := mulPoint(sumPoint(sumPoint(proof.Beta, mulPoint(proof.Cby, x)), mulPoint(p.hide, proof.ZB)), x)
	pc := mulPoint(sumPoint(sumPoint(sumPoint(proof.Gamma, mulPoint(proof.Delta, x)), mulPoint(proof.Cd, mul(x, x))), mulPoint(p.hide, proof.ZC)), mul(x, x))
	Ps[3] = sumPoint(sumPoint(pa, pb), pc)
	ipas[3] = proof.Final
	ch[3], e = directOptimizedIPA(t, Ps[3], p.u, p.g, p.h, proof.Final, nil, false)
	if e != nil {
		return fmt.Errorf("final direct IPA: %w", e)
	}
	_ = t.challenge("aggregate/projection-rho")
	return consumeAggregateTranscript(t, p, proof)
}
func directOptimizedIPA(t *transcript, P, U bn254.G1Affine, G, H []bn254.G1Affine, ipa IPAProof, publicB []fr.Element, derivePublic bool) ([]fr.Element, error) {
	rounds := len(ipa.L)
	if rounds != log2(len(G)) || len(H) != len(G) || len(ipa.R) != rounds {
		return nil, errors.New("bad direct IPA shape")
	}
	probe := *t
	ch := make([]fr.Element, rounds)
	for i := range ch {
		probe.point("ipa/L", ipa.L[i])
		probe.point("ipa/R", ipa.R[i])
		ch[i] = probe.challenge("ipa/x")
	}
	q := ipa
	if derivePublic && len(publicB) > 0 {
		q.B = evalFoldedPublic(ch, publicB)
	}
	ok, e := IPAVerify(t, P, U, G, H, q, publicB)
	if e != nil {
		return nil, e
	}
	if !ok {
		return nil, errors.New("direct IPA equation rejected")
	}
	return ch, nil
}
func evalFoldedPublic(ch, b []fr.Element) fr.Element {
	bb := append([]fr.Element(nil), b...)
	for _, x := range ch {
		left, right := split(bb)
		bb = plusVec(left, scaleVec(right, x))
	}
	return bb[0]
}

func validateOptimizedProof(p *PublicParams, s Statement, proof OptimizedProof) error {
	if e := checkPP(p); e != nil {
		return e
	}
	points := []bn254.G1Affine{s.Ca, s.Cb, s.Cc, proof.Cay, proof.Cby, proof.Cd, proof.Alpha, proof.Beta, proof.Gamma, proof.Delta, proof.VPrime, proof.W}
	for i := range proof.Projections {
		q := proof.Projections[i]
		points = append(points, q.In, q.Out)
		rounds := 0
		if i == 0 {
			rounds = log2(p.m * p.n)
		} else if i == 1 {
			rounds = log2(p.m * p.inner)
		} else {
			rounds = log2(p.inner * p.n)
		}
		if len(q.IPA.L) != rounds || len(q.IPA.R) != rounds {
			return errors.New("invalid optimized projection IPA shape")
		}
		points = append(points, q.IPA.L...)
		points = append(points, q.IPA.R...)
	}
	if len(proof.Final.L) != log2(p.inner) || len(proof.Final.R) != log2(p.inner) {
		return errors.New("invalid optimized final IPA shape")
	}
	points = append(points, proof.Final.L...)
	points = append(points, proof.Final.R...)
	for i := range points {
		if !points[i].IsOnCurve() || !points[i].IsInSubGroup() {
			return fmt.Errorf("invalid optimized proof point %d", i)
		}
	}
	return nil
}

func (p OptimizedProof) MarshalBinaryFor(pp *PublicParams) ([]byte, error) {
	if e := checkPP(pp); e != nil {
		return nil, e
	}
	var b bytes.Buffer
	b.WriteString("ZKO1")
	if e := binary.Write(&b, binary.BigEndian, [3]uint32{uint32(pp.m), uint32(pp.inner), uint32(pp.n)}); e != nil {
		return nil, e
	}
	for _, q := range []bn254.G1Affine{p.Cay, p.Cby, p.Cd} {
		if e := writePoint(&b, q); e != nil {
			return nil, e
		}
	}
	for i := range p.Projections {
		q := p.Projections[i]
		for _, v := range []bn254.G1Affine{q.In, q.Out} {
			if e := writePoint(&b, v); e != nil {
				return nil, e
			}
		}
		for _, v := range []fr.Element{q.ZIn, q.ZOut} {
			if e := writeScalar(&b, v); e != nil {
				return nil, e
			}
		}
		rounds := log2(pp.m * pp.n)
		if i == 1 {
			rounds = log2(pp.m * pp.inner)
		}
		if i == 2 {
			rounds = log2(pp.inner * pp.n)
		}
		if e := writeOptimizedIPA(&b, q.IPA, rounds, true); e != nil {
			return nil, e
		}
	}
	for _, q := range []bn254.G1Affine{p.Alpha, p.Beta, p.Gamma, p.Delta} {
		if e := writePoint(&b, q); e != nil {
			return nil, e
		}
	}
	for _, q := range []fr.Element{p.ZA, p.ZB, p.ZC} {
		if e := writeScalar(&b, q); e != nil {
			return nil, e
		}
	}
	if e := writeOptimizedIPA(&b, p.Final, log2(pp.inner), false); e != nil {
		return nil, e
	}
	if e := writePoint(&b, p.VPrime); e != nil {
		return nil, e
	}
	if e := writePoint(&b, p.W); e != nil {
		return nil, e
	}
	return b.Bytes(), nil
}
func writeOptimizedIPA(w io.Writer, p IPAProof, rounds int, publicB bool) error {
	if len(p.L) != rounds || len(p.R) != rounds {
		return errors.New("invalid optimized IPA rounds")
	}
	if e := binary.Write(w, binary.BigEndian, uint32(rounds)); e != nil {
		return e
	}
	for i := range p.L {
		if e := writePoint(w, p.L[i]); e != nil {
			return e
		}
		if e := writePoint(w, p.R[i]); e != nil {
			return e
		}
	}
	if e := writeScalar(w, p.A); e != nil {
		return e
	}
	if !publicB {
		return writeScalar(w, p.B)
	}
	return nil
}
func UnmarshalOptimizedProof(pp *PublicParams, data []byte) (OptimizedProof, error) {
	var p OptimizedProof
	if e := checkPP(pp); e != nil {
		return p, e
	}
	r := bytes.NewReader(data)
	head := make([]byte, 16)
	if _, e := io.ReadFull(r, head); e != nil {
		return p, e
	}
	if string(head[:4]) != "ZKO1" || binary.BigEndian.Uint32(head[4:8]) != uint32(pp.m) || binary.BigEndian.Uint32(head[8:12]) != uint32(pp.inner) || binary.BigEndian.Uint32(head[12:16]) != uint32(pp.n) {
		return p, errors.New("optimized proof header/dimensions mismatch")
	}
	var e error
	p.Cay, e = readPoint(r)
	if e != nil {
		return p, e
	}
	p.Cby, e = readPoint(r)
	if e != nil {
		return p, e
	}
	p.Cd, e = readPoint(r)
	if e != nil {
		return p, e
	}
	for i := range p.Projections {
		q := &p.Projections[i]
		q.In, e = readPoint(r)
		if e != nil {
			return p, e
		}
		q.Out, e = readPoint(r)
		if e != nil {
			return p, e
		}
		q.ZIn, e = readScalar(r)
		if e != nil {
			return p, e
		}
		q.ZOut, e = readScalar(r)
		if e != nil {
			return p, e
		}
		rounds := log2(pp.m * pp.n)
		if i == 1 {
			rounds = log2(pp.m * pp.inner)
		}
		if i == 2 {
			rounds = log2(pp.inner * pp.n)
		}
		q.IPA, e = readOptimizedIPA(r, rounds, true)
		if e != nil {
			return p, e
		}
	}
	p.Alpha, e = readPoint(r)
	if e != nil {
		return p, e
	}
	p.Beta, e = readPoint(r)
	if e != nil {
		return p, e
	}
	p.Gamma, e = readPoint(r)
	if e != nil {
		return p, e
	}
	p.Delta, e = readPoint(r)
	if e != nil {
		return p, e
	}
	p.ZA, e = readScalar(r)
	if e != nil {
		return p, e
	}
	p.ZB, e = readScalar(r)
	if e != nil {
		return p, e
	}
	p.ZC, e = readScalar(r)
	if e != nil {
		return p, e
	}
	p.Final, e = readOptimizedIPA(r, log2(pp.inner), false)
	if e != nil {
		return p, e
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
		return p, errors.New("trailing bytes in optimized proof")
	}
	return p, nil
}
func readOptimizedIPA(r io.Reader, rounds int, publicB bool) (IPAProof, error) {
	var p IPAProof
	var n uint32
	if e := binary.Read(r, binary.BigEndian, &n); e != nil {
		return p, e
	}
	if n != uint32(rounds) {
		return p, errors.New("wrong optimized IPA round count")
	}
	p.L = make([]bn254.G1Affine, n)
	p.R = make([]bn254.G1Affine, n)
	for i := range p.L {
		var e error
		p.L[i], e = readPoint(r)
		if e != nil {
			return p, e
		}
		p.R[i], e = readPoint(r)
		if e != nil {
			return p, e
		}
	}
	var e error
	p.A, e = readScalar(r)
	if e != nil {
		return p, e
	}
	if !publicB {
		p.B, e = readScalar(r)
	}
	return p, e
}

// ProveConservative creates the six-IPA reference proof with separate scalar
// and output-vector knowledge checks.
func ProveConservative(p *PublicParams, s Statement, w Witness) (Proof, error) { return Prove(p, s, w) }

// VerifyConservative verifies the conservative reference proof with the direct IPA equations.
func VerifyConservative(p *PublicParams, s Statement, proof Proof) error {
	return VerifyDirect(p, s, proof)
}

// MarshalBinary serializes an optimized proof using pp dimensions.
func (p OptimizedProof) MarshalBinary(pp *PublicParams) ([]byte, error) {
	return p.MarshalBinaryFor(pp)
}

// UnmarshalBinary parses a complete canonical optimized proof.
func (p *OptimizedProof) UnmarshalBinary(pp *PublicParams, data []byte) error {
	v, e := UnmarshalOptimizedProof(pp, data)
	if e != nil {
		return e
	}
	*p = v
	return nil
}
