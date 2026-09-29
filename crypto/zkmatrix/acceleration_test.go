package zkmatrix

import (
	"fmt"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"math/big"
	"reflect"
	"strings"
	"testing"
)

func TestFactorizedPolynomialEvaluations(t *testing.T) {
	p, e := Setup(4, 2, 8)
	if e != nil {
		t.Fatal(e)
	}
	z, _ := randScalar()
	y, _ := randScalar()
	x, _ := randScalar()
	descs := []accelDescriptor{{kind: accelC, y: y, x: x}, {kind: accelARcom}, {kind: accelAHD, y: y, xHD: x}, {kind: accelBRcom}, {kind: accelBHD, y: y, xHD: x}, {kind: accelDot}}
	for _, d := range descs {
		rounds := 0
		switch d.kind {
		case accelC:
			rounds = log2(p.m * p.n)
		case accelARcom, accelBRcom, accelDot:
			rounds = log2(p.inner)
		case accelAHD:
			rounds = log2(p.m) + log2(p.inner)
		case accelBHD:
			rounds = log2(p.n) + log2(p.inner)
		}
		ch := make([]fr.Element, rounds)
		for i := range ch {
			ch[i], e = randScalar()
			if e != nil {
				t.Fatal(e)
			}
		}
		ipa := IPAProof{A: randOrFatal(t), B: randOrFatal(t), challenges: ch}
		coeff, e := proverCoefficients(p, ipa, d)
		if e != nil {
			t.Fatalf("kind %d coefficients: %v", d.kind, e)
		}
		got, e := factorizedPhi(p, d, ipa, ch, z)
		if e != nil {
			t.Fatalf("kind %d eval: %v", d.kind, e)
		}
		want := polyEval(coeff, z)
		if !got.Equal(&want) {
			t.Fatalf("kind %d factorized polynomial mismatch", d.kind)
		}
	}
	for rounds := 0; rounds <= 5; rounds++ {
		ch := make([]fr.Element, rounds)
		for i := range ch {
			ch[i], e = randScalar()
			if e != nil {
				t.Fatal(e)
			}
		}
		for _, stride := range []int{1, 2, 8} {
			got := evalX(ch, z, stride)
			weights := foldingWeights(ch)
			var want fr.Element
			for i := range weights {
				term := mul(weights[i], pow(z, stride*i))
				want.Add(&want, &term)
			}
			if !got.Equal(&want) {
				t.Fatalf("factor X mismatch rounds=%d stride=%d", rounds, stride)
			}
		}
	}
}
func randOrFatal(t *testing.T) fr.Element {
	t.Helper()
	x, e := randScalar()
	if e != nil {
		t.Fatal(e)
	}
	return x
}
func TestAcceleratedProofAndAllIPAFieldsRejectMutations(t *testing.T) {
	p, e := Setup(2, 2, 2)
	if e != nil {
		t.Fatal(e)
	}
	a, b := matrix(2, 2, 5), matrix(2, 2, 17)
	c, e := mulMatrix(a, b)
	if e != nil {
		t.Fatal(e)
	}
	s, w := makeStatement(t, p, a, b, c)
	proof, e := Prove(p, s, w)
	if e != nil {
		t.Fatal(e)
	}
	if e = Verify(p, s, proof); e != nil {
		t.Fatal(e)
	}
	if e = VerifyDirect(p, s, proof); e != nil {
		t.Fatalf("direct reference rejected accelerated proof: %v", e)
	}
	paths := []func(*Proof) *IPAProof{func(p *Proof) *IPAProof { return &p.Projections[0].First }, func(p *Proof) *IPAProof { return &p.Projections[1].First }, func(p *Proof) *IPAProof { return &p.Projections[1].Second }, func(p *Proof) *IPAProof { return &p.Projections[2].First }, func(p *Proof) *IPAProof { return &p.Projections[2].Second }, func(p *Proof) *IPAProof { return &p.Final }}
	for i, path := range paths {
		for _, field := range []string{"VPrime", "W", "L", "R", "A", "B"} {
			bad := cloneProof(proof)
			ipa := path(&bad)
			switch field {
			case "VPrime":
				ipa.VPrime = sumPoint(ipa.VPrime, p.hide)
			case "W":
				ipa.W = sumPoint(ipa.W, p.hide)
			case "L":
				if len(ipa.L) > 0 {
					ipa.L[0] = sumPoint(ipa.L[0], p.hide)
				}
			case "R":
				if len(ipa.R) > 0 {
					ipa.R[0] = sumPoint(ipa.R[0], p.hide)
				}
			case "A":
				ipa.A = add(ipa.A, fr.One())
			case "B":
				ipa.B = add(ipa.B, fr.One())
			}
			if Verify(p, s, bad) == nil {
				t.Fatalf("accepted mutation path=%d field=%s", i, field)
			}
		}
	}
}
func cloneProof(p Proof) Proof {
	for i := range p.Projections {
		p.Projections[i].First.L = append([]bn254.G1Affine(nil), p.Projections[i].First.L...)
		p.Projections[i].First.R = append([]bn254.G1Affine(nil), p.Projections[i].First.R...)
		p.Projections[i].Second.L = append([]bn254.G1Affine(nil), p.Projections[i].Second.L...)
		p.Projections[i].Second.R = append([]bn254.G1Affine(nil), p.Projections[i].Second.R...)
	}
	p.Final.L = append([]bn254.G1Affine(nil), p.Final.L...)
	p.Final.R = append([]bn254.G1Affine(nil), p.Final.R...)
	return p
}
func TestKZGEquationDoesNotReplaceKnowledgeEquation(t *testing.T) {
	p, e := Setup(2, 2, 2)
	if e != nil {
		t.Fatal(e)
	}
	a, b := matrix(1, 2, 11), matrix(1, 2, 31)
	av, _ := flatten(a, 1, 2)
	bv, _ := flatten(b, 1, 2)
	P1, _ := msm(p.g, av)
	P2, _ := msm(p.h, bv)
	P := sumPoint(sumPoint(P1, P2), mulPoint(p.u, dot(av, bv)))
	tr := &transcript{}
	ipa, e := IPAProve(tr, P, p.u, p.g, p.h, av, bv)
	if e != nil {
		t.Fatal(e)
	}
	d := accelDescriptor{kind: accelDot}
	if e = attachAccelerator(tr, p, &ipa, P, d); e != nil {
		t.Fatal(e)
	}
	// Recompute the verifier transcript and independently check Eq. 14's KZG equation.
	tv := &transcript{}
	ch := make([]fr.Element, len(ipa.L))
	for i := range ch {
		tv.point("ipa/L", ipa.L[i])
		tv.point("ipa/R", ipa.R[i])
		ch[i] = tv.challenge("ipa/x")
	}
	tv.scalar("ipa/a", ipa.A)
	tv.scalar("ipa/b", ipa.B)
	z, e := evalChallenge(tv, p)
	if e != nil {
		t.Fatal(e)
	}
	orig, e := ipaCommitment(P, ipa, ch)
	if e != nil {
		t.Fatal(e)
	}
	phi, e := factorizedPhi(p, d, ipa, ch, z)
	if e != nil {
		t.Fatal(e)
	}
	phiG := mulPoint(p.srs[0], phi)
	var diff bn254.G1Affine
	diff.Sub(&phiG, &orig)
	var zG2, q2 bn254.G2Affine
	zG2.ScalarMultiplication(&p.g2, z.BigInt(new(big.Int)))
	q2.Sub(&zG2, &p.tauG2)
	var negW bn254.G1Affine
	negW.Neg(&ipa.W)
	ok, e := bn254.PairingCheck([]bn254.G1Affine{diff, negW}, []bn254.G2Affine{p.g2, q2})
	if e != nil || !ok {
		t.Fatalf("valid KZG equation failed: ok=%v err=%v", ok, e)
	}
	// Changing only V' preserves that KZG equation (which omits V'), but must fail Eq. 14's knowledge check.
	forged := ipa
	forged.VPrime = sumPoint(forged.VPrime, p.hide)
	negW.Neg(&forged.W)
	ok, e = bn254.PairingCheck([]bn254.G1Affine{diff, negW}, []bn254.G2Affine{p.g2, q2})
	if e != nil || !ok {
		t.Fatalf("forgery unexpectedly changed KZG equation: %v", e)
	}
	if e = verifyIPAAccelerated(&transcript{}, p, P, forged, d, nil); e == nil || !strings.Contains(e.Error(), "pairing") {
		t.Fatal("forged V' passed knowledge consistency pairing")
	}
}
func TestSetupDoesNotRetainTrapdoorsAndParamsAreOpaque(t *testing.T) {
	p, e := Setup(2, 2, 2)
	if e != nil {
		t.Fatal(e)
	}
	typ := reflect.TypeOf(*p)
	for i := 0; i < typ.NumField(); i++ {
		name := strings.ToLower(typ.Field(i).Name)
		if name == "tau" || name == "nu" || strings.Contains(name, "secret") {
			t.Fatalf("retained setup secret field %q", typ.Field(i).Name)
		}
	}
	if p.shifted[0].IsInfinity() {
		t.Fatal("shifted SRS omitted nu*G1 at exponent zero")
	}
}

func TestOptimizedPaperCompositionRectangularRoundtripAndTampering(t *testing.T) {
	cases := [][3]int{{2, 2, 2}, {4, 4, 4}, {2, 4, 2}, {4, 2, 8}}
	for _, d := range cases {
		t.Run(fmt.Sprintf("%dx%dx%d", d[0], d[1], d[2]), func(t *testing.T) {
			p, e := Setup(d[0], d[1], d[2])
			if e != nil {
				t.Fatal(e)
			}
			a, b := matrix(d[0], d[1], 13), matrix(d[1], d[2], 47)
			c, e := mulMatrix(a, b)
			if e != nil {
				t.Fatal(e)
			}
			s, w := makeStatement(t, p, a, b, c)
			proof, e := ProveOptimized(p, s, w)
			if e != nil {
				t.Fatal(e)
			}
			if e = VerifyOptimized(p, s, proof); e != nil {
				t.Fatalf("optimized verifier rejected valid proof: %v", e)
			}
			if e = VerifyOptimizedDirect(p, s, proof); e != nil {
				t.Fatalf("direct reference rejected valid optimized proof: %v", e)
			}
			raw, e := proof.MarshalBinaryFor(p)
			if e != nil {
				t.Fatal(e)
			}
			decoded, e := UnmarshalOptimizedProof(p, raw)
			if e != nil {
				t.Fatal(e)
			}
			if e = VerifyOptimized(p, s, decoded); e != nil {
				t.Fatalf("serialized proof rejected: %v", e)
			}
			if e = VerifyOptimizedDirect(p, s, decoded); e != nil {
				t.Fatalf("serialized proof failed direct verifier: %v", e)
			}
			if _, e = UnmarshalOptimizedProof(p, append(append([]byte(nil), raw...), 0)); e == nil {
				t.Fatal("accepted trailing proof byte")
			}
			badC := matrix(d[0], d[2], 213)
			ss, ww := makeStatement(t, p, a, b, badC)
			badProof, e := ProveOptimized(p, ss, ww)
			if e != nil {
				t.Fatal(e)
			}
			if VerifyOptimized(p, ss, badProof) == nil {
				t.Fatal("accepted false C")
			}
			for i := 0; i < 3; i++ {
				sm := s
				switch i {
				case 0:
					sm.Ca = sumPoint(sm.Ca, p.hide)
				case 1:
					sm.Cb = sumPoint(sm.Cb, p.hide)
				case 2:
					sm.Cc = sumPoint(sm.Cc, p.hide)
				}
				if VerifyOptimized(p, sm, proof) == nil {
					t.Fatalf("accepted mutated input commitment %d", i)
				}
			}
			for _, field := range []string{"Cay", "Cby", "Cd", "mask-in", "mask-out", "z-in", "z-out", "VPrime", "W", "L", "R", "A", "B"} {
				bad := cloneOptimized(proof)
				switch field {
				case "Cay":
					bad.Cay = sumPoint(bad.Cay, p.hide)
				case "Cby":
					bad.Cby = sumPoint(bad.Cby, p.hide)
				case "Cd":
					bad.Cd = sumPoint(bad.Cd, p.hide)
				case "mask-in":
					bad.Projections[1].In = sumPoint(bad.Projections[1].In, p.hide)
				case "mask-out":
					bad.Projections[2].Out = sumPoint(bad.Projections[2].Out, p.hide)
				case "z-in":
					bad.Projections[1].ZIn = add(bad.Projections[1].ZIn, fr.One())
				case "z-out":
					bad.Projections[2].ZOut = add(bad.Projections[2].ZOut, fr.One())
				case "VPrime":
					bad.VPrime = sumPoint(bad.VPrime, p.hide)
				case "W":
					bad.W = sumPoint(bad.W, p.hide)
				case "L":
					bad.Projections[1].IPA.L[0] = sumPoint(bad.Projections[1].IPA.L[0], p.hide)
				case "R":
					bad.Projections[2].IPA.R[0] = sumPoint(bad.Projections[2].IPA.R[0], p.hide)
				case "A":
					bad.Final.A = add(bad.Final.A, fr.One())
				case "B":
					bad.Final.B = add(bad.Final.B, fr.One())
				}
				if VerifyOptimized(p, s, bad) == nil {
					t.Fatalf("accepted optimized mutation %s", field)
				}
			}
		})
	}
}
func cloneOptimized(p OptimizedProof) OptimizedProof {
	for i := range p.Projections {
		p.Projections[i].IPA.L = append([]bn254.G1Affine(nil), p.Projections[i].IPA.L...)
		p.Projections[i].IPA.R = append([]bn254.G1Affine(nil), p.Projections[i].IPA.R...)
	}
	p.Final.L = append([]bn254.G1Affine(nil), p.Final.L...)
	p.Final.R = append([]bn254.G1Affine(nil), p.Final.R...)
	return p
}

func TestEquation22StructuredSRSLayoutAndOptimizedBytes(t *testing.T) {
	p, e := Setup(4, 2, 8)
	if e != nil {
		t.Fatal(e)
	}
	D := 32
	if 4*2 > D {
		D = 8
	}
	if 2*8 > D {
		D = 16
	}
	if p.uOff != D+1 || p.gOff != D+2 || p.hOff != D+3 || p.q != D+2*p.inner+1 {
		t.Fatalf("wrong Eq22 offsets: D=%d offsets U/G/H/q=%d/%d/%d/%d", D, p.uOff, p.gOff, p.hOff, p.q)
	}
	for i := 0; i < p.m*p.inner; i++ {
		if !p.a[i].Equal(&p.srs[1+i]) {
			t.Fatal("A matrix base is not common SRS prefix")
		}
	}
	for i := 0; i < p.inner*p.n; i++ {
		if !p.b[i].Equal(&p.srs[1+i]) {
			t.Fatal("B matrix base is not common SRS prefix")
		}
	}
	for i := 0; i < p.m*p.n; i++ {
		if !p.c[i].Equal(&p.srs[1+i]) {
			t.Fatal("C matrix base is not common SRS prefix")
		}
	}
	for k := 0; k < p.inner; k++ {
		if !p.g[k].Equal(&p.srs[p.gOff+2*k]) || !p.h[k].Equal(&p.srs[p.hOff+2*k]) {
			t.Fatal("projected vector bases do not use Eq22 stride 2")
		}
	}
	a, b := matrix(4, 2, 2), matrix(2, 8, 70)
	c, _ := mulMatrix(a, b)
	s, w := makeStatement(t, p, a, b, c)
	proof, e := ProveOptimized(p, s, w)
	if e != nil {
		t.Fatal(e)
	}
	raw, e := proof.MarshalBinaryFor(p)
	if e != nil {
		t.Fatal(e)
	}
	rounds := log2(p.m*p.n) + log2(p.m*p.inner) + log2(p.inner*p.n) + log2(p.inner)
	want := 32 + (15+2*rounds+14)*bn254.SizeOfG1AffineCompressed // header/dimensions and four IPA round counts
	if len(raw) != want {
		t.Fatalf("serialized optimized length %d, want %d from 15 fixed points, %d IPA rounds and 14 scalars plus framing", len(raw), want, rounds)
	}
}
