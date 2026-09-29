package zkmatrix

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

func matrix(rows, cols int, seed uint64) [][]fr.Element {
	m := make([][]fr.Element, rows)
	for i := range m {
		m[i] = make([]fr.Element, cols)
		for j := range m[i] {
			var x fr.Element
			x.SetUint64(seed + uint64(i*cols+j+1))
			m[i][j] = x
		}
	}
	return m
}
func makeStatement(t *testing.T, p *PublicParams, a, b, c [][]fr.Element) (Statement, Witness) {
	t.Helper()
	s, ra, rb, e := CommitInputs(p, a, b)
	if e != nil {
		t.Fatal(e)
	}
	sc, rc, e := CommitOutput(p, c)
	if e != nil {
		t.Fatal(e)
	}
	s.Cc = sc.Cc
	return s, Witness{A: a, B: b, C: c, RA: ra, RB: rb, RC: rc}
}
func TestDirectProofRectangularAndMutations(t *testing.T) {
	dims := [][3]int{{2, 2, 2}, {4, 4, 4}, {8, 8, 8}, {2, 4, 2}, {4, 2, 8}}
	for _, d := range dims {
		t.Run(string(rune('0'+d[0]))+"x"+string(rune('0'+d[1]))+"x"+string(rune('0'+d[2])), func(t *testing.T) {
			p, e := Setup(d[0], d[1], d[2])
			if e != nil {
				t.Fatal(e)
			}
			a := matrix(d[0], d[1], 10)
			b := matrix(d[1], d[2], 80)
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
				t.Fatalf("valid proof rejected: %v", e)
			}
			blob, e := proof.MarshalBinaryFor(p)
			if e != nil {
				t.Fatal(e)
			}
			decoded, e := UnmarshalProof(p, blob)
			if e != nil {
				t.Fatal(e)
			}
			if e = Verify(p, s, decoded); e != nil {
				t.Fatalf("roundtrip rejected: %v", e)
			}
			if _, e = UnmarshalProof(p, append(append([]byte(nil), blob...), 0)); e == nil {
				t.Fatal("accepted proof trailing byte")
			}
			// A false output matrix has a correctly formed commitment/opening, but the verifier must reject its proof.
			bad := matrix(d[0], d[2], 190)
			ss, ww := makeStatement(t, p, a, b, bad)
			badProof, e := Prove(p, ss, ww)
			if e != nil {
				t.Fatal(e)
			}
			if Verify(p, ss, badProof) == nil {
				t.Fatal("accepted false C witness")
			}
			// Mutating each statement commitment invalidates the transcript.
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
				if Verify(p, sm, proof) == nil {
					t.Fatalf("accepted mutated commitment %d", i)
				}
			}
			mutated := proof
			mutated.Projections[1].In = sumPoint(mutated.Projections[1].In, p.hide)
			if Verify(p, s, mutated) == nil {
				t.Fatal("accepted mutated mask commitment")
			}
			mutated = proof
			mutated.Projections[1].ZIn = add(mutated.Projections[1].ZIn, fr.One())
			if Verify(p, s, mutated) == nil {
				t.Fatal("accepted mutated mask response")
			}
			mutated = proof
			mutated.Final.A = add(mutated.Final.A, fr.One())
			if Verify(p, s, mutated) == nil {
				t.Fatal("accepted mutated final scalar")
			}
		})
	}
}
func TestMalformedProofSerialization(t *testing.T) {
	p, _ := Setup(2, 2, 2)
	if Verify(p, Statement{}, Proof{}) == nil {
		t.Fatal("accepted empty proof")
	}
	if _, e := UnmarshalProof(p, nil); e == nil {
		t.Fatal("accepted empty proof")
	}
	s := Statement{}
	blob, e := MarshalStatement(p, s)
	if e != nil {
		t.Fatal(e)
	}
	blob = append(blob, 0)
	if _, e = UnmarshalStatement(p, blob); e == nil {
		t.Fatal("accepted statement trailing byte")
	}
}

func TestStandaloneIPARejectsMutations(t *testing.T) {
	p, err := Setup(4, 4, 4)
	if err != nil {
		t.Fatal(err)
	}
	a, err := randVec(4)
	if err != nil {
		t.Fatal(err)
	}
	b, err := randVec(4)
	if err != nil {
		t.Fatal(err)
	}
	u := p.u
	g, _ := msm(p.g, a)
	h, _ := msm(p.h, b)
	P := sumPoint(sumPoint(g, h), mulPoint(u, dot(a, b)))
	tr := &transcript{}
	proof, err := IPAProve(tr, P, u, p.g, p.h, a, b)
	if err != nil {
		t.Fatal(err)
	}
	verify := func(pr IPAProof) bool {
		v := &transcript{}
		ok, e := IPAVerify(v, P, u, p.g, p.h, pr, nil)
		return e == nil && ok
	}
	if !verify(proof) {
		t.Fatal("valid standalone IPA rejected")
	}
	bad := proof
	bad.L = append([]bn254.G1Affine(nil), proof.L...)
	bad.L[0] = sumPoint(bad.L[0], p.hide)
	if verify(bad) {
		t.Fatal("accepted mutated IPA L point")
	}
	bad = proof
	bad.R = append([]bn254.G1Affine(nil), proof.R...)
	bad.R[0] = sumPoint(bad.R[0], p.hide)
	if verify(bad) {
		t.Fatal("accepted mutated IPA R point")
	}
	bad = proof
	bad.A = add(bad.A, fr.One())
	if verify(bad) {
		t.Fatal("accepted mutated IPA final scalar")
	}
	bad = proof
	bad.L = bad.L[:len(bad.L)-1]
	if verify(bad) {
		t.Fatal("accepted missing IPA round")
	}
}

func TestReplayAgainstDifferentDimensionsAndParams(t *testing.T) {
	p, err := Setup(2, 2, 2)
	if err != nil {
		t.Fatal(err)
	}
	a := matrix(2, 2, 3)
	b := matrix(2, 2, 9)
	c, err := mulMatrix(a, b)
	if err != nil {
		t.Fatal(err)
	}
	s, w := makeStatement(t, p, a, b, c)
	proof, err := Prove(p, s, w)
	if err != nil {
		t.Fatal(err)
	}
	other, err := Setup(2, 4, 2)
	if err != nil {
		t.Fatal(err)
	}
	if Verify(other, s, proof) == nil {
		t.Fatal("accepted proof under different dimensions/parameters")
	}
	if _, err = UnmarshalStatement(other, mustStatementBytes(t, p, s)); err == nil {
		t.Fatal("accepted statement under different dimensions")
	}
}
func mustStatementBytes(t *testing.T, p *PublicParams, s Statement) []byte {
	t.Helper()
	b, e := MarshalStatement(p, s)
	if e != nil {
		t.Fatal(e)
	}
	return b
}
