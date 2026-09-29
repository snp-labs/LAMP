// Package zkmatrix implements an independent zkMatrix construction with a
// structured-SRS pairing verifier and a direct-verifier reference path.
package zkmatrix

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"
	"runtime"
	"sync"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

const domain = "lamp/independent-zkmatrix/accelerated/v1"
const maxDimension = 1 << 15
const defaultMaxMatrixElements = 1 << 20

type PublicParams struct {
	m, inner, n                           int
	c, a, b                               []bn254.G1Affine
	g, h                                  []bn254.G1Affine
	u, hide                               bn254.G1Affine
	srs, shifted                          []bn254.G1Affine
	g2, tauG2, nuG2                       bn254.G2Affine
	uOff, gOff, hOff, aOff, bOff, cOff, q int
	fingerprint                           [32]byte
	validated                             bool
}
type Statement struct{ Ca, Cb, Cc bn254.G1Affine }
type Witness struct {
	A, B, C    [][]fr.Element
	RA, RB, RC fr.Element
}
type IPAProof struct {
	L, R       []bn254.G1Affine
	A, B       fr.Element
	VPrime, W  bn254.G1Affine
	challenges []fr.Element
}
type ProjectionProof struct {
	In, Out       bn254.G1Affine
	ZIn, ZOut     fr.Element
	KnowledgeR    bn254.G1Affine
	KnowledgeZ    fr.Element
	First, Second IPAProof
}
type Proof struct {
	Cay, Cby, Cd              bn254.G1Affine
	Projections               [3]ProjectionProof
	Alpha, Beta, Gamma, Delta bn254.G1Affine
	ZA, ZB, ZC                fr.Element
	Final                     IPAProof
}

func power2(n int) bool              { return n > 0 && n&(n-1) == 0 }
func validateDims(m, k, n int) error { return validateDimsLimit(m, k, n, defaultMaxMatrixElements) }
func validateDimsLimit(m, k, n, maxElements int) error {
	if !power2(m) || !power2(k) || !power2(n) || m > maxDimension || k > maxDimension || n > maxDimension {
		return errors.New("dimensions must be positive powers of two no larger than 32768")
	}
	if maxElements < 1 {
		return errors.New("maximum matrix element limit must be positive")
	}
	if int64(m)*int64(k) > int64(maxElements) || int64(k)*int64(n) > int64(maxElements) || int64(m)*int64(n) > int64(maxElements) {
		return fmt.Errorf("matrix element count exceeds explicit limit %d", maxElements)
	}
	return nil
}
func Setup(m, k, n int) (*PublicParams, error) {
	return SetupWithLimit(m, k, n, defaultMaxMatrixElements)
}
func SetupWithLimit(m, k, n, maxElements int) (*PublicParams, error) {
	if err := validateDimsLimit(m, k, n, maxElements); err != nil {
		return nil, err
	}
	tau, err := nonzeroScalar()
	if err != nil {
		return nil, err
	}
	nu, err := nonzeroScalar()
	if err != nil {
		return nil, err
	}
	_, _, g1, g2 := bn254.Generators()
	d := m * n
	if m*k > d {
		d = m * k
	}
	if k*n > d {
		d = k * n
	}
	p := &PublicParams{m: m, inner: k, n: n, g2: g2, aOff: 1, bOff: 1, cOff: 1, uOff: d + 1, gOff: d + 2, hOff: d + 3}
	p.q = d + 2*k + 1
	p.srs = make([]bn254.G1Affine, p.q+1)
	p.shifted = make([]bn254.G1Affine, p.q+1)
	p.srs[0] = g1
	tauPowers := make([]fr.Element, p.q)
	shiftedScalars := make([]fr.Element, p.q+1)
	cur := fr.One()
	for i := 0; i <= p.q; i++ {
		shiftedScalars[i].Mul(&cur, &nu)
		if i < p.q {
			cur.Mul(&cur, &tau)
			tauPowers[i] = cur
		}
	}
	copy(p.srs[1:], bn254.BatchScalarMultiplicationG1(&g1, tauPowers))
	copy(p.shifted, bn254.BatchScalarMultiplicationG1(&g1, shiftedScalars))
	for i := range tauPowers {
		tauPowers[i] = fr.Element{}
	}
	for i := range shiftedScalars {
		shiftedScalars[i] = fr.Element{}
	}
	p.u = p.srs[p.uOff]
	p.g = make([]bn254.G1Affine, k)
	p.h = make([]bn254.G1Affine, k)
	for i := 0; i < k; i++ {
		p.g[i] = p.srs[p.gOff+2*i]
		p.h[i] = p.srs[p.hOff+2*i]
	}
	p.a = p.srs[1 : 1+m*k]
	p.b = p.srs[1 : 1+k*n]
	p.c = p.srs[1 : 1+m*n]
	p.tauG2.ScalarMultiplication(&g2, tau.BigInt(new(big.Int)))
	p.nuG2.ScalarMultiplication(&g2, nu.BigInt(new(big.Int)))
	dims := [3]int{m, k, n}
	p.hide, err = bn254.HashToG1(append([]byte(domain+"/hiding/"), encodeDims(dims)...), []byte(domain+"/bases"))
	if err != nil {
		return nil, err
	}
	p.fingerprint = fingerprint(p)
	p.validated = true
	// tau and nu exist only as local setup values; no secret scalar is retained.
	return p, nil
}
func nonzeroScalar() (fr.Element, error) {
	for {
		x, e := randScalar()
		if e != nil {
			return x, e
		}
		if !x.IsZero() {
			return x, nil
		}
	}
}
func encodeDims(d [3]int) []byte {
	var b [12]byte
	for i, x := range d {
		binary.BigEndian.PutUint32(b[i*4:], uint32(x))
	}
	return b[:]
}
func fingerprint(p *PublicParams) [32]byte {
	h := sha256.New()
	h.Write([]byte(domain))
	h.Write(encodeDims([3]int{p.m, p.inner, p.n}))
	var b [4]byte
	for _, x := range []int{p.uOff, p.gOff, p.hOff, p.aOff, p.bOff, p.cOff, p.q} {
		binary.BigEndian.PutUint32(b[:], uint32(x))
		h.Write(b[:])
	}
	for _, g := range [][]bn254.G1Affine{p.srs, p.shifted, {p.hide}} {
		for i := range g {
			x := g[i].Bytes()
			h.Write(x[:])
		}
	}
	for _, g := range []bn254.G2Affine{p.g2, p.tauG2, p.nuG2} {
		x := g.Bytes()
		h.Write(x[:])
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}
func (p *PublicParams) Dimensions() (int, int, int) {
	if p == nil {
		return 0, 0, 0
	}
	return p.m, p.inner, p.n
}
func checkPP(p *PublicParams) error {
	if p == nil {
		return errors.New("nil public parameters")
	}
	if !p.validated {
		return errors.New("unvalidated public parameters")
	}
	if !power2(p.m) || !power2(p.inner) || !power2(p.n) {
		return errors.New("invalid public parameter dimensions")
	}
	if p.q < 1 || len(p.srs) != p.q+1 || len(p.shifted) != p.q+1 {
		return errors.New("invalid SRS shape")
	}
	return nil
}
func randScalar() (fr.Element, error) { var x fr.Element; _, e := x.SetRandom(); return x, e }
func randVec(n int) ([]fr.Element, error) {
	v := make([]fr.Element, n)
	for i := range v {
		x, e := randScalar()
		if e != nil {
			return nil, e
		}
		v[i] = x
	}
	return v, nil
}
func add(a, b fr.Element) fr.Element { var z fr.Element; z.Add(&a, &b); return z }
func sub(a, b fr.Element) fr.Element { var z fr.Element; z.Sub(&a, &b); return z }
func mul(a, b fr.Element) fr.Element { var z fr.Element; z.Mul(&a, &b); return z }
func neg(a fr.Element) fr.Element    { var z fr.Element; z.Neg(&a); return z }
func inv(a fr.Element) fr.Element    { var z fr.Element; z.Inverse(&a); return z }
func dot(a, b []fr.Element) fr.Element {
	var z fr.Element
	for i := range a {
		z.Add(&z, new(fr.Element).Mul(&a[i], &b[i]))
	}
	return z
}
func scaleVec(a []fr.Element, s fr.Element) []fr.Element {
	z := make([]fr.Element, len(a))
	for i := range a {
		z[i].Mul(&a[i], &s)
	}
	return z
}
func plusVec(a, b []fr.Element) []fr.Element {
	z := make([]fr.Element, len(a))
	for i := range a {
		z[i].Add(&a[i], &b[i])
	}
	return z
}
func sumPoint(a, b bn254.G1Affine) bn254.G1Affine { var z bn254.G1Affine; z.Add(&a, &b); return z }
func mulPoint(p bn254.G1Affine, s fr.Element) bn254.G1Affine {
	var z bn254.G1Affine
	z.ScalarMultiplication(&p, s.BigInt(new(big.Int)))
	return z
}
func msm(bases []bn254.G1Affine, scalars []fr.Element) (bn254.G1Affine, error) {
	if len(bases) != len(scalars) {
		return bn254.G1Affine{}, errors.New("MSM length mismatch")
	}
	if len(bases) == 0 {
		return bn254.G1Affine{}, nil
	}
	var z bn254.G1Affine
	_, e := z.MultiExp(bases, scalars, ecc.MultiExpConfig{NbTasks: runtime.GOMAXPROCS(0)})
	return z, e
}

// parallelPoints evaluates independent group operations with a bounded worker
// pool. Small folds remain serial to avoid channel/scheduling overhead.
func parallelPoints(n int, f func(int)) {
	workers := runtime.GOMAXPROCS(0)
	if workers < 2 || n < 128 {
		for i := 0; i < n; i++ {
			f(i)
		}
		return
	}
	if workers > n {
		workers = n
	}
	jobs := make(chan int, workers*2)
	var wg sync.WaitGroup
	wg.Add(workers)
	for w := 0; w < workers; w++ {
		go func() {
			defer wg.Done()
			for i := range jobs {
				f(i)
			}
		}()
	}
	for i := 0; i < n; i++ {
		jobs <- i
	}
	close(jobs)
	wg.Wait()
}
func commit(v []fr.Element, g []bn254.G1Affine, h bn254.G1Affine, r fr.Element) (bn254.G1Affine, error) {
	p, e := msm(g, v)
	if e != nil {
		return p, e
	}
	return sumPoint(p, mulPoint(h, r)), nil
}
func flatten(m [][]fr.Element, rows, cols int) ([]fr.Element, error) {
	if len(m) != rows {
		return nil, fmt.Errorf("expected %d rows", rows)
	}
	v := make([]fr.Element, 0, rows*cols)
	for _, r := range m {
		if len(r) != cols {
			return nil, fmt.Errorf("expected row width %d", cols)
		}
		v = append(v, r...)
	}
	return v, nil
}
func CommitInputs(p *PublicParams, a, b [][]fr.Element) (Statement, fr.Element, fr.Element, error) {
	var s Statement
	if e := checkPP(p); e != nil {
		return s, fr.Element{}, fr.Element{}, e
	}
	av, e := flatten(a, p.m, p.inner)
	if e != nil {
		return s, fr.Element{}, fr.Element{}, e
	}
	bv, e := flatten(b, p.inner, p.n)
	if e != nil {
		return s, fr.Element{}, fr.Element{}, e
	}
	ra, e := randScalar()
	if e != nil {
		return s, ra, fr.Element{}, e
	}
	rb, e := randScalar()
	if e != nil {
		return s, ra, rb, e
	}
	s.Ca, e = commit(av, p.a, p.hide, ra)
	if e != nil {
		return s, ra, rb, e
	}
	s.Cb, e = commit(bv, p.b, p.hide, rb)
	return s, ra, rb, e
}
func mulMatrix(a, b [][]fr.Element) ([][]fr.Element, error) {
	if len(a) == 0 || len(b) == 0 || len(a[0]) != len(b) {
		return nil, errors.New("matrix dimensions mismatch")
	}
	c := make([][]fr.Element, len(a))
	for i := range a {
		if len(a[i]) != len(b) {
			return nil, errors.New("ragged matrix")
		}
		c[i] = make([]fr.Element, len(b[0]))
		for j := range b[0] {
			for k := range b {
				c[i][j].Add(&c[i][j], new(fr.Element).Mul(&a[i][k], &b[k][j]))
			}
		}
	}
	return c, nil
}

type transcript struct {
	buf     bytes.Buffer
	counter uint64
}

func (t *transcript) raw(label string, b []byte) {
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(label)))
	t.buf.Write(n[:])
	t.buf.WriteString(label)
	binary.BigEndian.PutUint32(n[:], uint32(len(b)))
	t.buf.Write(n[:])
	t.buf.Write(b)
}
func (t *transcript) point(label string, p bn254.G1Affine) { b := p.Bytes(); t.raw(label, b[:]) }
func scalarBytes(x fr.Element) []byte                      { b := x.Bytes(); return b[:] }
func (t *transcript) scalar(label string, x fr.Element)    { t.raw(label, scalarBytes(x)) }
func (t *transcript) challenge(label string) fr.Element {
	for {
		var c [8]byte
		binary.BigEndian.PutUint64(c[:], t.counter)
		t.counter++
		h := sha256.New()
		h.Write([]byte(domain + "/transcript/" + label))
		h.Write(t.buf.Bytes())
		h.Write(c[:])
		var x fr.Element
		x.SetBytes(h.Sum(nil))
		if !x.IsZero() {
			t.scalar("challenge/"+label, x)
			return x
		}
	}
}
func initTranscript(p *PublicParams, s Statement) *transcript {
	t := &transcript{}
	t.raw("domain", []byte(domain))
	var d [12]byte
	binary.BigEndian.PutUint32(d[:], uint32(p.m))
	binary.BigEndian.PutUint32(d[4:], uint32(p.inner))
	binary.BigEndian.PutUint32(d[8:], uint32(p.n))
	t.raw("dimensions", d[:])
	t.raw("parameter-fingerprint", p.fingerprint[:])
	t.point("Ca", s.Ca)
	t.point("Cb", s.Cb)
	t.point("Cc", s.Cc)
	return t
}
func pow(x fr.Element, n int) fr.Element {
	z := fr.One()
	base := x
	for n > 0 {
		if n&1 == 1 {
			z.Mul(&z, &base)
		}
		base.Square(&base)
		n >>= 1
	}
	return z
}
func projectionPowers(y fr.Element, m, k, n int) ([]fr.Element, []fr.Element) {
	yl := make([]fr.Element, m)
	yr := make([]fr.Element, n)
	if m > 0 {
		yl[0] = fr.One()
		step := pow(y, n)
		for i := 1; i < m; i++ {
			yl[i].Mul(&yl[i-1], &step)
		}
	}
	if n > 0 {
		yr[0] = fr.One()
		for i := 1; i < n; i++ {
			yr[i].Mul(&yr[i-1], &y)
		}
	}
	return yl, yr
}

func split(v []fr.Element) ([]fr.Element, []fr.Element) { n := len(v) / 2; return v[:n], v[n:] }
func splitP(v []bn254.G1Affine) ([]bn254.G1Affine, []bn254.G1Affine) {
	n := len(v) / 2
	return v[:n], v[n:]
}
func appendScaledPoint(acc *bn254.G1Affine, p bn254.G1Affine, s fr.Element) {
	q := mulPoint(p, s)
	acc.Add(acc, &q)
}
func IPAProve(t *transcript, P, U bn254.G1Affine, G, H []bn254.G1Affine, a, b []fr.Element) (IPAProof, error) {
	var proof IPAProof
	if len(a) == 0 || len(a) != len(b) || len(a) != len(G) || len(a) != len(H) || !power2(len(a)) {
		return proof, errors.New("invalid IPA lengths")
	}
	aa := append([]fr.Element(nil), a...)
	bb := append([]fr.Element(nil), b...)
	gg := append([]bn254.G1Affine(nil), G...)
	hh := append([]bn254.G1Affine(nil), H...)
	for len(aa) > 1 {
		al, ar := split(aa)
		bl, br := split(bb)
		gl, gr := splitP(gg)
		hl, hr := splitP(hh)
		la, e := msm(gr, al)
		if e != nil {
			return proof, e
		}
		lb, e := msm(hl, br)
		if e != nil {
			return proof, e
		}
		l := sumPoint(sumPoint(la, lb), mulPoint(U, dot(al, br)))
		ra, e := msm(gl, ar)
		if e != nil {
			return proof, e
		}
		rb, e := msm(hr, bl)
		if e != nil {
			return proof, e
		}
		r := sumPoint(sumPoint(ra, rb), mulPoint(U, dot(ar, bl)))
		proof.L = append(proof.L, l)
		proof.R = append(proof.R, r)
		t.point("ipa/L", l)
		t.point("ipa/R", r)
		x := t.challenge("ipa/x")
		proof.challenges = append(proof.challenges, x)
		xi := inv(x)
		aa = plusVec(al, scaleVec(ar, xi))
		bb = plusVec(bl, scaleVec(br, x))
		ng := make([]bn254.G1Affine, len(gl))
		nh := make([]bn254.G1Affine, len(hl))
		parallelPoints(len(gl), func(i int) {
			ng[i] = sumPoint(gl[i], mulPoint(gr[i], x))
			nh[i] = sumPoint(hl[i], mulPoint(hr[i], xi))
		})
		gg, hh = ng, nh
		P = sumPoint(sumPoint(P, mulPoint(l, x)), mulPoint(r, xi))
	}
	proof.A = aa[0]
	proof.B = bb[0]
	t.scalar("ipa/a", proof.A)
	t.scalar("ipa/b", proof.B)
	return proof, nil
}
func IPAVerify(t *transcript, P, U bn254.G1Affine, G, H []bn254.G1Affine, proof IPAProof, publicB []fr.Element) (bool, error) {
	if len(G) == 0 || len(G) != len(H) || !power2(len(G)) || len(proof.L) != log2(len(G)) || len(proof.R) != len(proof.L) {
		return false, errors.New("invalid IPA proof shape")
	}
	gg := append([]bn254.G1Affine(nil), G...)
	hh := append([]bn254.G1Affine(nil), H...)
	b := append([]fr.Element(nil), publicB...)
	for i := range proof.L {
		t.point("ipa/L", proof.L[i])
		t.point("ipa/R", proof.R[i])
		x := t.challenge("ipa/x")
		xi := inv(x)
		if len(b) > 0 {
			bl, br := split(b)
			b = plusVec(bl, scaleVec(br, x))
		}
		gl, gr := splitP(gg)
		hl, hr := splitP(hh)
		ng := make([]bn254.G1Affine, len(gl))
		nh := make([]bn254.G1Affine, len(hl))
		for j := range gl {
			ng[j] = sumPoint(gl[j], mulPoint(gr[j], x))
			nh[j] = sumPoint(hl[j], mulPoint(hr[j], xi))
		}
		gg, hh = ng, nh
		P = sumPoint(sumPoint(P, mulPoint(proof.L[i], x)), mulPoint(proof.R[i], xi))
	}
	t.scalar("ipa/a", proof.A)
	if len(publicB) == 0 {
		t.scalar("ipa/b", proof.B)
	} else {
		if len(b) != 1 {
			return false, errors.New("invalid public IPA vector")
		}
		if !proof.B.Equal(&b[0]) {
			return false, errors.New("public-vector IPA folded scalar mismatch")
		}
		t.scalar("ipa/b", proof.B)
	}
	bv := proof.B
	rhs := sumPoint(sumPoint(mulPoint(U, mul(proof.A, bv)), msmOne(gg[0], proof.A)), msmOne(hh[0], bv))
	return P.Equal(&rhs), nil
}
func msmOne(p bn254.G1Affine, s fr.Element) bn254.G1Affine { return mulPoint(p, s) }
func log2(n int) int {
	r := 0
	for n > 1 {
		n >>= 1
		r++
	}
	return r
}

type accelKind uint8

const (
	accelC accelKind = iota
	accelARcom
	accelAHD
	accelBRcom
	accelBHD
	accelDot
)

type accelDescriptor struct {
	kind      accelKind
	y, x, xHD fr.Element
}

func inverseChallenges(x []fr.Element) []fr.Element {
	z := make([]fr.Element, len(x))
	for i := range x {
		z[i] = inv(x[i])
	}
	return z
}
func foldingWeights(x []fr.Element) []fr.Element {
	w := []fr.Element{fr.One()}
	for j := len(x) - 1; j >= 0; j-- {
		n := len(w)
		w = append(w, make([]fr.Element, n)...)
		for i := 0; i < n; i++ {
			w[n+i].Mul(&w[i], &x[j])
		}
	}
	return w
}
func addCoeff(c []fr.Element, at int, v fr.Element) error {
	if at < 0 || at >= len(c) {
		return fmt.Errorf("coefficient index %d outside SRS", at)
	}
	c[at].Add(&c[at], &v)
	return nil
}
func proverCoefficients(p *PublicParams, ipa IPAProof, d accelDescriptor) ([]fr.Element, error) {
	c := make([]fr.Element, p.q+1)
	xi := foldingWeights(ipa.challenges)
	a, b := ipa.A, ipa.B
	put := func(i int, v fr.Element) error { return addCoeff(c, i, v) }
	switch d.kind {
	case accelC:
		if len(ipa.challenges) != log2(p.m*p.n) {
			return nil, errors.New("C IPA challenge shape mismatch")
		}
		if e := put(p.uOff, mul(mul(a, b), d.x)); e != nil {
			return nil, e
		}
		for i := range xi {
			if e := put(p.cOff+i, mul(a, xi[i])); e != nil {
				return nil, e
			}
		}
	case accelARcom, accelBRcom:
		if len(ipa.challenges) != log2(p.inner) {
			return nil, errors.New("Rcom challenge shape mismatch")
		}
		off := p.gOff
		if d.kind == accelBRcom {
			off = p.hOff
		}
		for i := range xi {
			if e := put(off+2*i, mul(a, xi[i])); e != nil {
				return nil, e
			}
		}
	case accelAHD:
		rm, rk := log2(p.m), log2(p.inner)
		if len(ipa.challenges) != rm+rk {
			return nil, errors.New("A HD challenge shape mismatch")
		}
		xo := foldingWeights(ipa.challenges[:rm])
		xk := foldingWeights(ipa.challenges[rm:])
		yl, _ := projectionPowers(d.y, p.m, p.inner, p.n)
		for i := 0; i < p.m; i++ {
			for k := 0; k < p.inner; k++ {
				id := i*p.inner + k
				if e := put(p.aOff+id, mul(a, xi[id])); e != nil {
					return nil, e
				}
				v := mul(mul(mul(a, d.xHD), xo[i]), mul(yl[i], xk[k]))
				if e := put(p.gOff+2*k, v); e != nil {
					return nil, e
				}
			}
		}
	case accelBHD:
		rn, rk := log2(p.n), log2(p.inner)
		if len(ipa.challenges) != rn+rk {
			return nil, errors.New("B HD challenge shape mismatch")
		}
		xo := foldingWeights(ipa.challenges[:rn])
		xk := foldingWeights(ipa.challenges[rn:])
		_, yr := projectionPowers(d.y, p.m, p.inner, p.n)
		for j := 0; j < p.n; j++ {
			for k := 0; k < p.inner; k++ {
				id := j*p.inner + k
				if e := put(p.bOff+k*p.n+j, mul(a, xi[id])); e != nil {
					return nil, e
				}
				v := mul(mul(mul(a, d.xHD), xo[j]), mul(yr[j], xk[k]))
				if e := put(p.hOff+2*k, v); e != nil {
					return nil, e
				}
			}
		}
	case accelDot:
		if len(ipa.challenges) != log2(p.inner) {
			return nil, errors.New("dot IPA challenge shape mismatch")
		}
		xii := foldingWeights(inverseChallenges(ipa.challenges))
		if e := put(p.uOff, mul(a, b)); e != nil {
			return nil, e
		}
		for i := range xi {
			if e := put(p.gOff+2*i, mul(a, xi[i])); e != nil {
				return nil, e
			}
			if e := put(p.hOff+2*i, mul(b, xii[i])); e != nil {
				return nil, e
			}
		}
	default:
		return nil, errors.New("unknown accelerator descriptor")
	}
	return c, nil
}

func polyEval(c []fr.Element, z fr.Element) fr.Element {
	var v fr.Element
	for i := len(c) - 1; i >= 0; i-- {
		v.Mul(&v, &z)
		v.Add(&v, &c[i])
	}
	return v
}
func quotientCoefficients(c []fr.Element, z fr.Element) []fr.Element {
	q := make([]fr.Element, len(c))
	if len(c) < 2 {
		return q
	}
	for i := len(c) - 1; i >= 1; i-- {
		q[i-1] = c[i]
		if i < len(c)-1 {
			q[i-1].Add(&q[i-1], new(fr.Element).Mul(&z, &q[i]))
		}
	}
	return q
}
func evalChallenge(t *transcript, p *PublicParams) (fr.Element, error) {
	for i := 0; i < 2; i++ {
		z := t.challenge("ipa/evaluation")
		var zG2 bn254.G2Affine
		zG2.ScalarMultiplication(&p.g2, z.BigInt(new(big.Int)))
		if !zG2.Equal(&p.tauG2) {
			return z, nil
		}
		t.raw("ipa/evaluation-retry", []byte{byte(i)})
	}
	return fr.Element{}, errors.New("evaluation point collided with setup point")
}
func ipaCommitment(P bn254.G1Affine, ipa IPAProof, challenges []fr.Element) (bn254.G1Affine, error) {
	if len(ipa.L) != len(ipa.R) || len(challenges) != len(ipa.L) {
		return bn254.G1Affine{}, errors.New("IPA challenge/round mismatch")
	}
	v := P
	for i, x := range challenges {
		v = sumPoint(sumPoint(v, mulPoint(ipa.L[i], x)), mulPoint(ipa.R[i], inv(x)))
	}
	return v, nil
}
func consumeAccelTranscript(t *transcript, ipa IPAProof, p *PublicParams) error {
	if _, e := evalChallenge(t, p); e != nil {
		return e
	}
	t.point("ipa/Vprime", ipa.VPrime)
	t.point("ipa/W", ipa.W)
	t.challenge("ipa/batch-theta")
	return nil
}
func appendAccelTranscript(t *transcript, ipa *IPAProof) {
	t.point("ipa/Vprime", ipa.VPrime)
	t.point("ipa/W", ipa.W)
	t.challenge("ipa/batch-theta")
}
func attachAccelerator(t *transcript, p *PublicParams, ipa *IPAProof, P bn254.G1Affine, d accelDescriptor) error {
	z, e := evalChallenge(t, p)
	if e != nil {
		return e
	}
	coeff, e := proverCoefficients(p, *ipa, d)
	if e != nil {
		return e
	}
	qcoeff := quotientCoefficients(coeff, z)
	ipa.VPrime, e = msm(p.shifted, coeff)
	if e != nil {
		return e
	}
	ipa.W, e = msm(p.srs, qcoeff)
	if e != nil {
		return e
	}
	appendAccelTranscript(t, ipa)
	return nil
}
func evalX(challenges []fr.Element, z fr.Element, stride int) fr.Element {
	v := fr.One()
	if len(challenges) == 0 {
		return v
	}
	factor := pow(z, stride)
	for j := len(challenges) - 1; j >= 0; j-- {
		term := mul(challenges[j], factor)
		onePlus := add(fr.One(), term)
		v.Mul(&v, &onePlus)
		factor.Square(&factor)
	}
	return v
}

func factorizedPhi(p *PublicParams, d accelDescriptor, ipa IPAProof, challenges []fr.Element, z fr.Element) (fr.Element, error) {
	a, b := ipa.A, ipa.B
	switch d.kind {
	case accelC:
		xterm := mul(mul(a, b), d.x)
		v := mul(xterm, pow(z, p.uOff))
		term2 := mul(mul(a, pow(z, p.cOff)), evalX(challenges, z, 1))
		v.Add(&v, &term2)
		return v, nil
	case accelARcom:
		return mul(mul(a, pow(z, p.gOff)), evalX(challenges, z, 2)), nil
	case accelBRcom:
		return mul(mul(a, pow(z, p.hOff)), evalX(challenges, z, 2)), nil
	case accelAHD:
		rm := log2(p.m)
		xo, xk := challenges[:rm], challenges[rm:]
		first := mul(mul(pow(z, p.aOff), evalX(xo, z, p.inner)), evalX(xk, z, 1))
		yl := evalX(xo, d.y, p.n)
		second := mul(mul(mul(d.xHD, pow(z, p.gOff)), yl), evalX(xk, z, 2))
		return mul(a, add(first, second)), nil
	case accelBHD:
		rn := log2(p.n)
		xo, xk := challenges[:rn], challenges[rn:]
		first := mul(mul(pow(z, p.bOff), evalX(xo, z, 1)), evalX(xk, z, p.n))
		yr := evalX(xo, d.y, 1)
		second := mul(mul(mul(d.xHD, pow(z, p.hOff)), yr), evalX(xk, z, 2))
		return mul(a, add(first, second)), nil
	case accelDot:
		first := mul(mul(a, b), pow(z, p.uOff))
		second := mul(mul(a, pow(z, p.gOff)), evalX(challenges, z, 2))
		third := mul(mul(b, pow(z, p.hOff)), evalX(inverseChallenges(challenges), z, 2))
		return add(add(first, second), third), nil
	default:
		return fr.Element{}, errors.New("unknown accelerator descriptor")
	}
}
func pairingVerify(t *transcript, p *PublicParams, ipa IPAProof, P bn254.G1Affine, d accelDescriptor, challenges []fr.Element) error {
	z, e := evalChallenge(t, p)
	if e != nil {
		return e
	}
	t.point("ipa/Vprime", ipa.VPrime)
	t.point("ipa/W", ipa.W)
	theta := t.challenge("ipa/batch-theta")
	originalV, e := ipaCommitment(P, ipa, challenges)
	if e != nil {
		return e
	}
	ph, e := factorizedPhi(p, d, ipa, challenges, z)
	if e != nil {
		return e
	}
	phiG := mulPoint(p.srs[0], ph)
	var negativeV bn254.G1Affine
	negativeV.Neg(&originalV)
	scaledVprime := mulPoint(ipa.VPrime, theta)
	first := sumPoint(sumPoint(phiG, negativeV), scaledVprime)
	var negativeW bn254.G1Affine
	negativeW.Neg(&ipa.W)
	negativeThetaV := negPoint(originalV, theta)
	var zG2 bn254.G2Affine
	zG2.ScalarMultiplication(&p.g2, z.BigInt(new(big.Int)))
	var q2 bn254.G2Affine
	q2.Sub(&zG2, &p.tauG2)
	ok, e := bn254.PairingCheck([]bn254.G1Affine{first, negativeW, negativeThetaV}, []bn254.G2Affine{p.g2, q2, p.nuG2})
	if e != nil {
		return e
	}
	if !ok {
		return errors.New("accelerated IPA pairing check rejected")
	}
	return nil
}

func negPoint(p bn254.G1Affine, s fr.Element) bn254.G1Affine { return mulPoint(p, neg(s)) }

func CommitOutput(p *PublicParams, c [][]fr.Element) (Statement, fr.Element, error) {
	var s Statement
	if e := checkPP(p); e != nil {
		return s, fr.Element{}, e
	}
	v, e := flatten(c, p.m, p.n)
	if e != nil {
		return s, fr.Element{}, e
	}
	r, e := randScalar()
	if e != nil {
		return s, r, e
	}
	s.Cc, e = commit(v, p.c, p.hide, r)
	return s, r, e
}
func checkWitness(p *PublicParams, w Witness) error {
	if _, e := flatten(w.A, p.m, p.inner); e != nil {
		return e
	}
	if _, e := flatten(w.B, p.inner, p.n); e != nil {
		return e
	}
	if _, e := flatten(w.C, p.m, p.n); e != nil {
		return e
	}
	return nil
}
func weightedA(a [][]fr.Element, y []fr.Element) []fr.Element {
	out := make([]fr.Element, len(a[0]))
	for i := range a {
		for k := range out {
			out[k].Add(&out[k], new(fr.Element).Mul(&a[i][k], &y[i]))
		}
	}
	return out
}
func weightedB(b [][]fr.Element, y []fr.Element) []fr.Element {
	out := make([]fr.Element, len(b))
	for k := range b {
		for j := range b[k] {
			out[k].Add(&out[k], new(fr.Element).Mul(&b[k][j], &y[j]))
		}
	}
	return out
}
func flatWeights(yL, yR []fr.Element) []fr.Element {
	z := make([]fr.Element, len(yL)*len(yR))
	for i := range yL {
		for j := range yR {
			z[i*len(yR)+j].Mul(&yL[i], &yR[j])
		}
	}
	return z
}
func linear(v []fr.Element, kind, inner int, weights []fr.Element) []fr.Element {
	if kind == 0 {
		return []fr.Element{dot(v, weights)}
	}
	k := inner
	out := make([]fr.Element, k)
	if kind == 1 {
		rows := len(weights)
		for i := 0; i < rows; i++ {
			for j := 0; j < k; j++ {
				out[j].Add(&out[j], new(fr.Element).Mul(&v[i*k+j], &weights[i]))
			}
		}
	} else {
		cols := len(weights)
		for i := 0; i < k; i++ {
			for j := 0; j < cols; j++ {
				out[i].Add(&out[i], new(fr.Element).Mul(&v[i*cols+j], &weights[j]))
			}
		}
	}
	return out
}
func linearBases(p *PublicParams, kind int) []bn254.G1Affine {
	if kind == 0 {
		return p.c
	}
	if kind == 1 {
		return p.a
	}
	return p.b
}
func outputBases(p *PublicParams, kind int) []bn254.G1Affine {
	if kind == 0 {
		return []bn254.G1Affine{p.u}
	}
	if kind == 1 {
		return p.g
	}
	return p.h
}
func applyLinear(v []fr.Element, kind, inner int, weights []fr.Element) []fr.Element {
	return linear(v, kind, inner, weights)
}
func zeroBases(n int) []bn254.G1Affine { return make([]bn254.G1Affine, n) }
func Prove(p *PublicParams, s Statement, w Witness) (Proof, error) {
	var proof Proof
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
	weights := flatWeights(yL, yR)
	ay := weightedA(w.A, yL)
	by := weightedB(w.B, yR)
	d := dot(cv, weights)
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
	cay, e := commit(ay, p.g, p.hide, ray)
	if e != nil {
		return proof, e
	}
	cby, e := commit(by, p.h, p.hide, rby)
	if e != nil {
		return proof, e
	}
	cd, e := commit([]fr.Element{d}, []bn254.G1Affine{p.u}, p.hide, rd)
	if e != nil {
		return proof, e
	}
	proof.Cay = cay
	proof.Cby = cby
	proof.Cd = cd
	t.point("projection/Cay", cay)
	t.point("projection/Cby", cby)
	t.point("projection/Cd", cd)
	// Input/output masks are generated independently for all three linear projections.
	vA, _ := flatten(w.A, p.m, p.inner)
	vB, _ := flatten(w.B, p.inner, p.n)
	cA, e := projectionProve(t, p, 0, cv, []fr.Element{d}, weights, y, s.Cc, cd, w.RC, rd)
	if e != nil {
		return proof, e
	}
	proof.Projections[0] = cA
	cB, e := projectionProve(t, p, 1, vA, ay, yL, y, s.Ca, cay, w.RA, ray)
	if e != nil {
		return proof, e
	}
	proof.Projections[1] = cB
	cC, e := projectionProve(t, p, 2, vB, by, yR, y, s.Cb, cby, w.RB, rby)
	if e != nil {
		return proof, e
	}
	proof.Projections[2] = cC
	// Final zero-knowledge dot-product proof (Algorithm 5 on vectors).
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
	pa := mulPoint(sumPoint(sumPoint(proof.Alpha, mulPoint(cay, x)), mulPoint(p.hide, proof.ZA)), x)
	pb := mulPoint(sumPoint(sumPoint(proof.Beta, mulPoint(cby, x)), mulPoint(p.hide, proof.ZB)), x)
	pc := mulPoint(sumPoint(sumPoint(sumPoint(proof.Gamma, mulPoint(proof.Delta, x)), mulPoint(cd, mul(x, x))), mulPoint(p.hide, proof.ZC)), mul(x, x))
	P := sumPoint(sumPoint(pa, pb), pc)
	aPrime := scaleVec(plusVec(alpha, scaleVec(ay, x)), x)
	bPrime := scaleVec(plusVec(beta, scaleVec(by, x)), x)
	proof.Final, e = IPAProve(t, P, p.u, p.g, p.h, aPrime, bPrime)
	if e != nil {
		return proof, e
	}
	if e = attachAccelerator(t, p, &proof.Final, P, accelDescriptor{kind: accelDot}); e != nil {
		return proof, e
	}
	return proof, nil
}
func projectionProve(t *transcript, p *PublicParams, kind int, v, out, weights []fr.Element, matrixY fr.Element, Cin, Cout bn254.G1Affine, rin, rout fr.Element) (ProjectionProof, error) {
	var pr ProjectionProof
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
	om := applyLinear(vm, kind, p.inner, weights)
	if kind == 0 {
		k, e := randScalar()
		if e != nil {
			return pr, e
		}
		pr.KnowledgeR = mulPoint(p.u, k)
		t.point("projection/knowledge-R", pr.KnowledgeR)
		h := t.challenge("projection/knowledge-h")
		pr.KnowledgeZ = add(k, mul(h, om[0]))
		t.scalar("projection/knowledge-z", pr.KnowledgeZ)
		x := t.challenge("projection/ipa-x")
		P := sumPoint(pin, mulPoint(pout, x))
		pr.First, e = IPAProve(t, P, mulPoint(p.u, x), linearBases(p, 0), zeroBases(len(v)), vm, weights)
		if e != nil {
			return pr, e
		}
		if e = attachAccelerator(t, p, &pr.First, P, accelDescriptor{kind: accelC, y: matrixY, x: x}); e != nil {
			return pr, e
		}
		return pr, nil
	}
	zeros := make([]fr.Element, p.inner)
	pr.First, e = IPAProve(t, pout, outputBases(p, kind)[0], outputBases(p, kind), zeroBases(p.inner), om, zeros)
	if e != nil {
		return pr, e
	}
	rcomKind := accelARcom
	if kind == 2 {
		rcomKind = accelBRcom
	}
	if e = attachAccelerator(t, p, &pr.First, pout, accelDescriptor{kind: rcomKind}); e != nil {
		return pr, e
	}
	pr.First.B = fr.Element{}
	x := t.challenge("projection/hd-x")
	var transBases []bn254.G1Affine
	var transV []fr.Element
	var outG bn254.G1Affine
	outer := weights
	if kind == 1 {
		transBases = linearBases(p, 1)
		transV = vm
		outG = p.g[0]
	} else {
		transBases = make([]bn254.G1Affine, len(p.b))
		transV = make([]fr.Element, len(vm))
		idx := 0
		for j := 0; j < p.n; j++ {
			for k := 0; k < p.inner; k++ {
				transBases[idx] = p.b[k*p.n+j]
				transV[idx] = vm[k*p.n+j]
				idx++
			}
		}
		outG = p.h[0]
	}
	// W_jk = input-base_jk + x * weight_j * output-generator_k.
	W := make([]bn254.G1Affine, len(transBases))
	for i := range W {
		outerIndex := i / p.inner
		innerIndex := i % p.inner
		var ug bn254.G1Affine
		if kind == 1 {
			ug = p.g[innerIndex]
		} else {
			ug = p.h[innerIndex]
		}
		W[i] = sumPoint(transBases[i], mulPoint(ug, mul(x, outer[outerIndex])))
	}
	ppout := sumPoint(pin, mulPoint(pout, x))
	pr.Second, e = IPAProve(t, ppout, outG, W, zeroBases(len(W)), transV, make([]fr.Element, len(W)))
	if e != nil {
		return pr, e
	}
	hdKind := accelAHD
	if kind == 2 {
		hdKind = accelBHD
	}
	if e = attachAccelerator(t, p, &pr.Second, ppout, accelDescriptor{kind: hdKind, y: matrixY, xHD: x}); e != nil {
		return pr, e
	}
	pr.Second.B = fr.Element{}
	return pr, nil
}
func VerifyDirect(p *PublicParams, s Statement, proof Proof) error {
	if e := validateProof(p, s, proof); e != nil {
		return e
	}
	if e := checkPP(p); e != nil {
		return e
	}
	points := []bn254.G1Affine{s.Ca, s.Cb, s.Cc, proof.Cay, proof.Cby, proof.Cd, proof.Alpha, proof.Beta, proof.Gamma, proof.Delta}
	for i := range proof.Projections {
		q := proof.Projections[i]
		points = append(points, q.In, q.Out, q.KnowledgeR)
		points = append(points, q.First.VPrime, q.First.W, q.Second.VPrime, q.Second.W)
		points = append(points, q.First.L...)
		points = append(points, q.First.R...)
		points = append(points, q.Second.L...)
		points = append(points, q.Second.R...)
	}
	points = append(points, proof.Final.VPrime, proof.Final.W)
	points = append(points, proof.Final.L...)
	points = append(points, proof.Final.R...)
	for i := range points {
		if !points[i].IsOnCurve() || !points[i].IsInSubGroup() {
			return fmt.Errorf("invalid point at proof position %d", i)
		}
	}
	t := initTranscript(p, s)
	y := t.challenge("matrix/y")
	yL, yR := projectionPowers(y, p.m, p.inner, p.n)
	weights := flatWeights(yL, yR)
	t.point("projection/Cay", proof.Cay)
	t.point("projection/Cby", proof.Cby)
	t.point("projection/Cd", proof.Cd)
	inputs := []bn254.G1Affine{s.Cc, s.Ca, s.Cb}
	outputs := []bn254.G1Affine{proof.Cd, proof.Cay, proof.Cby}
	kinds := []int{0, 1, 2}
	ws := [][]fr.Element{weights, yL, yR}
	for i := 0; i < 3; i++ {
		if e := verifyProjection(t, p, kinds[i], ws[i], inputs[i], outputs[i], proof.Projections[i]); e != nil {
			return fmt.Errorf("projection %d: %w", i, e)
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
	P := sumPoint(sumPoint(pa, pb), pc)
	ok, e := IPAVerify(t, P, p.u, p.g, p.h, proof.Final, nil)
	if e != nil {
		return e
	}
	if !ok {
		return errors.New("final dot-product IPA rejected")
	}
	if e = consumeAccelTranscript(t, proof.Final, p); e != nil {
		return e
	}
	return nil
}
func validateProof(pp *PublicParams, s Statement, proof Proof) error {
	if e := checkPP(pp); e != nil {
		return e
	}
	expected := [][2]int{{log2(pp.m * pp.n), 0}, {log2(pp.inner), log2(pp.m * pp.inner)}, {log2(pp.inner), log2(pp.inner * pp.n)}}
	points := []bn254.G1Affine{s.Ca, s.Cb, s.Cc, proof.Cay, proof.Cby, proof.Cd, proof.Alpha, proof.Beta, proof.Gamma, proof.Delta}
	addIPA := func(ipa IPAProof, rounds int) error {
		if rounds < 0 || rounds > 64 || len(ipa.L) != rounds || len(ipa.R) != rounds {
			return errors.New("invalid IPA proof round count")
		}
		points = append(points, ipa.VPrime, ipa.W)
		points = append(points, ipa.L...)
		points = append(points, ipa.R...)
		return nil
	}
	for i := range proof.Projections {
		q := proof.Projections[i]
		points = append(points, q.In, q.Out, q.KnowledgeR)
		if e := addIPA(q.First, expected[i][0]); e != nil {
			return e
		}
		if i > 0 {
			if e := addIPA(q.Second, expected[i][1]); e != nil {
				return e
			}
		}
	}
	if e := addIPA(proof.Final, log2(pp.inner)); e != nil {
		return e
	}
	for i := range points {
		if !points[i].IsOnCurve() || !points[i].IsInSubGroup() {
			return fmt.Errorf("invalid proof or statement point %d", i)
		}
	}
	return nil
}
func Verify(pp *PublicParams, s Statement, proof Proof) error {
	if e := validateProof(pp, s, proof); e != nil {
		return e
	}
	t := initTranscript(pp, s)
	y := t.challenge("matrix/y")
	t.point("projection/Cay", proof.Cay)
	t.point("projection/Cby", proof.Cby)
	t.point("projection/Cd", proof.Cd)
	if e := verifyProjectionAccelerated(t, pp, 0, weightsDescriptor{y: y}, s.Cc, proof.Cd, proof.Projections[0]); e != nil {
		return fmt.Errorf("projection 0: %w", e)
	}
	if e := verifyProjectionAccelerated(t, pp, 1, weightsDescriptor{y: y}, s.Ca, proof.Cay, proof.Projections[1]); e != nil {
		return fmt.Errorf("projection 1: %w", e)
	}
	if e := verifyProjectionAccelerated(t, pp, 2, weightsDescriptor{y: y}, s.Cb, proof.Cby, proof.Projections[2]); e != nil {
		return fmt.Errorf("projection 2: %w", e)
	}
	t.point("final/alpha", proof.Alpha)
	t.point("final/beta", proof.Beta)
	t.point("final/gamma", proof.Gamma)
	t.point("final/delta", proof.Delta)
	x := t.challenge("final/x")
	t.scalar("final/za", proof.ZA)
	t.scalar("final/zb", proof.ZB)
	t.scalar("final/zc", proof.ZC)
	pa := mulPoint(sumPoint(sumPoint(proof.Alpha, mulPoint(proof.Cay, x)), mulPoint(pp.hide, proof.ZA)), x)
	pb := mulPoint(sumPoint(sumPoint(proof.Beta, mulPoint(proof.Cby, x)), mulPoint(pp.hide, proof.ZB)), x)
	pc := mulPoint(sumPoint(sumPoint(sumPoint(proof.Gamma, mulPoint(proof.Delta, x)), mulPoint(proof.Cd, mul(x, x))), mulPoint(pp.hide, proof.ZC)), mul(x, x))
	P := sumPoint(sumPoint(pa, pb), pc)
	if e := verifyIPAAccelerated(t, pp, P, proof.Final, accelDescriptor{kind: accelDot}, nil); e != nil {
		return fmt.Errorf("final dot IPA: %w", e)
	}
	return nil
}

type weightsDescriptor struct{ y fr.Element }

func verifyProjectionAccelerated(t *transcript, p *PublicParams, kind int, d weightsDescriptor, Cin, Cout bn254.G1Affine, pr ProjectionProof) error {
	t.point("projection/mask-in", pr.In)
	t.point("projection/mask-out", pr.Out)
	tau := t.challenge("projection/mask-t")
	t.scalar("projection/z-in", pr.ZIn)
	t.scalar("projection/z-out", pr.ZOut)
	pin := sumPoint(sumPoint(pr.In, mulPoint(Cin, tau)), mulPoint(p.hide, neg(pr.ZIn)))
	pout := sumPoint(sumPoint(pr.Out, mulPoint(Cout, tau)), mulPoint(p.hide, neg(pr.ZOut)))
	if kind == 0 {
		t.point("projection/knowledge-R", pr.KnowledgeR)
		h := t.challenge("projection/knowledge-h")
		t.scalar("projection/knowledge-z", pr.KnowledgeZ)
		lhs := mulPoint(p.u, pr.KnowledgeZ)
		rhs := sumPoint(pr.KnowledgeR, mulPoint(pout, h))
		if !lhs.Equal(&rhs) {
			return errors.New("scalar projection knowledge check failed")
		}
		x := t.challenge("projection/ipa-x")
		P := sumPoint(pin, mulPoint(pout, x))
		return verifyIPAAccelerated(t, p, P, pr.First, accelDescriptor{kind: accelC, y: d.y, x: x}, &d.y)
	}
	expected := fr.Element{}
	rcom := accelARcom
	if kind == 2 {
		rcom = accelBRcom
	}
	if e := verifyIPAAccelerated(t, p, pout, pr.First, accelDescriptor{kind: rcom}, &expected); e != nil {
		if kind == 2 {
			return fmt.Errorf("B output knowledge: %w", e)
		}
		return fmt.Errorf("A output knowledge: %w", e)
	}
	x := t.challenge("projection/hd-x")
	hd := accelAHD
	if kind == 2 {
		hd = accelBHD
	}
	return verifyIPAAccelerated(t, p, sumPoint(pin, mulPoint(pout, x)), pr.Second, accelDescriptor{kind: hd, y: d.y, xHD: x}, &expected)
}
func verifyIPAAccelerated(t *transcript, p *PublicParams, P bn254.G1Affine, proof IPAProof, d accelDescriptor, publicB *fr.Element) error {
	expectedRounds := 0
	switch d.kind {
	case accelC:
		expectedRounds = log2(p.m * p.n)
	case accelARcom, accelBRcom:
		expectedRounds = log2(p.inner)
	case accelAHD:
		expectedRounds = log2(p.m) + log2(p.inner)
	case accelBHD:
		expectedRounds = log2(p.n) + log2(p.inner)
	case accelDot:
		expectedRounds = log2(p.inner)
	default:
		return errors.New("unknown IPA descriptor")
	}
	if expectedRounds > 64 || len(proof.L) != expectedRounds || len(proof.R) != expectedRounds {
		return errors.New("invalid accelerated IPA shape")
	}
	challenges := make([]fr.Element, expectedRounds)
	for i := 0; i < expectedRounds; i++ {
		t.point("ipa/L", proof.L[i])
		t.point("ipa/R", proof.R[i])
		challenges[i] = t.challenge("ipa/x")
	}
	t.scalar("ipa/a", proof.A)
	t.scalar("ipa/b", proof.B)
	if publicB != nil {
		var want fr.Element
		if d.kind == accelC {
			want = evalX(challenges, d.y, 1)
		}
		if !proof.B.Equal(&want) {
			return errors.New("public IPA folded scalar mismatch")
		}
	}
	return pairingVerify(t, p, proof, P, d, challenges)
}

func verifyProjection(t *transcript, p *PublicParams, kind int, weights []fr.Element, Cin, Cout bn254.G1Affine, pr ProjectionProof) error {
	t.point("projection/mask-in", pr.In)
	t.point("projection/mask-out", pr.Out)
	tau := t.challenge("projection/mask-t")
	t.scalar("projection/z-in", pr.ZIn)
	t.scalar("projection/z-out", pr.ZOut)
	pin := sumPoint(sumPoint(pr.In, mulPoint(Cin, tau)), mulPoint(p.hide, neg(pr.ZIn)))
	pout := sumPoint(sumPoint(pr.Out, mulPoint(Cout, tau)), mulPoint(p.hide, neg(pr.ZOut)))
	if kind == 0 {
		t.point("projection/knowledge-R", pr.KnowledgeR)
		h := t.challenge("projection/knowledge-h")
		t.scalar("projection/knowledge-z", pr.KnowledgeZ)
		lhs := mulPoint(p.u, pr.KnowledgeZ)
		rhs := sumPoint(pr.KnowledgeR, mulPoint(pout, h))
		if !lhs.Equal(&rhs) {
			return errors.New("scalar projection knowledge check failed")
		}
		x := t.challenge("projection/ipa-x")
		P := sumPoint(pin, mulPoint(pout, x))
		ok, e := IPAVerify(t, P, mulPoint(p.u, x), linearBases(p, 0), zeroBases(p.m*p.n), pr.First, weights)
		if e != nil {
			return e
		}
		if !ok {
			return errors.New("scalar projection IPA rejected")
		}
		if e = consumeAccelTranscript(t, pr.First, p); e != nil {
			return e
		}
		return nil
	}
	zero := make([]fr.Element, p.inner)
	ok, e := IPAVerify(t, pout, p.u, outputBases(p, kind), zeroBases(p.inner), pr.First, zero)
	if e != nil {
		return e
	}
	if !ok {
		return errors.New("projection output knowledge IPA rejected")
	}
	if e = consumeAccelTranscript(t, pr.First, p); e != nil {
		return e
	}
	x := t.challenge("projection/hd-x")
	bases := linearBases(p, kind)
	bvec := make([]bn254.G1Affine, len(bases))
	vlen := len(bases)
	var outBases []bn254.G1Affine
	var outerCount int
	if kind == 1 {
		bvec = bases
		outBases = p.g
		outerCount = p.m
	} else {
		idx := 0
		for j := 0; j < p.n; j++ {
			for k := 0; k < p.inner; k++ {
				bvec[idx] = p.b[k*p.n+j]
				idx++
			}
		}
		outBases = p.h
		outerCount = p.n
	}
	W := make([]bn254.G1Affine, vlen)
	for i := range W {
		oi := i / p.inner
		ki := i % p.inner
		W[i] = sumPoint(bvec[i], mulPoint(outBases[ki], mul(x, weights[oi])))
	}
	pp := sumPoint(pin, mulPoint(pout, x))
	ok, e = IPAVerify(t, pp, p.u, W, zeroBases(vlen), pr.Second, make([]fr.Element, vlen))
	if e != nil {
		return e
	}
	if !ok {
		return errors.New("projection input relation IPA rejected")
	}
	if e = consumeAccelTranscript(t, pr.Second, p); e != nil {
		return e
	}
	_ = outerCount
	return nil
}

func writePoint(w io.Writer, p bn254.G1Affine) error { b := p.Bytes(); _, e := w.Write(b[:]); return e }
func writeScalar(w io.Writer, s fr.Element) error    { b := s.Bytes(); _, e := w.Write(b[:]); return e }
func readPoint(r io.Reader) (bn254.G1Affine, error) {
	var p bn254.G1Affine
	var b [bn254.SizeOfG1AffineCompressed]byte
	if _, e := io.ReadFull(r, b[:]); e != nil {
		return p, e
	}
	n, e := p.SetBytes(b[:])
	if e != nil {
		return p, e
	}
	if n != len(b) || !p.IsOnCurve() || !p.IsInSubGroup() {
		return p, errors.New("non-canonical or invalid point")
	}
	return p, nil
}
func readScalar(r io.Reader) (fr.Element, error) {
	var s fr.Element
	var b [32]byte
	if _, e := io.ReadFull(r, b[:]); e != nil {
		return s, e
	}
	if e := s.SetBytesCanonical(b[:]); e != nil {
		return s, e
	}
	return s, nil
}
func writeIPA(w io.Writer, p IPAProof) error {
	if len(p.L) != len(p.R) || len(p.L) > 64 {
		return errors.New("invalid IPA rounds")
	}
	if e := binary.Write(w, binary.BigEndian, uint32(len(p.L))); e != nil {
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
	if e := writeScalar(w, p.B); e != nil {
		return e
	}
	if e := writePoint(w, p.VPrime); e != nil {
		return e
	}
	return writePoint(w, p.W)
}
func readIPA(r io.Reader, expected int) (IPAProof, error) {
	var p IPAProof
	var n uint32
	if e := binary.Read(r, binary.BigEndian, &n); e != nil {
		return p, e
	}
	if n != uint32(expected) {
		return p, fmt.Errorf("wrong IPA round count: got %d, want %d", n, expected)
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
	p.B, e = readScalar(r)
	if e != nil {
		return p, e
	}
	p.VPrime, e = readPoint(r)
	if e != nil {
		return p, e
	}
	p.W, e = readPoint(r)
	return p, e
}
func (p Proof) MarshalBinaryFor(pp *PublicParams) ([]byte, error) {
	if e := checkPP(pp); e != nil {
		return nil, e
	}
	var b bytes.Buffer
	b.WriteString("ZKM1")
	for _, q := range []bn254.G1Affine{p.Cay, p.Cby, p.Cd} {
		if e := writePoint(&b, q); e != nil {
			return nil, e
		}
	}
	for i := range p.Projections {
		q := p.Projections[i]
		for _, v := range []bn254.G1Affine{q.In, q.Out, q.KnowledgeR} {
			if e := writePoint(&b, v); e != nil {
				return nil, e
			}
		}
		for _, v := range []fr.Element{q.ZIn, q.ZOut, q.KnowledgeZ} {
			if e := writeScalar(&b, v); e != nil {
				return nil, e
			}
		}
		rounds := log2(pp.inner)
		if i == 0 {
			rounds = log2(pp.m * pp.n)
		}
		if len(q.First.L) != rounds || len(q.First.R) != rounds {
			return nil, errors.New("invalid first IPA shape")
		}
		if e := writeIPA(&b, q.First); e != nil {
			return nil, e
		}
		if i > 0 {
			secondRounds := log2(pp.m * pp.inner)
			if i == 2 {
				secondRounds = log2(pp.inner * pp.n)
			}
			if len(q.Second.L) != secondRounds || len(q.Second.R) != secondRounds {
				return nil, errors.New("invalid second IPA shape")
			}
			if e := writeIPA(&b, q.Second); e != nil {
				return nil, e
			}
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
	if e := writeIPA(&b, p.Final); e != nil {
		return nil, e
	}
	return b.Bytes(), nil
}
func UnmarshalProof(pp *PublicParams, data []byte) (Proof, error) {
	var p Proof
	if e := checkPP(pp); e != nil {
		return p, e
	}
	r := bytes.NewReader(data)
	magic := make([]byte, 4)
	if _, e := io.ReadFull(r, magic); e != nil {
		return p, e
	}
	if string(magic) != "ZKM1" {
		return p, errors.New("invalid proof encoding")
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
		q.KnowledgeR, e = readPoint(r)
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
		q.KnowledgeZ, e = readScalar(r)
		if e != nil {
			return p, e
		}
		rounds := log2(pp.inner)
		if i == 0 {
			rounds = log2(pp.m * pp.n)
		}
		q.First, e = readIPA(r, rounds)
		if e != nil {
			return p, e
		}
		if i > 0 {
			secondRounds := log2(pp.m * pp.inner)
			if i == 2 {
				secondRounds = log2(pp.inner * pp.n)
			}
			q.Second, e = readIPA(r, secondRounds)
			if e != nil {
				return p, e
			}
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
	p.Final, e = readIPA(r, log2(pp.inner))
	if e != nil {
		return p, e
	}
	if r.Len() != 0 {
		return p, errors.New("trailing bytes in proof")
	}
	return p, nil
}
func MarshalStatement(pp *PublicParams, s Statement) ([]byte, error) {
	if e := checkPP(pp); e != nil {
		return nil, e
	}
	var b bytes.Buffer
	b.WriteString("ZKS1")
	var d [12]byte
	binary.BigEndian.PutUint32(d[:], uint32(pp.m))
	binary.BigEndian.PutUint32(d[4:], uint32(pp.inner))
	binary.BigEndian.PutUint32(d[8:], uint32(pp.n))
	b.Write(d[:])
	for _, p := range []bn254.G1Affine{s.Ca, s.Cb, s.Cc} {
		if e := writePoint(&b, p); e != nil {
			return nil, e
		}
	}
	return b.Bytes(), nil
}
func UnmarshalStatement(pp *PublicParams, data []byte) (Statement, error) {
	var s Statement
	if e := checkPP(pp); e != nil {
		return s, e
	}
	r := bytes.NewReader(data)
	var h [16]byte
	if _, e := io.ReadFull(r, h[:]); e != nil {
		return s, e
	}
	if string(h[:4]) != "ZKS1" || binary.BigEndian.Uint32(h[4:8]) != uint32(pp.m) || binary.BigEndian.Uint32(h[8:12]) != uint32(pp.inner) || binary.BigEndian.Uint32(h[12:16]) != uint32(pp.n) {
		return s, errors.New("statement domain or dimensions mismatch")
	}
	var e error
	s.Ca, e = readPoint(r)
	if e != nil {
		return s, e
	}
	s.Cb, e = readPoint(r)
	if e != nil {
		return s, e
	}
	s.Cc, e = readPoint(r)
	if e != nil {
		return s, e
	}
	if r.Len() != 0 {
		return s, errors.New("trailing bytes in statement")
	}
	return s, nil
}

// MarshalBinary serializes a proof with dimensions taken from its public parameters.
func (p Proof) MarshalBinary(pp *PublicParams) ([]byte, error) { return p.MarshalBinaryFor(pp) }

// UnmarshalBinary replaces the proof only after a complete canonical parse.
func (p *Proof) UnmarshalBinary(pp *PublicParams, data []byte) error {
	parsed, err := UnmarshalProof(pp, data)
	if err != nil {
		return err
	}
	*p = parsed
	return nil
}

// MarshalBinary serializes a statement and binds the dimensions into its frame.
func (s Statement) MarshalBinary(pp *PublicParams) ([]byte, error) { return MarshalStatement(pp, s) }

// UnmarshalBinary parses a statement and rejects dimension mismatches or trailing data.
func (s *Statement) UnmarshalBinary(pp *PublicParams, data []byte) error {
	parsed, err := UnmarshalStatement(pp, data)
	if err != nil {
		return err
	}
	*s = parsed
	return nil
}

// SetupSRSInfo reports the number of public G1 SRS points and their compressed
// encoding size, including both unshifted and nu-shifted powers and G2 anchors.
func (p *PublicParams) SetupSRSInfo() (g1Points, compressedBytes int) {
	if p == nil {
		return 0, 0
	}
	g1Points = 2 * len(p.srs)
	compressedBytes = 2*len(p.srs)*bn254.SizeOfG1AffineCompressed + 3*bn254.SizeOfG2AffineCompressed
	return
}
