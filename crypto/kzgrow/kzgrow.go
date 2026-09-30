// Package kzgrow implements a non-ZK, full-field Freivalds proof for three
// matrices committed row by row with KZG. This is a distinct row-KZG/Freivalds
// variant, not the sampled-column protocol used by the current LAMP paper.
package kzgrow

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"runtime"
	"sync"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/fft"
	"github.com/consensys/gnark-crypto/ecc/bn254/kzg"
	"github.com/consensys/gnark-crypto/utils"
)

type Statement struct {
	A, B, C []kzg.Digest
}

type Witness struct {
	values [3][][]fr.Element
	coeffs [3][][]fr.Element
	S      Statement
}

type Proof struct {
	X     []fr.Element
	Batch kzg.BatchOpeningProof // B_0(s), ..., B_{K-1}(s), C_r(s)
}

// DirectProof uses KZG homomorphism to check the whole second folded
// polynomial by commitment equality, without a point opening.
type DirectProof struct {
	X []fr.Element
}

type CommitTimings struct {
	Interpolate time.Duration
	KZGCommit   time.Duration
	Workers     int
}

func powerOfTwo(n int) bool { return n >= 2 && n&(n-1) == 0 }

func validateMatrix(matrix [][]fr.Element, k int) error {
	if len(matrix) != k {
		return fmt.Errorf("expected %d rows, got %d", k, len(matrix))
	}
	for i := range matrix {
		if len(matrix[i]) != k {
			return fmt.Errorf("row %d has length %d, expected %d", i, len(matrix[i]), k)
		}
	}
	return nil
}

func parallelRows(count, workers int, fn func(int)) {
	jobs := make(chan int)
	var wg sync.WaitGroup
	for worker := 0; worker < workers; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				fn(i)
			}
		}()
	}
	for i := 0; i < count; i++ {
		jobs <- i
	}
	close(jobs)
	wg.Wait()
}

// Commit fixes the three K×K matrices. Each row is represented by its unique
// degree-<K polynomial on the K-root evaluation domain. The caller supplies
// a trusted SRS whose trapdoor is unavailable to the prover.
func Commit(a, b, c [][]fr.Element, srs *kzg.SRS, workers int) (*Witness, CommitTimings, error) {
	var timings CommitTimings
	k := len(a)
	if !powerOfTwo(k) || srs == nil || len(srs.Pk.G1) < k || workers < 1 {
		return nil, timings, errors.New("invalid K, SRS, or worker count")
	}
	for _, matrix := range [][][]fr.Element{a, b, c} {
		if err := validateMatrix(matrix, k); err != nil {
			return nil, timings, err
		}
	}
	if workers > runtime.GOMAXPROCS(0) {
		workers = runtime.GOMAXPROCS(0)
	}
	timings.Workers = workers
	w := &Witness{values: [3][][]fr.Element{a, b, c}}
	matrices := [3][][]fr.Element{a, b, c}
	domain := fft.NewDomain(uint64(k))
	start := time.Now()
	for m := range matrices {
		w.coeffs[m] = make([][]fr.Element, k)
		parallelRows(k, workers, func(i int) {
			coeffs := append([]fr.Element(nil), matrices[m][i]...)
			domain.FFTInverse(coeffs, fft.DIF)
			utils.BitReverse(coeffs)
			w.coeffs[m][i] = coeffs
		})
	}
	timings.Interpolate = time.Since(start)
	digests := [3][]kzg.Digest{make([]kzg.Digest, k), make([]kzg.Digest, k), make([]kzg.Digest, k)}
	var commitErr error
	var errMu sync.Mutex
	start = time.Now()
	for m := range digests {
		parallelRows(k, workers, func(i int) {
			digest, err := kzg.Commit(w.coeffs[m][i], srs.Pk, 1)
			if err != nil {
				errMu.Lock()
				if commitErr == nil {
					commitErr = err
				}
				errMu.Unlock()
				return
			}
			digests[m][i] = digest
		})
		if commitErr != nil {
			return nil, timings, commitErr
		}
	}
	timings.KZGCommit = time.Since(start)
	w.S = Statement{A: digests[0], B: digests[1], C: digests[2]}
	return w, timings, nil
}

func (s Statement) K() int { return len(s.A) }

func (s Statement) validate() error {
	k := len(s.A)
	if !powerOfTwo(k) || len(s.B) != k || len(s.C) != k {
		return errors.New("invalid statement digest shape")
	}
	for _, list := range [][]kzg.Digest{s.A, s.B, s.C} {
		for _, digest := range list {
			if !digest.IsInSubGroup() {
				return errors.New("statement digest outside subgroup")
			}
		}
	}
	return nil
}

func (s Statement) challenge(label string, x []fr.Element) fr.Element {
	h := sha256.New()
	_, _ = h.Write([]byte("LAMP-row-KZG-Freivalds-v1"))
	var size [8]byte
	binary.BigEndian.PutUint64(size[:], uint64(s.K()))
	_, _ = h.Write(size[:])
	_, _ = h.Write([]byte(label))
	for _, list := range [][]kzg.Digest{s.A, s.B, s.C} {
		for _, digest := range list {
			point := digest.Bytes()
			_, _ = h.Write(point[:])
		}
	}
	for _, value := range x {
		encoded := value.Bytes()
		_, _ = h.Write(encoded[:])
	}
	var out fr.Element
	out.SetBytes(h.Sum(nil))
	return out
}

func powers(base fr.Element, n int) []fr.Element {
	out := make([]fr.Element, n)
	out[0].SetOne()
	for i := 1; i < n; i++ {
		out[i].Mul(&out[i-1], &base)
	}
	return out
}

func aggregateDigests(digests []kzg.Digest, scalars []fr.Element) (kzg.Digest, error) {
	var out bn254.G1Affine
	_, err := out.MultiExp(digests, scalars, ecc.MultiExpConfig{})
	return out, err
}

func aggregateRows(rows [][]fr.Element, scalars []fr.Element) []fr.Element {
	k := len(rows)
	out := make([]fr.Element, k)
	for row := 0; row < k; row++ {
		for col := 0; col < k; col++ {
			var term fr.Element
			term.Mul(&scalars[row], &rows[row][col])
			out[col].Add(&out[col], &term)
		}
	}
	return out
}

// Prove sends the first Freivalds fold x, then uses one batched KZG opening
// for all B row evaluations and the aggregated C row at a full-field point.
func Prove(w *Witness, srs *kzg.SRS) (Proof, error) {
	var proof Proof
	if w == nil || srs == nil {
		return proof, errors.New("missing witness or SRS")
	}
	if err := w.S.validate(); err != nil {
		return proof, err
	}
	k := w.S.K()
	r := w.S.challenge("row-fold-r", nil)
	rPowers := powers(r, k)
	proof.X = aggregateRows(w.values[0], rPowers)
	s := w.S.challenge("column-evaluation-s", proof.X)
	cR := aggregateRows(w.coeffs[2], rPowers)
	cDigest, err := aggregateDigests(w.S.C, rPowers)
	if err != nil {
		return proof, err
	}
	polys := make([][]fr.Element, k+1)
	digests := make([]kzg.Digest, k+1)
	copy(polys, w.coeffs[1])
	copy(digests, w.S.B)
	polys[k], digests[k] = cR, cDigest
	proof.Batch, err = kzg.BatchOpenSinglePoint(polys, digests, s, sha256.New(), srs.Pk)
	if err != nil {
		return proof, err
	}
	return proof, nil
}

func ProveDirect(w *Witness) (DirectProof, error) {
	if w == nil {
		return DirectProof{}, errors.New("missing witness")
	}
	if err := w.S.validate(); err != nil {
		return DirectProof{}, err
	}
	r := w.S.challenge("row-fold-r", nil)
	return DirectProof{X: aggregateRows(w.values[0], powers(r, w.S.K()))}, nil
}

// VerifyDirect makes two homomorphic commitment-equality checks. Under KZG
// binding, the first forces X=r^T A and the second forces X^T B=r^T C as
// degree-<K row polynomials, hence as K×K matrices on the evaluation domain.
func VerifyDirect(statement Statement, proof DirectProof, srs *kzg.SRS) error {
	if err := statement.validate(); err != nil {
		return err
	}
	k := statement.K()
	if srs == nil || len(srs.Pk.G1) < k || len(proof.X) != k {
		return errors.New("invalid SRS or direct proof shape")
	}
	r := statement.challenge("row-fold-r", nil)
	rPowers := powers(r, k)
	xCoeffs := append([]fr.Element(nil), proof.X...)
	domain := fft.NewDomain(uint64(k))
	domain.FFTInverse(xCoeffs, fft.DIF)
	utils.BitReverse(xCoeffs)
	xCommit, err := kzg.Commit(xCoeffs, srs.Pk)
	if err != nil {
		return err
	}
	aAggregate, err := aggregateDigests(statement.A, rPowers)
	if err != nil {
		return err
	}
	if !xCommit.Equal(&aAggregate) {
		return errors.New("direct first fold is not bound to A")
	}
	bAggregate, err := aggregateDigests(statement.B, proof.X)
	if err != nil {
		return err
	}
	cAggregate, err := aggregateDigests(statement.C, rPowers)
	if err != nil {
		return err
	}
	if !bAggregate.Equal(&cAggregate) {
		return errors.New("direct second fold differs from C")
	}
	return nil
}

// Verify accepts exactly when the matrices fixed by the supplied row digests
// satisfy the randomized full-field matrix-product identity.
func Verify(statement Statement, proof Proof, srs *kzg.SRS) error {
	if err := statement.validate(); err != nil {
		return err
	}
	k := statement.K()
	if srs == nil || len(srs.Pk.G1) < k || len(proof.X) != k || len(proof.Batch.ClaimedValues) != k+1 {
		return errors.New("invalid SRS or proof shape")
	}
	r := statement.challenge("row-fold-r", nil)
	rPowers := powers(r, k)
	xCoeffs := append([]fr.Element(nil), proof.X...)
	domain := fft.NewDomain(uint64(k))
	domain.FFTInverse(xCoeffs, fft.DIF)
	utils.BitReverse(xCoeffs)
	xCommit, err := kzg.Commit(xCoeffs, srs.Pk)
	if err != nil {
		return err
	}
	aAggregate, err := aggregateDigests(statement.A, rPowers)
	if err != nil {
		return err
	}
	if !xCommit.Equal(&aAggregate) {
		return errors.New("first Freivalds fold is not bound to A")
	}
	s := statement.challenge("column-evaluation-s", proof.X)
	cAggregate, err := aggregateDigests(statement.C, rPowers)
	if err != nil {
		return err
	}
	digests := make([]kzg.Digest, k+1)
	copy(digests, statement.B)
	digests[k] = cAggregate
	if err := kzg.BatchVerifySinglePoint(digests, &proof.Batch, s, sha256.New(), srs.Vk); err != nil {
		return fmt.Errorf("batch KZG opening: %w", err)
	}
	var left fr.Element
	for i := 0; i < k; i++ {
		var term fr.Element
		term.Mul(&proof.X[i], &proof.Batch.ClaimedValues[i])
		left.Add(&left, &term)
	}
	if !left.Equal(&proof.Batch.ClaimedValues[k]) {
		return errors.New("second Freivalds fold differs from C")
	}
	return nil
}
