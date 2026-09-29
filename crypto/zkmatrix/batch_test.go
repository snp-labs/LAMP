package zkmatrix

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

func TestBatchOptimizedQ1Q2Q3AndMutations(t *testing.T) {
	for _, dims := range [][3]int{{4, 4, 4}, {2, 4, 8}} {
		p, err := Setup(dims[0], dims[1], dims[2])
		if err != nil {
			t.Fatal(err)
		}
		for q := 1; q <= 3; q++ {
			t.Run("q"+string(rune('0'+q)), func(t *testing.T) {
				statements := make(BatchStatement, q)
				witnesses := make(BatchWitness, q)
				for i := 0; i < q; i++ {
					a := matrix(dims[0], dims[1], uint64(11+100*i))
					b := matrix(dims[1], dims[2], uint64(51+100*i))
					c, e := mulMatrix(a, b)
					if e != nil {
						t.Fatal(e)
					}
					statements[i], witnesses[i] = makeStatement(t, p, a, b, c)
				}
				proof, err := ProveBatch(p, statements, witnesses)
				if err != nil {
					t.Fatal(err)
				}
				if err = VerifyBatch(p, statements, proof); err != nil {
					t.Fatalf("accelerated batch rejected: %v", err)
				}
				if err = VerifyBatchDirect(p, statements, proof); err != nil {
					t.Fatalf("direct batch rejected: %v", err)
				}
				blob, err := proof.MarshalBinaryFor(p)
				if err != nil {
					t.Fatal(err)
				}
				decoded, err := UnmarshalBatchProof(p, blob)
				if err != nil {
					t.Fatal(err)
				}
				if err = VerifyBatch(p, statements, decoded); err != nil {
					t.Fatalf("decoded batch rejected: %v", err)
				}
				if err = VerifyBatchDirect(p, statements, decoded); err != nil {
					t.Fatalf("decoded batch rejected by direct verifier: %v", err)
				}
				wantPoints := 2*(log2(dims[0]*dims[2])+log2(dims[0]*dims[1])+log2(dims[1]*dims[2])+q*log2(dims[1])) + 7*q + 8
				wantScalars := 5*q + 9
				wantBytes := 20 + (wantPoints+wantScalars)*32 + 4*(3+q)
				if len(blob) != wantBytes {
					t.Fatalf("batch serialized bytes=%d, want canonical count %d", len(blob), wantBytes)
				}
				if _, err = UnmarshalBatchProof(p, append(append([]byte(nil), blob...), 0)); err == nil {
					t.Fatal("accepted trailing byte")
				}
				bad := proof
				bad.Intermediate = append([]BatchIntermediate(nil), proof.Intermediate...)
				bad.Intermediate[0].Cay = sumPoint(bad.Intermediate[0].Cay, p.hide)
				if VerifyBatch(p, statements, bad) == nil {
					t.Fatal("accepted mutated intermediate commitment")
				}
				bad = proof
				bad.Projections[1].ZOut = add(bad.Projections[1].ZOut, fr.One())
				if VerifyBatch(p, statements, bad) == nil {
					t.Fatal("accepted mutated projection response")
				}
				bad = proof
				bad.Finals = append([]BatchFinalProof(nil), proof.Finals...)
				bad.Finals[0].ZC = add(bad.Finals[0].ZC, fr.One())
				if VerifyBatch(p, statements, bad) == nil {
					t.Fatal("accepted mutated final response")
				}
				bad = proof
				bad.Finals = append([]BatchFinalProof(nil), proof.Finals...)
				bad.Finals[0].IPA.L = append([]bn254.G1Affine(nil), proof.Finals[0].IPA.L...)
				bad.Finals[0].IPA.L[0] = sumPoint(bad.Finals[0].IPA.L[0], p.hide)
				if VerifyBatch(p, statements, bad) == nil {
					t.Fatal("accepted mutated final IPA")
				}
				bad = proof
				bad.VPrime = sumPoint(bad.VPrime, p.hide)
				if VerifyBatch(p, statements, bad) == nil {
					t.Fatal("accepted mutated accelerator commitment")
				}
				if q > 1 {
					reordered := append(BatchStatement(nil), statements...)
					rw := append(BatchWitness(nil), witnesses...)
					reordered[0], reordered[1] = reordered[1], reordered[0]
					rw[0], rw[1] = rw[1], rw[0]
					if VerifyBatch(p, reordered, proof) == nil {
						t.Fatal("accepted reordered statements")
					}
					if VerifyBatch(p, statements[:q-1], proof) == nil {
						t.Fatal("accepted removed claim")
					}
				}
				// A structurally valid batch with any false output claim must fail.
				for badAt := 0; badAt < q; badAt++ {
					bs := append(BatchStatement(nil), statements...)
					bw := append(BatchWitness(nil), witnesses...)
					badW := bw[badAt]
					falseC := matrix(dims[0], dims[2], uint64(991+badAt))
					fs, fw := makeStatement(t, p, badW.A, badW.B, falseC)
					bs[badAt], bw[badAt] = fs, fw
					fp, e := ProveBatch(p, bs, bw)
					if e != nil {
						t.Fatal(e)
					}
					if VerifyBatch(p, bs, fp) == nil {
						t.Fatalf("accepted false C claim at %d", badAt)
					}
				}
				for pos := 0; pos < 3*q; pos++ {
					sm := append(BatchStatement(nil), statements...)
					which := pos % 3
					at := pos / 3
					switch which {
					case 0:
						sm[at].Ca = sumPoint(sm[at].Ca, p.hide)
					case 1:
						sm[at].Cb = sumPoint(sm[at].Cb, p.hide)
					case 2:
						sm[at].Cc = sumPoint(sm[at].Cc, p.hide)
					}
					if VerifyBatch(p, sm, proof) == nil {
						t.Fatalf("accepted mutated statement position %d", pos)
					}
				}
				withExtra := append(append(BatchStatement(nil), statements...), statements[0])
				if VerifyBatch(p, withExtra, proof) == nil {
					t.Fatal("accepted appended claim")
				}
			})
		}
	}
}
