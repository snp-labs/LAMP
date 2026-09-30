package kzgrow

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/kzg"
)

func testSRS(t *testing.T, k int) *kzg.SRS {
	t.Helper()
	var alpha fr.Element
	if _, err := alpha.SetRandom(); err != nil {
		t.Fatal(err)
	}
	var alphaBig big.Int
	alpha.BigInt(&alphaBig)
	srs, err := kzg.NewSRS(uint64(k), &alphaBig)
	if err != nil {
		t.Fatal(err)
	}
	return srs
}

func testMatrices(k int) ([][]fr.Element, [][]fr.Element, [][]fr.Element) {
	a := make([][]fr.Element, k)
	b := make([][]fr.Element, k)
	c := make([][]fr.Element, k)
	u, v := make([]fr.Element, k), make([]fr.Element, k)
	for i := 0; i < k; i++ {
		u[i].SetUint64(uint64(i + 2))
		v[i].SetUint64(uint64(2*i + 3))
	}
	for i := 0; i < k; i++ {
		a[i], b[i], c[i] = make([]fr.Element, k), make([]fr.Element, k), make([]fr.Element, k)
		for j := 0; j < k; j++ {
			a[i][j].Mul(&u[i], &v[j])
			if i == j {
				var one fr.Element
				one.SetOne()
				a[i][j].Add(&a[i][j], &one)
			}
			b[i][j].SetUint64(uint64(7 + 3*i + 5*j + i*j))
		}
	}
	w := make([]fr.Element, k)
	for j := 0; j < k; j++ {
		for i := 0; i < k; i++ {
			var term fr.Element
			term.Mul(&v[i], &b[i][j])
			w[j].Add(&w[j], &term)
		}
	}
	for i := 0; i < k; i++ {
		for j := 0; j < k; j++ {
			var term fr.Element
			term.Mul(&u[i], &w[j])
			c[i][j].Add(&b[i][j], &term)
		}
	}
	return a, b, c
}

func TestKZGRowFreivaldsHonestAndTampered(t *testing.T) {
	for _, k := range []int{4, 8} {
		srs := testSRS(t, k)
		a, b, c := testMatrices(k)
		w, _, err := Commit(a, b, c, srs, 2)
		if err != nil {
			t.Fatal(err)
		}
		proof, err := Prove(w, srs)
		if err != nil {
			t.Fatal(err)
		}
		if err := Verify(w.S, proof, srs); err != nil {
			t.Fatalf("honest K=%d rejected: %v", k, err)
		}
		root, err := w.S.Root()
		if err != nil {
			t.Fatal(err)
		}
		if err := VerifyWithRoot(root, w.S, proof, srs); err != nil {
			t.Fatal(err)
		}
		direct, err := ProveDirect(w)
		if err != nil {
			t.Fatal(err)
		}
		if err := VerifyDirectWithRoot(root, w.S, direct, srs); err != nil {
			t.Fatalf("honest direct K=%d rejected: %v", k, err)
		}
		directWire, err := direct.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		decodedDirect, err := UnmarshalDirectProof(directWire)
		if err != nil {
			t.Fatal(err)
		}
		if err := VerifyDirectWithRoot(root, w.S, decodedDirect, srs); err != nil {
			t.Fatal(err)
		}
		badRoot := root
		badRoot[0] ^= 1
		if VerifyWithRoot(badRoot, w.S, proof, srs) == nil {
			t.Fatal("modified root accepted")
		}
		if VerifyDirectWithRoot(badRoot, w.S, direct, srs) == nil {
			t.Fatal("modified root accepted by direct verifier")
		}
		proofBytes, err := proof.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		decodedProof, err := UnmarshalProof(proofBytes)
		if err != nil {
			t.Fatal(err)
		}
		statementBytes, err := w.S.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		decodedStatement, err := UnmarshalStatement(statementBytes)
		if err != nil {
			t.Fatal(err)
		}
		if err := Verify(decodedStatement, decodedProof, srs); err != nil {
			t.Fatalf("decoded K=%d rejected: %v", k, err)
		}
		proofBytes[len(proofBytes)-1] ^= 1
		if tampered, err := UnmarshalProof(proofBytes); err == nil && Verify(w.S, tampered, srs) == nil {
			t.Fatal("tampered serialized proof accepted")
		}
		badX := proof
		badX.X = append([]fr.Element(nil), proof.X...)
		var one fr.Element
		one.SetOne()
		badX.X[0].Add(&badX.X[0], &one)
		if Verify(w.S, badX, srs) == nil {
			t.Fatal("modified first fold accepted")
		}
		badDirect := direct
		badDirect.X = append([]fr.Element(nil), direct.X...)
		badDirect.X[0].Add(&badDirect.X[0], &one)
		if VerifyDirect(w.S, badDirect, srs) == nil {
			t.Fatal("modified first fold accepted by direct verifier")
		}
		badClaim := proof
		badClaim.Batch.ClaimedValues = append([]fr.Element(nil), proof.Batch.ClaimedValues...)
		badClaim.Batch.ClaimedValues[0].Add(&badClaim.Batch.ClaimedValues[0], &one)
		if Verify(w.S, badClaim, srs) == nil {
			t.Fatal("modified B evaluation accepted")
		}
		badStatement := w.S
		badStatement.C = append([]kzg.Digest(nil), w.S.C...)
		badStatement.C[0] = w.S.B[0]
		if Verify(badStatement, proof, srs) == nil {
			t.Fatal("modified C commitment accepted")
		}
		c[0][0].Add(&c[0][0], &one)
		wrong, _, err := Commit(a, b, c, srs, 2)
		if err != nil {
			t.Fatal(err)
		}
		wrongProof, err := Prove(wrong, srs)
		if err != nil {
			t.Fatal(err)
		}
		if Verify(wrong.S, wrongProof, srs) == nil {
			t.Fatal("incorrect matrix product accepted")
		}
		wrongDirect, err := ProveDirect(wrong)
		if err != nil {
			t.Fatal(err)
		}
		if VerifyDirect(wrong.S, wrongDirect, srs) == nil {
			t.Fatal("incorrect matrix product accepted by direct verifier")
		}
	}
}

func TestKZGRowRejectsMalformedInput(t *testing.T) {
	srs := testSRS(t, 4)
	a, b, c := testMatrices(4)
	a[0] = a[0][:3]
	if _, _, err := Commit(a, b, c, srs, 2); err == nil {
		t.Fatal("non-square matrix accepted")
	}
}

func TestKZGRowDenseGeneralProduct(t *testing.T) {
	const k = 8
	a, b, c := make([][]fr.Element, k), make([][]fr.Element, k), make([][]fr.Element, k)
	for i := 0; i < k; i++ {
		a[i], b[i], c[i] = make([]fr.Element, k), make([]fr.Element, k), make([]fr.Element, k)
		for j := 0; j < k; j++ {
			a[i][j].SetUint64(uint64(1 + 19*i + 7*j + i*j))
			b[i][j].SetUint64(uint64(3 + 5*i + 23*j + 2*i*j))
		}
	}
	for i := 0; i < k; i++ {
		for j := 0; j < k; j++ {
			for h := 0; h < k; h++ {
				var term fr.Element
				term.Mul(&a[i][h], &b[h][j])
				c[i][j].Add(&c[i][j], &term)
			}
		}
	}
	srs := testSRS(t, k)
	w, _, err := Commit(a, b, c, srs, 2)
	if err != nil {
		t.Fatal(err)
	}
	pointProof, err := Prove(w, srs)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(w.S, pointProof, srs); err != nil {
		t.Fatal(err)
	}
	directProof, err := ProveDirect(w)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyDirect(w.S, directProof, srs); err != nil {
		t.Fatal(err)
	}
}
