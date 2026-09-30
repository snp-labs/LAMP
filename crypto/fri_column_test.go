package crypto

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/fri"
)

func TestFRIColumnOpeningAndWrongRoot(t *testing.T) {
	const k = 8
	coefficients := make([]fr.Element, k)
	for i := range coefficients {
		coefficients[i].SetUint64(uint64(5 + 3*i + i*i))
	}
	column, err := CommitFRIColumn(coefficients)
	if err != nil {
		t.Fatal(err)
	}
	encoder, err := NewColumnCoefficientEncoder(k, fri.GetRho()*k)
	if err != nil {
		t.Fatal(err)
	}
	roots := encoder.Roots()
	for _, position := range []uint64{0, 1, 7, 23, 63} {
		opening, err := column.Open(position)
		if err != nil {
			t.Fatal(err)
		}
		if err := VerifyFRIColumn(k, column.Root(), position, column.ProximityProof(), opening); err != nil {
			t.Fatalf("position %d: %v", position, err)
		}
		expected := FoldPowers(coefficients, roots[position])
		if !opening.ClaimedValue.Equal(&expected) {
			t.Fatalf("FRI opening at position %d disagrees with coefficient evaluation", position)
		}
		badRoot := column.Root()
		badRoot[0] ^= 1
		if VerifyFRIColumn(k, badRoot, position, column.ProximityProof(), opening) == nil {
			t.Fatal("mismatched transcript root accepted")
		}
		badOpening := opening
		badOpening.ClaimedValue.SetUint64(12345)
		if VerifyFRIColumn(k, column.Root(), position, column.ProximityProof(), badOpening) == nil {
			t.Fatal("claimed value detached from FRI leaf accepted")
		}
		if VerifyFRIColumn(k, column.Root(), uint64(fri.GetRho()*k), column.ProximityProof(), opening) == nil {
			t.Fatal("out-of-range position accepted")
		}
	}
	if VerifyFRIColumn(k, column.Root(), 0, fri.ProofOfProximity{}, fri.OpeningProof{}) == nil {
		t.Fatal("malformed proximity proof accepted")
	}
}
