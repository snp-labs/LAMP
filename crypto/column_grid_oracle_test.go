package crypto

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

func TestColumnGridOpeningBindsCellsCoordinatesAndRoot(t *testing.T) {
	const k, m, n = 4, 8, 8
	var matrices [3][][]fr.Element
	for matrix := range matrices {
		matrices[matrix] = make([][]fr.Element, n)
		for col := 0; col < n; col++ {
			matrices[matrix][col] = make([]fr.Element, k)
			for row := 0; row < k; row++ {
				matrices[matrix][col][row].SetUint64(uint64(1 + 100*matrix + 10*col + row))
			}
		}
	}
	oracle, _, err := BuildColumnGridOracle(matrices[0], matrices[1], matrices[2], k, m)
	if err != nil {
		t.Fatal(err)
	}
	serial, _, err := BuildColumnGridOracle(matrices[0], matrices[1], matrices[2], k, m, 1)
	if err != nil {
		t.Fatal(err)
	}
	if oracle.Root() != serial.Root() {
		t.Fatal("parallel and serial commitments differ")
	}
	opening, err := oracle.Open(3, 2, 5)
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyColumnGridOpening(oracle.Root(), n, m, opening) {
		t.Fatal("honest opening rejected")
	}
	roots := oracle.encoder.Roots()
	for matrix := range matrices {
		wantR := FoldPowers(matrices[matrix][3], roots[2])
		wantB := FoldPowers(matrices[matrix][3], roots[5])
		if !opening.AtR[matrix].Equal(&wantR) || !opening.AtB[matrix].Equal(&wantB) {
			t.Fatalf("fold mismatch for matrix %d", matrix)
		}
	}
	changed := opening
	changed.AtR[0].SetUint64(999)
	if VerifyColumnGridOpening(oracle.Root(), n, m, changed) {
		t.Fatal("modified A cell accepted")
	}
	changed = opening
	changed.ColumnIndex++
	if VerifyColumnGridOpening(oracle.Root(), n, m, changed) {
		t.Fatal("modified column coordinate accepted")
	}
	changed = opening
	changed.RowB++
	if VerifyColumnGridOpening(oracle.Root(), n, m, changed) {
		t.Fatal("modified row coordinate accepted")
	}
	changed = opening
	changed.ColumnPath = append([][32]byte(nil), opening.ColumnPath...)
	changed.ColumnPath[0][0] ^= 1
	if VerifyColumnGridOpening(oracle.Root(), n, m, changed) {
		t.Fatal("modified column path accepted")
	}
	changedRoot := oracle.Root()
	changedRoot[0] ^= 1
	if VerifyColumnGridOpening(changedRoot, n, m, opening) {
		t.Fatal("modified root accepted")
	}
	matrices[0][3][0].SetUint64(777)
	rebuilt, err := oracle.Open(3, 2, 5)
	if err != nil {
		t.Fatal(err)
	}
	if VerifyColumnGridOpening(oracle.Root(), n, m, rebuilt) {
		t.Fatal("source mutation after commitment accepted")
	}
}

func TestColumnGridRejectsBadShapesAndIndices(t *testing.T) {
	a := make([][]fr.Element, 8)
	for i := range a {
		a[i] = make([]fr.Element, 4)
	}
	if _, _, err := BuildColumnGridOracle(a, a[:7], a, 4, 8); err == nil {
		t.Fatal("unequal column counts accepted")
	}
	if _, _, err := BuildColumnGridOracle(a, a, a, 4, 4); err == nil {
		t.Fatal("invalid vertical rate accepted")
	}
	oracle, _, err := BuildColumnGridOracle(a, a, a, 4, 8)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := oracle.Open(8, 0, 0); err == nil {
		t.Fatal("out-of-range column accepted")
	}
	if _, err := oracle.Open(0, -1, 0); err == nil {
		t.Fatal("out-of-range row accepted")
	}
}
