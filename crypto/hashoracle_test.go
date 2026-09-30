package crypto

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

func TestHashABCOpeningBindsValuesIndicesAndProof(t *testing.T) {
	makeCols := func(offset uint64) [][]fr.Element {
		cols := make([][]fr.Element, 8)
		for i := range cols {
			cols[i] = make([]fr.Element, 4)
			for j := range cols[i] {
				cols[i][j].SetUint64(offset + uint64(i*4+j))
			}
		}
		return cols
	}
	a, b, c := makeCols(1), makeCols(50), makeCols(100)
	oracle, err := BuildHashABCOracle(a, b, c)
	if err != nil {
		t.Fatal(err)
	}
	opening, err := oracle.Open([]int{3, 1, 3, 6})
	if err != nil {
		t.Fatal(err)
	}
	x, y, z := make([][]fr.Element, 3), make([][]fr.Element, 3), make([][]fr.Element, 3)
	for i, idx := range opening.Indices {
		x[i], y[i], z[i] = append([]fr.Element(nil), a[idx]...), append([]fr.Element(nil), b[idx]...), append([]fr.Element(nil), c[idx]...)
	}
	verify := func(op HashABCOpening) bool {
		return VerifyHashABCOpening(oracle.Root(), 8, op, x, y, z)
	}
	if !verify(opening) {
		t.Fatal("honest multiproof rejected")
	}
	x[1][0].SetUint64(123456)
	if verify(opening) {
		t.Fatal("changed matrix entry accepted")
	}
	x[1][0] = a[opening.Indices[1]][0]
	changed := opening
	changed.Indices = append([]int(nil), opening.Indices...)
	changed.Indices[1] = 4
	if verify(changed) {
		t.Fatal("changed index accepted")
	}
	changed = opening
	changed.Salts = append([][32]byte(nil), opening.Salts...)
	changed.Salts[0][0] ^= 1
	if verify(changed) {
		t.Fatal("changed salt accepted")
	}
	changed = opening
	changed.Siblings = append([][32]byte(nil), opening.Siblings...)
	changed.Siblings[0][0] ^= 1
	if verify(changed) {
		t.Fatal("changed Merkle sibling accepted")
	}
}

func TestHashABCOpeningAllSmallQuerySets(t *testing.T) {
	cols := make([][]fr.Element, 8)
	for i := range cols {
		cols[i] = make([]fr.Element, 2)
		cols[i][0].SetUint64(uint64(i + 1))
		cols[i][1].SetUint64(uint64(10 + i))
	}
	oracle, err := BuildHashABCOracle(cols, cols, cols)
	if err != nil {
		t.Fatal(err)
	}
	for mask := 1; mask < 1<<8; mask++ {
		indices := make([]int, 0, 8)
		for i := 0; i < 8; i++ {
			if mask&(1<<i) != 0 {
				indices = append(indices, i)
			}
		}
		opening, err := oracle.Open(indices)
		if err != nil {
			t.Fatal(err)
		}
		values := make([][]fr.Element, len(indices))
		for i, idx := range indices {
			values[i] = cols[idx]
		}
		if !VerifyHashABCOpening(oracle.Root(), 8, opening, values, values, values) {
			t.Fatalf("valid query set %08b rejected", mask)
		}
	}
}
