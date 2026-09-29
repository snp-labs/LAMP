package main

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

func TestMultiplyRectangularBN254(t *testing.T) {
	// These signed integer products are calculated by hand; negative values are
	// represented by their canonical BN254 field residues.
	a := fieldMatrix([][]int64{{-1, 2, 3}, {4, 5, -6}})
	b := fieldMatrix([][]int64{{7, -8}, {9, 10}, {11, 12}})
	aBefore, bBefore := cloneMatrix(a), cloneMatrix(b)

	got, err := multiply(a, b)
	if err != nil {
		t.Fatal(err)
	}
	want := fieldMatrix([][]int64{{44, 64}, {7, -54}})
	assertMatrixEqual(t, got, want)
	assertMatrixEqual(t, a, aBefore)
	assertMatrixEqual(t, b, bBefore)
}

func TestMultiplySquareBN254(t *testing.T) {
	a := fieldMatrix([][]int64{{1, 2}, {3, 4}})
	b := fieldMatrix([][]int64{{5, 6}, {7, 8}})
	got, err := multiply(a, b)
	if err != nil {
		t.Fatal(err)
	}
	assertMatrixEqual(t, got, fieldMatrix([][]int64{{19, 22}, {43, 50}}))
}

func TestMultiplyFullFieldValue(t *testing.T) {
	minusOne := new(big.Int).Sub(fr.Modulus(), big.NewInt(1))
	var a00, b00, b01 fr.Element
	a00.SetBigInt(minusOne)
	b00.SetInt64(2)
	b01.SetBigInt(minusOne)
	a := [][]fr.Element{{a00}}
	b := [][]fr.Element{{b00, b01}}

	got, err := multiply(a, b)
	if err != nil {
		t.Fatal(err)
	}
	want := fieldMatrix([][]int64{{-2, 1}})
	assertMatrixEqual(t, got, want)
}

func TestMultiplyRejectsInvalidDimensions(t *testing.T) {
	valid := fieldMatrix([][]int64{{1, 2}, {3, 4}})
	validB := fieldMatrix([][]int64{{1}, {2}})
	tests := []struct {
		name string
		a, b [][]fr.Element
	}{
		{name: "empty A", a: nil, b: validB},
		{name: "empty B", a: valid, b: nil},
		{name: "empty A row", a: fieldMatrix([][]int64{{}}), b: fieldMatrix([][]int64{{1}})},
		{name: "empty B row", a: fieldMatrix([][]int64{{1}}), b: fieldMatrix([][]int64{{}})},
		{name: "incompatible inner dimension", a: valid, b: fieldMatrix([][]int64{{1, 2, 3}})},
		{name: "ragged A", a: fieldMatrix([][]int64{{1, 2}, {3}}), b: validB},
		{name: "ragged B", a: fieldMatrix([][]int64{{1, 2}}), b: fieldMatrix([][]int64{{1}, {2, 3}})},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, err := multiply(tt.a, tt.b); err == nil || got != nil {
				t.Fatalf("multiply() = (%v, %v), want (nil, error)", got, err)
			}
		})
	}
}

func fieldMatrix(values [][]int64) [][]fr.Element {
	out := make([][]fr.Element, len(values))
	for i := range values {
		out[i] = make([]fr.Element, len(values[i]))
		for j, value := range values[i] {
			out[i][j].SetInt64(value)
		}
	}
	return out
}

func cloneMatrix(in [][]fr.Element) [][]fr.Element {
	out := make([][]fr.Element, len(in))
	for i := range in {
		out[i] = append([]fr.Element(nil), in[i]...)
	}
	return out
}

func assertMatrixEqual(t *testing.T, got, want [][]fr.Element) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("matrix row count = %d, want %d", len(got), len(want))
	}
	for i := range want {
		if len(got[i]) != len(want[i]) {
			t.Fatalf("row %d length = %d, want %d", i, len(got[i]), len(want[i]))
		}
		for j := range want[i] {
			if !got[i][j].Equal(&want[i][j]) {
				t.Errorf("matrix[%d][%d] = %s, want %s", i, j, got[i][j].String(), want[i][j].String())
			}
		}
	}
}
