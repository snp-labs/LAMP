package main

import (
	"strings"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

func TestResearchBackendsRejectIncorrectProduct(t *testing.T) {
	const k = 8
	honest := makeMatrices(k, 19)
	if _, err := runDirect(honest, 2*k, 8); err != nil {
		t.Fatalf("honest direct proof: %v", err)
	}
	if _, err := runKZG(honest, 2*k); err != nil {
		t.Fatalf("honest KZG proof: %v", err)
	}
	bad := makeMatrices(k, 19)
	var one fr.Element
	one.SetOne()
	// A nonzero constant shift to one C row changes every encoded column.
	for j := 0; j < k; j++ {
		bad.c[0][j].Add(&bad.c[0][j], &one)
	}
	if _, err := runDirect(bad, 2*k, 8); err == nil || !strings.Contains(err.Error(), "LAMP fold rejected") {
		t.Fatalf("direct path did not reject incorrect C at fold check: %v", err)
	}
	if _, err := runKZG(bad, 2*k); err == nil || !strings.Contains(err.Error(), "KZG folded value") {
		t.Fatalf("KZG path did not reject incorrect C at folded value check: %v", err)
	}
}
