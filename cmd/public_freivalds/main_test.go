package main

import (
	"testing"

	"example.com/lamp/matrix"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

func TestVerifyPublicProduct(t *testing.T) {
	a := matrix.GenerateRandomMatrix(4, 4)
	b := matrix.GenerateRandomMatrix(4, 4)
	c := matrix.MatMul(a, b, 4)
	r := matrix.GenerateRandomVector(4)
	r[0].SetOne()
	if !verifyPublicProduct(a, b, c, r) {
		t.Fatal("honest product rejected")
	}
	var one fr.Element
	one.SetOne()
	c[0][0].Add(&c[0][0], &one)
	if verifyPublicProduct(a, b, c, r) {
		t.Fatal("tampered product accepted")
	}
}
