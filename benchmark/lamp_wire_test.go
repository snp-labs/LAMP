package benchmark

import (
	"bytes"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend/groth16"
)

func TestLAMPCanonicalPayloadRoundTripAndCanonicalRejection(t *testing.T) {
	_, _, g, _ := bn254.Generators()
	mk := func(n uint64) bn254.G1Affine {
		var x fr.Element
		x.SetUint64(n)
		var p bn254.G1Affine
		p.ScalarMultiplication(&g, x.BigInt(new(big.Int)))
		return p
	}
	p := LAMPCanonicalPayload{Groth16: groth16.NewProof(ecc.BN254), ABCLeaves: []bn254.G1Affine{mk(2), mk(2)}, XYZLeaves: []bn254.G1Affine{mk(3)}, ABCMerkle: []fr.Element{fr.One()}, XYZMerkle: []fr.Element{fr.Element{}}, QALinks: []bn254.G1Affine{mk(4)}}
	blob, err := p.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := UnmarshalLAMPCanonicalPayload(blob)
	if err != nil {
		t.Fatal(err)
	}
	if len(decoded.ABCLeaves) != 2 || !decoded.ABCLeaves[0].Equal(&decoded.ABCLeaves[1]) || len(decoded.XYZLeaves) != 1 || len(decoded.QALinks) != 1 {
		t.Fatal("roundtrip lost ordered duplicate components")
	}
	var a, b bytes.Buffer
	p.Groth16.WriteTo(&a)
	decoded.Groth16.WriteTo(&b)
	if !bytes.Equal(a.Bytes(), b.Bytes()) {
		t.Fatal("Groth16 compressed bytes changed on roundtrip")
	}
	if _, err = UnmarshalLAMPCanonicalPayload(append(blob, 0)); err == nil {
		t.Fatal("accepted trailing bytes")
	}
	_ = ecc.BN254
}
