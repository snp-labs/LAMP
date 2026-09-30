package circuit

import (
	"fmt"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/algopts"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/emulated"
)

// LAMPKZGLinkCircuit is an isolated research variant of the original LAMP
// circuit. Its embedded LAMPCircuit preserves the encoded-column checks.
// Instead of an external Pedersen/CP-link proof, it binds each sampled column
// and sampled XYZ triple to a public KZG digest inside Groth16. The native
// verifier must still check digest Merkle membership and derive challenges.
// This circuit is not used by the default LAMP command.
type LAMPKZGLinkCircuit struct {
	LAMPCircuit
	ABCDigests []sw_bn254.G1Affine `gnark:",public"`
	XYZDigests []sw_bn254.G1Affine `gnark:",public"`
	ABCBases   []bn254.G1Affine    `gnark:"-"`
	XYZBases   []bn254.G1Affine    `gnark:"-"`
}

func (c *LAMPKZGLinkCircuit) Define(api frontend.API) error {
	if err := c.LAMPCircuit.Define(api); err != nil {
		return err
	}
	if len(c.ABCBases) != 3*c.K || len(c.XYZBases) != 3 ||
		len(c.ABCDigests) != len(c.Indices) || len(c.XYZDigests) != len(c.Indices) {
		return fmt.Errorf("KZG link shape mismatch")
	}
	curve, err := sw_emulated.New[sw_bn254.BaseField, sw_bn254.ScalarField](api,
		sw_emulated.GetCurveParams[sw_bn254.BaseField]())
	if err != nil {
		return err
	}
	scalars, err := emulated.NewField[sw_bn254.ScalarField](api)
	if err != nil {
		return err
	}
	abcBases := make([]*sw_bn254.G1Affine, len(c.ABCBases))
	for i, p := range c.ABCBases {
		value := sw_bn254.NewG1Affine(p)
		abcBases[i] = &value
	}
	xyzBases := make([]*sw_bn254.G1Affine, len(c.XYZBases))
	for i, p := range c.XYZBases {
		value := sw_bn254.NewG1Affine(p)
		xyzBases[i] = &value
	}
	for i := range c.Indices {
		// The native Fr value is canonical. Decomposing it to bits lets the
		// non-native BN254 G1 gadget consume the exact same scalar.
		abcScalars := make([]*emulated.Element[sw_bn254.ScalarField], 3*c.K)
		for j, value := range c.ColsEncABC[i] {
			abcScalars[j] = scalars.FromBits(api.ToBinary(value, 254)...)
		}
		abcDigest, err := curve.MultiScalarMul(abcBases, abcScalars, algopts.WithCompleteArithmetic())
		if err != nil {
			return err
		}
		curve.AssertIsOnCurve(&c.ABCDigests[i])
		curve.AssertIsEqual(abcDigest, &c.ABCDigests[i])

		xyzScalars := make([]*emulated.Element[sw_bn254.ScalarField], 3)
		for j, value := range c.QueriedEncValues[i] {
			xyzScalars[j] = scalars.FromBits(api.ToBinary(value, 254)...)
		}
		xyzDigest, err := curve.MultiScalarMul(xyzBases, xyzScalars, algopts.WithCompleteArithmetic())
		if err != nil {
			return err
		}
		curve.AssertIsOnCurve(&c.XYZDigests[i])
		curve.AssertIsEqual(xyzDigest, &c.XYZDigests[i])
	}
	return nil
}
