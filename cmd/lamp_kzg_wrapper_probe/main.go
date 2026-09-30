// Command lamp_kzg_wrapper_probe counts the R1CS constraints needed to verify
// one BN254 KZG opening and one G1 MSM inside BN254 Groth16 circuits. These
// are isolated components, not a complete outer wrapper. The direct variant
// does not use the KZG-opening component.
package main

import (
	"crypto/rand"
	"encoding/json"
	"flag"
	"log"
	"os"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	kzgnative "github.com/consensys/gnark-crypto/ecc/bn254/kzg"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/commitments/kzg"
	"github.com/consensys/gnark/std/math/emulated"
)

type singleKZGCircuit struct {
	kzg.VerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine]
	kzg.Commitment[sw_bn254.G1Affine]
	kzg.OpeningProof[sw_bn254.ScalarField, sw_bn254.G1Affine]
	Point emulated.Element[sw_bn254.ScalarField]
}

type rowMSMCircuit struct {
	Points  []sw_bn254.G1Affine
	Scalars []emulated.Element[sw_bn254.ScalarField]
	Result  sw_bn254.G1Affine
}

func (c *rowMSMCircuit) Define(api frontend.API) error {
	curve, err := sw_emulated.New[sw_bn254.BaseField, sw_bn254.ScalarField](api, sw_emulated.GetCurveParams[sw_bn254.BaseField]())
	if err != nil {
		return err
	}
	points := make([]*sw_bn254.G1Affine, len(c.Points))
	scalars := make([]*emulated.Element[sw_bn254.ScalarField], len(c.Scalars))
	for i := range points {
		points[i], scalars[i] = &c.Points[i], &c.Scalars[i]
	}
	result, err := curve.MultiScalarMul(points, scalars)
	if err != nil {
		return err
	}
	curve.AssertIsEqual(result, &c.Result)
	return nil
}

func (c *singleKZGCircuit) Define(api frontend.API) error {
	verifier, err := kzg.NewVerifier[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](api)
	if err != nil {
		return err
	}
	return verifier.CheckOpeningProof(c.Commitment, c.OpeningProof, c.Point, c.VerifyingKey)
}

func main() {
	prove := flag.Bool("prove", false, "also set up and prove one private KZG-opening check")
	msmK := flag.Int("msm-k", 0, "also count constraints for one BN254 row-commitment MSM of this length")
	flag.Parse()
	start := time.Now()
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &singleKZGCircuit{})
	if err != nil {
		log.Fatal(err)
	}
	result := map[string]any{"schema": "one_bn254_kzg_verifier_in_bn254_groth16_lower_bound_v1",
		"constraints": cs.GetNbConstraints(), "compile_seconds": time.Since(start).Seconds(),
		"scope": "single_kzg_opening_only_not_matrix_protocol"}
	if *msmK > 0 {
		if *msmK > 32 {
			log.Fatal("msm-k pilot is limited to 32")
		}
		msmCircuit := &rowMSMCircuit{Points: make([]sw_bn254.G1Affine, *msmK),
			Scalars: make([]emulated.Element[sw_bn254.ScalarField], *msmK)}
		msmStart := time.Now()
		msmCS, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, msmCircuit)
		if err != nil {
			log.Fatal(err)
		}
		result["msm_k"] = *msmK
		result["msm_constraints"] = msmCS.GetNbConstraints()
		result["msm_compile_seconds"] = time.Since(msmStart).Seconds()
	}
	if *prove {
		alpha, err := rand.Int(rand.Reader, ecc.BN254.ScalarField())
		if err != nil {
			log.Fatal(err)
		}
		srs, err := kzgnative.NewSRS(4, alpha)
		if err != nil {
			log.Fatal(err)
		}
		poly := make([]fr.Element, 4)
		for i := range poly {
			if _, err := poly[i].SetRandom(); err != nil {
				log.Fatal(err)
			}
		}
		commitment, err := kzgnative.Commit(poly, srs.Pk)
		if err != nil {
			log.Fatal(err)
		}
		var point fr.Element
		if _, err := point.SetRandom(); err != nil {
			log.Fatal(err)
		}
		opening, err := kzgnative.Open(poly, point, srs.Pk)
		if err != nil {
			log.Fatal(err)
		}
		wCommitment, err := kzg.ValueOfCommitment[sw_bn254.G1Affine](commitment)
		if err != nil {
			log.Fatal(err)
		}
		wOpening, err := kzg.ValueOfOpeningProof[sw_bn254.ScalarField, sw_bn254.G1Affine](opening)
		if err != nil {
			log.Fatal(err)
		}
		wKey, err := kzg.ValueOfVerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine](srs.Vk)
		if err != nil {
			log.Fatal(err)
		}
		wPoint, err := kzg.ValueOfScalar[sw_bn254.ScalarField](point)
		if err != nil {
			log.Fatal(err)
		}
		assignment := &singleKZGCircuit{VerifyingKey: wKey, Commitment: wCommitment, OpeningProof: wOpening, Point: wPoint}
		start = time.Now()
		pk, vk, err := groth16.Setup(cs)
		if err != nil {
			log.Fatal(err)
		}
		result["groth16_setup_seconds"] = time.Since(start).Seconds()
		witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
		if err != nil {
			log.Fatal(err)
		}
		start = time.Now()
		outerProof, err := groth16.Prove(cs, pk, witness)
		if err != nil {
			log.Fatal(err)
		}
		result["groth16_prove_seconds"] = time.Since(start).Seconds()
		publicWitness, err := witness.Public()
		if err != nil {
			log.Fatal(err)
		}
		start = time.Now()
		if err := groth16.Verify(outerProof, vk, publicWitness); err != nil {
			log.Fatal(err)
		}
		result["groth16_verify_seconds"] = time.Since(start).Seconds()
		result["verified"] = true
	}
	if err := json.NewEncoder(os.Stdout).Encode(result); err != nil {
		log.Fatal(err)
	}
}
