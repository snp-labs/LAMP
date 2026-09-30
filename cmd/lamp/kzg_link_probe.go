package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"runtime"
	"time"

	"example.com/lamp/circuit"
	"example.com/lamp/crypto"
	"example.com/lamp/matrix"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/fft"
	"github.com/consensys/gnark-crypto/ecc/bn254/kzg"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
)

// runKZGLinkProbe reuses the original LAMP ECC/sampled-column circuit and
// proves links to KZG commitments *inside* Groth16. It deliberately does not
// alter the normal LAMP prover, official commitments, or comparison results.
func runKZGLinkProbe(logK, L int) error {
	K, N := 1<<logK, 2<<logK
	depth := logK + 1
	encoder := crypto.NewEncoder(K, N)
	var alpha fr.Element
	if _, err := alpha.SetRandom(); err != nil {
		return err
	}
	var alphaBig big.Int
	alpha.BigInt(&alphaBig)
	setupSRSStart := time.Now()
	srs, err := kzg.NewSRS(uint64(3*K), &alphaBig)
	if err != nil {
		return err
	}
	srsSeconds := time.Since(setupSRSStart).Seconds()
	alpha.SetZero()
	alphaBig.SetUint64(0)

	// Deterministic dense matrices make the pilot reproducible. The SRS
	// trapdoor remains cryptographically random and is excluded from proving.
	a, b := make([][]fr.Element, K), make([][]fr.Element, K)
	for i := 0; i < K; i++ {
		a[i], b[i] = make([]fr.Element, K), make([]fr.Element, K)
		for j := 0; j < K; j++ {
			a[i][j].SetUint64(uint64(11 + 7*i + 19*j + i*j))
			b[i][j].SetUint64(uint64(23 + 13*i + 5*j + 2*i*j))
		}
	}
	c := matrix.MatMul(a, b, K)
	start := time.Now()
	colsA, err := encoder.EncodeRowsToColumns(a)
	if err != nil {
		return err
	}
	colsB, err := encoder.EncodeRowsToColumns(b)
	if err != nil {
		return err
	}
	colsC, err := encoder.EncodeRowsToColumns(c)
	if err != nil {
		return err
	}
	encodingSeconds := time.Since(start).Seconds()
	start = time.Now()
	abcDigests := make([]bn254.G1Affine, N)
	for j := 0; j < N; j++ {
		abcDigests[j], err = kzg.Commit(combineABCColumn(colsA[j], colsB[j], colsC[j], K), srs.Pk)
		if err != nil {
			return err
		}
	}
	abcTree, rootABC := crypto.BuildMerkleTreeFromGroupElements(abcDigests, depth)
	cmABC := crypto.HashElementsMiMC(rootABC)
	r := crypto.HashElements(cmABC)
	bChallenge := crypto.HashElements(cmABC, uint64Element(challengeBLabel))
	commitABCSeconds := time.Since(start).Seconds()
	rPowers, bPowers := matrix.Powers(r, K), matrix.Powers(bChallenge, K)
	vecX := matrix.VecMatMul(rPowers, a, K)
	vecYZ := matrix.VecMatMul(vecX, b, K)
	vecBTest := matrix.VecMatMul(bPowers, b, K)
	_, encX, err := encoder.Encode(vecX)
	if err != nil {
		return err
	}
	_, encYZ, err := encoder.Encode(vecYZ)
	if err != nil {
		return err
	}
	_, encBTest, err := encoder.Encode(vecBTest)
	if err != nil {
		return err
	}
	start = time.Now()
	xyzDigests := make([]bn254.G1Affine, N)
	for j := 0; j < N; j++ {
		xyzDigests[j], err = kzg.Commit([]fr.Element{encX[j], encYZ[j], encBTest[j]}, srs.Pk)
		if err != nil {
			return err
		}
	}
	xyzTree, rootXYZ := crypto.BuildMerkleTreeFromGroupElements(xyzDigests, depth)
	cmXYZ := crypto.HashElementsMiMC(rootXYZ)
	indices, err := crypto.GenerateIndices(cmXYZ, N, L)
	if err != nil {
		return err
	}
	commitXYZSeconds := time.Since(start).Seconds()

	makeCircuit := func() *circuit.LAMPKZGLinkCircuit {
		domainN := fft.NewDomain(uint64(N))
		rootsN := crypto.GetDomainRoots(domainN, N)
		weightsN := crypto.PrecomputeBarycentricWeights(rootsN)
		domainK := fft.NewDomain(uint64(K))
		rootsK := crypto.GetDomainRoots(domainK, K)
		weightsK := crypto.PrecomputeBarycentricWeights(rootsK)
		shape := circuit.LAMPCircuit{
			K: K, N: N, Depth: depth,
			DomainK: rootsK, WeightsK: weightsK,
			DomainN: rootsN, WeightsN: weightsN,
			ColsEncABC: make([][]frontend.Variable, L),
			Indices:    make([]frontend.Variable, L),
			VecX:       make([]frontend.Variable, K), VecYZ: make([]frontend.Variable, K),
			VecBTest: make([]frontend.Variable, K),
			EncX:     make([]frontend.Variable, N), EncYZ: make([]frontend.Variable, N),
			EncBTest:         make([]frontend.Variable, N),
			QueriedEncValues: make([][]frontend.Variable, L),
		}
		for i := 0; i < L; i++ {
			shape.ColsEncABC[i] = make([]frontend.Variable, 3*K)
			shape.QueriedEncValues[i] = make([]frontend.Variable, 3)
		}
		return &circuit.LAMPKZGLinkCircuit{
			LAMPCircuit: shape,
			ABCDigests:  make([]sw_bn254.G1Affine, L),
			XYZDigests:  make([]sw_bn254.G1Affine, L),
			ABCBases:    append([]bn254.G1Affine(nil), srs.Pk.G1[:3*K]...),
			XYZBases:    append([]bn254.G1Affine(nil), srs.Pk.G1[:3]...),
		}
	}

	empty := makeCircuit()
	start = time.Now()
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, empty)
	if err != nil {
		return fmt.Errorf("compile KZG-linked LAMP circuit: %w", err)
	}
	compileSeconds := time.Since(start).Seconds()
	start = time.Now()
	pk, vk, err := groth16.Setup(cs)
	if err != nil {
		return err
	}
	groth16SetupSeconds := time.Since(start).Seconds()
	assignment := makeCircuit()
	assignment.RootABC, assignment.RootXYZ = rootABC, rootXYZ
	assignment.CmABC, assignment.CmXYZ = cmABC, cmXYZ
	assignment.ChallengeR, assignment.ChallengeB = r, bChallenge
	for j := 0; j < K; j++ {
		assignment.VecX[j], assignment.VecYZ[j], assignment.VecBTest[j] = vecX[j], vecYZ[j], vecBTest[j]
	}
	for j := 0; j < N; j++ {
		assignment.EncX[j], assignment.EncYZ[j], assignment.EncBTest[j] = encX[j], encYZ[j], encBTest[j]
	}
	for i, j := range indices {
		assignment.Indices[i] = j
		column := combineABCColumn(colsA[j], colsB[j], colsC[j], K)
		for h, value := range column {
			assignment.ColsEncABC[i][h] = value
		}
		assignment.QueriedEncValues[i] = []frontend.Variable{encX[j], encYZ[j], encBTest[j]}
		assignment.ABCDigests[i] = sw_bn254.NewG1Affine(abcDigests[j])
		assignment.XYZDigests[i] = sw_bn254.NewG1Affine(xyzDigests[j])
	}
	start = time.Now()
	witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		return err
	}
	proof, err := groth16.Prove(cs, pk, witness)
	if err != nil {
		return fmt.Errorf("prove KZG-linked LAMP circuit: %w", err)
	}
	proveSeconds := time.Since(start).Seconds()
	start = time.Now()
	// Reconstruct every Groth16 public input from the externally checked
	// transcript. Never accept prover-supplied public challenges or digest
	// points without tying them to the Merkle roots below.
	publicAssignment := makeCircuit()
	publicAssignment.RootABC, publicAssignment.RootXYZ = rootABC, rootXYZ
	publicAssignment.CmABC, publicAssignment.CmXYZ = cmABC, cmXYZ
	publicAssignment.ChallengeR, publicAssignment.ChallengeB = r, bChallenge
	for i, j := range indices {
		publicAssignment.Indices[i] = j
		publicAssignment.ABCDigests[i] = sw_bn254.NewG1Affine(abcDigests[j])
		publicAssignment.XYZDigests[i] = sw_bn254.NewG1Affine(xyzDigests[j])
	}
	publicWitness, err := frontend.NewWitness(publicAssignment, ecc.BN254.ScalarField(), frontend.PublicOnly())
	if err != nil {
		return err
	}
	if err := groth16.Verify(proof, vk, publicWitness); err != nil {
		return err
	}
	checkABC, checkXYZ := crypto.HashElementsMiMC(rootABC), crypto.HashElementsMiMC(rootXYZ)
	if !checkABC.Equal(&cmABC) || !checkXYZ.Equal(&cmXYZ) {
		return fmt.Errorf("native commitment hash mismatch")
	}
	checkR := crypto.HashElements(cmABC)
	checkB := crypto.HashElements(cmABC, uint64Element(challengeBLabel))
	if !checkR.Equal(&r) || !checkB.Equal(&bChallenge) {
		return fmt.Errorf("native challenge mismatch")
	}
	expectedIndices, err := crypto.GenerateIndices(cmXYZ, N, L)
	if err != nil {
		return err
	}
	for i, j := range expectedIndices {
		if indices[i] != j {
			return fmt.Errorf("native index mismatch")
		}
	}
	selectedABC, selectedXYZ := make([]fr.Element, L), make([]fr.Element, L)
	for i, j := range indices {
		selectedABC[i] = crypto.HashPoint(abcDigests[j])
		selectedXYZ[i] = crypto.HashPoint(xyzDigests[j])
	}
	proofABC := crypto.GetMerkleMultiProof(abcTree, indices, depth)
	proofXYZ := crypto.GetMerkleMultiProof(xyzTree, indices, depth)
	if !crypto.VerifyMerkleMultiProof(rootABC, selectedABC, indices, proofABC, depth) ||
		!crypto.VerifyMerkleMultiProof(rootXYZ, selectedXYZ, indices, proofXYZ, depth) {
		return fmt.Errorf("native digest Merkle membership failed")
	}
	verifySeconds := time.Since(start).Seconds()
	// A different public digest leaves every original LAMP fold unchanged,
	// but the new KZG link constraints must reject it.
	badAssignment := *assignment
	badAssignment.ABCDigests = append([]sw_bn254.G1Affine(nil), assignment.ABCDigests...)
	badAssignment.ABCDigests[0] = sw_bn254.NewG1Affine(abcDigests[(indices[0]+1)%N])
	badWitness, err := frontend.NewWitness(&badAssignment, ecc.BN254.ScalarField())
	if err != nil {
		return err
	}
	if _, err := groth16.Prove(cs, pk, badWitness); err == nil {
		return fmt.Errorf("tampered KZG digest unexpectedly proved")
	}
	var proofBuffer bytes.Buffer
	if _, err := proof.WriteTo(&proofBuffer); err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{
		"schema":       "lamp_original_ecc_in_groth16_kzg_link_research_v1",
		"branch_scope": "research_only_not_main_lamp",
		"log_k":        logK, "K": K, "N": N, "queries": L,
		"constraints": cs.GetNbConstraints(), "groth16_proof_bytes": proofBuffer.Len(),
		"merkle_proof_bytes":              crypto.MerkleMultiProofSizeBytes(proofABC) + crypto.MerkleMultiProofSizeBytes(proofXYZ),
		"sampled_digest_bytes_compressed": 2 * L * 32,
		"verified":                        true, "tampered_kzg_digest_rejected": true, "indices": indices,
		"go_version": runtime.Version(), "goos": runtime.GOOS, "goarch": runtime.GOARCH,
		"timings_seconds": map[string]float64{
			"srs_setup":                   srsSeconds,
			"matrix_encoding":             encodingSeconds,
			"abc_kzg_commit_and_merkle":   commitABCSeconds,
			"xyz_kzg_commit_and_merkle":   commitXYZSeconds,
			"circuit_compile":             compileSeconds,
			"groth16_setup":               groth16SetupSeconds,
			"groth16_witness_and_prove":   proveSeconds,
			"groth16_and_external_verify": verifySeconds,
		},
	})
}
