package circuit

import (
	"fmt"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/consensys/gnark/std/lookup/logderivlookup"
)

// SparseFRILAMPCircuit retains LAMP's sampled horizontal RS fold checks.
// Native FRI verification authenticates AOpen/COpen before they become public
// inputs; B columns stay private in Groth16 and are hash-bound to the public
// BColumnHashes. The external verifier must also bind the hashes, challenges,
// and indices to its commitment transcript. This is research-only.
type SparseFRILAMPCircuit struct {
	K, N, Repetitions int
	DomainK, WeightsK []fr.Element
	DomainN, WeightsN []fr.Element

	ChallengeB    frontend.Variable     `gnark:",public"`
	Indices       []frontend.Variable   `gnark:",public"`
	AOpen         [][]frontend.Variable `gnark:",public"` // [T][L]
	COpen         [][]frontend.Variable `gnark:",public"` // [T][L]
	BColumnHashes []frontend.Variable   `gnark:",public"` // [L]
	XYZHashes     []frontend.Variable   `gnark:",public"` // [L]

	BColumns      [][]frontend.Variable // [L][K]
	VecX          [][]frontend.Variable // [T][K]
	VecYZ         [][]frontend.Variable // [T][K]
	EncX          [][]frontend.Variable // [T][N]
	EncYZ         [][]frontend.Variable // [T][N]
	VecBTest      []frontend.Variable   // [K]
	EncBTest      []frontend.Variable   // [N]
	QueriedValues [][]frontend.Variable // [L][2T+1], X_0,YZ_0,...,X_{T-1},YZ_{T-1},BTest
}

func (c *SparseFRILAMPCircuit) Define(api frontend.API) error {
	L := len(c.Indices)
	if c.K < 2 || c.N <= c.K || c.Repetitions < 1 || L < 1 ||
		len(c.AOpen) != c.Repetitions || len(c.COpen) != c.Repetitions ||
		len(c.VecX) != c.Repetitions || len(c.VecYZ) != c.Repetitions ||
		len(c.EncX) != c.Repetitions || len(c.EncYZ) != c.Repetitions ||
		len(c.BColumnHashes) != L || len(c.XYZHashes) != L ||
		len(c.BColumns) != L || len(c.QueriedValues) != L ||
		len(c.VecBTest) != c.K || len(c.EncBTest) != c.N {
		return fmt.Errorf("sparse FRI LAMP circuit shape mismatch")
	}
	committer, ok := api.(frontend.Committer)
	if !ok {
		return fmt.Errorf("Groth16 witness commitment API unavailable")
	}
	h, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}
	xTables := make([]logderivlookup.Table, c.Repetitions)
	yTables := make([]logderivlookup.Table, c.Repetitions)
	rsWitness := make([]frontend.Variable, 0, (2*c.Repetitions+1)*(c.K+c.N))
	for t := 0; t < c.Repetitions; t++ {
		if len(c.AOpen[t]) != L || len(c.COpen[t]) != L ||
			len(c.VecX[t]) != c.K || len(c.VecYZ[t]) != c.K ||
			len(c.EncX[t]) != c.N || len(c.EncYZ[t]) != c.N {
			return fmt.Errorf("sparse FRI LAMP repetition %d shape mismatch", t)
		}
		xTables[t], yTables[t] = logderivlookup.New(api), logderivlookup.New(api)
		for j := 0; j < c.N; j++ {
			xTables[t].Insert(c.EncX[t][j])
			yTables[t].Insert(c.EncYZ[t][j])
		}
		rsWitness = append(rsWitness, c.VecX[t]...)
		rsWitness = append(rsWitness, c.VecYZ[t]...)
		rsWitness = append(rsWitness, c.EncX[t]...)
		rsWitness = append(rsWitness, c.EncYZ[t]...)
	}
	bTable := logderivlookup.New(api)
	for j := 0; j < c.N; j++ {
		bTable.Insert(c.EncBTest[j])
	}
	rsWitness = append(rsWitness, c.VecBTest...)
	rsWitness = append(rsWitness, c.EncBTest...)
	rsPoint, err := committer.Commit(rsWitness...)
	if err != nil {
		return err
	}
	bPowers := Powers(api, c.ChallengeB, c.K)
	for j := 0; j < L; j++ {
		if len(c.BColumns[j]) != c.K || len(c.QueriedValues[j]) != 2*c.Repetitions+1 {
			return fmt.Errorf("sparse FRI LAMP query %d shape mismatch", j)
		}
		index := c.Indices[j]
		for t := 0; t < c.Repetitions; t++ {
			openedX := c.QueriedValues[j][2*t]
			openedYZ := c.QueriedValues[j][2*t+1]
			api.AssertIsEqual(xTables[t].Lookup(index)[0], openedX)
			api.AssertIsEqual(yTables[t].Lookup(index)[0], openedYZ)
			api.AssertIsEqual(openedX, c.AOpen[t][j])
			api.AssertIsEqual(openedYZ, c.COpen[t][j])
			api.AssertIsEqual(openedYZ, Fold(api, c.VecX[t], c.BColumns[j]))
		}
		openedBTest := c.QueriedValues[j][2*c.Repetitions]
		api.AssertIsEqual(bTable.Lookup(index)[0], openedBTest)
		api.AssertIsEqual(openedBTest, Fold(api, bPowers, c.BColumns[j]))
		h.Reset()
		h.Write(c.BColumns[j]...)
		api.AssertIsEqual(h.Sum(), c.BColumnHashes[j])
		h.Reset()
		h.Write(c.QueriedValues[j]...)
		api.AssertIsEqual(h.Sum(), c.XYZHashes[j])
	}
	for t := 0; t < c.Repetitions; t++ {
		VerifyRSEncoding(api, c.K, c.N, c.DomainK, c.WeightsK, c.DomainN, c.WeightsN,
			c.VecX[t], c.EncX[t], rsPoint)
		VerifyRSEncoding(api, c.K, c.N, c.DomainK, c.WeightsK, c.DomainN, c.WeightsN,
			c.VecYZ[t], c.EncYZ[t], rsPoint)
	}
	VerifyRSEncoding(api, c.K, c.N, c.DomainK, c.WeightsK, c.DomainN, c.WeightsN,
		c.VecBTest, c.EncBTest, rsPoint)
	return nil
}
