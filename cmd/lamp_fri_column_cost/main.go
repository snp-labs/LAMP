// Command lamp_fri_column_cost measures one FRI-committed vertical column.
// It is a component measurement, not a matrix protocol benchmark.
package main

import (
	"encoding/json"
	"flag"
	"log"
	"os"
	"runtime"
	"time"

	"example.com/lamp/crypto"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/fri"
)

func main() {
	logK := flag.Int("logK", 8, "base-2 log of vertical polynomial degree bound")
	flag.Parse()
	if *logK < 2 || *logK > 12 {
		log.Fatal("logK must be in [2,12]")
	}
	k := 1 << *logK
	coefficients := make([]fr.Element, k)
	for i := range coefficients {
		coefficients[i].SetUint64(uint64(i*i + 17*i + 101))
	}
	start := time.Now()
	column, err := crypto.CommitFRIColumn(coefficients)
	if err != nil {
		log.Fatal(err)
	}
	commit := time.Since(start).Seconds()
	position := uint64(k / 3)
	start = time.Now()
	opening, err := column.Open(position)
	if err != nil {
		log.Fatal(err)
	}
	open := time.Since(start).Seconds()
	start = time.Now()
	if err := crypto.VerifyFRIColumn(k, column.Root(), position, column.ProximityProof(), opening); err != nil {
		log.Fatal(err)
	}
	verify := time.Since(start).Seconds()
	pathBytes := 0
	for _, item := range opening.ProofSet {
		pathBytes += len(item)
	}
	proximityBytes := 0
	for _, round := range column.ProximityProof().Rounds {
		proximityBytes += 32
		for _, interaction := range round.Interactions {
			for _, path := range interaction {
				proximityBytes += len(path.MerkleRoot)
				for _, item := range path.ProofSet {
					proximityBytes += len(item)
				}
			}
		}
	}
	if err := json.NewEncoder(os.Stdout).Encode(map[string]any{
		"schema": "lamp_fri_single_column_component_v1", "K": k, "M": fri.GetRho() * k,
		"commit_proximity_seconds": commit, "open_seconds": open, "verify_seconds": verify,
		"opening_payload_estimate_bytes": pathBytes, "proximity_payload_estimate_bytes": proximityBytes,
		"verified": true, "go_version": runtime.Version(), "goos": runtime.GOOS, "goarch": runtime.GOARCH,
	}); err != nil {
		log.Fatal(err)
	}
}
