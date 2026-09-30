package crypto

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"math/bits"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/fri"
)

// FRIColumn fixes a degree-<K vertical column on gnark-crypto's rate-1/8
// radix-two FRI domain. It is a research component, not a production PCS.
type FRIColumn struct {
	coefficients []fr.Element
	proximity    fri.ProofOfProximity
	root         []byte
	iopp         fri.Iopp
}

// CommitFRIColumn builds a low-degree proof for the coefficients of a single
// vertical column. The returned root must be bound into the matrix transcript
// before sampling positions are chosen.
func CommitFRIColumn(coefficients []fr.Element) (*FRIColumn, error) {
	if len(coefficients) < 2 || !isPowerOfTwo(len(coefficients)) {
		return nil, fmt.Errorf("FRI column length must be a power of two >= 2")
	}
	iopp := fri.RADIX_2_FRI.New(uint64(len(coefficients)), sha256.New())
	proof, err := iopp.BuildProofOfProximity(coefficients)
	if err != nil {
		return nil, err
	}
	root, err := friInitialRoot(proof)
	if err != nil {
		return nil, err
	}
	return &FRIColumn{
		// The caller retains the original column through all openings. Avoid
		// duplicating K field elements for every matrix column.
		coefficients: coefficients,
		proximity:    proof,
		root:         append([]byte(nil), root...),
		iopp:         iopp,
	}, nil
}

func friInitialRoot(proof fri.ProofOfProximity) ([]byte, error) {
	if len(proof.Rounds) == 0 || len(proof.Rounds[0].Interactions) == 0 {
		return nil, fmt.Errorf("FRI proof has no initial root")
	}
	root := proof.Rounds[0].Interactions[0][0].MerkleRoot
	if len(root) != 32 {
		return nil, fmt.Errorf("FRI root must be 32 bytes, got %d", len(root))
	}
	return root, nil
}

func (c *FRIColumn) Root() [32]byte {
	var root [32]byte
	copy(root[:], c.root)
	return root
}

func (c *FRIColumn) Open(position uint64) (fri.OpeningProof, error) {
	return c.iopp.Open(c.coefficients, position)
}

// VerifyFRIColumn checks both the proximity proof and an opening against a
// root already fixed by the encompassing matrix commitment.
func VerifyFRIColumn(k int, expectedRoot [32]byte, position uint64, proof fri.ProofOfProximity, opening fri.OpeningProof) error {
	if k < 2 || !isPowerOfTwo(k) {
		return fmt.Errorf("invalid FRI column length")
	}
	if position >= uint64(fri.GetRho()*k) {
		return fmt.Errorf("FRI opening position out of range")
	}
	if len(proof.Rounds) != 1 || len(proof.Rounds[0].Interactions) != bits.Len(uint(k))-1 {
		return fmt.Errorf("malformed FRI round structure")
	}
	for _, interaction := range proof.Rounds[0].Interactions {
		for _, path := range interaction {
			if len(path.MerkleRoot) != 32 || len(path.ProofSet) == 0 || len(path.ProofSet[0]) != 32 {
				return fmt.Errorf("malformed FRI Merkle interaction")
			}
		}
	}
	root, err := friInitialRoot(proof)
	if err != nil {
		return err
	}
	if !bytes.Equal(root, expectedRoot[:]) {
		return fmt.Errorf("FRI root does not match matrix transcript")
	}
	// gnark-crypto's VerifyOpening authenticates ProofSet[0], while the
	// separately exported ClaimedValue is used by the caller's algebraic
	// relation. Bind the two explicitly before consuming the claim.
	if len(opening.ProofSet) == 0 || len(opening.ProofSet[0]) != 32 {
		return fmt.Errorf("FRI opening has no leaf")
	}
	claimed := opening.ClaimedValue.Bytes()
	if !bytes.Equal(claimed[:], opening.ProofSet[0]) {
		return fmt.Errorf("FRI claimed value differs from authenticated leaf")
	}
	iopp := fri.RADIX_2_FRI.New(uint64(k), sha256.New())
	if err := iopp.VerifyProofOfProximity(proof); err != nil {
		return fmt.Errorf("FRI low-degree proof: %w", err)
	}
	if err := iopp.VerifyOpening(position, opening, proof); err != nil {
		return fmt.Errorf("FRI column opening: %w", err)
	}
	return nil
}

func (c *FRIColumn) ProximityProof() fri.ProofOfProximity { return c.proximity }
