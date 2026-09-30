package kzgrow

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/kzg"
)

const proofMagic = "KRF1"
const directMagic = "KRD1"
const statementMagic = "KRS1"

func (p Proof) MarshalBinary() ([]byte, error) {
	k := len(p.X)
	if !powerOfTwo(k) || len(p.Batch.ClaimedValues) != k+1 {
		return nil, errors.New("invalid proof dimensions")
	}
	data := make([]byte, 8+32*(2*k+2))
	copy(data[:4], proofMagic)
	binary.BigEndian.PutUint32(data[4:8], uint32(k))
	pos := 8
	for _, value := range p.X {
		v := value.Bytes()
		copy(data[pos:pos+32], v[:])
		pos += 32
	}
	for _, value := range p.Batch.ClaimedValues {
		v := value.Bytes()
		copy(data[pos:pos+32], v[:])
		pos += 32
	}
	h := p.Batch.H.Bytes()
	copy(data[pos:pos+32], h[:])
	return data, nil
}

func UnmarshalProof(data []byte) (Proof, error) {
	var proof Proof
	if len(data) < 8 || string(data[:4]) != proofMagic {
		return proof, errors.New("invalid proof header")
	}
	k := int(binary.BigEndian.Uint32(data[4:8]))
	if !powerOfTwo(k) || len(data) != 8+32*(2*k+2) {
		return proof, errors.New("invalid proof length")
	}
	proof.X = make([]fr.Element, k)
	proof.Batch.ClaimedValues = make([]fr.Element, k+1)
	pos := 8
	for i := range proof.X {
		if err := proof.X[i].SetBytesCanonical(data[pos : pos+32]); err != nil {
			return Proof{}, err
		}
		pos += 32
	}
	for i := range proof.Batch.ClaimedValues {
		if err := proof.Batch.ClaimedValues[i].SetBytesCanonical(data[pos : pos+32]); err != nil {
			return Proof{}, err
		}
		pos += 32
	}
	if _, err := proof.Batch.H.SetBytes(data[pos : pos+32]); err != nil || !proof.Batch.H.IsInSubGroup() {
		return Proof{}, errors.New("invalid KZG quotient point")
	}
	return proof, nil
}

func (s Statement) MarshalBinary() ([]byte, error) {
	if err := s.validate(); err != nil {
		return nil, err
	}
	k := s.K()
	data := make([]byte, 8+3*k*32)
	copy(data[:4], statementMagic)
	binary.BigEndian.PutUint32(data[4:8], uint32(k))
	pos := 8
	for _, list := range [][]kzg.Digest{s.A, s.B, s.C} {
		for _, point := range list {
			encoded := point.Bytes()
			copy(data[pos:pos+32], encoded[:])
			pos += 32
		}
	}
	return data, nil
}

func UnmarshalStatement(data []byte) (Statement, error) {
	var statement Statement
	if len(data) < 8 || string(data[:4]) != statementMagic {
		return statement, errors.New("invalid statement header")
	}
	k := int(binary.BigEndian.Uint32(data[4:8]))
	if !powerOfTwo(k) || len(data) != 8+3*k*32 {
		return statement, errors.New("invalid statement length")
	}
	statement.A, statement.B, statement.C = make([]kzg.Digest, k), make([]kzg.Digest, k), make([]kzg.Digest, k)
	pos := 8
	for _, list := range [][]kzg.Digest{statement.A, statement.B, statement.C} {
		for i := range list {
			if _, err := list[i].SetBytes(data[pos : pos+32]); err != nil || !list[i].IsInSubGroup() {
				return Statement{}, errors.New("invalid statement point")
			}
			pos += 32
		}
	}
	return statement, nil
}

func (s Statement) Root() ([32]byte, error) {
	data, err := s.MarshalBinary()
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(data), nil
}

// VerifyWithRoot additionally binds the row digests to a 32-byte external
// statement root. The verifier still consumes all row digests as input.
func VerifyWithRoot(root [32]byte, statement Statement, proof Proof, srs *kzg.SRS) error {
	computed, err := statement.Root()
	if err != nil {
		return err
	}
	if computed != root {
		return errors.New("row commitment root mismatch")
	}
	return Verify(statement, proof, srs)
}

func (p DirectProof) MarshalBinary() ([]byte, error) {
	k := len(p.X)
	if !powerOfTwo(k) {
		return nil, errors.New("invalid direct proof dimensions")
	}
	data := make([]byte, 8+32*k)
	copy(data[:4], directMagic)
	binary.BigEndian.PutUint32(data[4:8], uint32(k))
	for i, value := range p.X {
		encoded := value.Bytes()
		copy(data[8+32*i:8+32*(i+1)], encoded[:])
	}
	return data, nil
}

func UnmarshalDirectProof(data []byte) (DirectProof, error) {
	var proof DirectProof
	if len(data) < 8 || string(data[:4]) != directMagic {
		return proof, errors.New("invalid direct proof header")
	}
	k := int(binary.BigEndian.Uint32(data[4:8]))
	if !powerOfTwo(k) || len(data) != 8+32*k {
		return proof, errors.New("invalid direct proof length")
	}
	proof.X = make([]fr.Element, k)
	for i := range proof.X {
		if err := proof.X[i].SetBytesCanonical(data[8+32*i : 8+32*(i+1)]); err != nil {
			return DirectProof{}, err
		}
	}
	return proof, nil
}

func VerifyDirectWithRoot(root [32]byte, statement Statement, proof DirectProof, srs *kzg.SRS) error {
	computed, err := statement.Root()
	if err != nil {
		return err
	}
	if computed != root {
		return errors.New("row commitment root mismatch")
	}
	return VerifyDirect(statement, proof, srs)
}
