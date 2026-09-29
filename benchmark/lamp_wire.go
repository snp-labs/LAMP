package benchmark

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend/groth16"
)

// LAMPCanonicalPayload describes the comparison-only minimal proof payload.
// Public roots, derived indices/challenges, keys and public witness are excluded.
type LAMPCanonicalPayload struct {
	Groth16              groth16.Proof
	ABCLeaves, XYZLeaves []bn254.G1Affine
	ABCMerkle, XYZMerkle []fr.Element
	QALinks              []bn254.G1Affine
}

func (p LAMPCanonicalPayload) MarshalBinary() ([]byte, error) {
	var proof bytes.Buffer
	if _, err := p.Groth16.WriteTo(&proof); err != nil {
		return nil, err
	}
	var b bytes.Buffer
	b.WriteString("LCP1")
	if err := writeFrame(&b, proof.Bytes()); err != nil {
		return nil, err
	}
	for _, points := range [][]bn254.G1Affine{p.ABCLeaves, p.XYZLeaves, p.QALinks} {
		if len(points) > 1<<24 {
			return nil, errors.New("too many canonical points")
		}
		_ = binary.Write(&b, binary.BigEndian, uint32(len(points)))
		for _, pt := range points {
			v := pt.Bytes()
			b.Write(v[:])
		}
	}
	for _, values := range [][]fr.Element{p.ABCMerkle, p.XYZMerkle} {
		if len(values) > 1<<24 {
			return nil, errors.New("too many canonical Merkle scalars")
		}
		_ = binary.Write(&b, binary.BigEndian, uint32(len(values)))
		for _, v := range values {
			x := v.Bytes()
			b.Write(x[:])
		}
	}
	return b.Bytes(), nil
}

func UnmarshalLAMPCanonicalPayload(data []byte) (LAMPCanonicalPayload, error) {
	var p LAMPCanonicalPayload
	if len(data) < 8 || len(data) > 1<<30 {
		return p, errors.New("canonical LAMP payload size invalid")
	}
	r := bytes.NewReader(data)
	head := make([]byte, 4)
	if _, err := io.ReadFull(r, head); err != nil {
		return p, err
	}
	if string(head) != "LCP1" {
		return p, errors.New("canonical LAMP payload header mismatch")
	}
	proofBytes, err := readFrame(r)
	if err != nil {
		return p, err
	}
	p.Groth16 = groth16.NewProof(ecc.BN254)
	n, err := p.Groth16.ReadFrom(bytes.NewReader(proofBytes))
	if err != nil || int(n) != len(proofBytes) {
		return p, errors.New("Groth16 payload decoding failed")
	}
	groups := []*[]bn254.G1Affine{&p.ABCLeaves, &p.XYZLeaves, &p.QALinks}
	for _, dst := range groups {
		count, err := readCount(r)
		if err != nil {
			return p, err
		}
		*dst = make([]bn254.G1Affine, count)
		for i := range *dst {
			buf := make([]byte, bn254.SizeOfG1AffineCompressed)
			if _, err = io.ReadFull(r, buf); err != nil {
				return p, err
			}
			if _, err = (*dst)[i].SetBytes(buf); err != nil {
				return p, err
			}
			if !(*dst)[i].IsOnCurve() || !(*dst)[i].IsInSubGroup() {
				return p, errors.New("invalid canonical G1 point")
			}
			canonical := (*dst)[i].Bytes()
			if !bytes.Equal(canonical[:], buf) {
				return p, errors.New("noncanonical G1 encoding")
			}
		}
	}
	groupsF := []*[]fr.Element{&p.ABCMerkle, &p.XYZMerkle}
	for _, dst := range groupsF {
		count, err := readCount(r)
		if err != nil {
			return p, err
		}
		*dst = make([]fr.Element, count)
		for i := range *dst {
			buf := make([]byte, fr.Bytes)
			if _, err = io.ReadFull(r, buf); err != nil {
				return p, err
			}
			if err = (*dst)[i].SetBytesCanonical(buf); err != nil {
				return p, err
			}
		}
	}
	if r.Len() != 0 {
		return p, errors.New("trailing canonical LAMP payload bytes")
	}
	return p, nil
}
func writeFrame(w io.Writer, b []byte) error {
	if len(b) > 1<<30 {
		return errors.New("frame too large")
	}
	if err := binary.Write(w, binary.BigEndian, uint32(len(b))); err != nil {
		return err
	}
	_, err := w.Write(b)
	return err
}
func readFrame(r *bytes.Reader) ([]byte, error) {
	var n uint32
	if err := binary.Read(r, binary.BigEndian, &n); err != nil {
		return nil, err
	}
	if n > 1<<30 || uint64(n) > uint64(r.Len()) {
		return nil, errors.New("invalid frame length")
	}
	b := make([]byte, n)
	_, err := io.ReadFull(r, b)
	return b, err
}
func readCount(r *bytes.Reader) (int, error) {
	var n uint32
	if err := binary.Read(r, binary.BigEndian, &n); err != nil {
		return 0, err
	}
	if n > 1<<24 {
		return 0, errors.New("canonical group count too large")
	}
	need := uint64(n) * bn254.SizeOfG1AffineCompressed
	if need > uint64(r.Len()) && need > 0 {
		return 0, errors.New("truncated canonical group")
	}
	return int(n), nil
}
