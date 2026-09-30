package crypto

// This package only measures a hash oracle commitment. Its openings disclose
// entire encoded columns, so it is not a zero-knowledge LAMP backend.

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"sort"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

type HashABCOracle struct {
	levels [][][32]byte
	salts  [][32]byte
	k      int
	n      int
}

type HashABCOpening struct {
	Indices  []int
	Salts    [][32]byte
	Siblings [][32]byte
}

// HashABCLeaf binds one encoded A/B/C column to its index, vector length, and
// independent 256-bit salt. A verifier must receive the column values to use
// this hash; the salt alone does not prove a private relation.
func HashABCLeaf(index int, salt [32]byte, a, b, c []fr.Element) ([32]byte, error) {
	if index < 0 || len(a) == 0 || len(a) != len(b) || len(a) != len(c) {
		return [32]byte{}, errors.New("invalid ABC leaf shape")
	}
	h := sha256.New()
	_, _ = h.Write([]byte("LAMP-hash-ABC-leaf-v1"))
	var header [16]byte
	binary.BigEndian.PutUint64(header[:8], uint64(index))
	binary.BigEndian.PutUint64(header[8:], uint64(len(a)))
	_, _ = h.Write(header[:])
	_, _ = h.Write(salt[:])
	for _, cols := range [][]fr.Element{a, b, c} {
		for _, v := range cols {
			raw := v.Bytes()
			_, _ = h.Write(raw[:])
		}
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out, nil
}

func hashABCNode(left, right [32]byte) [32]byte {
	var input [81]byte
	copy(input[:17], "LAMP-hash-node-v1")
	copy(input[17:49], left[:])
	copy(input[49:], right[:])
	return sha256.Sum256(input[:])
}

// BuildHashABCOracle constructs an array-backed Merkle tree over the same
// encoded columns consumed by BatchPedersenCommitABCBlinded.
func BuildHashABCOracle(a, b, c [][]fr.Element) (*HashABCOracle, error) {
	n := len(a)
	if n == 0 || n != len(b) || n != len(c) || n&(n-1) != 0 {
		return nil, errors.New("ABC columns must have equal power-of-two length")
	}
	k := len(a[0])
	if k == 0 {
		return nil, errors.New("empty ABC columns")
	}
	oracle := &HashABCOracle{k: k, n: n, salts: make([][32]byte, n)}
	oracle.levels = append(oracle.levels, make([][32]byte, n))
	for i := 0; i < n; i++ {
		if len(a[i]) != k || len(b[i]) != k || len(c[i]) != k {
			return nil, errors.New("inconsistent ABC column length")
		}
		if _, err := rand.Read(oracle.salts[i][:]); err != nil {
			return nil, err
		}
		leaf, err := HashABCLeaf(i, oracle.salts[i], a[i], b[i], c[i])
		if err != nil {
			return nil, err
		}
		oracle.levels[0][i] = leaf
	}
	for width := n; width > 1; width >>= 1 {
		last := oracle.levels[len(oracle.levels)-1]
		next := make([][32]byte, width/2)
		for i := range next {
			next[i] = hashABCNode(last[2*i], last[2*i+1])
		}
		oracle.levels = append(oracle.levels, next)
	}
	return oracle, nil
}

func (o *HashABCOracle) Root() [32]byte { return o.levels[len(o.levels)-1][0] }
func (o *HashABCOracle) K() int         { return o.k }
func (o *HashABCOracle) N() int         { return o.n }

func (o *HashABCOracle) StoredBytes() int {
	hashes := 0
	for _, level := range o.levels {
		hashes += len(level)
	}
	return 32 * (hashes + len(o.salts))
}

func sortedUniqueHashIndices(indices []int, n int) ([]int, error) {
	if len(indices) == 0 {
		return nil, errors.New("empty query set")
	}
	unique := make(map[int]struct{}, len(indices))
	for _, idx := range indices {
		if idx < 0 || idx >= n {
			return nil, errors.New("query index out of range")
		}
		unique[idx] = struct{}{}
	}
	out := make([]int, 0, len(unique))
	for idx := range unique {
		out = append(out, idx)
	}
	sort.Ints(out)
	return out, nil
}

func (o *HashABCOracle) Open(indices []int) (HashABCOpening, error) {
	current, err := sortedUniqueHashIndices(indices, o.n)
	if err != nil {
		return HashABCOpening{}, err
	}
	opening := HashABCOpening{Indices: append([]int(nil), current...), Salts: make([][32]byte, len(current))}
	for i, idx := range current {
		opening.Salts[i] = o.salts[idx]
	}
	for level := 0; level < len(o.levels)-1; level++ {
		known := make(map[int]bool, len(current))
		next := make(map[int]bool, len(current))
		for _, idx := range current {
			known[idx] = true
		}
		for _, idx := range current {
			if !known[idx^1] {
				opening.Siblings = append(opening.Siblings, o.levels[level][idx^1])
			}
			next[idx/2] = true
		}
		current = current[:0]
		for idx := range next {
			current = append(current, idx)
		}
		sort.Ints(current)
	}
	return opening, nil
}

// VerifyHashABCOpening checks Merkle authentication only. A/B/C columns are
// disclosed to the verifier by this opening.
func VerifyHashABCOpening(root [32]byte, n int, opening HashABCOpening, a, b, c [][]fr.Element) bool {
	if n <= 0 || n&(n-1) != 0 || len(opening.Indices) == 0 ||
		len(opening.Indices) != len(opening.Salts) ||
		len(opening.Indices) != len(a) || len(a) != len(b) || len(a) != len(c) {
		return false
	}
	current := make(map[int][32]byte, len(a))
	for i, idx := range opening.Indices {
		if idx < 0 || idx >= n || (i > 0 && opening.Indices[i-1] >= idx) {
			return false
		}
		leaf, err := HashABCLeaf(idx, opening.Salts[i], a[i], b[i], c[i])
		if err != nil {
			return false
		}
		current[idx] = leaf
	}
	pos := 0
	for width := n; width > 1; width >>= 1 {
		keys := make([]int, 0, len(current))
		for idx := range current {
			keys = append(keys, idx)
		}
		sort.Ints(keys)
		next := make(map[int][32]byte, len(keys))
		for _, idx := range keys {
			sibling, exists := current[idx^1]
			if !exists {
				if pos >= len(opening.Siblings) {
					return false
				}
				sibling = opening.Siblings[pos]
				pos++
			} else if idx&1 != 0 {
				continue
			}
			var parent [32]byte
			if idx&1 == 0 {
				parent = hashABCNode(current[idx], sibling)
			} else {
				parent = hashABCNode(sibling, current[idx])
			}
			next[idx/2] = parent
		}
		current = next
	}
	return pos == len(opening.Siblings) && len(current) == 1 && current[0] == root
}

func (o HashABCOpening) DisclosedBytes(k int) int {
	return 32 * (len(o.Siblings) + len(o.Salts) + len(o.Indices)*3*k)
}
