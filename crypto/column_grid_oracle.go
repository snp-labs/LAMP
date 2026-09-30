package crypto

// This is an authenticated opening component for a column-extended matrix.
// It does not prove that a committed column is low degree, and it does not
// prove the remaining x^T B inner product in LAMP.

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"runtime"
	"sync"
	"time"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

type ColumnGridTimings struct {
	Encode  time.Duration
	Hash    time.Duration
	Workers int
}

type ColumnGridOracle struct {
	k, m, n int
	columns [3][][]fr.Element
	encoder *ColumnCoefficientEncoder
	outer   *columnHashTree
}

type ColumnGridOpening struct {
	ColumnIndex int
	RowR        int
	RowB        int
	AtR         [3]fr.Element
	AtB         [3]fr.Element
	RowRPath    [][32]byte
	RowBPath    [][32]byte
	ColumnPath  [][32]byte
}

func (o ColumnGridOpening) Bytes() int {
	return 24 + 6*32 + 32*(len(o.RowRPath)+len(o.RowBPath)+len(o.ColumnPath))
}

type columnHashTree struct {
	levels [][][32]byte
}

func newColumnHashTree(leaves [][32]byte) *columnHashTree {
	t := &columnHashTree{levels: [][][32]byte{leaves}}
	for width := len(leaves); width > 1; width >>= 1 {
		prev := t.levels[len(t.levels)-1]
		next := make([][32]byte, width/2)
		for i := range next {
			next[i] = hashABCNode(prev[2*i], prev[2*i+1])
		}
		t.levels = append(t.levels, next)
	}
	return t
}

func (t *columnHashTree) root() [32]byte { return t.levels[len(t.levels)-1][0] }

func (t *columnHashTree) path(index int) [][32]byte {
	path := make([][32]byte, len(t.levels)-1)
	for level := range path {
		path[level] = t.levels[level][index^1]
		index >>= 1
	}
	return path
}

func verifyColumnHashPath(root, leaf [32]byte, index, count int, path [][32]byte) bool {
	if index < 0 || index >= count || !isPowerOfTwo(count) || len(path) != bitLog2(count) {
		return false
	}
	value := leaf
	for _, sibling := range path {
		if index&1 == 0 {
			value = hashABCNode(value, sibling)
		} else {
			value = hashABCNode(sibling, value)
		}
		index >>= 1
	}
	return value == root
}

func bitLog2(n int) int {
	out := 0
	for n > 1 {
		n >>= 1
		out++
	}
	return out
}

func hashGridCell(column, row int, values [3]fr.Element) [32]byte {
	const tag = "LAMP-column-grid-cell-v1"
	var input [len(tag) + 16 + 3*32]byte
	copy(input[:len(tag)], tag)
	binary.BigEndian.PutUint64(input[len(tag):len(tag)+8], uint64(column))
	binary.BigEndian.PutUint64(input[len(tag)+8:len(tag)+16], uint64(row))
	for i, value := range values {
		bytes := value.Bytes()
		copy(input[len(tag)+16+i*32:len(tag)+16+(i+1)*32], bytes[:])
	}
	return sha256.Sum256(input[:])
}

func validateGridColumns(a, b, c [][]fr.Element, k int) error {
	if !isPowerOfTwo(len(a)) || len(a) != len(b) || len(a) != len(c) {
		return fmt.Errorf("A/B/C need the same power-of-two number of columns")
	}
	for j := range a {
		if len(a[j]) != k || len(b[j]) != k || len(c[j]) != k {
			return fmt.Errorf("column %d has an incorrect length", j)
		}
	}
	return nil
}

// BuildColumnGridOracle commits to three matrices after extending every
// length-K column to M coefficient-RS evaluations. Its two Merkle levels
// authenticate cell triples and then column roots. Source columns are retained
// for rebuilding only the queried column trees during Open.
func BuildColumnGridOracle(a, b, c [][]fr.Element, k, m int, workerCount ...int) (*ColumnGridOracle, ColumnGridTimings, error) {
	var timings ColumnGridTimings
	if err := validateGridColumns(a, b, c, k); err != nil {
		return nil, timings, err
	}
	encoder, err := NewColumnCoefficientEncoder(k, m)
	if err != nil {
		return nil, timings, err
	}
	n := len(a)
	workers := runtime.GOMAXPROCS(0)
	if len(workerCount) > 0 {
		workers = workerCount[0]
	}
	if len(workerCount) > 1 || workers < 1 {
		return nil, timings, fmt.Errorf("expected one positive worker count")
	}
	if workers > n {
		workers = n
	}
	timings.Workers = workers
	workerEncoders := make([]*ColumnCoefficientEncoder, workers)
	for i := range workerEncoders {
		workerEncoders[i], err = NewColumnCoefficientEncoder(k, m)
		if err != nil {
			return nil, timings, err
		}
	}
	columnRoots := make([][32]byte, n)
	columns := [3][][]fr.Element{a, b, c}
	batchSize := 8 * workers
	for first := 0; first < n; first += batchSize {
		last := first + batchSize
		if last > n {
			last = n
		}
		count := last - first
		encoded := make([][3][]fr.Element, count)
		encodeErrors := make([]error, count)
		start := time.Now()
		parallelGridColumns(count, workers, func(slot, worker int) {
			for matrix := range columns {
				encoded[slot][matrix], encodeErrors[slot] = workerEncoders[worker].Encode(columns[matrix][first+slot])
				if encodeErrors[slot] != nil {
					return
				}
			}
		})
		timings.Encode += time.Since(start)
		for _, encodeErr := range encodeErrors {
			if encodeErr != nil {
				return nil, timings, encodeErr
			}
		}
		start = time.Now()
		parallelGridColumns(count, workers, func(slot, _ int) {
			j := first + slot
			leaves := make([][32]byte, m)
			for row := range leaves {
				leaves[row] = hashGridCell(j, row, [3]fr.Element{encoded[slot][0][row], encoded[slot][1][row], encoded[slot][2][row]})
			}
			columnRoots[j] = newColumnHashTree(leaves).root()
		})
		timings.Hash += time.Since(start)
	}
	start := time.Now()
	outer := newColumnHashTree(columnRoots)
	timings.Hash += time.Since(start)
	return &ColumnGridOracle{k: k, m: m, n: n, columns: columns, encoder: encoder, outer: outer}, timings, nil
}

func parallelGridColumns(count, workers int, work func(slot, worker int)) {
	jobs := make(chan int)
	var group sync.WaitGroup
	for worker := 0; worker < workers; worker++ {
		group.Add(1)
		go func(worker int) {
			defer group.Done()
			for slot := range jobs {
				work(slot, worker)
			}
		}(worker)
	}
	for slot := 0; slot < count; slot++ {
		jobs <- slot
	}
	close(jobs)
	group.Wait()
}

func (o *ColumnGridOracle) Root() [32]byte { return o.outer.root() }

// Open authenticates the A/B/C cell triple at rowR and rowB of one column.
// Rebuilding the queried column tree is charged to opening time.
func (o *ColumnGridOracle) Open(column, rowR, rowB int) (ColumnGridOpening, error) {
	var opening ColumnGridOpening
	if column < 0 || column >= o.n || rowR < 0 || rowR >= o.m || rowB < 0 || rowB >= o.m {
		return opening, fmt.Errorf("grid query outside committed domain")
	}
	var encoded [3][]fr.Element
	for matrix := range o.columns {
		var err error
		encoded[matrix], err = o.encoder.Encode(o.columns[matrix][column])
		if err != nil {
			return opening, err
		}
	}
	leaves := make([][32]byte, o.m)
	for row := range leaves {
		leaves[row] = hashGridCell(column, row, [3]fr.Element{encoded[0][row], encoded[1][row], encoded[2][row]})
	}
	tree := newColumnHashTree(leaves)
	opening.ColumnIndex, opening.RowR, opening.RowB = column, rowR, rowB
	for matrix := range opening.AtR {
		opening.AtR[matrix] = encoded[matrix][rowR]
		opening.AtB[matrix] = encoded[matrix][rowB]
	}
	opening.RowRPath = tree.path(rowR)
	opening.RowBPath = tree.path(rowB)
	opening.ColumnPath = o.outer.path(column)
	return opening, nil
}

func VerifyColumnGridOpening(root [32]byte, n, m int, opening ColumnGridOpening) bool {
	innerR := hashGridCell(opening.ColumnIndex, opening.RowR, opening.AtR)
	innerB := hashGridCell(opening.ColumnIndex, opening.RowB, opening.AtB)
	columnRoot := [32]byte{}
	// Both paths must lead to the same column root.
	if opening.RowR < 0 || opening.RowR >= m || len(opening.RowRPath) != bitLog2(m) {
		return false
	}
	columnRoot = foldColumnHashPath(innerR, opening.RowR, opening.RowRPath)
	if !verifyColumnHashPath(columnRoot, innerB, opening.RowB, m, opening.RowBPath) {
		return false
	}
	return verifyColumnHashPath(root, columnRoot, opening.ColumnIndex, n, opening.ColumnPath)
}

func foldColumnHashPath(leaf [32]byte, index int, path [][32]byte) [32]byte {
	value := leaf
	for _, sibling := range path {
		if index&1 == 0 {
			value = hashABCNode(value, sibling)
		} else {
			value = hashABCNode(sibling, value)
		}
		index >>= 1
	}
	return value
}
