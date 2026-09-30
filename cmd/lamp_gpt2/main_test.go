package main

import (
	"os"
	"path/filepath"
	"testing"

	"example.com/lamp/circuit"
	"example.com/lamp/crypto"
	"example.com/lamp/crypto/zkmatrix"
	"example.com/lamp/matrix"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

func TestRSWitnessCommitmentFollowsExternalGroups(t *testing.T) {
	p := prepareLayerShapeOnly(1, "1/2", 1)
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, buildCircuit(p, false))
	if err != nil {
		t.Fatal(err)
	}
	commitments := ccs.GetCommitments().(constraint.Groth16Commitments)
	if len(commitments) <= numGroups {
		t.Fatalf("got %d commitments, want RS witness at index %d", len(commitments), numGroups)
	}

	// Commit adds one private random mask after the explicitly committed values.
	want := lampGPT2RSWitnessLen(p) + 1
	if got := len(commitments[numGroups].PrivateCommitted); got != want {
		t.Fatalf("RS-witness commitment has %d private values, want %d", got, want)
	}
}

func TestGPT2MatrixClaimGroupsCoverOfficialGraphShapes(t *testing.T) {
	_, specs := buildGPT2MediumTensorShapes(8)
	groups, err := groupMatrixClaims(specs)
	if err != nil {
		t.Fatal(err)
	}
	total := 0
	shapeCounts := map[[3]int]int{}
	for _, group := range groups {
		total += len(group.claims)
		shapeCounts[[3]int{group.m, group.inner, group.n}] = len(group.claims)
	}
	if total != 36 {
		t.Fatalf("grouped %d claims, want 36", total)
	}
	if shapeCounts[[3]int{8, 64, 8}] != 16 || shapeCounts[[3]int{8, 8, 64}] != 16 {
		t.Fatalf("unexpected attention grouping: %#v", shapeCounts)
	}
	if shapeCounts[[3]int{8, 1024, 4096}] != 2 || shapeCounts[[3]int{8, 1024, 1024}] != 1 || shapeCounts[[3]int{8, 4096, 1024}] != 1 {
		t.Fatalf("unexpected projection grouping: %#v", shapeCounts)
	}
}

func TestGPT2S1024BaselinePlanHasFiveExpectedGroups(t *testing.T) {
	plan, err := planGPT2ZKMatrixBaseline(1024)
	if err != nil {
		t.Fatal(err)
	}
	if plan.ExecutionStatus != "planned_only" || plan.Claims != 36 || len(plan.Groups) != 5 {
		t.Fatalf("unexpected plan summary: status=%s claims=%d groups=%d", plan.ExecutionStatus, plan.Claims, len(plan.Groups))
	}
	got := make(map[int]int)
	total := 0
	for _, group := range plan.Groups {
		got[group.Claims]++
		total += group.Claims
	}
	want := map[int]int{1: 2, 2: 1, 16: 2}
	for n, count := range want {
		if got[n] != count {
			t.Fatalf("group size histogram %v, want %v", got, want)
		}
	}
	if total != 36 {
		t.Fatalf("plan covers %d claims, want 36", total)
	}
	if plan.GraphWiringCertified || plan.InputOutputBinding {
		t.Fatal("claims-only plan advertises graph wiring or public boundary binding")
	}
}

func TestGPT2BaselineResourceGuardUsesNominal256GiBUsableFloor(t *testing.T) {
	base := map[string]any{"cpu_count": 32, "memory_bytes": uint64(239) * (uint64(1) << 30)}
	if baselineResourceGuard(base) == nil {
		t.Fatal("239 GiB usable memory unexpectedly passed the guard")
	}
	base["memory_bytes"] = uint64(240) * (uint64(1) << 30)
	if err := baselineResourceGuard(base); err != nil {
		t.Fatalf("240 GiB usable memory should pass nominal 256 GiB host floor: %v", err)
	}
	base["cpu_count"] = 31
	if baselineResourceGuard(base) == nil {
		t.Fatal("31 CPUs unexpectedly passed the guard")
	}
}

func TestGPT2SequenceLogValidatedBeforeLengthCalculation(t *testing.T) {
	for _, invalid := range []int{-1, 11, 1000} {
		if _, err := gpt2SequenceLength(invalid); err == nil {
			t.Fatalf("sequence log %d passed validation", invalid)
		}
	}
	if got, err := gpt2SequenceLength(10); err != nil || got != 1024 {
		t.Fatalf("sequence log 10 returned %d, %v", got, err)
	}
}

func TestGPT2SourceFingerprintIncludesNestedAndUntrackedSources(t *testing.T) {
	root := t.TempDir()
	files := map[string]string{
		"cmd/lamp_gpt2/main.go":           "package main\n",
		"crypto/zkmatrix/new.go":          "package zkmatrix\n",
		"lib/gnark/go.mod":                "module fixture\n",
		"scripts/comparison/configs.json": "{}\n",
		"docs/notes.md":                   "excluded\n",
		".env":                            "SECRET=excluded\n",
	}
	for name, content := range files {
		path := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0644); err != nil {
			t.Fatal(err)
		}
	}
	first, count, err := baselineSourceFingerprint(root)
	if err != nil {
		t.Fatal(err)
	}
	if count != 4 {
		t.Fatalf("hashed %d source files, want 4", count)
	}
	if err := os.WriteFile(filepath.Join(root, "crypto/zkmatrix/new.go"), []byte("package zkmatrix\n// change\n"), 0644); err != nil {
		t.Fatal(err)
	}
	second, _, err := baselineSourceFingerprint(root)
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("untracked crypto source change did not change full source fingerprint")
	}
}

func TestGPT2TinyMatrixClaimBatchRoundTripAndRejectsFalseOutput(t *testing.T) {
	mat := func(values ...uint64) [][]fr.Element {
		out := make([][]fr.Element, 2)
		for i := range out {
			out[i] = make([]fr.Element, 2)
			for j := range out[i] {
				out[i][j].SetUint64(values[i*2+j])
			}
		}
		return out
	}
	a, b, c := mat(1, 2, 3, 4), mat(2, 0, 1, 2), mat(4, 4, 10, 8)
	claims := []claimSpec{tinyMatrixClaim("tiny0", a, b, c), tinyMatrixClaim("tiny1", a, b, c)}
	groups, err := groupMatrixClaims(claims)
	if err != nil || len(groups) != 1 || len(groups[0].claims) != 2 {
		t.Fatalf("tiny claims not batched: groups=%d err=%v", len(groups), err)
	}
	pp, err := zkmatrix.Setup(2, 2, 2)
	if err != nil {
		t.Fatal(err)
	}
	result, err := proveGPT2ClaimGroup(groups[0], pp, 0.01)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Verified || result.Claims != 2 || result.SerializedProofBytes == 0 || result.StatementBytes == 0 {
		t.Fatalf("invalid tiny baseline result: %+v", result)
	}
	falseC := mat(4, 4, 10, 9)
	falseGroup := matrixClaimGroup{m: 2, inner: 2, n: 2, claims: []claimSpec{tinyMatrixClaim("false_output", a, b, falseC)}}
	if _, err := proveGPT2ClaimGroup(falseGroup, pp, 0); err == nil {
		t.Fatal("false provided C was accepted")
	}
}

func tinyMatrixClaim(name string, a, b, c [][]fr.Element) claimSpec {
	makeTensor := func(name string, data [][]fr.Element) *tensor {
		return &tensor{name: name, rows: len(data), cols: len(data[0]), data: data}
	}
	return claimSpec{name: name, A: makeTensor(name+"_a", a), B: makeTensor(name+"_b", b), C: makeTensor(name+"_c", c)}
}

func TestBProximityFoldMatchesRectangularEncoding(t *testing.T) {
	const rows, cols, n = 3, 4, 8
	matB := make([][]fr.Element, rows)
	for i := range matB {
		matB[i] = make([]fr.Element, cols)
		for j := range matB[i] {
			matB[i][j].SetUint64(uint64(i*cols + j + 1))
		}
	}

	var challengeB fr.Element
	challengeB.SetUint64(7)
	bPowers := matrix.Powers(challengeB, rows)
	vecBTest := matrix.VecMatMulRect(bPowers, matB, rows, cols)

	encoder := crypto.NewEncoder(cols, n)
	_, encodedRows, err := encoder.EncodeRows(matB)
	if err != nil {
		t.Fatal(err)
	}
	encodedColumns := matrix.Transpose(encodedRows, rows, n)
	_, encBTest, err := encoder.Encode(vecBTest)
	if err != nil {
		t.Fatal(err)
	}

	for column := 0; column < n; column++ {
		if folded := foldNative(bPowers, encodedColumns[column]); !folded.Equal(&encBTest[column]) {
			t.Fatalf("folded B column %d does not match its RS codeword", column)
		}
	}

	var one fr.Element
	one.SetOne()
	encodedColumns[0][0].Add(&encodedColumns[0][0], &one)
	if folded := foldNative(bPowers, encodedColumns[0]); folded.Equal(&encBTest[0]) {
		t.Fatal("corrupted B column unexpectedly matched its RS codeword")
	}
}

func TestBProximityRSBatchesCoverEveryClaimOnce(t *testing.T) {
	_, specs := buildGPT2MediumTensorShapes(2)
	p := &preparedLayer{seqLen: 2, rho: "1/2", claims: make([]claimWitness, len(specs))}
	for i := range specs {
		p.claims[i].spec = specs[i]
	}

	p.addBProximityRSBatches()
	if len(p.rsBatches) != 4 {
		t.Fatalf("got %d B proximity batches, want 4 output-domain batches", len(p.rsBatches))
	}
	seen := make([]int, len(p.claims))
	for _, batch := range p.rsBatches {
		for _, term := range batch.terms {
			if term.side != circuit.LAMPGPT2RSSideBTest {
				t.Fatalf("unexpected RS side %d in B proximity batch", term.side)
			}
			seen[term.claimIndex]++
		}
	}
	for i, count := range seen {
		if count != 1 {
			t.Fatalf("claim %d appears in %d B proximity batches", i, count)
		}
	}
}

func foldNative(lhs, rhs []fr.Element) fr.Element {
	var out fr.Element
	for i := range lhs {
		var term fr.Element
		term.Mul(&lhs[i], &rhs[i])
		out.Add(&out, &term)
	}
	return out
}
