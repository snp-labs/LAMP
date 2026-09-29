package benchmark

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestAppendComparisonRawJSONL(t *testing.T) {
	p := filepath.Join(t.TempDir(), "nested", "raw.jsonl")
	r := ComparisonRawRecord{SchemaVersion: 1, Scheme: "lamp", VerificationSucceeded: true, TimingsSeconds: map[string]float64{"prove": 0.125}}
	if err := AppendComparisonRawJSONL(p, r); err != nil {
		t.Fatal(err)
	}
	if err := AppendComparisonRawJSONL(p, r); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	n := 0
	for s.Scan() {
		var got map[string]any
		if err = json.Unmarshal(s.Bytes(), &got); err != nil {
			t.Fatal(err)
		}
		if got["verification_succeeded"] != true {
			t.Fatal("missing successful verification status")
		}
		timing := got["timings_seconds"].(map[string]any)
		if timing["prove"] != 0.125 {
			t.Fatalf("timing rounded: %v", timing["prove"])
		}
		n++
	}
	if err = s.Err(); err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("got %d appended records", n)
	}
}
