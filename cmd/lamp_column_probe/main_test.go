package main

import "testing"

func TestColumnProbeAuthenticatesSampledFolds(t *testing.T) {
	r, err := run(4, 8, 8, 5, 123, 2)
	if err != nil {
		t.Fatal(err)
	}
	if !r.OpeningsVerified || !r.FoldChecksPassed || r.OpeningBytes == 0 || r.DistinctQueries == 0 {
		t.Fatalf("probe failed to authenticate its sampled folds: %+v", r)
	}
}
