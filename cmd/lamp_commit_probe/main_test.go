package main

import "testing"

func TestProbeVerifiesBothCommitments(t *testing.T) {
	r, err := run(16, 32, "1/2", 17, 7)
	if err != nil {
		t.Fatal(err)
	}
	if !r.HashOpeningVerified || r.DistinctQueries == 0 || r.PedersenRoot == "" ||
		r.HashRoot == "" || r.HashDisclosedBytes <= 0 {
		t.Fatalf("probe did not verify a complete opening: %+v", r)
	}
}
