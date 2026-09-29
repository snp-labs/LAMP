package zkmap_audit

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

func TestRectangularConvolutionExactCoefficients(t *testing.T) {
	r := RectangularConvolutionMismatch()
	if !r.Passed || r.Details["matrix_product_row_major"] != "[258 310 775 933]" || r.Details["truncated_convolution"] != "[34 89 188 341]" {
		t.Fatalf("unexpected direct arithmetic result: %+v", r)
	}
}

func TestPublicSRSAttacksN2AndN4(t *testing.T) {
	for _, n := range []int{2, 4} {
		t.Run("n="+fmt.Sprint(n), func(t *testing.T) {
			r := PairingAttackDiagnostic(n)
			if !r.Passed {
				t.Fatalf("pairing attack diagnostic failed: %+v", r)
			}
			for _, key := range []string{"invalid_C_neq_AB", "A_commitment_nonzero", "B_commitment_nonzero", "C_commitment_nonzero", "scalar_pairing_accepted", "appendix_e_algorithm2_accepted"} {
				if r.Details[key] != "true" {
					t.Errorf("%s = %q", key, r.Details[key])
				}
			}
			for _, key := range []string{"scalar_pairing_tampered_accepted", "appendix_e_algorithm2_tampered_accepted", "attack_trapdoor_input"} {
				want := "false"
				if key == "attack_trapdoor_input" {
					want = "false"
				}
				if r.Details[key] != want {
					t.Errorf("%s = %q, want %q", key, r.Details[key], want)
				}
			}
		})
	}
}

func TestLagrangeInterpolationAtDocumentedNodes(t *testing.T) {
	values := make([]fr.Element, 4)
	for i := range values {
		values[i].SetUint64(uint64((i + 1) * (i + 3)))
	}
	coeffs := interpolateAtIntegerNodes(values)
	for i, want := range values {
		var node fr.Element
		node.SetUint64(uint64(i))
		got := evalPolynomial(coeffs, node)
		if !got.Equal(&want) {
			t.Fatalf("P(%d)=%s, want %s", i, got.String(), want.String())
		}
	}
}

func TestAppendixInterpolationDiagnostic(t *testing.T) {
	r := AppendixInterpolationDiagnostic(2)
	if !r.Passed {
		t.Fatalf("interpolation diagnostic did not complete: %+v", r)
	}
	if r.Details["interpolation_nodes"] != "0..n-1" || r.Details["witness_polynomial_exists"] != "false" || r.Details["appendix_pairing_accepted"] != "not-run: no polynomial witness for selected interpolation" {
		t.Fatalf("unexpected selected-interpolation result: %+v", r.Details)
	}
}

func TestFullAuditJSONAndPassAggregation(t *testing.T) {
	data, err := ExportJSON()
	if err != nil {
		t.Fatal(err)
	}
	var summary AuditSummary
	if err := json.Unmarshal(data, &summary); err != nil {
		t.Fatal(err)
	}
	if !summary.AllPassed || len(summary.Results) != 4 {
		t.Fatalf("unexpected summary: %+v", summary)
	}
}
