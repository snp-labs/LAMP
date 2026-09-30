package benchmark

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
)

type ComparisonRawRecord struct {
	SchemaVersion              int                `json:"schema_version"`
	Scheme                     string             `json:"scheme"`
	Variant                    string             `json:"variant"`
	Workload                   string             `json:"workload"`
	SamplingProfile            string             `json:"sampling_profile"`
	ProtocolFidelity           string             `json:"protocol_fidelity,omitempty"`
	Dimensions                 map[string]int     `json:"dimensions"`
	BatchQ                     int                `json:"batch_q,omitempty"`
	QueryCount                 int                `json:"query_count"`
	DistinctQueryCount         *int               `json:"distinct_query_count,omitempty"`
	VerificationSucceeded      bool               `json:"verification_succeeded"`
	TimingsSeconds             map[string]float64 `json:"timings_seconds"`
	OriginalReportedProofBytes *int               `json:"original_reported_proof_bytes,omitempty"`
	CompressedPayloadBytes     *int               `json:"compressed_payload_bytes"`
	ProofSizeDefinition        string             `json:"proof_size_definition"`
	Host                       map[string]string  `json:"host"`
}

// AppendComparisonRawJSONL is an opt-in machine-readable side channel. It does
// not touch the historical CSV writer or round numeric measurements.
func AppendComparisonRawJSONL(path string, record any) error {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil
	}
	if info, err := os.Stat(path); err == nil && info.IsDir() {
		path = filepath.Join(path, "lamp_comparison.jsonl")
	}
	if strings.HasSuffix(path, string(os.PathSeparator)) {
		path = filepath.Join(path, "lamp_comparison.jsonl")
	}
	if path == "" {
		return errors.New("empty raw comparison path")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0644)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetEscapeHTML(false)
	return enc.Encode(record)
}
