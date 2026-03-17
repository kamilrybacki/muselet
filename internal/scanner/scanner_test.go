package scanner

import (
	"testing"

	"github.com/kamilrybacki/muselet/internal"
)

func TestScannerScanBytes(t *testing.T) {
	s := NewDefaultScanner()

	tests := []struct {
		name       string
		input      string
		vector     internal.Vector
		wantHits   bool
		wantRuleID string
	}{
		{"aws key in network", "AKIAIOSFODNN7EXAMPLE", internal.VectorNetwork, true, "aws-access-key"},
		{"clean code", "func main() {}", internal.VectorStdout, false, ""},
		{"connection string", "postgres://admin:s3cret@db:5432/mydb", internal.VectorNetwork, true, "connection-string"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results := s.ScanBytes([]byte(tt.input), tt.vector)
			if tt.wantHits && len(results) == 0 {
				t.Error("expected hits, got none")
			}
			if !tt.wantHits && len(results) > 0 {
				t.Errorf("expected no hits, got %d", len(results))
			}
			if tt.wantRuleID != "" && len(results) > 0 {
				found := false
				for _, r := range results {
					if r.RuleID == tt.wantRuleID {
						found = true
					}
				}
				if !found {
					t.Errorf("expected rule %q in results", tt.wantRuleID)
				}
			}
		})
	}
}

func TestScannerCategoryFiltering(t *testing.T) {
	// Scanner with only credentials enabled
	var rules []*Rule
	for _, r := range BuiltinRules {
		rules = append(rules, r)
	}
	s := NewScanner(rules, DefaultEntropyConfig(), CategoryConfig{
		Credentials:    true,
		Infrastructure: false,
		PII:            false,
	})

	// Should detect credentials
	results := s.ScanBytes([]byte("AKIAIOSFODNN7EXAMPLE"), internal.VectorNetwork)
	if len(results) == 0 {
		t.Error("should detect AWS key with credentials enabled")
	}

	// Should not detect PII
	results = s.ScanBytes([]byte("SSN: 123-45-6789"), internal.VectorStdout)
	if len(results) > 0 {
		t.Error("should not detect PII with PII disabled")
	}
}

func TestScannerLineNumbers(t *testing.T) {
	s := NewDefaultScanner()
	input := "line1\nline2\nAKIAIOSFODNN7EXAMPLE\nline4"
	results := s.ScanBytes([]byte(input), internal.VectorFilesystem)

	if len(results) == 0 {
		t.Fatal("expected hits")
	}
	if results[0].Line != 3 {
		t.Errorf("line number: want 3, got %d", results[0].Line)
	}
}

func TestStdoutPipelineChunkBoundary(t *testing.T) {
	var rules []*Rule
	for _, r := range BuiltinRules {
		rules = append(rules, r)
	}
	bundle := BuildScanBundle(rules, nil)
	pipeline := NewStdoutPipeline(bundle, 64)

	// Secret split across two chunks
	secret := "AKIAIOSFODNN7EXAMPLE"
	chunk1 := []byte("normal text " + secret[:10])
	chunk2 := []byte(secret[10:] + " more normal text")

	hits1 := pipeline.ProcessChunk(chunk1)
	hits2 := pipeline.ProcessChunk(chunk2)

	allHits := append(hits1, hits2...)
	if len(allHits) == 0 {
		t.Error("should detect secret split across chunks via overlap")
	}
}

func TestStdoutPipelineCleanData(t *testing.T) {
	var rules []*Rule
	for _, r := range BuiltinRules {
		rules = append(rules, r)
	}
	bundle := BuildScanBundle(rules, nil)
	pipeline := NewStdoutPipeline(bundle, 64)

	// Multiple clean chunks
	for i := 0; i < 10; i++ {
		hits := pipeline.ProcessChunk([]byte("just normal code output here\n"))
		if len(hits) != 0 {
			t.Errorf("chunk %d: expected no hits, got %d", i, len(hits))
		}
	}
}
