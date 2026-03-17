package scanner

import (
	"strings"
	"testing"

	"github.com/kamilrybacki/muselet/internal"
)

func TestContextAnalysis(t *testing.T) {
	analyzer := NewContextAnalyzer()

	tests := []struct {
		name            string
		match           internal.Match
		filePath        string
		content         []byte
		vector          internal.Vector
		wantFileRisk    internal.RiskLevel
		wantConfidRange [2]float64
	}{
		{
			name:            "secret in .env file via network",
			match:           internal.Match{RuleID: "aws-access-key", Category: "credentials"},
			filePath:        ".env",
			vector:          internal.VectorNetwork,
			wantFileRisk:    internal.RiskHigh,
			wantConfidRange: [2]float64{0.8, 1.0},
		},
		{
			name:            "same secret in test fixture",
			match:           internal.Match{RuleID: "aws-access-key", Category: "credentials"},
			filePath:        "tests/fixtures/aws_mock.go",
			content:         []byte(`// test data for AWS mock` + "\n" + `var testKey = "AKIAIOSFODNN7EXAMPLE"`),
			vector:          internal.VectorFilesystem,
			wantFileRisk:    internal.RiskLow,
			wantConfidRange: [2]float64{0.0, 0.55},
		},
		{
			name:            "private IP in docker-compose.yaml",
			match:           internal.Match{RuleID: "private-ip", Category: "infrastructure", Offset: 50},
			filePath:        "docker-compose.yaml",
			vector:          internal.VectorFilesystem,
			wantFileRisk:    internal.RiskMedium,
			wantConfidRange: [2]float64{0.2, 0.7},
		},
		{
			name:            "email in vendor directory",
			match:           internal.Match{RuleID: "email-address", Category: "pii"},
			filePath:        "vendor/github.com/pkg/errors/errors.go",
			vector:          internal.VectorFilesystem,
			wantFileRisk:    internal.RiskLow,
			wantConfidRange: [2]float64{0.0, 0.3},
		},
		{
			name:            "connection string near example keyword",
			match:           internal.Match{RuleID: "connection-string", Category: "credentials", Offset: 15},
			filePath:        "README.md",
			content:         []byte("## Example\n\npostgres://user:pass@localhost:5432/db"),
			vector:          internal.VectorStdout,
			wantFileRisk:    internal.RiskLow,
			wantConfidRange: [2]float64{0.0, 0.55},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := analyzer.Analyze(tt.match, internal.ContextInput{
				FilePath: tt.filePath,
				Content:  tt.content,
				Vector:   tt.vector,
			})
			if got.FileRisk != tt.wantFileRisk {
				t.Errorf("FileRisk: want %v, got %v", tt.wantFileRisk, got.FileRisk)
			}
			if got.Confidence < tt.wantConfidRange[0] || got.Confidence > tt.wantConfidRange[1] {
				t.Errorf("Confidence: got %f, want in [%f, %f]",
					got.Confidence, tt.wantConfidRange[0], tt.wantConfidRange[1])
			}
		})
	}
}

func TestFilePathRiskClassification(t *testing.T) {
	tests := []struct {
		path     string
		wantRisk internal.RiskLevel
	}{
		{".env", internal.RiskHigh},
		{".env.local", internal.RiskHigh},
		{".env.production", internal.RiskHigh},
		{"src/main.go", internal.RiskMedium},
		{"lib/auth.js", internal.RiskMedium},
		{"tests/unit/auth_test.go", internal.RiskLow},
		{"test/fixtures/mock_keys.json", internal.RiskLow},
		{"vendor/pkg/errors.go", internal.RiskLow},
		{"node_modules/express/index.js", internal.RiskLow},
		{"README.md", internal.RiskLow},
		{".github/workflows/ci.yaml", internal.RiskMedium},
		{"", internal.RiskMedium},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			got := ClassifyPathRisk(tt.path)
			if got != tt.wantRisk {
				t.Errorf("ClassifyPathRisk(%q) = %v, want %v", tt.path, got, tt.wantRisk)
			}
		})
	}
}

func TestNearbyMarkerDetection(t *testing.T) {
	tests := []struct {
		name        string
		content     string
		matchPos    int
		wantMarkers []string
	}{
		{
			"example nearby",
			"// This is an example API key\nkey = \"AKIAIOSFODNN7EXAMPLE\"",
			37,
			[]string{"example"},
		},
		{
			"test and dummy nearby",
			`var dummy = "AKIAIOSFODNN7EXAMPLE" // for testing`,
			15,
			[]string{"dummy", "testing"},
		},
		{
			"no markers",
			`production_key := "AKIAIOSFODNN7EXAMPLE"`,
			20,
			nil,
		},
		{
			"marker too far away",
			"// example\n" + strings.Repeat("x", 300) + "\nAKIAIOSFODNN7EXAMPLE",
			312,
			nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FindNearbyMarkers([]byte(tt.content), tt.matchPos, 200)
			if len(tt.wantMarkers) == 0 && len(got) == 0 {
				return
			}
			if len(got) != len(tt.wantMarkers) {
				t.Errorf("markers: want %v, got %v", tt.wantMarkers, got)
				return
			}
			// Check each expected marker is present
			for _, want := range tt.wantMarkers {
				found := false
				for _, g := range got {
					if g == want {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("missing marker %q in %v", want, got)
				}
			}
		})
	}
}
