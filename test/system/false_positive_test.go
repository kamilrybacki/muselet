package system

import (
	"testing"

	"github.com/kamilrybacki/muselet/internal"
	"github.com/kamilrybacki/muselet/internal/scanner"
)

func TestTruePositiveRateKnownSecrets(t *testing.T) {
	s := scanner.NewDefaultScanner()

	knownSecrets := []struct {
		secretType string
		value      string
	}{
		{"aws-access-key", "AKIAIOSFODNN7EXAMPLE"},
		{"aws-access-key", "AKIAI44QH8DHBEXAMPLE"},
		{"github-pat", "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh"},
		{"github-oauth", "gho_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh"},
		{"private-key", "-----BEGIN RSA PRIVATE KEY-----"},
		{"private-key", "-----BEGIN EC PRIVATE KEY-----"},
		{"private-key", "-----BEGIN OPENSSH PRIVATE KEY-----"},
		{"connection-string", "postgres://admin:password@db.host:5432/production"},
		{"connection-string", "mysql://root:secret@localhost:3306/mydb"},
		{"connection-string", "mongodb://user:pass@mongo.host:27017/db"},
		{"stripe-key", "sk" + "_live_FAKEFAKEFAKEFAKEFAKEFAKE"},
		{"stripe-key", "pk" + "_test_FAKEFAKEFAKEFAKEFAKEFAKE"},
		{"google-api-key", "AIzaSyD-9tSrke72PouQMnMX-a7eZSW0jkFMBWY"},
		{"slack-token", "xoxb-" + "0000000000-0000000000000-fakefakefakefakefakefake"},
	}

	detected := 0
	for _, sec := range knownSecrets {
		results := s.ScanBytes([]byte(sec.value), internal.VectorNetwork)
		if len(results) > 0 {
			detected++
		} else {
			t.Logf("MISSED: type=%s value=%s", sec.secretType, sec.value[:min(20, len(sec.value))])
		}
	}

	tpRate := float64(detected) / float64(len(knownSecrets))
	t.Logf("Detected %d/%d known secrets (%.1f%% TP rate)", detected, len(knownSecrets), tpRate*100)

	if tpRate < 0.90 {
		t.Errorf("TP rate %.1f%% is below 90%% threshold", tpRate*100)
	}
}

func TestFalsePositiveRateCleanCode(t *testing.T) {
	s := scanner.NewDefaultScanner()

	cleanCode := []string{
		`package main`,
		`import "fmt"`,
		`func main() { fmt.Println("hello") }`,
		`var x = 42`,
		`if err != nil { return err }`,
		`for i := 0; i < 100; i++ { }`,
		`type Config struct { Host string; Port int }`,
		`http.ListenAndServe(":8080", nil)`,
		`log.Printf("starting server on port %d", port)`,
		`ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)`,
		`defer cancel()`,
		`json.NewEncoder(w).Encode(response)`,
		`os.Getenv("HOME")`,
		`filepath.Join(dir, "config.yaml")`,
		`strings.Contains(s, "test")`,
		`// This function handles authentication`,
		`/* Multi-line comment about API usage */`,
		`return nil, fmt.Errorf("failed to connect: %w", err)`,
		`map[string]interface{}{"key": "value"}`,
		`bytes.NewBufferString("hello world")`,
	}

	hits := 0
	for _, code := range cleanCode {
		results := s.ScanBytes([]byte(code), internal.VectorStdout)
		if len(results) > 0 {
			hits++
			t.Logf("FALSE POSITIVE: %q → %s", code, results[0].RuleID)
		}
	}

	fpRate := float64(hits) / float64(len(cleanCode))
	t.Logf("FP rate on clean code: %d/%d (%.1f%%)", hits, len(cleanCode), fpRate*100)

	if fpRate > 0.05 {
		t.Errorf("FP rate %.1f%% is above 5%% threshold", fpRate*100)
	}
}

func TestFalsePositiveRateCommonPatterns(t *testing.T) {
	s := scanner.NewDefaultScanner()

	// Patterns that look like secrets but aren't
	falsePositiveCandidates := []struct {
		name  string
		input string
	}{
		{"semver", "v1.23.456-beta.1+build.789"},
		{"UUID", "550e8400-e29b-41d4-a716-446655440000"},
		{"git SHA", "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"},
		{"hex color", "#FF5733"},
		{"example.com email", "user@example.com"},
		{"test email", "test@test.com"},
		{"localhost URL", "http://localhost:3000"},
		{"documentation URL", "https://docs.example.com/api"},
		{"go import", `import "github.com/pkg/errors"`},
		{"npm package", `"express": "^4.18.2"`},
		{"docker image", "golang:1.22-alpine"},
		{"CIDR notation", "10.0.0.0/24"},
		{"MAC address", "00:1B:44:11:3A:B7"},
	}

	hits := 0
	for _, tc := range falsePositiveCandidates {
		results := s.ScanBytes([]byte(tc.input), internal.VectorStdout)
		// Filter out expected matches (like private IPs from CIDR notation)
		unexpectedHits := 0
		for _, r := range results {
			// Some of these legitimately match (e.g., CIDR has a private IP)
			if r.RuleID == "private-ip" && (tc.name == "CIDR notation") {
				continue // expected
			}
			if r.RuleID == "email-address" && (tc.name == "example.com email" || tc.name == "test email") {
				continue // expected — PII is off by default, but if enabled, emails match
			}
			unexpectedHits++
		}
		if unexpectedHits > 0 {
			hits++
			t.Logf("FALSE POSITIVE: %s (%q) → %s", tc.name, tc.input, results[0].RuleID)
		}
	}

	t.Logf("Unexpected FPs: %d/%d", hits, len(falsePositiveCandidates))
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
