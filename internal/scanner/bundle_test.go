package scanner

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAhoCorasickLiteralPrefixes(t *testing.T) {
	prefixes := []string{"AKIA", "ghp_", "gho_", "-----BEGIN", "sk-live-", "postgres://"}
	ac := BuildAhoCorasick(prefixes)

	tests := []struct {
		name       string
		input      string
		wantMatch  bool
		wantPrefix string
	}{
		{"aws key prefix", "foo AKIAIOSFODNN7EXAMPLE bar", true, "AKIA"},
		{"github pat prefix", "token=ghp_abc123", true, "ghp_"},
		{"private key prefix", "-----BEGIN RSA PRIVATE KEY-----", true, "-----BEGIN"},
		{"no prefix match", "just regular code here", false, ""},
		{"partial prefix", "AKI is not enough", false, ""},
		{"prefix at very end", "key=AKIA", true, "AKIA"},
		{"prefix at start", "AKIA1234567890ABCDEF", true, "AKIA"},
		{"multiple prefixes", "ghp_token and AKIA_key", true, "ghp_"},
		{"empty input", "", false, ""},
		{"case sensitive", "akia_not_uppercase", false, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches := ac.FindAll([]byte(tt.input))
			if tt.wantMatch {
				if len(matches) == 0 {
					t.Error("expected match, got none")
				} else if matches[0].Pattern != tt.wantPrefix {
					t.Errorf("first match pattern: want %q, got %q", tt.wantPrefix, matches[0].Pattern)
				}
			} else {
				if len(matches) != 0 {
					t.Errorf("expected no matches, got %d", len(matches))
				}
			}
		})
	}
}

func TestBloomFilterSafeTokens(t *testing.T) {
	repoTokens := []string{
		"functionName", "variableName", "https://api.example.com",
		"SomeStructName", "anotherIdentifier123",
	}

	bf := NewBloomFilter(1000, 0.001)
	for _, tok := range repoTokens {
		bf.Add([]byte(tok))
	}

	// Known tokens should be in filter
	for _, tok := range repoTokens {
		if !bf.Test([]byte(tok)) {
			t.Errorf("repo token %q should be in filter", tok)
		}
	}

	// Novel secrets should not be in filter (high probability)
	novelSecrets := []string{
		"AKIAIOSFODNN7EXAMPLE",
		"ghp_1234567890abcdefghijklmnopqrstuvwxyz",
		"sk-live-4eC39HqLyjWDarjtT1zdp7dc",
	}
	falsePositives := 0
	for _, s := range novelSecrets {
		if bf.Test([]byte(s)) {
			falsePositives++
		}
	}
	if falsePositives > 0 {
		t.Errorf("unexpected false positives: %d", falsePositives)
	}
}

func TestScanBundleSerialization(t *testing.T) {
	var rules []*Rule
	for _, r := range BuiltinRules {
		rules = append(rules, r)
	}
	bundle := BuildScanBundle(rules, nil)

	data, err := bundle.Marshal()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	restored, err := UnmarshalScanBundle(data)
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	testInput := []byte("my key is AKIAIOSFODNN7EXAMPLE ok")
	origHits := bundle.HotScan(testInput)
	restoredHits := restored.HotScan(testInput)

	if len(origHits) != len(restoredHits) {
		t.Errorf("hits mismatch: orig=%d, restored=%d", len(origHits), len(restoredHits))
	}
}

func TestScanBundleHotPathSkipsCleanData(t *testing.T) {
	var rules []*Rule
	for _, r := range BuiltinRules {
		rules = append(rules, r)
	}
	bundle := BuildScanBundle(rules, nil)

	cleanInputs := []string{
		`func main() { fmt.Println("hello") }`,
		`import "net/http"`,
		`for i := 0; i < 100; i++ {`,
		`// This is a comment about authentication`,
		`var config = map[string]string{}`,
	}

	for _, input := range cleanInputs {
		hits := bundle.HotScan([]byte(input))
		if len(hits) != 0 {
			t.Errorf("clean input should not trigger hot path: %s (got %d hits)", input, len(hits))
		}
	}
}

func TestScanBundleDetectsSecrets(t *testing.T) {
	var rules []*Rule
	for _, r := range BuiltinRules {
		rules = append(rules, r)
	}
	bundle := BuildScanBundle(rules, nil)

	dirtyInputs := []struct {
		name  string
		input string
	}{
		{"aws key", "key=AKIAIOSFODNN7EXAMPLE"},
		{"github pat", "token=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"},
		{"private key", "-----BEGIN RSA PRIVATE KEY-----"},
		{"postgres conn", "postgres://admin:secret@db:5432/mydb"},
	}

	for _, tt := range dirtyInputs {
		t.Run(tt.name, func(t *testing.T) {
			hits := bundle.HotScan([]byte(tt.input))
			if len(hits) == 0 {
				t.Errorf("should detect secret in: %s", tt.input)
			}
		})
	}
}

func TestBuildBloomFilterFromRepo(t *testing.T) {
	dir := t.TempDir()

	// Create some files
	for i := 0; i < 10; i++ {
		content := []byte(strings.Repeat("var x = 42\n", 10))
		os.WriteFile(filepath.Join(dir, "file"+string(rune('0'+i))+".go"), content, 0644)
	}

	bf := BuildBloomFilterFromRepo(dir)
	if bf.Cap() == 0 {
		t.Error("bloom filter should have non-zero capacity")
	}
}

func TestBloomFilterCapacity(t *testing.T) {
	bf := NewBloomFilter(1000, 0.001)
	if bf.Cap() == 0 {
		t.Error("capacity should be > 0")
	}
	if bf.K() == 0 {
		t.Error("K should be > 0")
	}
}

func TestBloomFilterBytes(t *testing.T) {
	bf := NewBloomFilter(100, 0.01)
	bf.Add([]byte("test"))

	data := bf.Bytes()
	restored := BloomFilterFromBytes(data, bf.K())

	if !restored.Test([]byte("test")) {
		t.Error("restored filter should contain 'test'")
	}
}
