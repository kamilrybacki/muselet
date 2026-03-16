package scanner

import (
	"strings"
	"testing"

	"github.com/kamilrybacki/muselet/internal"
)

func BenchmarkHotPathCleanData(b *testing.B) {
	var rules []*Rule
	for _, r := range BuiltinRules {
		rules = append(rules, r)
	}
	bundle := BuildScanBundle(rules, nil)
	chunk := []byte(strings.Repeat("func main() { fmt.Println(x) }\n", 128))

	b.ResetTimer()
	b.SetBytes(int64(len(chunk)))
	for i := 0; i < b.N; i++ {
		bundle.HotScan(chunk)
	}
}

func BenchmarkHotPathWithSecret(b *testing.B) {
	var rules []*Rule
	for _, r := range BuiltinRules {
		rules = append(rules, r)
	}
	bundle := BuildScanBundle(rules, nil)
	chunk := []byte("normal text AKIAIOSFODNN7EXAMPLE more text\n")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		bundle.HotScan(chunk)
	}
}

func BenchmarkBloomFilterLookup(b *testing.B) {
	bf := NewBloomFilter(100_000, 0.001)
	for i := 0; i < 100_000; i++ {
		bf.Add([]byte(strings.Repeat("a", 20)))
	}
	token := []byte("novel_token_not_in_filter_at_all")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		bf.Test(token)
	}
}

func BenchmarkAhoCorasickScan(b *testing.B) {
	prefixes := []string{"AKIA", "ghp_", "gho_", "-----BEGIN", "sk-live-", "postgres://",
		"mysql://", "mongodb://", "redis://", "amqp://", "Bearer ", "Basic "}
	ac := BuildAhoCorasick(prefixes)
	chunk := []byte(strings.Repeat("normal code without any secret prefixes at all\n", 100))

	b.ResetTimer()
	b.SetBytes(int64(len(chunk)))
	for i := 0; i < b.N; i++ {
		ac.FindAll(chunk)
	}
}

func BenchmarkFullScannerScan(b *testing.B) {
	s := NewDefaultScanner()
	chunk := []byte(strings.Repeat("var x = 42; func foo() { return bar(x) }\n", 100))

	b.ResetTimer()
	b.SetBytes(int64(len(chunk)))
	for i := 0; i < b.N; i++ {
		s.ScanBytes(chunk, "stdout")
	}
}

func BenchmarkShannonEntropy(b *testing.B) {
	token := []byte("aK8jR2mP9xQ4wL7nB3vF6yT1uH5sD0eC")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ShannonEntropy(token)
	}
}

func BenchmarkContextAnalysis(b *testing.B) {
	analyzer := NewContextAnalyzer()
	match := internal.Match{RuleID: "aws-access-key", Matched: "AKIAIOSFODNN7EXAMPLE", Offset: 100, Category: "credentials"}
	content := []byte(strings.Repeat("x", 200) + "AKIAIOSFODNN7EXAMPLE" + strings.Repeat("y", 200))
	input := internal.ContextInput{FilePath: "src/config.go", Content: content, Vector: internal.VectorStdout}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		analyzer.Analyze(match, input)
	}
}
