package system

import (
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/kamilrybacki/muselet/internal/scanner"
)

func percentile(durations []time.Duration, pct int) time.Duration {
	if len(durations) == 0 {
		return 0
	}
	sorted := make([]time.Duration, len(durations))
	copy(sorted, durations)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	idx := len(sorted) * pct / 100
	if idx >= len(sorted) {
		idx = len(sorted) - 1
	}
	return sorted[idx]
}

func maxDuration(durations []time.Duration) time.Duration {
	if len(durations) == 0 {
		return 0
	}
	m := durations[0]
	for _, d := range durations[1:] {
		if d > m {
			m = d
		}
	}
	return m
}

func TestLatencyBudgetHotPathCleanData(t *testing.T) {
	var rules []*scanner.Rule
	for _, r := range scanner.BuiltinRules {
		rules = append(rules, r)
	}
	bundle := scanner.BuildScanBundle(rules, nil)

	// Generate clean chunks
	chunk := []byte(strings.Repeat("func main() { fmt.Println(x) }\n", 128)) // ~4KB
	n := 1000

	latencies := make([]time.Duration, n)
	for i := 0; i < n; i++ {
		start := time.Now()
		bundle.HotScan(chunk)
		latencies[i] = time.Since(start)
	}

	p50 := percentile(latencies, 50)
	p99 := percentile(latencies, 99)

	t.Logf("Hot path clean data: p50=%v p99=%v max=%v", p50, p99, maxDuration(latencies))

	// These are generous budgets — actual should be much faster
	if p50 > 1*time.Millisecond {
		t.Errorf("p50 too high: %v (budget: 1ms)", p50)
	}
	if p99 > 5*time.Millisecond {
		t.Errorf("p99 too high: %v (budget: 5ms)", p99)
	}
}

func TestLatencyBudgetHotPathWithSecrets(t *testing.T) {
	var rules []*scanner.Rule
	for _, r := range scanner.BuiltinRules {
		rules = append(rules, r)
	}
	bundle := scanner.BuildScanBundle(rules, nil)

	n := 100
	latencies := make([]time.Duration, n)
	for i := 0; i < n; i++ {
		chunk := []byte("line: key=AKIAIOSFODNN7EXAMPLE rest of output\n")
		start := time.Now()
		bundle.HotScan(chunk)
		latencies[i] = time.Since(start)
	}

	p50 := percentile(latencies, 50)
	t.Logf("Hot path dirty data: p50=%v max=%v", p50, maxDuration(latencies))

	if p50 > 5*time.Millisecond {
		t.Errorf("p50 too high: %v (budget: 5ms)", p50)
	}
}

func TestLatencyBudgetBundleCompilation(t *testing.T) {
	var rules []*scanner.Rule
	for _, r := range scanner.BuiltinRules {
		rules = append(rules, r)
	}

	start := time.Now()
	_ = scanner.BuildScanBundle(rules, nil)
	elapsed := time.Since(start)

	t.Logf("Bundle compilation: %v", elapsed)

	if elapsed > 500*time.Millisecond {
		t.Errorf("bundle compilation too slow: %v (budget: 500ms)", elapsed)
	}
}

func TestLatencyBudgetEntropyCalculation(t *testing.T) {
	token := []byte("aK8jR2mP9xQ4wL7nB3vF6yT1uH5sD0eC")
	n := 10000

	start := time.Now()
	for i := 0; i < n; i++ {
		scanner.ShannonEntropy(token)
	}
	elapsed := time.Since(start)
	perOp := elapsed / time.Duration(n)

	t.Logf("Shannon entropy: %v per op", perOp)

	if perOp > 50*time.Microsecond {
		t.Errorf("entropy calculation too slow: %v per op (budget: 50μs)", perOp)
	}
}

func TestLatencyBudgetBloomFilterBuild(t *testing.T) {
	// Simulate building a bloom filter with 100K tokens
	bf := scanner.NewBloomFilter(100_000, 0.001)

	start := time.Now()
	for i := 0; i < 100_000; i++ {
		token := []byte(strings.Repeat("a", 20))
		bf.Add(token)
	}
	elapsed := time.Since(start)

	t.Logf("Bloom filter 100K inserts: %v", elapsed)

	if elapsed > 2*time.Second {
		t.Errorf("bloom filter build too slow: %v (budget: 2s)", elapsed)
	}
}
