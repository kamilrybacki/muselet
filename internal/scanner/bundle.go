package scanner

import (
	"bytes"
	"encoding/gob"
	"hash/fnv"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"unicode"

	"github.com/kamilrybacki/muselet/internal"
)

// ScanBundle is a compiled, optimized representation of the policy for hot-path scanning.
type ScanBundle struct {
	LiteralPrefixes *AhoCorasick
	SafeFilter      *BloomFilter
	CriticalRules   []*Rule
	PolicyHash      string
	mu              sync.RWMutex
}

// BuildScanBundle compiles a policy into a scan bundle.
func BuildScanBundle(rules []*Rule, safeFilter *BloomFilter) *ScanBundle {
	// Extract literal prefixes from rules
	var prefixes []string
	prefixMap := map[string]bool{
		"AKIA":        true,
		"ghp_":        true,
		"gho_":        true,
		"ghu_":        true,
		"-----BEGIN":  true,
		"sk-live-":    true,
		"sk-test-":    true,
		"sk_live_":    true,
		"sk_test_":    true,
		"pk_live_":    true,
		"pk_test_":    true,
		"postgres://": true,
		"mysql://":    true,
		"mongodb://":  true,
		"redis://":    true,
		"amqp://":     true,
		"mssql://":    true,
		"xoxb-":       true,
		"xoxp-":       true,
		"xoxa-":       true,
		"AIza":        true,
	}

	for p := range prefixMap {
		prefixes = append(prefixes, p)
	}

	ac := BuildAhoCorasick(prefixes)

	// Select critical rules (highest confidence, fastest patterns)
	var critical []*Rule
	for _, r := range rules {
		if r.Severity == internal.SeverityCritical || r.Severity == internal.SeverityHigh {
			critical = append(critical, r)
		}
	}

	// Compute policy hash
	h := fnv.New64a()
	for _, r := range rules {
		h.Write([]byte(r.ID))
		h.Write([]byte(r.Pattern))
	}

	if safeFilter == nil {
		safeFilter = NewBloomFilter(1000, 0.001)
	}

	return &ScanBundle{
		LiteralPrefixes: ac,
		SafeFilter:      safeFilter,
		CriticalRules:   critical,
		PolicyHash:      string(h.Sum(nil)),
	}
}

// HotScan performs the fast in-agent scan using bloom filter + Aho-Corasick + critical regexes.
func (sb *ScanBundle) HotScan(data []byte) []internal.Match {
	sb.mu.RLock()
	defer sb.mu.RUnlock()

	// Step 1: Check bloom filter for tokens - if all tokens are known-safe, skip
	tokens := tokenizeForBloom(data)
	allSafe := true
	for _, tok := range tokens {
		if len(tok) >= 8 && !sb.SafeFilter.Test(tok) {
			allSafe = false
			break
		}
	}
	if allSafe && len(tokens) > 0 {
		return nil
	}

	// Step 2: Aho-Corasick for literal prefixes
	acMatches := sb.LiteralPrefixes.FindAll(data)
	if len(acMatches) == 0 {
		return nil
	}

	// Step 3: Run critical regexes only on regions around AC matches
	var results []internal.Match
	for _, acm := range acMatches {
		// Extract a window around the AC match
		start := acm.Offset
		end := acm.Offset + 256 // check up to 256 bytes after the prefix
		if end > len(data) {
			end = len(data)
		}
		window := data[start:end]

		for _, rule := range sb.CriticalRules {
			hits := rule.Scan(window)
			for i := range hits {
				hits[i].Offset += start // adjust offset to full data
				results = append(results, hits[i])
			}
		}
	}

	return deduplicateMatches(results)
}

// Marshal serializes the scan bundle.
func (sb *ScanBundle) Marshal() ([]byte, error) {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)

	data := scanBundleData{
		Prefixes:   sb.LiteralPrefixes.Patterns(),
		BloomData:  sb.SafeFilter.Bytes(),
		BloomK:     sb.SafeFilter.K(),
		PolicyHash: sb.PolicyHash,
	}
	for _, r := range sb.CriticalRules {
		data.Rules = append(data.Rules, ruleData{
			ID:       r.ID,
			Pattern:  r.Pattern,
			Category: r.Category,
			Severity: string(r.Severity),
			Action:   string(r.DefaultAction),
		})
	}
	if err := enc.Encode(data); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// UnmarshalScanBundle deserializes a scan bundle.
func UnmarshalScanBundle(data []byte) (*ScanBundle, error) {
	var sbd scanBundleData
	dec := gob.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(&sbd); err != nil {
		return nil, err
	}

	ac := BuildAhoCorasick(sbd.Prefixes)
	bf := BloomFilterFromBytes(sbd.BloomData, sbd.BloomK)

	var rules []*Rule
	for _, rd := range sbd.Rules {
		r := &Rule{
			ID:            rd.ID,
			Pattern:       rd.Pattern,
			Category:      rd.Category,
			Severity:      internal.Severity(rd.Severity),
			DefaultAction: internal.Action(rd.Action),
		}
		_ = r.Compile()
		rules = append(rules, r)
	}

	return &ScanBundle{
		LiteralPrefixes: ac,
		SafeFilter:      bf,
		CriticalRules:   rules,
		PolicyHash:      sbd.PolicyHash,
	}, nil
}

type scanBundleData struct {
	Prefixes   []string
	BloomData  []byte
	BloomK     uint
	PolicyHash string
	Rules      []ruleData
}

type ruleData struct {
	ID       string
	Pattern  string
	Category string
	Severity string
	Action   string
}

// BuildBloomFilterFromRepo scans a repository and builds a bloom filter of known tokens.
func BuildBloomFilterFromRepo(repoPath string) *BloomFilter {
	bf := NewBloomFilter(100_000, 0.001)

	_ = filepath.Walk(repoPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			base := filepath.Base(path)
			if base == ".git" || base == "node_modules" || base == "vendor" || base == "__pycache__" {
				return filepath.SkipDir
			}
			return nil
		}
		// Skip binary/large files
		if info.Size() > 1<<20 { // 1MB
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		tokens := tokenizeForBloom(data)
		for _, tok := range tokens {
			if len(tok) >= 8 {
				bf.Add(tok)
			}
		}
		return nil
	})
	return bf
}

func tokenizeForBloom(data []byte) [][]byte {
	var tokens [][]byte
	start := -1
	for i, b := range data {
		if isBloomTokenChar(b) {
			if start == -1 {
				start = i
			}
		} else {
			if start != -1 {
				tokens = append(tokens, data[start:i])
				start = -1
			}
		}
	}
	if start != -1 {
		tokens = append(tokens, data[start:])
	}
	return tokens
}

func isBloomTokenChar(b byte) bool {
	r := rune(b)
	return unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_' || r == '-' || r == '.' || r == '/' || r == '+' || r == '='
}

func deduplicateMatches(matches []internal.Match) []internal.Match {
	if len(matches) <= 1 {
		return matches
	}
	seen := make(map[string]bool)
	var result []internal.Match
	for _, m := range matches {
		key := m.RuleID + ":" + strings.Repeat("0", m.Offset)
		if key == "" {
			key = m.Matched
		}
		// Use offset as unique key
		oKey := string(rune(m.Offset)) + m.RuleID
		if !seen[oKey] {
			seen[oKey] = true
			result = append(result, m)
		}
	}
	return result
}
