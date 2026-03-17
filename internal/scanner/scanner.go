package scanner

import (
	"bytes"
	"sync"

	"github.com/kamilrybacki/muselet/internal"
)

// Scanner is the full DLP scanner combining pattern matching, entropy analysis, and context.
type Scanner struct {
	rules           []*Rule
	entropyScanner  *EntropyScanner
	contextAnalyzer *ContextAnalyzer
	categories      CategoryConfig
	mu              sync.RWMutex
}

// CategoryConfig enables/disables detection categories.
type CategoryConfig struct {
	Credentials    bool
	Infrastructure bool
	PII            bool
	Proprietary    bool
}

// DefaultCategoryConfig returns the default category configuration.
func DefaultCategoryConfig() CategoryConfig {
	return CategoryConfig{
		Credentials:    true,
		Infrastructure: true,
		PII:            false,
		Proprietary:    false,
	}
}

// NewScanner creates a new scanner with the given rules and config.
func NewScanner(rules []*Rule, entropyConfig EntropyConfig, categories CategoryConfig) *Scanner {
	return &Scanner{
		rules:           rules,
		entropyScanner:  NewEntropyScanner(entropyConfig),
		contextAnalyzer: NewContextAnalyzer(),
		categories:      categories,
	}
}

// NewDefaultScanner creates a scanner with built-in rules and default config.
func NewDefaultScanner() *Scanner {
	var rules []*Rule
	for _, r := range BuiltinRules {
		rules = append(rules, r)
	}
	return NewScanner(rules, DefaultEntropyConfig(), DefaultCategoryConfig())
}

// ScanBytes scans raw bytes and returns all results.
func (s *Scanner) ScanBytes(data []byte, vector internal.Vector) []internal.ScanResult {
	return s.ScanFile("", data, vector)
}

// ScanFile scans a file's content and returns results with context analysis.
func (s *Scanner) ScanFile(filePath string, content []byte, vector internal.Vector) []internal.ScanResult {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var results []internal.ScanResult

	// Run pattern rules
	for _, rule := range s.rules {
		if !s.isCategoryEnabled(rule.Category) {
			continue
		}
		matches := rule.Scan(content)
		for _, match := range matches {
			ctx := s.contextAnalyzer.Analyze(match, internal.ContextInput{
				FilePath: filePath,
				Content:  content,
				Vector:   vector,
			})
			results = append(results, internal.ScanResult{
				Match:      match,
				FilePath:   filePath,
				Line:       lineNumber(content, match.Offset),
				Vector:     vector,
				Confidence: ctx.Confidence,
				Action:     rule.DefaultAction,
				Severity:   rule.Severity,
			})
		}
	}

	// Run entropy scanner
	entropyMatches := s.entropyScanner.Scan(content)
	for _, match := range entropyMatches {
		ctx := s.contextAnalyzer.Analyze(match, internal.ContextInput{
			FilePath: filePath,
			Content:  content,
			Vector:   vector,
		})
		results = append(results, internal.ScanResult{
			Match:      match,
			FilePath:   filePath,
			Line:       lineNumber(content, match.Offset),
			Vector:     vector,
			Confidence: ctx.Confidence,
			Action:     internal.ActionAlert,
			Severity:   internal.SeverityMedium,
		})
	}

	return results
}

func (s *Scanner) isCategoryEnabled(category string) bool {
	switch category {
	case "credentials":
		return s.categories.Credentials
	case "infrastructure":
		return s.categories.Infrastructure
	case "pii":
		return s.categories.PII
	case "proprietary":
		return s.categories.Proprietary
	default:
		return true
	}
}

func lineNumber(content []byte, offset int) int {
	if offset <= 0 || offset > len(content) {
		return 1
	}
	return bytes.Count(content[:offset], []byte("\n")) + 1
}

// StdoutPipeline processes streaming stdout data with overlap for split-secret detection.
type StdoutPipeline struct {
	bundle      *ScanBundle
	overlapSize int
	prevTail    []byte
}

// NewStdoutPipeline creates a new stdout pipeline.
func NewStdoutPipeline(bundle *ScanBundle, overlapSize int) *StdoutPipeline {
	return &StdoutPipeline{
		bundle:      bundle,
		overlapSize: overlapSize,
	}
}

// ProcessChunk processes a chunk of stdout data, using overlap to catch split secrets.
func (sp *StdoutPipeline) ProcessChunk(chunk []byte) []internal.Match {
	var scanData []byte
	overlapLen := 0
	if len(sp.prevTail) > 0 {
		scanData = append(sp.prevTail, chunk...)
		overlapLen = len(sp.prevTail)
	} else {
		scanData = chunk
	}

	// Save tail for next chunk
	if len(chunk) >= sp.overlapSize {
		sp.prevTail = make([]byte, sp.overlapSize)
		copy(sp.prevTail, chunk[len(chunk)-sp.overlapSize:])
	} else {
		sp.prevTail = make([]byte, len(chunk))
		copy(sp.prevTail, chunk)
	}

	hits := sp.bundle.HotScan(scanData)

	// Adjust offsets to account for overlap prefix and filter duplicates from previous chunk
	var filtered []internal.Match
	for _, h := range hits {
		// Only include matches that touch the new chunk
		if h.Offset+h.Length > overlapLen {
			adjusted := h
			if h.Offset >= overlapLen {
				adjusted.Offset -= overlapLen
			}
			filtered = append(filtered, adjusted)
		}
	}

	return filtered
}
