package scanner

import (
	"path/filepath"
	"regexp"
	"strings"

	"github.com/kamilrybacki/muselet/internal"
)

// ContextAnalyzer evaluates match context to adjust confidence.
type ContextAnalyzer struct {
	markerPattern *regexp.Regexp
}

// NewContextAnalyzer creates a new context analyzer.
func NewContextAnalyzer() *ContextAnalyzer {
	return &ContextAnalyzer{
		markerPattern: regexp.MustCompile(`(?i)\b(test|example|dummy|fake|mock|sample|placeholder|xxx|todo|fixme)\b`),
	}
}

// Analyze evaluates a match in context and returns a signal.
func (ca *ContextAnalyzer) Analyze(match internal.Match, input internal.ContextInput) internal.ContextSignal {
	signal := internal.ContextSignal{}

	// File risk
	signal.FileRisk = ClassifyPathRisk(input.FilePath)

	// Vector risk
	signal.VectorRisk = classifyVectorRisk(input.Vector)

	// Nearby markers
	if len(input.Content) > 0 && match.Offset >= 0 {
		signal.NearbyMarkers = FindNearbyMarkers(input.Content, match.Offset, 200)
	}

	// Calculate confidence
	signal.Confidence = calculateConfidence(signal, match)

	return signal
}

// ClassifyPathRisk classifies a file path's risk level.
func ClassifyPathRisk(path string) internal.RiskLevel {
	if path == "" {
		return internal.RiskMedium
	}

	lower := strings.ToLower(path)
	base := filepath.Base(lower)

	// High risk files
	if strings.HasPrefix(base, ".env") ||
		base == "credentials.json" ||
		base == "secrets.yaml" || base == "secrets.yml" ||
		strings.Contains(lower, "/secrets/") {
		return internal.RiskHigh
	}

	// Low risk paths
	if strings.HasPrefix(lower, "test") || strings.HasPrefix(lower, "tests/") ||
		strings.Contains(lower, "/test/") || strings.Contains(lower, "/tests/") ||
		strings.Contains(lower, "/fixtures/") || strings.Contains(lower, "/testdata/") ||
		strings.Contains(lower, "/mock") ||
		strings.HasPrefix(lower, "vendor/") || strings.Contains(lower, "/vendor/") ||
		strings.HasPrefix(lower, "node_modules/") || strings.Contains(lower, "/node_modules/") ||
		strings.HasSuffix(lower, "_test.go") || strings.HasSuffix(lower, ".test.js") ||
		strings.HasSuffix(lower, ".test.ts") || strings.HasSuffix(lower, "_test.py") ||
		strings.HasSuffix(lower, ".spec.js") || strings.HasSuffix(lower, ".spec.ts") ||
		base == "readme.md" || base == "readme.txt" ||
		strings.HasSuffix(lower, ".md") {
		return internal.RiskLow
	}

	// Medium risk: CI configs
	if strings.Contains(lower, ".github/") || strings.Contains(lower, ".gitlab-ci") {
		return internal.RiskMedium
	}

	// Default
	return internal.RiskMedium
}

func classifyVectorRisk(v internal.Vector) internal.RiskLevel {
	switch v {
	case internal.VectorNetwork:
		return internal.RiskHigh
	case internal.VectorPatch:
		return internal.RiskHigh
	case internal.VectorStdout, internal.VectorStderr:
		return internal.RiskMedium
	case internal.VectorFilesystem:
		return internal.RiskMedium
	default:
		return internal.RiskMedium
	}
}

// FindNearbyMarkers finds suppression markers near a match position.
func FindNearbyMarkers(content []byte, matchPos int, windowSize int) []string {
	start := matchPos - windowSize
	if start < 0 {
		start = 0
	}
	end := matchPos + windowSize
	if end > len(content) {
		end = len(content)
	}

	window := content[start:end]
	markers := regexp.MustCompile(`(?i)\b(test|testing|example|dummy|fake|mock|sample|placeholder)\b`)
	found := markers.FindAllString(string(window), -1)

	// Deduplicate and lowercase
	seen := make(map[string]bool)
	var unique []string
	for _, m := range found {
		lower := strings.ToLower(m)
		if !seen[lower] {
			seen[lower] = true
			unique = append(unique, lower)
		}
	}
	return unique
}

func calculateConfidence(signal internal.ContextSignal, match internal.Match) float64 {
	// Base confidence from the rule's category
	base := 0.7
	switch match.Category {
	case "credentials":
		base = 0.85
	case "entropy":
		base = 0.5
	case "infrastructure":
		base = 0.5
	case "pii":
		base = 0.4
	}

	// Adjust for file risk
	switch signal.FileRisk {
	case internal.RiskHigh:
		base += 0.1
	case internal.RiskLow:
		base -= 0.3
	}

	// Adjust for vector risk
	switch signal.VectorRisk {
	case internal.RiskHigh:
		base += 0.1
	case internal.RiskLow:
		base -= 0.1
	}

	// Adjust for nearby markers
	if len(signal.NearbyMarkers) > 0 {
		base -= 0.2 * float64(len(signal.NearbyMarkers))
	}

	// Clamp
	if base < 0.0 {
		base = 0.0
	}
	if base > 1.0 {
		base = 1.0
	}
	return base
}
