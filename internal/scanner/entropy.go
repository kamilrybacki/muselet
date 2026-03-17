package scanner

import (
	"math"
	"unicode"

	"github.com/kamilrybacki/muselet/internal"
)

// EntropyConfig holds configuration for entropy-based detection.
type EntropyConfig struct {
	Threshold float64
	MinLength int
	MaxLength int
}

// DefaultEntropyConfig returns sensible defaults for entropy detection.
func DefaultEntropyConfig() EntropyConfig {
	return EntropyConfig{
		Threshold: 4.5,
		MinLength: 20,
		MaxLength: 128,
	}
}

// EntropyScanner detects high-entropy strings that may be secrets.
type EntropyScanner struct {
	config EntropyConfig
}

// NewEntropyScanner creates a new entropy scanner.
func NewEntropyScanner(config EntropyConfig) *EntropyScanner {
	return &EntropyScanner{config: config}
}

// Scan splits input into tokens and flags high-entropy ones.
func (es *EntropyScanner) Scan(data []byte) []internal.Match {
	tokens := tokenize(data)
	var matches []internal.Match
	for _, tok := range tokens {
		if len(tok.value) < es.config.MinLength || len(tok.value) > es.config.MaxLength {
			continue
		}
		entropy := ShannonEntropy([]byte(tok.value))
		if entropy >= es.config.Threshold {
			matches = append(matches, internal.Match{
				RuleID:   "high-entropy-string",
				Offset:   tok.offset,
				Length:   len(tok.value),
				Matched:  tok.value,
				Category: "entropy",
			})
		}
	}
	return matches
}

// ShannonEntropy calculates the Shannon entropy of a byte slice.
func ShannonEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}
	freq := make(map[byte]int)
	for _, b := range data {
		freq[b]++
	}
	length := float64(len(data))
	entropy := 0.0
	for _, count := range freq {
		p := float64(count) / length
		if p > 0 {
			entropy -= p * math.Log2(p)
		}
	}
	return entropy
}

type token struct {
	value  string
	offset int
}

func tokenize(data []byte) []token {
	var tokens []token
	start := -1
	for i, b := range data {
		if isTokenChar(rune(b)) {
			if start == -1 {
				start = i
			}
		} else {
			if start != -1 {
				tokens = append(tokens, token{
					value:  string(data[start:i]),
					offset: start,
				})
				start = -1
			}
		}
	}
	if start != -1 {
		tokens = append(tokens, token{
			value:  string(data[start:]),
			offset: start,
		})
	}
	return tokens
}

func isTokenChar(r rune) bool {
	return unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_' || r == '-' || r == '.' || r == '/' || r == '+' || r == '='
}
