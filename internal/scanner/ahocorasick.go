package scanner

import "sort"

// AhoCorasick implements a simple multi-pattern string matcher.
type AhoCorasick struct {
	patterns []string
}

// ACMatch represents a match found by Aho-Corasick.
type ACMatch struct {
	Pattern string
	Offset  int
}

// BuildAhoCorasick creates a new Aho-Corasick matcher from literal patterns.
func BuildAhoCorasick(patterns []string) *AhoCorasick {
	return &AhoCorasick{patterns: patterns}
}

// FindAll finds all pattern matches in the data.
func (ac *AhoCorasick) FindAll(data []byte) []ACMatch {
	if len(data) == 0 || len(ac.patterns) == 0 {
		return nil
	}

	var matches []ACMatch
	str := string(data)
	for _, pattern := range ac.patterns {
		pLen := len(pattern)
		if pLen == 0 || pLen > len(str) {
			continue
		}
		offset := 0
		for {
			idx := indexOf(str[offset:], pattern)
			if idx == -1 {
				break
			}
			matches = append(matches, ACMatch{
				Pattern: pattern,
				Offset:  offset + idx,
			})
			offset += idx + 1
		}
	}
	// Sort by offset so matches are returned in input order
	sort.Slice(matches, func(i, j int) bool {
		return matches[i].Offset < matches[j].Offset
	})
	return matches
}

// Patterns returns the patterns in this matcher.
func (ac *AhoCorasick) Patterns() []string {
	result := make([]string, len(ac.patterns))
	copy(result, ac.patterns)
	return result
}

func indexOf(s, substr string) int {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}
