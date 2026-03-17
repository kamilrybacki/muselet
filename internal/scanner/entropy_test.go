package scanner

import (
	"strings"
	"testing"
)

func TestShannonEntropy(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantRange [2]float64
	}{
		{"empty string", "", [2]float64{0, 0}},
		{"single char repeated", "aaaaaaaaaa", [2]float64{0, 0.01}},
		{"low entropy english", "hello world", [2]float64{2.5, 3.5}},
		{"hex string medium", "deadbeef01234567", [2]float64{3.5, 4.2}},
		{"base64 secret high", "aK8jR2mP9xQ4wL7nB3vF6yT1uH5sD0eC", [2]float64{4.2, 5.0}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ShannonEntropy([]byte(tt.input))
			if got < tt.wantRange[0] || got > tt.wantRange[1] {
				t.Errorf("ShannonEntropy(%q) = %f, want in [%f, %f]",
					tt.input, got, tt.wantRange[0], tt.wantRange[1])
			}
		})
	}
}

func TestEntropyScanner(t *testing.T) {
	s := NewEntropyScanner(EntropyConfig{
		Threshold: 4.5,
		MinLength: 20,
		MaxLength: 128,
	})

	tests := []struct {
		name     string
		input    string
		wantHits int
	}{
		{"high entropy 32-char token", "aK8jR2mP9xQ4wL7nB3vF6yT1uH5sD0e", 1},
		{"short high-entropy", "aK8jR2", 0},
		{"long low-entropy", strings.Repeat("abc", 20), 0},
		{"english sentence", "the quick brown fox jumps over the lazy dog", 0},
		{"file path", "/usr/local/bin/some-program-name", 0},
		{"repeated pattern", "abcabcabcabcabcabcabcabc", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hits := s.Scan([]byte(tt.input))
			if len(hits) != tt.wantHits {
				t.Errorf("want %d hits, got %d", tt.wantHits, len(hits))
			}
		})
	}
}

func TestEntropyDeterministic(t *testing.T) {
	input := []byte("aK8jR2mP9xQ4wL7nB3vF6yT1uH5sD0e")
	first := ShannonEntropy(input)
	for i := 0; i < 100; i++ {
		got := ShannonEntropy(input)
		if got != first {
			t.Errorf("iteration %d: got %f, want %f", i, got, first)
		}
	}
}

func TestEntropyScannerMaxLength(t *testing.T) {
	s := NewEntropyScanner(EntropyConfig{
		Threshold: 3.0,
		MinLength: 5,
		MaxLength: 10,
	})

	// Token of length 15 — exceeds MaxLength, should not match
	hits := s.Scan([]byte("aK8jR2mP9xQ4wL7"))
	if len(hits) != 0 {
		t.Error("should not match tokens exceeding MaxLength")
	}
}
