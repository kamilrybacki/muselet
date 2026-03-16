package proxy

import (
	"fmt"
	"testing"
)

func TestDNSTunnelingSuspiciousLongLabel(t *testing.T) {
	detector := NewDNSTunnelDetector(DNSConfig{
		MaxLabelLength:   50,
		MaxQueryRate:     10,
		EntropyThreshold: 4.0,
	})

	tests := []struct {
		name       string
		query      string
		suspicious bool
	}{
		{"normal query", "api.anthropic.com", false},
		{"simple domain", "github.com", false},
		{"long encoded subdomain", "aGVsbG8gdGhpcyBpcyBhIHNlY3JldCBtZXNzYWdlIHRoYXQgaXMgdG9vIGxvbmc.evil.com", true},
		{"high entropy subdomain", "xK9mR2pQ7wL4nB8vF3yT6u.evil.com", true},
		{"short subdomain", "www.google.com", false},
		{"single label", "localhost", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := detector.IsSuspicious(tt.query)
			if got != tt.suspicious {
				t.Errorf("IsSuspicious(%q) = %v, want %v", tt.query, got, tt.suspicious)
			}
		})
	}
}

func TestDNSTunnelingRateDetection(t *testing.T) {
	detector := NewDNSTunnelDetector(DNSConfig{
		MaxLabelLength:   50,
		MaxQueryRate:     10,
		EntropyThreshold: 4.0,
	})

	// Record 15 queries to the same base domain
	for i := 0; i < 15; i++ {
		detector.RecordQuery(fmt.Sprintf("q%d.exfil.evil.com", i))
	}

	if !detector.IsRateSuspicious("evil.com") {
		t.Error("should be rate-suspicious after 15 queries (threshold 10)")
	}

	// Different domain should not be suspicious
	if detector.IsRateSuspicious("google.com") {
		t.Error("google.com should not be rate-suspicious")
	}
}

func TestDNSExtractBaseDomain(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"api.anthropic.com", "anthropic.com"},
		{"sub.deep.example.com", "example.com"},
		{"example.com", "example.com"},
		{"localhost", "localhost"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := extractBaseDomain(tt.input)
			if got != tt.want {
				t.Errorf("extractBaseDomain(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}
