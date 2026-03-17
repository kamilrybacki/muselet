package proxy

import (
	"strings"
	"sync"
	"time"

	"github.com/kamilrybacki/muselet/internal/scanner"
)

// DNSConfig configures DNS tunneling detection.
type DNSConfig struct {
	MaxLabelLength   int
	MaxQueryRate     int // per second per base domain
	EntropyThreshold float64
}

// DefaultDNSConfig returns sensible defaults.
func DefaultDNSConfig() DNSConfig {
	return DNSConfig{
		MaxLabelLength:   50,
		MaxQueryRate:     10,
		EntropyThreshold: 4.0,
	}
}

// DNSTunnelDetector detects potential DNS-based data exfiltration.
type DNSTunnelDetector struct {
	config     DNSConfig
	queryRates map[string]*rateBucket
	mu         sync.Mutex
}

type rateBucket struct {
	count     int
	windowEnd time.Time
}

// NewDNSTunnelDetector creates a new DNS tunnel detector.
func NewDNSTunnelDetector(config DNSConfig) *DNSTunnelDetector {
	return &DNSTunnelDetector{
		config:     config,
		queryRates: make(map[string]*rateBucket),
	}
}

// IsSuspicious checks if a DNS query name looks like tunneling.
func (d *DNSTunnelDetector) IsSuspicious(queryName string) bool {
	labels := strings.Split(queryName, ".")
	if len(labels) < 2 {
		return false
	}

	// Check for unusually long subdomain labels
	for i, label := range labels {
		if i == len(labels)-1 {
			break // skip TLD
		}
		if len(label) > d.config.MaxLabelLength {
			return true
		}
		// Check entropy of subdomain labels
		if len(label) > 10 {
			entropy := scanner.ShannonEntropy([]byte(label))
			if entropy >= d.config.EntropyThreshold {
				return true
			}
		}
	}

	return false
}

// RecordQuery records a DNS query for rate analysis.
func (d *DNSTunnelDetector) RecordQuery(queryName string) {
	d.mu.Lock()
	defer d.mu.Unlock()

	baseDomain := extractBaseDomain(queryName)
	now := time.Now()

	bucket, exists := d.queryRates[baseDomain]
	if !exists || now.After(bucket.windowEnd) {
		d.queryRates[baseDomain] = &rateBucket{
			count:     1,
			windowEnd: now.Add(time.Second),
		}
		return
	}
	bucket.count++
}

// IsRateSuspicious checks if the query rate for a domain is suspicious.
func (d *DNSTunnelDetector) IsRateSuspicious(baseDomain string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()

	bucket, exists := d.queryRates[baseDomain]
	if !exists {
		return false
	}
	return bucket.count > d.config.MaxQueryRate
}

func extractBaseDomain(queryName string) string {
	labels := strings.Split(queryName, ".")
	if len(labels) <= 2 {
		return queryName
	}
	return strings.Join(labels[len(labels)-2:], ".")
}
