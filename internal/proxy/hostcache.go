package proxy

import (
	"sync"
	"time"
)

// Verdict represents a host-level verdict.
type Verdict int

const (
	// Unknown means the host hasn't been seen before.
	Unknown Verdict = iota
	// Allow means the host is allowed.
	Allow
	// Block means the host is blocked.
	Block
)

// HostCache caches host-level allow/block decisions.
type HostCache struct {
	mu      sync.RWMutex
	allowed map[string]time.Time
	blocked map[string]struct{}
	ttl     time.Duration
}

// NewHostCache creates a new host cache. If ttl is 0, entries never expire.
func NewHostCache(ttl time.Duration) *HostCache {
	return &HostCache{
		allowed: make(map[string]time.Time),
		blocked: make(map[string]struct{}),
		ttl:     ttl,
	}
}

// NewHostCacheWithAllowlist creates a host cache pre-populated with allowed hosts.
func NewHostCacheWithAllowlist(ttl time.Duration, hosts []string) *HostCache {
	hc := NewHostCache(ttl)
	for _, h := range hosts {
		hc.Allow(h)
	}
	return hc
}

// Check returns the cached verdict for a host.
func (hc *HostCache) Check(host string) Verdict {
	hc.mu.RLock()
	defer hc.mu.RUnlock()

	if _, ok := hc.blocked[host]; ok {
		return Block
	}
	if t, ok := hc.allowed[host]; ok {
		if hc.ttl > 0 && time.Now().After(t) {
			return Unknown
		}
		return Allow
	}
	return Unknown
}

// Allow marks a host as allowed.
func (hc *HostCache) Allow(host string) {
	hc.mu.Lock()
	defer hc.mu.Unlock()

	var expiry time.Time
	if hc.ttl > 0 {
		expiry = time.Now().Add(hc.ttl)
	} else {
		expiry = time.Now().Add(100 * 365 * 24 * time.Hour) // effectively never
	}
	hc.allowed[host] = expiry
}

// Block marks a host as blocked.
func (hc *HostCache) Block(host string) {
	hc.mu.Lock()
	defer hc.mu.Unlock()
	hc.blocked[host] = struct{}{}
}
