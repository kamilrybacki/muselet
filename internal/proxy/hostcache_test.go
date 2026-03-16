package proxy

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestHostCacheAllowCaching(t *testing.T) {
	hc := NewHostCache(1 * time.Minute)
	if v := hc.Check("api.example.com"); v != Unknown {
		t.Errorf("want Unknown, got %v", v)
	}

	hc.Allow("api.example.com")
	if v := hc.Check("api.example.com"); v != Allow {
		t.Errorf("want Allow, got %v", v)
	}
}

func TestHostCacheBlockCaching(t *testing.T) {
	hc := NewHostCache(1 * time.Minute)
	hc.Block("evil.com")
	if v := hc.Check("evil.com"); v != Block {
		t.Errorf("want Block, got %v", v)
	}
}

func TestHostCacheExpiry(t *testing.T) {
	hc := NewHostCache(10 * time.Millisecond)
	hc.Allow("api.example.com")
	if v := hc.Check("api.example.com"); v != Allow {
		t.Errorf("want Allow before expiry, got %v", v)
	}

	time.Sleep(15 * time.Millisecond)
	if v := hc.Check("api.example.com"); v != Unknown {
		t.Errorf("want Unknown after expiry, got %v", v)
	}
}

func TestHostCacheBlockNeverExpires(t *testing.T) {
	hc := NewHostCache(10 * time.Millisecond)
	hc.Block("evil.com")
	time.Sleep(15 * time.Millisecond)
	if v := hc.Check("evil.com"); v != Block {
		t.Errorf("blocks should persist: want Block, got %v", v)
	}
}

func TestHostCacheConcurrentAccess(t *testing.T) {
	hc := NewHostCache(1 * time.Minute)
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(2)
		host := fmt.Sprintf("host-%d.com", i)
		go func() { defer wg.Done(); hc.Allow(host) }()
		go func() { defer wg.Done(); hc.Check(host) }()
	}
	wg.Wait()
	// No race, no panic
}

func TestHostCachePrePopulatedAllowlist(t *testing.T) {
	hc := NewHostCacheWithAllowlist(1*time.Minute, []string{
		"api.anthropic.com", "github.com", "registry.npmjs.org",
	})
	if v := hc.Check("api.anthropic.com"); v != Allow {
		t.Errorf("want Allow, got %v", v)
	}
	if v := hc.Check("github.com"); v != Allow {
		t.Errorf("want Allow, got %v", v)
	}
	if v := hc.Check("attacker.com"); v != Unknown {
		t.Errorf("want Unknown, got %v", v)
	}
}

func TestHostCacheZeroTTL(t *testing.T) {
	hc := NewHostCache(0) // 0 means no expiry
	hc.Allow("test.com")
	// Should still be allowed even after a brief sleep
	time.Sleep(10 * time.Millisecond)
	if v := hc.Check("test.com"); v != Allow {
		t.Errorf("want Allow with zero TTL, got %v", v)
	}
}
