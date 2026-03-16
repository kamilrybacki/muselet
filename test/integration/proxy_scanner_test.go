package integration

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kamilrybacki/muselet/internal/proxy"
	"github.com/kamilrybacki/muselet/internal/scanner"
)

func TestProxyScannerIntegration(t *testing.T) {
	s := scanner.NewDefaultScanner()

	// Start target server
	targetCalled := false
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetCalled = true
		w.WriteHeader(200)
	}))
	defer target.Close()

	host := strings.TrimPrefix(target.URL, "http://")
	hostname := strings.Split(host, ":")[0]

	p := proxy.NewDLPProxy(s, proxy.ProxyConfig{
		AllowedHosts: []string{hostname},
	})
	proxyServer := httptest.NewServer(p)
	defer proxyServer.Close()

	// Clean POST — should reach target
	targetCalled = false
	req, _ := http.NewRequest("POST", proxyServer.URL, strings.NewReader("normal data"))
	req.Host = host // full host:port so proxy can forward
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("clean request: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Errorf("clean request: want 200, got %d", resp.StatusCode)
	}
	if !targetCalled {
		t.Error("target should have been called for clean request")
	}

	// Dirty POST — should be blocked
	targetCalled = false
	req, _ = http.NewRequest("POST", proxyServer.URL,
		strings.NewReader("secret=AKIAIOSFODNN7EXAMPLE"))
	req.Host = host
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("dirty request: %v", err)
	}
	if resp.StatusCode != 403 {
		t.Errorf("dirty request: want 403, got %d", resp.StatusCode)
	}
	if targetCalled {
		t.Error("target should NOT have been called for dirty request")
	}
}

func TestProxyDNSIntegration(t *testing.T) {
	detector := proxy.NewDNSTunnelDetector(proxy.DNSConfig{
		MaxLabelLength:   50,
		MaxQueryRate:     5,
		EntropyThreshold: 4.0,
	})

	// Normal queries should pass
	if detector.IsSuspicious("api.anthropic.com") {
		t.Error("normal domain should not be suspicious")
	}

	// Encoded data in subdomain
	if !detector.IsSuspicious("aGVsbG8gdGhpcyBpcyBhIHNlY3JldCBtZXNzYWdlIHRoYXQgaXMgdG9vIGxvbmc.evil.com") {
		t.Error("long subdomain should be suspicious")
	}
}
