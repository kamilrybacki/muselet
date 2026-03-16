package proxy

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kamilrybacki/muselet/internal/scanner"
)

func TestProxyBlocksSecretInPostBody(t *testing.T) {
	s := scanner.NewDefaultScanner()
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer target.Close()

	// Use full host:port for both allowlist and Host header
	targetHost := strings.TrimPrefix(target.URL, "http://")
	targetHostname := strings.Split(targetHost, ":")[0]

	proxy := NewDLPProxy(s, ProxyConfig{
		AllowedHosts: []string{targetHostname},
	})
	proxyServer := httptest.NewServer(proxy)
	defer proxyServer.Close()

	// Clean request — should pass
	// Set Host to full host:port so proxy can forward
	req, _ := http.NewRequest("POST", proxyServer.URL, strings.NewReader("just normal data"))
	req.Host = targetHost // full host:port
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("clean request: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Errorf("clean request: want 200, got %d", resp.StatusCode)
	}

	// Request with secret in body — should be blocked
	req, _ = http.NewRequest("POST", proxyServer.URL, strings.NewReader("key=AKIAIOSFODNN7EXAMPLE"))
	req.Host = targetHost
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("dirty request: %v", err)
	}
	if resp.StatusCode != 403 {
		t.Errorf("dirty request: want 403, got %d", resp.StatusCode)
	}
}

func TestProxyBlocksUnknownHost(t *testing.T) {
	s := scanner.NewDefaultScanner()
	proxy := NewDLPProxy(s, ProxyConfig{
		AllowedHosts: []string{"api.anthropic.com"},
	})
	proxyServer := httptest.NewServer(proxy)
	defer proxyServer.Close()

	req, _ := http.NewRequest("GET", proxyServer.URL+"/steal", nil)
	req.Host = "evil-exfil-server.com"
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	if resp.StatusCode != 403 {
		t.Errorf("want 403 for unknown host, got %d", resp.StatusCode)
	}
}

func TestProxySNIInspection(t *testing.T) {
	s := scanner.NewDefaultScanner()
	proxy := NewDLPProxy(s, ProxyConfig{
		AllowedHosts: []string{"good.example.com"},
		TLSMode:      SNIOnly,
	})

	verdict := proxy.EvaluateCONNECT("good.example.com:443")
	if verdict != Allow {
		t.Errorf("want Allow for good host, got %v", verdict)
	}

	verdict = proxy.EvaluateCONNECT("evil.example.com:443")
	if verdict == Allow {
		t.Error("should not Allow unknown host")
	}
}

func TestProxyAllowsGetWithoutBody(t *testing.T) {
	s := scanner.NewDefaultScanner()
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("OK"))
	}))
	defer target.Close()

	targetHost := strings.TrimPrefix(target.URL, "http://")
	targetHostname := strings.Split(targetHost, ":")[0]

	proxy := NewDLPProxy(s, ProxyConfig{
		AllowedHosts: []string{targetHostname},
	})
	proxyServer := httptest.NewServer(proxy)
	defer proxyServer.Close()

	req, _ := http.NewRequest("GET", proxyServer.URL+"/api/data", nil)
	req.Host = targetHost
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Errorf("want 200, got %d", resp.StatusCode)
	}
}
