package e2e

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kamilrybacki/muselet/internal/proxy"
	"github.com/kamilrybacki/muselet/internal/scanner"
)

// TestE2ENetworkProxyBlocking tests the full network proxy flow without Docker.
func TestE2ENetworkProxyBlocking(t *testing.T) {
	s := scanner.NewDefaultScanner()

	secretReceived := false
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if strings.Contains(string(body), "AKIAIOSFODNN7EXAMPLE") {
			secretReceived = true
		}
		w.WriteHeader(200)
	}))
	defer target.Close()

	targetHost := strings.TrimPrefix(target.URL, "http://")
	hostname := strings.Split(targetHost, ":")[0]

	p := proxy.NewDLPProxy(s, proxy.ProxyConfig{
		AllowedHosts: []string{hostname},
	})
	proxyServer := httptest.NewServer(p)
	defer proxyServer.Close()

	req, _ := http.NewRequest("POST", proxyServer.URL+"/steal",
		strings.NewReader("key=AKIAIOSFODNN7EXAMPLE"))
	req.Host = targetHost // full host:port
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}

	if resp.StatusCode != 403 {
		t.Errorf("want 403, got %d", resp.StatusCode)
	}
	if secretReceived {
		t.Error("secret reached the target server — DLP failed!")
	}
}

// TestE2ENetworkProxyAllowsCleanTraffic ensures clean data passes through.
func TestE2ENetworkProxyAllowsCleanTraffic(t *testing.T) {
	s := scanner.NewDefaultScanner()

	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("OK"))
	}))
	defer target.Close()

	targetHost := strings.TrimPrefix(target.URL, "http://")
	hostname := strings.Split(targetHost, ":")[0]

	p := proxy.NewDLPProxy(s, proxy.ProxyConfig{
		AllowedHosts: []string{hostname},
	})
	proxyServer := httptest.NewServer(p)
	defer proxyServer.Close()

	req, _ := http.NewRequest("POST", proxyServer.URL+"/api",
		strings.NewReader("normal data without secrets"))
	req.Host = targetHost
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Errorf("clean request should pass: want 200, got %d", resp.StatusCode)
	}
}

// TestE2ENetworkHostBlocking tests that unknown hosts are blocked.
func TestE2ENetworkHostBlocking(t *testing.T) {
	s := scanner.NewDefaultScanner()

	p := proxy.NewDLPProxy(s, proxy.ProxyConfig{
		AllowedHosts: []string{"api.anthropic.com"},
	})
	proxyServer := httptest.NewServer(p)
	defer proxyServer.Close()

	req, _ := http.NewRequest("GET", proxyServer.URL+"/steal", nil)
	req.Host = "evil-exfil-server.com"
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	if resp.StatusCode != 403 {
		t.Errorf("non-allowlisted host should be blocked: want 403, got %d", resp.StatusCode)
	}
}

// TestE2EMultipleSecretTypes tests detection of various secret formats.
func TestE2EMultipleSecretTypes(t *testing.T) {
	s := scanner.NewDefaultScanner()

	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer target.Close()

	targetHost := strings.TrimPrefix(target.URL, "http://")
	hostname := strings.Split(targetHost, ":")[0]

	p := proxy.NewDLPProxy(s, proxy.ProxyConfig{
		AllowedHosts: []string{hostname},
	})
	proxyServer := httptest.NewServer(p)
	defer proxyServer.Close()

	secrets := []struct {
		name   string
		body   string
		expect int
	}{
		{"aws key", "AKIAIOSFODNN7EXAMPLE", 403},
		{"github pat", "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij", 403},
		{"postgres conn", "postgres://admin:secret@db:5432/prod", 403},
		{"private key", "-----BEGIN RSA PRIVATE KEY-----", 403},
		{"clean data", "just a normal message", 200},
	}

	for _, tt := range secrets {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := http.NewRequest("POST", proxyServer.URL, strings.NewReader(tt.body))
			req.Host = targetHost
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("request: %v", err)
			}
			if resp.StatusCode != tt.expect {
				t.Errorf("want %d, got %d", tt.expect, resp.StatusCode)
			}
		})
	}
}
