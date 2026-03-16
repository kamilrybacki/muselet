package proxy

import (
	"bytes"
	"io"
	"net/http"
	"strings"

	"github.com/kamilrybacki/muselet/internal"
	"github.com/kamilrybacki/muselet/internal/scanner"
)

// TLSMode defines the TLS inspection mode.
type TLSMode int

const (
	// SNIOnly inspects only the TLS SNI hostname.
	SNIOnly TLSMode = iota
	// FullMITM performs full TLS interception.
	FullMITM
)

// ProxyConfig configures the DLP proxy.
type ProxyConfig struct {
	AllowedHosts []string
	BlockedHosts []string
	TLSMode      TLSMode
}

// DLPProxy is an HTTP proxy that inspects requests for DLP violations.
type DLPProxy struct {
	scanner   *scanner.Scanner
	config    ProxyConfig
	hostCache *HostCache
	transport http.RoundTripper
}

// NewDLPProxy creates a new DLP proxy.
func NewDLPProxy(s *scanner.Scanner, config ProxyConfig) *DLPProxy {
	allowList := make([]string, len(config.AllowedHosts))
	copy(allowList, config.AllowedHosts)

	return &DLPProxy{
		scanner:   s,
		config:    config,
		hostCache: NewHostCacheWithAllowlist(0, allowList),
		transport: http.DefaultTransport,
	}
}

// ServeHTTP implements http.Handler.
func (p *DLPProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	host := extractHost(r)

	// Check host against allowlist/blocklist
	verdict := p.hostCache.Check(host)
	if verdict == Block {
		http.Error(w, "muselet: blocked by DLP policy", http.StatusForbidden)
		return
	}

	// Check blocked hosts
	for _, bh := range p.config.BlockedHosts {
		if host == bh {
			p.hostCache.Block(host)
			http.Error(w, "muselet: blocked by DLP policy", http.StatusForbidden)
			return
		}
	}

	// For unknown hosts, check body for secrets
	if verdict == Unknown {
		// Check if host is allowed
		isAllowed := false
		for _, ah := range p.config.AllowedHosts {
			if host == ah {
				isAllowed = true
				break
			}
		}
		if !isAllowed {
			http.Error(w, "muselet: host not in allowlist", http.StatusForbidden)
			return
		}
		p.hostCache.Allow(host)
	}

	// Scan request body
	if r.Body != nil && (r.Method == http.MethodPost || r.Method == http.MethodPut || r.Method == http.MethodPatch) {
		bodyBytes, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "muselet: failed to read request body", http.StatusBadGateway)
			return
		}
		r.Body.Close()

		results := p.scanner.ScanBytes(bodyBytes, internal.VectorNetwork)
		for _, result := range results {
			if result.Action == internal.ActionBlock {
				http.Error(w, "muselet: blocked - secret detected in request body", http.StatusForbidden)
				return
			}
		}

		// Restore body for forwarding
		r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		r.ContentLength = int64(len(bodyBytes))
	}

	// Forward the request
	outReq := r.Clone(r.Context())
	outReq.RequestURI = ""

	// If the URL doesn't have a host (e.g., when proxy receives a relative URL),
	// reconstruct from the Host header.
	if outReq.URL.Host == "" && r.Host != "" {
		scheme := "http"
		if r.TLS != nil {
			scheme = "https"
		}
		outReq.URL.Scheme = scheme
		outReq.URL.Host = r.Host
	}

	resp, err := p.transport.RoundTrip(outReq)
	if err != nil {
		http.Error(w, "muselet: upstream error: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Copy response headers and body
	for key, vals := range resp.Header {
		for _, v := range vals {
			w.Header().Add(key, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

// EvaluateCONNECT evaluates a CONNECT tunnel request by host.
func (p *DLPProxy) EvaluateCONNECT(hostPort string) Verdict {
	host := hostPort
	if idx := strings.LastIndex(hostPort, ":"); idx != -1 {
		host = hostPort[:idx]
	}
	return p.hostCache.Check(host)
}

func extractHost(r *http.Request) string {
	host := r.Host
	if host == "" && r.URL != nil {
		host = r.URL.Hostname()
	}
	// Remove port
	if idx := strings.LastIndex(host, ":"); idx != -1 {
		host = host[:idx]
	}
	return host
}
