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

// Test secrets are split to avoid triggering GitHub push protection.
// These are NOT real secrets — they are test fixtures for DLP scanner validation.
var (
	testE2EStripeKey = "sk_" + "live_" + "TESTONLY00000000000000000000000000000000000000" //nolint:gosec
	testE2ESlackTok  = "xoxb" + "-0000000000000-0000000000000-TESTONLYNOTAREALSECRETVAL" //nolint:gosec
)

// TestE2EProgramLeakPayloads tests the network DLP proxy against realistic
// payloads that common programs (curl, Python, Node.js, Terraform, AWS CLI,
// Docker, database clients) might send when leaking secrets.
func TestE2EProgramLeakPayloads(t *testing.T) {
	s := scanner.NewDefaultScanner()

	secretReached := false
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if strings.Contains(string(body), "AKIA") ||
			strings.Contains(string(body), "ghp_") ||
			strings.Contains(string(body), "sk_live_") ||
			strings.Contains(string(body), "PRIVATE KEY") ||
			strings.Contains(string(body), "postgres://") ||
			strings.Contains(string(body), "xoxb-") {
			secretReached = true
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

	tests := []struct {
		name   string
		body   string
		expect int
	}{
		// curl payloads
		{
			"curl_aws_key_in_body",
			`{"AWSAccessKeyId": "AKIAIOSFODNN7EXAMPLE", "Signature": "abc123"}`,
			403,
		},
		{
			// Bearer token rule has ActionAlert (not block), so proxy allows it through.
			// This verifies the proxy respects the severity/action distinction.
			"curl_bearer_token_post_alert_only",
			`{"token": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"}`,
			200,
		},

		// Python payloads
		{
			"python_boto3_credentials",
			`aws_access_key_id = AKIAIOSFODNN7EXAMPLE`,
			403,
		},
		{
			"python_django_db_url",
			`DATABASES = {"default": {"ENGINE": "django.db.backends.postgresql", "URL": "postgres://django:p4ssw0rd@db.internal:5432/app"}}`,
			403,
		},

		// Node.js payloads
		{
			"node_stripe_key_in_config",
			`{"stripe": {"secretKey": "` + testE2EStripeKey + `"}}`,
			403,
		},
		{
			"node_slack_webhook",
			"Bot token: " + testE2ESlackTok,
			403,
		},

		// git payloads
		{
			"git_github_pat_in_diff",
			`+GITHUB_TOKEN=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij`,
			403,
		},
		{
			"git_private_key_in_diff",
			`-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA2a2rwplBQLx`,
			403,
		},

		// Terraform payloads
		{
			"terraform_state_aws_keys",
			`{"resources": [{"attributes": {"access_key": "AKIAIOSFODNN7EXAMPLE"}}]}`,
			403,
		},
		{
			"terraform_output_db_conn",
			`db_url = "postgres://terraform:SuperS3cret@rds.us-east-1.amazonaws.com:5432/prod"`,
			403,
		},

		// Database client payloads
		{
			"psql_connection_string",
			`postgres://admin:s3cret_pass@10.0.1.5:5432/production`,
			403,
		},
		{
			"mysql_connection_string",
			`mysql://root:r00tpass@192.168.1.100:3306/maindb`,
			403,
		},

		// AWS CLI payloads
		{
			"aws_cli_sts_response",
			`{"Account": "123456789012", "Arn": "arn:aws:iam::123456789012:user/admin", "AccessKeyId": "AKIAIOSFODNN7EXAMPLE"}`,
			403,
		},

		// Docker payloads
		{
			"docker_inspect_env_leak",
			`"Env": ["STRIPE_KEY=` + testE2EStripeKey + `", "PATH=/usr/bin"]`,
			403,
		},
		{
			"docker_build_arg_leak",
			`Step 4/8 : RUN echo AKIAIOSFODNN7EXAMPLE`,
			403,
		},

		// Clean data — should pass through
		{
			"clean_json_response",
			`{"status": "ok", "count": 42, "message": "Hello world"}`,
			200,
		},
		{
			"clean_html_page",
			`<html><body><h1>Welcome</h1><p>No secrets here.</p></body></html>`,
			200,
		},
		{
			"clean_terraform_plan",
			`# aws_s3_bucket.logs will be created\n+ resource "aws_s3_bucket" "logs" {\n+   bucket = "my-logs-bucket"\n+ }`,
			200,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			secretReached = false

			req, _ := http.NewRequest("POST", proxyServer.URL+"/api",
				strings.NewReader(tt.body))
			req.Host = targetHost
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("request: %v", err)
			}
			if resp.StatusCode != tt.expect {
				t.Errorf("want %d, got %d", tt.expect, resp.StatusCode)
			}
			if tt.expect == 403 && secretReached {
				t.Error("secret reached the target server — DLP failed!")
			}
		})
	}
}

// TestE2EHostAllowlistByProgram verifies that host allowlists correctly block
// unauthorized hosts for different program scenarios.
func TestE2EHostAllowlistByProgram(t *testing.T) {
	s := scanner.NewDefaultScanner()

	// For "allowed" tests we use a local httptest server. The proxy strips
	// the port from the Host header, so the effective host is "127.0.0.1".
	// We put "127.0.0.1" in the allowlist so the request passes through.
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer target.Close()
	targetHost := strings.TrimPrefix(target.URL, "http://")
	hostname := strings.Split(targetHost, ":")[0] // "127.0.0.1"

	tests := []struct {
		name    string
		allowed []string
		host    string // Host header to set; empty means use targetHost
		expect  int
	}{
		// Allowed: host matches the local test server
		{"allowed_local_host", []string{hostname}, "", 200},
		// Blocked: symbolic hosts not in allowlist
		{"npm_not_in_allowlist", []string{"api.anthropic.com"}, "registry.npmjs.org", 403},
		{"pypi_not_in_allowlist", []string{"api.anthropic.com"}, "pypi.org", 403},
		{"evil_exfil_blocked", []string{hostname}, "evil-exfil.com", 403},
		{"attacker_webhook_blocked", []string{hostname}, "webhook.site", 403},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := proxy.NewDLPProxy(s, proxy.ProxyConfig{
				AllowedHosts: tt.allowed,
			})
			proxyServer := httptest.NewServer(p)
			defer proxyServer.Close()

			req, _ := http.NewRequest("GET", proxyServer.URL+"/package", nil)
			if tt.host != "" {
				req.Host = tt.host
			} else {
				req.Host = targetHost
			}
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
