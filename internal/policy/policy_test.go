package policy

import (
	"testing"

	"github.com/kamilrybacki/muselet/internal"
)

func TestPolicyLoadingValid(t *testing.T) {
	yaml := `
version: 1
rules:
  - id: aws-access-key
    pattern: "AKIA[0-9A-Z]{16}"
    action: block
    severity: critical
vectors:
  network:
    enabled: true
    allowed_hosts:
      - "api.anthropic.com"
`
	p, err := ParsePolicy([]byte(yaml))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if p.Version != 1 {
		t.Errorf("version: want 1, got %d", p.Version)
	}
	if len(p.Rules) != 1 {
		t.Errorf("rules: want 1, got %d", len(p.Rules))
	}
	if p.Rules[0].Action != internal.ActionBlock {
		t.Errorf("action: want block, got %s", p.Rules[0].Action)
	}
	if !p.Vectors.Network.Enabled {
		t.Error("network should be enabled")
	}
	if len(p.Vectors.Network.AllowedHosts) != 1 || p.Vectors.Network.AllowedHosts[0] != "api.anthropic.com" {
		t.Errorf("allowed hosts: %v", p.Vectors.Network.AllowedHosts)
	}
}

func TestPolicyLoadingInvalidYAML(t *testing.T) {
	_, err := ParsePolicy([]byte("not: [valid: yaml"))
	if err == nil {
		t.Error("expected error for invalid YAML")
	}
}

func TestPolicyLoadingUnsupportedVersion(t *testing.T) {
	_, err := ParsePolicy([]byte("version: 99"))
	if err == nil {
		t.Error("expected error for unsupported version")
	}
}

func TestPolicyLoadingInvalidAction(t *testing.T) {
	yaml := `
version: 1
rules:
  - id: test
    pattern: "foo"
    action: explode
`
	_, err := ParsePolicy([]byte(yaml))
	if err == nil {
		t.Error("expected error for invalid action")
	}
}

func TestPolicyLoadingInvalidRegex(t *testing.T) {
	yaml := `
version: 1
rules:
  - id: test
    pattern: "[invalid"
    action: block
`
	_, err := ParsePolicy([]byte(yaml))
	if err == nil {
		t.Error("expected error for invalid regex")
	}
}

func TestPolicyMerging(t *testing.T) {
	baseYaml := `
version: 1
rules:
  - id: aws-access-key
    pattern: "AKIA[0-9A-Z]{16}"
    action: block
    severity: critical
categories:
  credentials:
    enabled: true
  pii:
    enabled: false
`
	overrideYaml := `
version: 1
overrides:
  patterns:
    - rule: aws-access-key
      paths: ["tests/**"]
      action: suppress
categories:
  pii:
    enabled: true
`
	basePol, err := ParsePolicy([]byte(baseYaml))
	if err != nil {
		t.Fatalf("parse base: %v", err)
	}
	overPol, err := ParsePolicy([]byte(overrideYaml))
	if err != nil {
		t.Fatalf("parse override: %v", err)
	}
	merged := MergePolicies(basePol, overPol)

	// Override should suppress aws key in tests
	if !merged.IsRuleSuppressed("aws-access-key", "tests/fixture.go") {
		t.Error("aws-access-key should be suppressed in tests/**")
	}

	// But not in src
	if merged.IsRuleSuppressed("aws-access-key", "src/main.go") {
		t.Error("aws-access-key should NOT be suppressed in src/")
	}

	// PII should now be enabled
	if !merged.Categories.PII.Enabled {
		t.Error("PII should be enabled after merge")
	}
}

func TestPolicyHierarchy(t *testing.T) {
	builtin := DefaultPolicy()

	globalYaml := `
version: 1
vectors:
  network:
    allowed_hosts: ["corp-api.internal.com"]
`
	repoYaml := `
version: 1
overrides:
  patterns:
    - rule: generic-api-key
      paths: ["docs/**"]
      action: suppress
`
	global, _ := ParsePolicy([]byte(globalYaml))
	repo, _ := ParsePolicy([]byte(repoYaml))

	cliFlags := CLIOverrides{
		AllowHosts:    []string{"webhook.site"},
		SuppressRules: []string{"high-entropy-string"},
	}

	final := ResolvePolicyHierarchy(builtin, global, repo, cliFlags)

	// CLI: webhook.site allowed
	found := false
	for _, h := range final.Vectors.Network.AllowedHosts {
		if h == "webhook.site" {
			found = true
		}
	}
	if !found {
		t.Error("webhook.site should be in allowed hosts from CLI")
	}

	// Global: corp API allowed
	found = false
	for _, h := range final.Vectors.Network.AllowedHosts {
		if h == "corp-api.internal.com" {
			found = true
		}
	}
	if !found {
		t.Error("corp-api.internal.com should be in allowed hosts from global")
	}

	// Builtin: anthropic always allowed
	found = false
	for _, h := range final.Vectors.Network.AllowedHosts {
		if h == "api.anthropic.com" {
			found = true
		}
	}
	if !found {
		t.Error("api.anthropic.com should be in allowed hosts from builtin")
	}

	// CLI: entropy suppressed globally
	if !final.IsRuleSuppressed("high-entropy-string", "any/path") {
		t.Error("high-entropy-string should be suppressed from CLI override")
	}

	// Repo: generic-api-key suppressed in docs
	if !final.IsRuleSuppressed("generic-api-key", "docs/example.md") {
		t.Error("generic-api-key should be suppressed in docs/**")
	}
	if final.IsRuleSuppressed("generic-api-key", "src/auth.go") {
		t.Error("generic-api-key should NOT be suppressed in src/")
	}
}

func TestPolicyEvaluate(t *testing.T) {
	yaml := `
version: 1
overrides:
  patterns:
    - rule: aws-access-key
      paths: ["tests/**"]
      action: suppress
`
	pol, _ := ParsePolicy([]byte(yaml))

	// In tests — suppressed
	result := pol.Evaluate(
		internal.Match{RuleID: "aws-access-key"},
		internal.ContextInput{FilePath: "tests/fixture.go", Vector: internal.VectorFilesystem},
	)
	if result.Action != internal.ActionSuppress {
		t.Errorf("want suppress in tests, got %s", result.Action)
	}

	// Outside tests — no override (empty action)
	result = pol.Evaluate(
		internal.Match{RuleID: "aws-access-key"},
		internal.ContextInput{FilePath: "src/main.go", Vector: internal.VectorNetwork},
	)
	if result.Action == internal.ActionSuppress {
		t.Error("should not suppress in src/")
	}
}

func TestDefaultPolicy(t *testing.T) {
	p := DefaultPolicy()
	if p.Version != 1 {
		t.Errorf("version: want 1, got %d", p.Version)
	}
	if !p.Vectors.Network.Enabled {
		t.Error("network should be enabled by default")
	}
	if !p.Vectors.Filesystem.Enabled {
		t.Error("filesystem should be enabled by default")
	}
	if !p.Vectors.Stdout.Enabled {
		t.Error("stdout should be enabled by default")
	}
	if !p.Vectors.Patches.Enabled {
		t.Error("patches should be enabled by default")
	}
	if p.Categories.PII != nil && p.Categories.PII.Enabled {
		t.Error("PII should be disabled by default")
	}
	if p.Interactive.TimeoutSeconds != 30 {
		t.Errorf("interactive timeout: want 30, got %d", p.Interactive.TimeoutSeconds)
	}
}

func TestPolicyVersionZeroDefaultsToOne(t *testing.T) {
	yaml := `
rules:
  - id: test
    pattern: "test"
    action: alert
`
	p, err := ParsePolicy([]byte(yaml))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if p.Version != 1 {
		t.Errorf("version: want 1 (default), got %d", p.Version)
	}
}
