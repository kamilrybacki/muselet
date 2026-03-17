package policy

import (
	"fmt"
	"path/filepath"
	"regexp"

	"github.com/kamilrybacki/muselet/internal"
	"gopkg.in/yaml.v3"
)

// Policy represents the full DLP policy configuration.
type Policy struct {
	Version      int                `yaml:"version"`
	Rules        []PolicyRule       `yaml:"rules,omitempty"`
	Categories   CategorySettings   `yaml:"categories,omitempty"`
	Vectors      VectorSettings     `yaml:"vectors,omitempty"`
	Overrides    Overrides          `yaml:"overrides,omitempty"`
	Interactive  InteractiveConfig  `yaml:"interactive,omitempty"`
	LearningMode bool              `yaml:"learning_mode,omitempty"`

	// compiled overrides
	compiledOverrides []compiledOverride
}

// PolicyRule defines a rule in the policy file.
type PolicyRule struct {
	ID          string          `yaml:"id"`
	Description string          `yaml:"description,omitempty"`
	Pattern     string          `yaml:"pattern"`
	Type        string          `yaml:"type,omitempty"` // "regex" or "entropy"
	Action      internal.Action `yaml:"action"`
	Severity    internal.Severity `yaml:"severity,omitempty"`
	Category    string          `yaml:"category,omitempty"`
}

// CategorySettings enables/disables categories.
type CategorySettings struct {
	Credentials    *CategoryConfig `yaml:"credentials,omitempty"`
	Infrastructure *CategoryConfig `yaml:"infrastructure,omitempty"`
	PII            *CategoryConfig `yaml:"pii,omitempty"`
	Proprietary    *CategoryConfig `yaml:"proprietary,omitempty"`
}

// CategoryConfig is per-category configuration.
type CategoryConfig struct {
	Enabled bool            `yaml:"enabled"`
	Action  internal.Action `yaml:"action,omitempty"`
}

// VectorSettings configures per-vector behavior.
type VectorSettings struct {
	Network    NetworkConfig    `yaml:"network,omitempty"`
	Filesystem FilesystemConfig `yaml:"filesystem,omitempty"`
	Stdout     StdoutConfig     `yaml:"stdout,omitempty"`
	Patches    PatchConfig      `yaml:"patches,omitempty"`
}

// NetworkConfig configures network DLP.
type NetworkConfig struct {
	Enabled          bool     `yaml:"enabled"`
	AllowedHosts     []string `yaml:"allowed_hosts,omitempty"`
	BlockedHosts     []string `yaml:"blocked_hosts,omitempty"`
	InspectTLS       bool     `yaml:"inspect_tls,omitempty"`
	BlockDNSTunneling bool    `yaml:"block_dns_tunneling,omitempty"`
}

// FilesystemConfig configures filesystem DLP.
type FilesystemConfig struct {
	Enabled    bool     `yaml:"enabled"`
	WatchPaths []string `yaml:"watch_paths,omitempty"`
	Excludes   []string `yaml:"excludes,omitempty"`
}

// StdoutConfig configures stdout DLP.
type StdoutConfig struct {
	Enabled        bool   `yaml:"enabled"`
	Mode           string `yaml:"mode,omitempty"` // "speculative", "synchronous", "async"
	HoldTimeoutMs  int    `yaml:"hold_timeout_ms,omitempty"`
}

// PatchConfig configures patch export DLP.
type PatchConfig struct {
	Enabled          bool `yaml:"enabled"`
	ScanBeforeExport bool `yaml:"scan_before_export,omitempty"`
}

// InteractiveConfig configures interactive prompts.
type InteractiveConfig struct {
	TimeoutSeconds int             `yaml:"timeout_seconds,omitempty"`
	OnTimeout      internal.Action `yaml:"on_timeout,omitempty"`
}

// Overrides configures rule and pattern overrides.
type Overrides struct {
	Network  NetworkOverride   `yaml:"network,omitempty"`
	Patterns []PatternOverride `yaml:"patterns,omitempty"`
}

// NetworkOverride overrides network settings.
type NetworkOverride struct {
	AllowedHosts []string `yaml:"allowed_hosts,omitempty"`
}

// PatternOverride suppresses or changes a rule for specific paths.
type PatternOverride struct {
	Rule   string          `yaml:"rule"`
	Paths  []string        `yaml:"paths,omitempty"`
	Match  string          `yaml:"match,omitempty"`
	Action internal.Action `yaml:"action"`
}

type compiledOverride struct {
	RuleID      string
	PathGlobs   []string
	MatchRegex  *regexp.Regexp
	Action      internal.Action
}

// CLIOverrides represents overrides passed via CLI flags.
type CLIOverrides struct {
	AllowHosts    []string
	BlockHosts    []string
	SuppressRules []string
	LearningMode  bool
}

// ParsePolicy parses a YAML policy.
func ParsePolicy(data []byte) (*Policy, error) {
	var p Policy
	if err := yaml.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("parse policy YAML: %w", err)
	}

	if p.Version == 0 {
		p.Version = 1
	}
	if p.Version != 1 {
		return nil, fmt.Errorf("unsupported policy version: %d", p.Version)
	}

	// Validate rules
	for _, r := range p.Rules {
		if r.Action != "" && r.Action != internal.ActionAllow &&
			r.Action != internal.ActionAlert && r.Action != internal.ActionBlock &&
			r.Action != internal.ActionRedact && r.Action != internal.ActionSuppress {
			return nil, fmt.Errorf("rule %q: invalid action %q", r.ID, r.Action)
		}
		if r.Pattern != "" {
			if _, err := regexp.Compile(r.Pattern); err != nil {
				return nil, fmt.Errorf("rule %q: failed to compile pattern: %w", r.ID, err)
			}
		}
	}

	// Compile overrides
	for _, o := range p.Overrides.Patterns {
		co := compiledOverride{
			RuleID:    o.Rule,
			PathGlobs: o.Paths,
			Action:    o.Action,
		}
		if o.Match != "" {
			re, err := regexp.Compile(o.Match)
			if err != nil {
				return nil, fmt.Errorf("override for rule %q: invalid match pattern: %w", o.Rule, err)
			}
			co.MatchRegex = re
		}
		p.compiledOverrides = append(p.compiledOverrides, co)
	}

	return &p, nil
}

// DefaultPolicy returns the built-in default policy.
func DefaultPolicy() *Policy {
	return &Policy{
		Version: 1,
		Categories: CategorySettings{
			Credentials:    &CategoryConfig{Enabled: true},
			Infrastructure: &CategoryConfig{Enabled: true},
			PII:            &CategoryConfig{Enabled: false},
			Proprietary:    &CategoryConfig{Enabled: false},
		},
		Vectors: VectorSettings{
			Network: NetworkConfig{
				Enabled:           true,
				AllowedHosts:      []string{"api.anthropic.com", "github.com"},
				BlockDNSTunneling: true,
			},
			Filesystem: FilesystemConfig{
				Enabled:    true,
				WatchPaths: []string{"/workspace", "/tmp"},
				Excludes:   []string{".git/**"},
			},
			Stdout: StdoutConfig{
				Enabled:       true,
				Mode:          "speculative",
				HoldTimeoutMs: 5,
			},
			Patches: PatchConfig{
				Enabled:          true,
				ScanBeforeExport: true,
			},
		},
		Interactive: InteractiveConfig{
			TimeoutSeconds: 30,
			OnTimeout:      internal.ActionBlock,
		},
	}
}

// IsRuleSuppressed checks if a rule is suppressed for a given path.
func (p *Policy) IsRuleSuppressed(ruleID string, filePath string) bool {
	for _, o := range p.compiledOverrides {
		if o.RuleID != ruleID {
			continue
		}
		if o.Action != internal.ActionSuppress {
			continue
		}
		if len(o.PathGlobs) == 0 {
			return true
		}
		for _, glob := range o.PathGlobs {
			if matched, _ := filepath.Match(glob, filePath); matched {
				return true
			}
			// Also try as a prefix match for ** patterns
			if matchGlobStar(glob, filePath) {
				return true
			}
		}
	}
	return false
}

// Evaluate evaluates a match against the policy.
func (p *Policy) Evaluate(match internal.Match, ctx internal.ContextInput) internal.ScanResult {
	result := internal.ScanResult{
		Match:  match,
		Vector: ctx.Vector,
	}

	// Check overrides
	for _, o := range p.compiledOverrides {
		if o.RuleID != match.RuleID {
			continue
		}
		pathMatches := len(o.PathGlobs) == 0
		for _, glob := range o.PathGlobs {
			if matched, _ := filepath.Match(glob, ctx.FilePath); matched {
				pathMatches = true
				break
			}
			if matchGlobStar(glob, ctx.FilePath) {
				pathMatches = true
				break
			}
		}
		if pathMatches {
			result.Action = o.Action
			return result
		}
	}

	return result
}

// MergePolicies merges a base and override policy.
func MergePolicies(base, override *Policy) *Policy {
	merged := *base

	// Merge overrides
	merged.compiledOverrides = append(merged.compiledOverrides, override.compiledOverrides...)
	merged.Overrides.Patterns = append(merged.Overrides.Patterns, override.Overrides.Patterns...)

	// Merge allowed hosts
	if len(override.Overrides.Network.AllowedHosts) > 0 {
		merged.Vectors.Network.AllowedHosts = append(
			merged.Vectors.Network.AllowedHosts,
			override.Overrides.Network.AllowedHosts...,
		)
	}

	if len(override.Vectors.Network.AllowedHosts) > 0 {
		merged.Vectors.Network.AllowedHosts = append(
			merged.Vectors.Network.AllowedHosts,
			override.Vectors.Network.AllowedHosts...,
		)
	}

	// Merge categories
	if override.Categories.Credentials != nil {
		merged.Categories.Credentials = override.Categories.Credentials
	}
	if override.Categories.Infrastructure != nil {
		merged.Categories.Infrastructure = override.Categories.Infrastructure
	}
	if override.Categories.PII != nil {
		merged.Categories.PII = override.Categories.PII
	}
	if override.Categories.Proprietary != nil {
		merged.Categories.Proprietary = override.Categories.Proprietary
	}

	return &merged
}

// ResolvePolicyHierarchy resolves the full policy hierarchy.
func ResolvePolicyHierarchy(builtin, global, repo *Policy, cli CLIOverrides) *Policy {
	merged := builtin
	if global != nil {
		merged = MergePolicies(merged, global)
	}
	if repo != nil {
		merged = MergePolicies(merged, repo)
	}

	// Apply CLI overrides
	if len(cli.AllowHosts) > 0 {
		merged.Vectors.Network.AllowedHosts = append(
			merged.Vectors.Network.AllowedHosts, cli.AllowHosts...)
	}
	if len(cli.BlockHosts) > 0 {
		merged.Vectors.Network.BlockedHosts = append(
			merged.Vectors.Network.BlockedHosts, cli.BlockHosts...)
	}
	for _, ruleID := range cli.SuppressRules {
		merged.compiledOverrides = append(merged.compiledOverrides, compiledOverride{
			RuleID: ruleID,
			Action: internal.ActionSuppress,
		})
	}
	if cli.LearningMode {
		merged.LearningMode = true
	}

	return merged
}

// matchGlobStar handles ** glob patterns.
func matchGlobStar(pattern, path string) bool {
	// Handle patterns like "tests/**" or "docs/**"
	if len(pattern) > 3 && pattern[len(pattern)-3:] == "/**" {
		prefix := pattern[:len(pattern)-3]
		if len(path) > len(prefix) && path[:len(prefix)] == prefix && path[len(prefix)] == '/' {
			return true
		}
		return path == prefix
	}
	return false
}
