package scanner

import (
	"regexp"
	"strings"

	"github.com/kamilrybacki/muselet/internal"
)

// Rule defines a pattern-based detection rule.
type Rule struct {
	ID            string          `yaml:"id"`
	Description   string          `yaml:"description"`
	Pattern       string          `yaml:"pattern"`
	Category      string          `yaml:"category"`
	Severity      internal.Severity `yaml:"severity"`
	DefaultAction internal.Action `yaml:"action"`
	compiled      *regexp.Regexp
}

// Compile compiles the rule's regex pattern.
func (r *Rule) Compile() error {
	re, err := regexp.Compile(r.Pattern)
	if err != nil {
		return err
	}
	r.compiled = re
	return nil
}

// Scan scans input bytes and returns all matches.
func (r *Rule) Scan(data []byte) []internal.Match {
	if r.compiled == nil {
		return nil
	}
	locs := r.compiled.FindAllIndex(data, -1)
	if locs == nil {
		return nil
	}
	matches := make([]internal.Match, 0, len(locs))
	for _, loc := range locs {
		matched := string(data[loc[0]:loc[1]])
		// Skip matches that span newlines
		if strings.Contains(matched, "\n") {
			continue
		}
		matches = append(matches, internal.Match{
			RuleID:   r.ID,
			Offset:   loc[0],
			Length:   loc[1] - loc[0],
			Matched:  matched,
			Category: r.Category,
		})
	}
	return matches
}

// MatchesBytes returns true if the rule matches the input.
func (r *Rule) MatchesBytes(data []byte) bool {
	if r.compiled == nil {
		return false
	}
	return r.compiled.Match(data)
}

// BuiltinRules contains all built-in detection rules.
var BuiltinRules map[string]*Rule

func init() {
	BuiltinRules = make(map[string]*Rule)
	for i := range builtinRuleDefs {
		rule := &builtinRuleDefs[i]
		_ = rule.Compile()
		BuiltinRules[rule.ID] = rule
	}
}

var builtinRuleDefs = []Rule{
	// --- Credentials ---
	{
		ID:            "aws-access-key",
		Description:   "AWS Access Key ID",
		Pattern:       `AKIA[0-9A-Z]{16}`,
		Category:      "credentials",
		Severity:      internal.SeverityCritical,
		DefaultAction: internal.ActionBlock,
	},
	{
		ID:            "aws-secret-key",
		Description:   "AWS Secret Access Key",
		Pattern:       `(?i)(?:aws_secret_access_key|aws_secret|secret_key)\s*[:=]\s*['"]?([A-Za-z0-9/+=]{40})['"]?`,
		Category:      "credentials",
		Severity:      internal.SeverityCritical,
		DefaultAction: internal.ActionBlock,
	},
	{
		ID:            "github-pat",
		Description:   "GitHub Personal Access Token",
		Pattern:       `ghp_[a-zA-Z0-9]{36}`,
		Category:      "credentials",
		Severity:      internal.SeverityCritical,
		DefaultAction: internal.ActionBlock,
	},
	{
		ID:            "github-oauth",
		Description:   "GitHub OAuth Access Token",
		Pattern:       `gho_[a-zA-Z0-9]{36}`,
		Category:      "credentials",
		Severity:      internal.SeverityCritical,
		DefaultAction: internal.ActionBlock,
	},
	{
		ID:            "github-app-token",
		Description:   "GitHub App Token",
		Pattern:       `ghu_[a-zA-Z0-9]{36}`,
		Category:      "credentials",
		Severity:      internal.SeverityHigh,
		DefaultAction: internal.ActionBlock,
	},
	{
		ID:            "private-key",
		Description:   "Private Key Header",
		Pattern:       `-----BEGIN\s+(RSA|EC|OPENSSH|DSA|PGP)\s+PRIVATE\s+KEY-----`,
		Category:      "credentials",
		Severity:      internal.SeverityCritical,
		DefaultAction: internal.ActionBlock,
	},
	{
		ID:            "connection-string",
		Description:   "Database Connection String with Credentials",
		Pattern:       `(?i)(?:postgres|mysql|mongodb|redis|amqp|mssql)://[^\s:]+:[^\s@]+@[^\s]+`,
		Category:      "credentials",
		Severity:      internal.SeverityHigh,
		DefaultAction: internal.ActionBlock,
	},
	{
		ID:            "bearer-token",
		Description:   "Authorization Bearer Token",
		Pattern:       `(?i)(?:Authorization:\s*Bearer|Bearer)\s+[a-zA-Z0-9\-_.]{20,}`,
		Category:      "credentials",
		Severity:      internal.SeverityHigh,
		DefaultAction: internal.ActionAlert,
	},
	{
		ID:            "generic-api-key",
		Description:   "Generic API Key Assignment",
		Pattern:       `(?i)(?:api[_-]?key|apikey|api[_-]?secret|api[_-]?token)\s*[:=]\s*['"]?[a-zA-Z0-9]{20,}['"]?`,
		Category:      "credentials",
		Severity:      internal.SeverityMedium,
		DefaultAction: internal.ActionAlert,
	},
	{
		ID:            "slack-token",
		Description:   "Slack Token",
		Pattern:       `xox[bporas]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,34}`,
		Category:      "credentials",
		Severity:      internal.SeverityHigh,
		DefaultAction: internal.ActionBlock,
	},
	{
		ID:            "stripe-key",
		Description:   "Stripe API Key",
		Pattern:       `(?:sk|pk)_(?:live|test)_[a-zA-Z0-9]{24,}`,
		Category:      "credentials",
		Severity:      internal.SeverityHigh,
		DefaultAction: internal.ActionBlock,
	},
	{
		ID:            "google-api-key",
		Description:   "Google API Key",
		Pattern:       `AIza[0-9A-Za-z\-_]{35}`,
		Category:      "credentials",
		Severity:      internal.SeverityHigh,
		DefaultAction: internal.ActionBlock,
	},
	// --- Infrastructure ---
	{
		ID:            "private-ip",
		Description:   "Private IP Address",
		Pattern:       `(?:^|[^0-9])(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})(?:[^0-9]|$)`,
		Category:      "infrastructure",
		Severity:      internal.SeverityMedium,
		DefaultAction: internal.ActionAlert,
	},
	{
		ID:            "aws-arn",
		Description:   "AWS Resource ARN",
		Pattern:       `arn:aws:[a-z0-9\-]+:[a-z0-9\-]*:\d{12}:[a-zA-Z0-9\-_/:.]+`,
		Category:      "infrastructure",
		Severity:      internal.SeverityMedium,
		DefaultAction: internal.ActionAlert,
	},
	// --- PII ---
	{
		ID:            "email-address",
		Description:   "Email Address",
		Pattern:       `[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`,
		Category:      "pii",
		Severity:      internal.SeverityLow,
		DefaultAction: internal.ActionAlert,
	},
	{
		ID:            "ssn",
		Description:   "US Social Security Number",
		Pattern:       `\b\d{3}-\d{2}-\d{4}\b`,
		Category:      "pii",
		Severity:      internal.SeverityHigh,
		DefaultAction: internal.ActionBlock,
	},
	{
		ID:            "credit-card",
		Description:   "Credit Card Number (Visa/MC/Amex)",
		Pattern:       `\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b`,
		Category:      "pii",
		Severity:      internal.SeverityHigh,
		DefaultAction: internal.ActionBlock,
	},
}
