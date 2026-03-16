package scanner

import (
	"regexp"
	"testing"

	"github.com/kamilrybacki/muselet/internal"
)

func assertMatchesEqual(t *testing.T, want, got []internal.Match) {
	t.Helper()
	if len(want) == 0 && len(got) == 0 {
		return
	}
	if len(want) != len(got) {
		t.Errorf("match count: want %d, got %d", len(want), len(got))
		for i, m := range got {
			t.Logf("  got[%d]: rule=%s offset=%d matched=%q", i, m.RuleID, m.Offset, m.Matched)
		}
		return
	}
	for i := range want {
		if want[i].RuleID != "" && want[i].RuleID != got[i].RuleID {
			t.Errorf("match[%d].RuleID: want %q, got %q", i, want[i].RuleID, got[i].RuleID)
		}
		if want[i].Offset != 0 && want[i].Offset != got[i].Offset {
			t.Errorf("match[%d].Offset: want %d, got %d", i, want[i].Offset, got[i].Offset)
		}
		if want[i].Length != 0 && want[i].Length != got[i].Length {
			t.Errorf("match[%d].Length: want %d, got %d", i, want[i].Length, got[i].Length)
		}
	}
}

func TestPatternMatching(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		ruleID   string
		input    string
		wantHits int
	}{
		// AWS
		{"aws access key in isolation", "aws-access-key", "AKIAIOSFODNN7EXAMPLE", 1},
		{"aws access key embedded in assignment", "aws-access-key", `aws_access_key_id = "AKIAIOSFODNN7EXAMPLE"`, 1},
		{"aws key prefix but too short", "aws-access-key", "AKIA1234", 0},
		{"AKIA inside a longer non-key word (17 chars)", "aws-access-key", "AKIAMORPHOLOGICAL", 0},
		{"multiple aws keys in one blob", "aws-access-key", "key1=AKIAIOSFODNN7EXAMPLE key2=AKIAI44QH8DHBEXAMPLE", 2},

		// GitHub PAT
		{"github pat v2", "github-pat", "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij", 1},
		{"ghp_ prefix but too short", "github-pat", "ghp_abc", 0},

		// Private Keys
		{"RSA private key header", "private-key", "-----BEGIN RSA PRIVATE KEY-----\nMIIE...", 1},
		{"EC private key header", "private-key", "-----BEGIN EC PRIVATE KEY-----", 1},
		{"public key should not match", "private-key", "-----BEGIN PUBLIC KEY-----", 0},

		// Connection Strings
		{"postgres connection string", "connection-string", `DATABASE_URL=postgres://admin:s3cret@db.internal:5432/mydb`, 1},
		{"mysql connection string", "connection-string", `mysql://root:pass@localhost:3306/db`, 1},

		// Bearer Token
		{"authorization bearer header", "bearer-token", `Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJz`, 1},

		// Edge Cases
		{"empty input", "aws-access-key", "", 0},
		{"binary garbage", "aws-access-key", string([]byte{0x00, 0xff, 0xfe, 0x89, 0x50, 0x4e, 0x47}), 0},

		// Stripe
		{"stripe live key", "stripe-key", "sk" + "_live_FAKEFAKEFAKEFAKEFAKEFAKE", 1},
		{"stripe test key", "stripe-key", "pk" + "_test_FAKEFAKEFAKEFAKEFAKEFAKE", 1},

		// Google
		{"google api key", "google-api-key", "AIzaSyD-9tSrke72PouQMnMX-a7eZSW0jkFMBWY", 1},

		// Slack
		{"slack bot token", "slack-token", "xoxb-" + "0000000000-0000000000000-fakefakefakefakefakefake", 1},

		// SSN
		{"social security number", "ssn", "SSN: 123-45-6789", 1},
		{"not an SSN (too many digits)", "ssn", "123-456-7890", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			rule, ok := BuiltinRules[tt.ruleID]
			if !ok {
				t.Fatalf("rule %q not found", tt.ruleID)
			}
			hits := rule.Scan([]byte(tt.input))
			if len(hits) != tt.wantHits {
				t.Errorf("want %d hits, got %d", tt.wantHits, len(hits))
				for i, h := range hits {
					t.Logf("  hit[%d]: offset=%d matched=%q", i, h.Offset, h.Matched)
				}
			}
		})
	}
}

func TestAllBuiltinRulesValid(t *testing.T) {
	for id, rule := range BuiltinRules {
		t.Run(id, func(t *testing.T) {
			if rule.ID == "" {
				t.Error("empty ID")
			}
			if rule.Description == "" {
				t.Error("empty description")
			}
			if rule.Pattern == "" {
				t.Error("empty pattern")
			}
			if rule.Severity == "" {
				t.Error("empty severity")
			}
			if rule.DefaultAction == "" {
				t.Error("empty default action")
			}

			// Pattern must compile
			_, err := regexp.Compile(rule.Pattern)
			if err != nil {
				t.Errorf("invalid regex: %v", err)
			}

			// Pattern must not match empty string
			if rule.MatchesBytes([]byte("")) {
				t.Error("matches empty string")
			}
		})
	}
}

func TestBuiltinRuleIDsUnique(t *testing.T) {
	seen := map[string]bool{}
	for _, r := range builtinRuleDefs {
		if seen[r.ID] {
			t.Errorf("duplicate rule ID: %s", r.ID)
		}
		seen[r.ID] = true
	}
}

func TestRuleCompileError(t *testing.T) {
	r := &Rule{Pattern: "[invalid"}
	err := r.Compile()
	if err == nil {
		t.Error("expected compile error for invalid regex")
	}
}

func TestRuleScanWithoutCompile(t *testing.T) {
	r := &Rule{Pattern: "test"}
	hits := r.Scan([]byte("test"))
	if len(hits) != 0 {
		t.Error("uncompiled rule should return no hits")
	}
}

func TestMatchesAcrossNewlines(t *testing.T) {
	// Keys split across lines should NOT match
	r := BuiltinRules["aws-access-key"]
	input := "AKIA12345678\n90ABCDEF"
	hits := r.Scan([]byte(input))
	for _, h := range hits {
		if len(h.Matched) == 20 {
			// A 20-char match spanning the newline would be wrong
			t.Error("should not match across newlines")
		}
	}
}
