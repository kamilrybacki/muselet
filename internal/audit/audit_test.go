package audit

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/kamilrybacki/muselet/internal"
)

func TestAuditLogEntry(t *testing.T) {
	var buf bytes.Buffer
	logger := NewAuditLogger(&buf, "session-abc123")

	logger.Log(internal.AuditEntry{
		Timestamp: time.Unix(1710612345, 0),
		Vector:    "network",
		Action:    "block",
		RuleID:    "aws-access-key",
		Detail:    "POST https://evil.com",
		Matched:   "AKIAIOSFODNN7EXAMPLE",
	})

	var parsed internal.AuditEntry
	err := json.Unmarshal(buf.Bytes()[:bytes.IndexByte(buf.Bytes(), '\n')], &parsed)
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if parsed.Action != "block" {
		t.Errorf("action: want block, got %s", parsed.Action)
	}
	if parsed.SessionID != "session-abc123" {
		t.Errorf("session: want session-abc123, got %s", parsed.SessionID)
	}
}

func TestAuditLogNeverContainsFullSecret(t *testing.T) {
	var buf bytes.Buffer
	logger := NewAuditLogger(&buf, "session-abc123")

	secret := "AKIAIOSFODNN7EXAMPLE"
	logger.Log(internal.AuditEntry{
		RuleID:  "aws-access-key",
		Matched: secret,
	})

	output := buf.String()
	if strings.Contains(output, secret) {
		t.Error("audit log must never contain the full secret value")
	}
	// Should contain truncated form
	if !strings.Contains(output, "AKIA") || !strings.Contains(output, "MPLE") {
		t.Error("should contain prefix and suffix of redacted secret")
	}
}

func TestAuditSummary(t *testing.T) {
	logger := NewAuditLogger(io.Discard, "session-abc123")
	logger.Log(internal.AuditEntry{Action: "block", Vector: "network"})
	logger.Log(internal.AuditEntry{Action: "block", Vector: "network"})
	logger.Log(internal.AuditEntry{Action: "alert", Vector: "stdout"})
	logger.Log(internal.AuditEntry{Action: "allow", Vector: "filesystem"})

	summary := logger.Summary()
	if summary.TotalEvents != 4 {
		t.Errorf("total: want 4, got %d", summary.TotalEvents)
	}
	if summary.Blocked != 2 {
		t.Errorf("blocked: want 2, got %d", summary.Blocked)
	}
	if summary.Alerted != 1 {
		t.Errorf("alerted: want 1, got %d", summary.Alerted)
	}
	if summary.Allowed != 1 {
		t.Errorf("allowed: want 1, got %d", summary.Allowed)
	}
	if summary.ByVector["network"] != 2 {
		t.Errorf("by vector network: want 2, got %d", summary.ByVector["network"])
	}
	if summary.ByVector["stdout"] != 1 {
		t.Errorf("by vector stdout: want 1, got %d", summary.ByVector["stdout"])
	}
}

func TestAuditWouldBlock(t *testing.T) {
	logger := NewAuditLogger(io.Discard, "test")
	logger.Log(internal.AuditEntry{Action: "allow", WouldAction: "block", Vector: "network"})
	logger.Log(internal.AuditEntry{Action: "allow", WouldAction: "block", Vector: "stdout"})

	summary := logger.Summary()
	if summary.WouldBlock != 2 {
		t.Errorf("would_block: want 2, got %d", summary.WouldBlock)
	}
}

func TestAuditEntries(t *testing.T) {
	logger := NewAuditLogger(io.Discard, "test")
	logger.Log(internal.AuditEntry{Action: "block", RuleID: "rule1"})
	logger.Log(internal.AuditEntry{Action: "allow", RuleID: "rule2"})

	entries := logger.Entries()
	if len(entries) != 2 {
		t.Errorf("entries: want 2, got %d", len(entries))
	}
	if entries[0].RuleID != "rule1" {
		t.Errorf("entry 0: want rule1, got %s", entries[0].RuleID)
	}
}

func TestRedactSecret(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"short", "***"},
		{"12345678", "***"},
		{"AKIAIOSFODNN7EXAMPLE", "AKIA...MPLE"},
		{"ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh", "ghp_...efgh"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := redactSecret(tt.input)
			if got != tt.want {
				t.Errorf("redactSecret(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestAuditTimestampAutoFill(t *testing.T) {
	var buf bytes.Buffer
	logger := NewAuditLogger(&buf, "test")

	// Log without timestamp
	logger.Log(internal.AuditEntry{Action: "allow"})

	var parsed internal.AuditEntry
	json.Unmarshal(buf.Bytes()[:bytes.IndexByte(buf.Bytes(), '\n')], &parsed)
	if parsed.Timestamp.IsZero() {
		t.Error("timestamp should be auto-filled")
	}
}
