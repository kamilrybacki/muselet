package audit

import (
	"encoding/json"
	"io"
	"sync"
	"time"

	"github.com/kamilrybacki/muselet/internal"
)

// Logger records structured audit events.
type Logger struct {
	writer    io.Writer
	sessionID string
	entries   []internal.AuditEntry
	mu        sync.Mutex
}

// NewAuditLogger creates a new audit logger.
func NewAuditLogger(w io.Writer, sessionID string) *Logger {
	return &Logger{
		writer:    w,
		sessionID: sessionID,
	}
}

// Log records an audit entry.
func (l *Logger) Log(entry internal.AuditEntry) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if entry.Timestamp.IsZero() {
		entry.Timestamp = time.Now()
	}
	entry.SessionID = l.sessionID

	// Redact secrets in the matched field
	if entry.Matched != "" {
		entry.Matched = redactSecret(entry.Matched)
	}

	l.entries = append(l.entries, entry)

	// Write as NDJSON
	data, err := json.Marshal(entry)
	if err != nil {
		return
	}
	l.writer.Write(append(data, '\n'))
}

// Summary returns an aggregate summary.
func (l *Logger) Summary() internal.AuditSummary {
	l.mu.Lock()
	defer l.mu.Unlock()

	summary := internal.AuditSummary{
		ByVector: make(map[string]int),
		ByRule:   make(map[string]int),
	}

	for _, e := range l.entries {
		summary.TotalEvents++
		switch e.Action {
		case "block":
			summary.Blocked++
		case "alert":
			summary.Alerted++
		case "allow":
			summary.Allowed++
		}
		if e.WouldAction == "block" {
			summary.WouldBlock++
		}
		if e.Vector != "" {
			summary.ByVector[e.Vector]++
		}
		if e.RuleID != "" {
			summary.ByRule[e.RuleID]++
		}
	}
	return summary
}

// Entries returns all recorded entries.
func (l *Logger) Entries() []internal.AuditEntry {
	l.mu.Lock()
	defer l.mu.Unlock()
	result := make([]internal.AuditEntry, len(l.entries))
	copy(result, l.entries)
	return result
}

// redactSecret truncates a secret value to show only prefix and suffix.
func redactSecret(s string) string {
	if len(s) <= 8 {
		return "***"
	}
	return s[:4] + "..." + s[len(s)-4:]
}
