package internal

import "time"

// Vector represents a DLP inspection vector.
type Vector string

const (
	VectorNetwork    Vector = "network"
	VectorStdout     Vector = "stdout"
	VectorStderr     Vector = "stderr"
	VectorFilesystem Vector = "filesystem"
	VectorPatch      Vector = "patch"
)

// Action represents the DLP enforcement action.
type Action string

const (
	ActionAllow   Action = "allow"
	ActionAlert   Action = "alert"
	ActionBlock   Action = "block"
	ActionRedact  Action = "redact"
	ActionSuppress Action = "suppress"
)

// Severity represents the severity level of a rule match.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
)

// RiskLevel represents contextual risk assessment.
type RiskLevel int

const (
	RiskLow RiskLevel = iota
	RiskMedium
	RiskHigh
)

func (r RiskLevel) String() string {
	switch r {
	case RiskLow:
		return "low"
	case RiskMedium:
		return "medium"
	case RiskHigh:
		return "high"
	default:
		return "unknown"
	}
}

// Match represents a pattern match found by the scanner.
type Match struct {
	RuleID   string
	Offset   int
	Length   int
	Matched  string
	Category string
}

// ScanResult is a fully evaluated match with context and verdict.
type ScanResult struct {
	Match
	FilePath   string
	Line       int
	Vector     Vector
	Confidence float64
	Action     Action
	Severity   Severity
}

// ContextSignal holds contextual information about a match.
type ContextSignal struct {
	FileRisk      RiskLevel
	VectorRisk    RiskLevel
	NearbyMarkers []string
	Confidence    float64
}

// ContextInput is the input for context analysis.
type ContextInput struct {
	FilePath string
	Content  []byte
	Vector   Vector
}

// Event represents an event sent from agent to sidecar.
type Event struct {
	Type      string `json:"type"`
	Timestamp int64  `json:"ts"`
	Data      string `json:"data,omitempty"`
	Path      string `json:"path,omitempty"`
	SHA256    string `json:"sha256,omitempty"`
	Method    string `json:"method,omitempty"`
	Host      string `json:"host,omitempty"`
	URL       string `json:"url,omitempty"`
	Body      string `json:"body,omitempty"`
	BodyHash  string `json:"body_hash,omitempty"`
	Patch     string `json:"patch,omitempty"`
	Priority  bool   `json:"priority,omitempty"`
}

// Verdict represents a verdict sent from sidecar to agent.
type Verdict struct {
	Type              string `json:"type"`
	RefTimestamp      int64  `json:"ref_ts,omitempty"`
	OriginalTimestamp int64  `json:"original_ts,omitempty"`
	Action            string `json:"action"`
	Reason            string `json:"reason,omitempty"`
	Matched           string `json:"matched,omitempty"`
	RuleID            string `json:"rule_id,omitempty"`
}

// FSEventOp represents a filesystem operation type.
type FSEventOp int

const (
	FSCreate FSEventOp = iota
	FSWrite
	FSRemove
	FSRename
)

// FSEvent represents a filesystem event.
type FSEvent struct {
	Op   FSEventOp
	Path string
	Time time.Time
}

// AuditEntry represents a single audit log entry.
type AuditEntry struct {
	Timestamp    time.Time `json:"timestamp"`
	SessionID    string    `json:"session_id"`
	Vector       string    `json:"vector"`
	Action       string    `json:"action"`
	RuleID       string    `json:"rule_id,omitempty"`
	Detail       string    `json:"detail,omitempty"`
	Matched      string    `json:"matched,omitempty"`
	Confidence   float64   `json:"confidence,omitempty"`
	UserOverride string    `json:"user_override,omitempty"`
	WouldAction  string    `json:"would_action,omitempty"`
}

// AuditSummary is an aggregate summary of audit events.
type AuditSummary struct {
	TotalEvents int
	Blocked     int
	Alerted     int
	Allowed     int
	WouldBlock  int
	ByVector    map[string]int
	ByRule      map[string]int
}

// HTTPRequest represents an HTTP request for proxy inspection.
type HTTPRequest struct {
	Method  string
	URL     string
	Host    string
	Headers map[string]string
	Body    []byte
}
