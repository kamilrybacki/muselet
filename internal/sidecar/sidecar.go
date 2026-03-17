package sidecar

import (
	"encoding/base64"
	"io"
	"log"
	"sync"
	"time"

	"github.com/kamilrybacki/muselet/internal"
	"github.com/kamilrybacki/muselet/internal/audit"
	"github.com/kamilrybacki/muselet/internal/policy"
	"github.com/kamilrybacki/muselet/internal/scanner"
	"github.com/kamilrybacki/muselet/internal/transport"
)

// Config configures the sidecar.
type Config struct {
	SocketPath string
	AuditLog   io.Writer
}

// Sidecar is the DLP sidecar controller.
type Sidecar struct {
	config      Config
	scanner     *scanner.Scanner
	policy      *policy.Policy
	auditLogger *audit.Logger
	server      *transport.SocketServer
	sessionID   string
	done        chan struct{}
	mu          sync.RWMutex
}

// NewSidecar creates a new sidecar.
func NewSidecar(config Config, pol *policy.Policy, sessionID string) (*Sidecar, error) {
	cats := scanner.DefaultCategoryConfig()
	if pol.Categories.Credentials != nil {
		cats.Credentials = pol.Categories.Credentials.Enabled
	}
	if pol.Categories.Infrastructure != nil {
		cats.Infrastructure = pol.Categories.Infrastructure.Enabled
	}
	if pol.Categories.PII != nil {
		cats.PII = pol.Categories.PII.Enabled
	}
	if pol.Categories.Proprietary != nil {
		cats.Proprietary = pol.Categories.Proprietary.Enabled
	}

	var rules []*scanner.Rule
	for _, r := range scanner.BuiltinRules {
		rules = append(rules, r)
	}
	// Add custom rules from policy
	for _, pr := range pol.Rules {
		r := &scanner.Rule{
			ID:            pr.ID,
			Description:   pr.Description,
			Pattern:       pr.Pattern,
			Category:      pr.Category,
			Severity:      pr.Severity,
			DefaultAction: pr.Action,
		}
		if err := r.Compile(); err != nil {
			return nil, err
		}
		rules = append(rules, r)
	}

	s := &Sidecar{
		config:      config,
		scanner:     scanner.NewScanner(rules, scanner.DefaultEntropyConfig(), cats),
		policy:      pol,
		auditLogger: audit.NewAuditLogger(config.AuditLog, sessionID),
		sessionID:   sessionID,
		done:        make(chan struct{}),
	}

	server, err := transport.NewSocketServer(config.SocketPath)
	if err != nil {
		return nil, err
	}
	s.server = server
	server.OnEvent(s.handleEvent)

	return s, nil
}

// Run starts the sidecar server.
func (s *Sidecar) Run() error {
	return s.server.Serve()
}

// Stop shuts down the sidecar.
func (s *Sidecar) Stop() error {
	close(s.done)
	return s.server.Close()
}

// AuditSummary returns the audit summary.
func (s *Sidecar) AuditSummary() internal.AuditSummary {
	return s.auditLogger.Summary()
}

// UpdatePolicy updates the policy and scanner.
func (s *Sidecar) UpdatePolicy(pol *policy.Policy) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.policy = pol
}

func (s *Sidecar) handleEvent(evt internal.Event) internal.Verdict {
	s.mu.RLock()
	pol := s.policy
	s.mu.RUnlock()

	switch evt.Type {
	case "stdout", "stderr":
		return s.handleStdoutEvent(evt, pol)
	case "net_request":
		return s.handleNetworkEvent(evt, pol)
	case "fs_write", "fs_create":
		return s.handleFSEvent(evt, pol)
	case "patch_export":
		return s.handlePatchEvent(evt, pol)
	case "heartbeat":
		return internal.Verdict{Action: "allow"}
	default:
		return internal.Verdict{Action: "allow"}
	}
}

func (s *Sidecar) handleStdoutEvent(evt internal.Event, pol *policy.Policy) internal.Verdict {
	data, err := base64.StdEncoding.DecodeString(evt.Data)
	if err != nil {
		return internal.Verdict{Action: "allow"}
	}

	results := s.scanner.ScanBytes(data, internal.VectorStdout)
	return s.evaluateResults(results, "stdout", pol, evt.Timestamp)
}

func (s *Sidecar) handleNetworkEvent(evt internal.Event, pol *policy.Policy) internal.Verdict {
	// Check host allowlist
	if evt.Host != "" {
		allowed := false
		for _, h := range pol.Vectors.Network.AllowedHosts {
			if h == evt.Host {
				allowed = true
				break
			}
		}
		if !allowed {
			s.auditLogger.Log(internal.AuditEntry{
				Timestamp: time.Now(),
				Vector:    "network",
				Action:    s.effectiveAction("block", pol),
				Detail:    evt.Method + " " + evt.URL,
				RuleID:    "host-not-allowed",
			})
			if pol.LearningMode {
				return internal.Verdict{Action: "allow"}
			}
			return internal.Verdict{
				Action: "block",
				Reason: "host not in allowlist: " + evt.Host,
			}
		}
	}

	// Scan body
	if evt.Body != "" {
		body, err := base64.StdEncoding.DecodeString(evt.Body)
		if err == nil {
			results := s.scanner.ScanBytes(body, internal.VectorNetwork)
			return s.evaluateResults(results, "network", pol, evt.Timestamp)
		}
	}

	s.auditLogger.Log(internal.AuditEntry{
		Timestamp: time.Now(),
		Vector:    "network",
		Action:    "allow",
		Detail:    evt.Method + " " + evt.URL,
	})
	return internal.Verdict{Action: "allow"}
}

func (s *Sidecar) handleFSEvent(evt internal.Event, pol *policy.Policy) internal.Verdict {
	data, err := base64.StdEncoding.DecodeString(evt.Data)
	if err != nil {
		return internal.Verdict{Action: "allow"}
	}

	results := s.scanner.ScanFile(evt.Path, data, internal.VectorFilesystem)
	return s.evaluateResults(results, "filesystem", pol, evt.Timestamp)
}

func (s *Sidecar) handlePatchEvent(evt internal.Event, pol *policy.Policy) internal.Verdict {
	data, err := base64.StdEncoding.DecodeString(evt.Patch)
	if err != nil {
		return internal.Verdict{Action: "allow"}
	}

	results := s.scanner.ScanBytes(data, internal.VectorPatch)
	return s.evaluateResults(results, "patch", pol, evt.Timestamp)
}

func (s *Sidecar) evaluateResults(results []internal.ScanResult, vector string, pol *policy.Policy, ts int64) internal.Verdict {
	highestAction := "allow"

	for _, result := range results {
		action := s.effectiveAction(string(result.Action), pol)

		// Check if rule is suppressed
		if pol.IsRuleSuppressed(result.RuleID, result.FilePath) {
			continue
		}

		entry := internal.AuditEntry{
			Timestamp:  time.Now(),
			Vector:     vector,
			Action:     action,
			RuleID:     result.RuleID,
			Detail:     result.FilePath,
			Matched:    result.Matched,
			Confidence: result.Confidence,
		}

		if pol.LearningMode && action == "block" {
			entry.Action = "allow"
			entry.WouldAction = "block"
		}

		s.auditLogger.Log(entry)

		if actionPriority(action) > actionPriority(highestAction) {
			highestAction = action
		}
	}

	if len(results) == 0 {
		s.auditLogger.Log(internal.AuditEntry{
			Timestamp: time.Now(),
			Vector:    vector,
			Action:    "allow",
		})
	}

	if pol.LearningMode {
		return internal.Verdict{Action: "allow", RefTimestamp: ts}
	}

	if highestAction == "block" {
		reason := "DLP policy violation"
		ruleID := ""
		if len(results) > 0 {
			reason = results[0].RuleID + ": " + results[0].Matched
			ruleID = results[0].RuleID
		}
		return internal.Verdict{
			Action:       "block",
			Reason:       reason,
			RuleID:       ruleID,
			RefTimestamp:  ts,
		}
	}

	return internal.Verdict{Action: "allow", RefTimestamp: ts}
}

func (s *Sidecar) effectiveAction(action string, pol *policy.Policy) string {
	if pol.LearningMode {
		return action // preserve for would_action tracking
	}
	return action
}

func actionPriority(action string) int {
	switch action {
	case "block":
		return 3
	case "alert":
		return 2
	case "redact":
		return 1
	case "allow":
		return 0
	default:
		return 0
	}
}

// LogError is a helper to log errors in the sidecar.
func LogError(msg string, err error) {
	if err != nil {
		log.Printf("muselet sidecar: %s: %v", msg, err)
	}
}
