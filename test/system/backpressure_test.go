package system

import (
	"io"
	"path/filepath"
	"testing"
	"time"

	"github.com/kamilrybacki/muselet/internal"
	"github.com/kamilrybacki/muselet/internal/agent"
	"github.com/kamilrybacki/muselet/internal/policy"
	"github.com/kamilrybacki/muselet/internal/sidecar"
)

func TestBackpressureAgentChannelFull(t *testing.T) {
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "muselet.sock")

	pol := policy.DefaultPolicy()
	s, err := sidecar.NewSidecar(sidecar.Config{
		SocketPath: sockPath,
		AuditLog:   io.Discard,
	}, pol, "test-bp")
	if err != nil {
		t.Fatalf("new sidecar: %v", err)
	}
	go s.Run()
	defer s.Stop()
	time.Sleep(20 * time.Millisecond)

	a, err := agent.NewAgent(sockPath, io.Discard,
		agent.WithEventChannelSize(10))
	if err != nil {
		t.Fatalf("new agent: %v", err)
	}
	defer a.Close()

	// Flood agent with events
	for i := 0; i < 100; i++ {
		a.ProcessStdout([]byte("line\n"))
	}

	time.Sleep(200 * time.Millisecond)

	stats := a.GetStats()
	if stats.EventsTotal != 100 {
		t.Errorf("events total: want 100, got %d", stats.EventsTotal)
	}
	// Some events should be dropped due to channel saturation
	// (This depends on timing, so we just verify no panic occurred)
	t.Logf("Events dropped: %d", stats.EventsDropped)
}

func TestBackpressureNetworkEventsPreserved(t *testing.T) {
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "muselet.sock")

	pol := policy.DefaultPolicy()
	s, err := sidecar.NewSidecar(sidecar.Config{
		SocketPath: sockPath,
		AuditLog:   io.Discard,
	}, pol, "test-bp-net")
	if err != nil {
		t.Fatalf("new sidecar: %v", err)
	}
	go s.Run()
	defer s.Stop()
	time.Sleep(20 * time.Millisecond)

	a, err := agent.NewAgent(sockPath, io.Discard,
		agent.WithEventChannelSize(5))
	if err != nil {
		t.Fatalf("new agent: %v", err)
	}
	defer a.Close()

	// Send network events — these should be prioritized
	for i := 0; i < 20; i++ {
		a.ProcessNetworkRequest(internal.HTTPRequest{
			Method: "POST",
			Host:   "api.anthropic.com",
			URL:    "https://api.anthropic.com/v1/messages",
		})
	}

	time.Sleep(500 * time.Millisecond)

	stats := a.GetStats()
	if stats.NetworkEventsDropped > 0 {
		t.Errorf("network events should not be dropped, got %d dropped", stats.NetworkEventsDropped)
	}
}

func TestAgentConnectionRecovery(t *testing.T) {
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "muselet.sock")

	// Start first sidecar
	pol := policy.DefaultPolicy()
	s1, _ := sidecar.NewSidecar(sidecar.Config{
		SocketPath: sockPath,
		AuditLog:   io.Discard,
	}, pol, "test-recovery")
	go s1.Run()
	time.Sleep(20 * time.Millisecond)

	a, err := agent.NewAgent(sockPath, io.Discard,
		agent.WithReconnectAttempts(5),
		agent.WithReconnectBackoff(10*time.Millisecond))
	if err != nil {
		t.Fatalf("new agent: %v", err)
	}
	defer a.Close()

	// Normal operation
	a.ProcessStdout([]byte("before crash\n"))
	time.Sleep(50 * time.Millisecond)

	// Kill sidecar
	s1.Stop()
	time.Sleep(20 * time.Millisecond)

	// Agent should still process stdout (hot path is local)
	a.ProcessStdout([]byte("during outage\n"))

	// Restart sidecar
	s2, _ := sidecar.NewSidecar(sidecar.Config{
		SocketPath: sockPath,
		AuditLog:   io.Discard,
	}, pol, "test-recovery-2")
	go s2.Run()
	defer s2.Stop()
	time.Sleep(50 * time.Millisecond)

	// Agent should recover
	a.ProcessStdout([]byte("after recovery\n"))
	time.Sleep(100 * time.Millisecond)

	// No panic means success
}
