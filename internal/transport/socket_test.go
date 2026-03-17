package transport

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/kamilrybacki/muselet/internal"
)

func TestNDJSONEventEncoding(t *testing.T) {
	tests := []struct {
		name  string
		event internal.Event
	}{
		{"stdout event", internal.Event{Type: "stdout", Timestamp: 1710612345, Data: "aGVsbG8="}},
		{"fs_write event", internal.Event{Type: "fs_write", Timestamp: 1710612346, Path: "/workspace/.env", SHA256: "abc123"}},
		{"heartbeat", internal.Event{Type: "heartbeat", Timestamp: 1710612360}},
		{"net request", internal.Event{Type: "net_request", Timestamp: 1710612351, Method: "POST", Host: "evil.com"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := EncodeEvent(tt.event)
			if err != nil {
				t.Fatalf("encode: %v", err)
			}

			// Must be single line
			for _, b := range data {
				if b == '\n' {
					t.Error("encoded event contains newline")
				}
			}

			decoded, err := DecodeEvent(data)
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			if decoded.Type != tt.event.Type {
				t.Errorf("type: want %q, got %q", tt.event.Type, decoded.Type)
			}
			if decoded.Timestamp != tt.event.Timestamp {
				t.Errorf("timestamp: want %d, got %d", tt.event.Timestamp, decoded.Timestamp)
			}
		})
	}
}

func TestNDJSONVerdictEncoding(t *testing.T) {
	tests := []struct {
		name    string
		verdict internal.Verdict
	}{
		{"allow", internal.Verdict{Type: "verdict", RefTimestamp: 123, Action: "allow"}},
		{"block with reason", internal.Verdict{Type: "verdict", RefTimestamp: 456, Action: "block", Reason: "AWS key detected"}},
		{"retract", internal.Verdict{Type: "retract", OriginalTimestamp: 789, Action: "alert", Reason: "entropy flagged"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := EncodeVerdict(tt.verdict)
			if err != nil {
				t.Fatalf("encode: %v", err)
			}

			decoded, err := DecodeVerdict(data)
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			if decoded.Action != tt.verdict.Action {
				t.Errorf("action: want %q, got %q", tt.verdict.Action, decoded.Action)
			}
			if decoded.Reason != tt.verdict.Reason {
				t.Errorf("reason: want %q, got %q", tt.verdict.Reason, decoded.Reason)
			}
		})
	}
}

func TestSocketRoundTrip(t *testing.T) {
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "test.sock")

	server, err := NewSocketServer(sockPath)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	received := make(chan internal.Event, 10)
	server.OnEvent(func(evt internal.Event) internal.Verdict {
		received <- evt
		if evt.Type == "fs_write" {
			return internal.Verdict{Action: "block", Reason: "test block"}
		}
		return internal.Verdict{Action: "allow"}
	})
	go server.Serve()
	defer server.Close()

	// Give server time to start
	time.Sleep(10 * time.Millisecond)

	client, err := NewSocketClient(sockPath)
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	defer client.Close()

	// Send event and get verdict
	verdict, err := client.SendSync(internal.Event{
		Type: "fs_write", Timestamp: 100, Path: "/workspace/.env",
	})
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	if verdict.Action != "block" {
		t.Errorf("verdict action: want block, got %s", verdict.Action)
	}

	// Verify server received it
	select {
	case evt := <-received:
		if evt.Type != "fs_write" {
			t.Errorf("received type: want fs_write, got %s", evt.Type)
		}
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for event")
	}
}

func TestSocketMultipleMessages(t *testing.T) {
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "test.sock")

	server, err := NewSocketServer(sockPath)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	count := 0
	server.OnEvent(func(evt internal.Event) internal.Verdict {
		count++
		return internal.Verdict{Action: "allow"}
	})
	go server.Serve()
	defer server.Close()

	time.Sleep(10 * time.Millisecond)

	client, err := NewSocketClient(sockPath)
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	defer client.Close()

	// Send 10 messages
	for i := 0; i < 10; i++ {
		_, err := client.SendSync(internal.Event{
			Type: "heartbeat", Timestamp: int64(i),
		})
		if err != nil {
			t.Fatalf("send %d: %v", i, err)
		}
	}

	time.Sleep(50 * time.Millisecond)
	if count != 10 {
		t.Errorf("server received %d events, want 10", count)
	}
}

func TestSocketReconnection(t *testing.T) {
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "test.sock")

	// Start first server
	server1, err := NewSocketServer(sockPath)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	server1.OnEvent(func(evt internal.Event) internal.Verdict {
		return internal.Verdict{Action: "allow"}
	})
	go server1.Serve()

	time.Sleep(10 * time.Millisecond)

	client, err := NewSocketClient(sockPath, WithReconnect(5, 10*time.Millisecond))
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	defer client.Close()

	// Verify first connection works
	_, err = client.SendSync(internal.Event{Type: "heartbeat", Timestamp: 1})
	if err != nil {
		t.Fatalf("first send: %v", err)
	}

	// Kill first server
	server1.Close()
	time.Sleep(20 * time.Millisecond)

	// Start second server on same socket
	server2, err := NewSocketServer(sockPath)
	if err != nil {
		t.Fatalf("new server2: %v", err)
	}
	server2.OnEvent(func(evt internal.Event) internal.Verdict {
		return internal.Verdict{Action: "allow"}
	})
	go server2.Serve()
	defer server2.Close()

	time.Sleep(20 * time.Millisecond)

	// Client should reconnect
	_, err = client.SendSync(internal.Event{Type: "heartbeat", Timestamp: 2})
	if err != nil {
		t.Fatalf("second send (after reconnect): %v", err)
	}
}
