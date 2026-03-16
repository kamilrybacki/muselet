package agent

import (
	"bytes"
	"fmt"
	"io"
	"sync"
	"testing"
)

func TestRetractLastLine(t *testing.T) {
	var buf bytes.Buffer
	r := NewRetractor(&buf)

	r.TrackLine("line 1")
	r.TrackLine("secret=AKIAIOSFODNN7EXAMPLE")

	err := r.Retract(1, "secret=[REDACTED:aws-key]")
	if err != nil {
		t.Fatalf("retract: %v", err)
	}

	// Should have written ANSI escape sequence
	output := buf.String()
	if output == "" {
		t.Error("expected ANSI output")
	}
	// Verify it contains the replacement text
	if !bytes.Contains(buf.Bytes(), []byte("secret=[REDACTED:aws-key]")) {
		t.Error("output should contain replacement text")
	}
}

func TestRetractThreeLinesBack(t *testing.T) {
	var buf bytes.Buffer
	r := NewRetractor(&buf)

	r.TrackLine("line 1")
	r.TrackLine("secret here")
	r.TrackLine("line 3")
	r.TrackLine("line 4")

	err := r.Retract(1, "[REDACTED]")
	if err != nil {
		t.Fatalf("retract: %v", err)
	}

	output := buf.String()
	if !bytes.Contains([]byte(output), []byte("[REDACTED]")) {
		t.Error("output should contain replacement")
	}
}

func TestRetractorLineTracking(t *testing.T) {
	r := NewRetractor(io.Discard)

	// Track 100 lines
	for i := 0; i < 100; i++ {
		r.TrackLine(fmt.Sprintf("line %d", i))
	}

	// Buffer should be bounded to maxBuffer (50)
	if r.BufferLen() != 50 {
		t.Errorf("buffer len: want 50, got %d", r.BufferLen())
	}

	// Can't retract line 0 (outside buffer since we tracked 100 lines)
	err := r.Retract(0, "replacement")
	if err == nil {
		t.Error("should error when retracting outside buffer")
	}

	// Can retract recent lines
	err = r.Retract(99, "replacement")
	if err != nil {
		t.Errorf("should be able to retract recent line: %v", err)
	}
}

func TestRetractorConcurrentWrites(t *testing.T) {
	r := NewRetractor(io.Discard)

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			r.TrackLine(fmt.Sprintf("line %d", n))
		}(i)
	}
	wg.Wait()
	// No race, no panic
	if r.BufferLen() != 50 {
		t.Errorf("buffer len: want 50, got %d", r.BufferLen())
	}
}

func TestRetractorEmpty(t *testing.T) {
	r := NewRetractor(io.Discard)
	err := r.Retract(0, "replacement")
	if err == nil {
		t.Error("should error on empty buffer")
	}
}
