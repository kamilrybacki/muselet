package agent

import (
	"fmt"
	"io"
	"sync"
)

// Retractor manages ANSI-based terminal line retraction.
type Retractor struct {
	writer      io.Writer
	lines       []string
	maxBuffer   int
	totalTracked int // total lines ever tracked (for absolute indexing)
	mu          sync.Mutex
}

// NewRetractor creates a new retractor writing to the given output.
func NewRetractor(w io.Writer) *Retractor {
	return &Retractor{
		writer:    w,
		maxBuffer: 50,
	}
}

// TrackLine records a line that was written to the terminal.
func (r *Retractor) TrackLine(line string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.lines = append(r.lines, line)
	r.totalTracked++
	if len(r.lines) > r.maxBuffer {
		r.lines = r.lines[len(r.lines)-r.maxBuffer:]
	}
}

// BufferLen returns the number of lines in the buffer.
func (r *Retractor) BufferLen() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.lines)
}

// Retract replaces a previously written line with a new string using ANSI escapes.
// lineIndex is the absolute index (0-based from the start of tracking).
func (r *Retractor) Retract(lineIndex int, replacement string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	// The buffer holds the last maxBuffer lines.
	// Absolute index of the first line in the buffer:
	bufStart := r.totalTracked - len(r.lines)

	relIndex := lineIndex - bufStart
	if relIndex < 0 || relIndex >= len(r.lines) {
		return fmt.Errorf("line %d is outside the retraction buffer (buffer starts at %d, len %d)",
			lineIndex, bufStart, len(r.lines))
	}

	// Calculate how many lines back from current position
	linesBack := len(r.lines) - 1 - relIndex

	// ANSI: move up N lines, clear line, write replacement, move back down
	seq := fmt.Sprintf("\033[%dA\033[2K%s\033[%dB", linesBack, replacement, linesBack)
	_, err := r.writer.Write([]byte(seq))
	if err != nil {
		return err
	}

	r.lines[relIndex] = replacement
	return nil
}
