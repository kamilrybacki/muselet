package agent

import (
	"encoding/base64"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/kamilrybacki/muselet/internal"
	"github.com/kamilrybacki/muselet/internal/scanner"
	"github.com/kamilrybacki/muselet/internal/transport"
	"github.com/kamilrybacki/muselet/internal/watcher"
)

// Config configures the agent.
type Config struct {
	SocketPath       string
	WatchDirs        []string
	WatchExcludes    []string
	EventChannelSize int
	ReconnectConfig  ReconnectConfig
}

// ReconnectConfig configures reconnection behavior.
type ReconnectConfig struct {
	MaxAttempts int
	Backoff     time.Duration
}

// Stats holds agent statistics.
type Stats struct {
	EventsTotal         int64
	EventsDropped       int64
	NetworkEventsDropped int64
}

// Agent is the in-container DLP agent.
type Agent struct {
	config    Config
	client    *transport.SocketClient
	bundle    *scanner.ScanBundle
	retractor *Retractor
	stdout    io.Writer
	eventChan chan internal.Event
	stats     Stats
	watcher   *watcher.Watcher
	done      chan struct{}
	wg        sync.WaitGroup
	bundleMu  sync.RWMutex

	retractions   []internal.Verdict
	retractionsMu sync.Mutex
}

// AgentOption configures the agent.
type AgentOption func(*Agent)

// WithWatchDir adds a watch directory.
func WithWatchDir(dir string) AgentOption {
	return func(a *Agent) {
		a.config.WatchDirs = append(a.config.WatchDirs, dir)
	}
}

// WithEventChannelSize sets the event channel buffer size.
func WithEventChannelSize(size int) AgentOption {
	return func(a *Agent) {
		a.config.EventChannelSize = size
	}
}

// WithReconnectAttempts sets reconnect attempts.
func WithReconnectAttempts(n int) AgentOption {
	return func(a *Agent) {
		a.config.ReconnectConfig.MaxAttempts = n
	}
}

// WithReconnectBackoff sets reconnect backoff.
func WithReconnectBackoff(d time.Duration) AgentOption {
	return func(a *Agent) {
		a.config.ReconnectConfig.Backoff = d
	}
}

// NewAgent creates a new agent.
func NewAgent(sockPath string, stdout io.Writer, opts ...AgentOption) (*Agent, error) {
	a := &Agent{
		config: Config{
			SocketPath:       sockPath,
			EventChannelSize: 1000,
			ReconnectConfig: ReconnectConfig{
				MaxAttempts: 5,
				Backoff:     100 * time.Millisecond,
			},
		},
		stdout:    stdout,
		retractor: NewRetractor(stdout),
		done:      make(chan struct{}),
	}

	for _, opt := range opts {
		opt(a)
	}

	a.eventChan = make(chan internal.Event, a.config.EventChannelSize)

	// Connect to sidecar
	client, err := transport.NewSocketClient(sockPath,
		transport.WithReconnect(a.config.ReconnectConfig.MaxAttempts,
			a.config.ReconnectConfig.Backoff))
	if err != nil {
		return nil, err
	}
	a.client = client

	// Build default bundle with builtin rules
	var defaultRules []*scanner.Rule
	for _, r := range scanner.BuiltinRules {
		defaultRules = append(defaultRules, r)
	}
	a.bundle = scanner.BuildScanBundle(defaultRules, nil)

	// Start event drain
	a.wg.Add(1)
	go a.drainEvents()

	return a, nil
}

// ProcessStdout processes a chunk of stdout data through the hot path.
func (a *Agent) ProcessStdout(data []byte) {
	a.bundleMu.RLock()
	bundle := a.bundle
	a.bundleMu.RUnlock()

	hits := bundle.HotScan(data)

	if len(hits) > 0 {
		// Block: send to sidecar synchronously for critical hits
		for _, hit := range hits {
			if hit.RuleID != "" {
				// Hold the data — don't forward to stdout
				a.emitEvent(internal.Event{
					Type:      "stdout",
					Timestamp: time.Now().UnixMilli(),
					Data:      base64.StdEncoding.EncodeToString(data),
					Priority:  true,
				})
				// Write redacted version
				redacted := strings.Replace(string(data), hit.Matched,
					"[REDACTED:"+hit.RuleID+"]", -1)
				a.stdout.Write([]byte(redacted))
				a.retractor.TrackLine(redacted)
				return
			}
		}
	}

	// Clean data — forward immediately
	a.stdout.Write(data)

	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		if line != "" {
			a.retractor.TrackLine(line)
		}
	}

	// Send to sidecar async
	a.emitEvent(internal.Event{
		Type:      "stdout",
		Timestamp: time.Now().UnixMilli(),
		Data:      base64.StdEncoding.EncodeToString(data),
	})
}

// ProcessNetworkRequest processes an outbound HTTP request.
func (a *Agent) ProcessNetworkRequest(req internal.HTTPRequest) {
	evt := internal.Event{
		Type:      "net_request",
		Timestamp: time.Now().UnixMilli(),
		Method:    req.Method,
		Host:      req.Host,
		URL:       req.URL,
		Priority:  true,
	}
	if len(req.Body) > 0 {
		evt.Body = base64.StdEncoding.EncodeToString(req.Body)
	}
	a.emitEvent(evt)
}

// ProcessFSWrite processes a filesystem write event.
func (a *Agent) ProcessFSWrite(path string, content []byte) {
	a.bundleMu.RLock()
	bundle := a.bundle
	a.bundleMu.RUnlock()

	hits := bundle.HotScan(content)
	priority := len(hits) > 0

	if priority {
		// Quarantine the file
		_ = watcher.QuarantineFile(path)
	}

	a.emitEvent(internal.Event{
		Type:      "fs_write",
		Timestamp: time.Now().UnixMilli(),
		Path:      path,
		Data:      base64.StdEncoding.EncodeToString(content),
		Priority:  priority,
	})
}

// ProcessPatchExport processes a patch export.
func (a *Agent) ProcessPatchExport(patch []byte) {
	a.emitEvent(internal.Event{
		Type:      "patch_export",
		Timestamp: time.Now().UnixMilli(),
		Patch:     base64.StdEncoding.EncodeToString(patch),
		Priority:  true,
	})
}

// RunWatcher starts the filesystem watcher.
func (a *Agent) RunWatcher() error {
	for _, dir := range a.config.WatchDirs {
		w, err := watcher.NewWatcher(dir, func(evt internal.FSEvent) {
			if evt.Op == internal.FSCreate || evt.Op == internal.FSWrite {
				content, err := os.ReadFile(evt.Path)
				if err != nil {
					return
				}
				a.ProcessFSWrite(evt.Path, content)
			}
		}, watcher.WithExcludes(a.config.WatchExcludes))
		if err != nil {
			return err
		}
		a.watcher = w
	}
	return nil
}

// StopWatcher stops the filesystem watcher.
func (a *Agent) StopWatcher() {
	if a.watcher != nil {
		a.watcher.Close()
	}
}

// RunProcess runs a child process and captures stdout/stderr.
func (a *Agent) RunProcess(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	stdout, _ := cmd.StdoutPipe()
	stderr, _ := cmd.StderrPipe()
	cmd.Stdin = os.Stdin

	if err := cmd.Start(); err != nil {
		return err
	}

	// Process stdout
	a.wg.Add(2)
	go func() {
		defer a.wg.Done()
		buf := make([]byte, 4096)
		for {
			n, err := stdout.Read(buf)
			if n > 0 {
				chunk := make([]byte, n)
				copy(chunk, buf[:n])
				a.ProcessStdout(chunk)
			}
			if err != nil {
				return
			}
		}
	}()

	// Process stderr
	go func() {
		defer a.wg.Done()
		buf := make([]byte, 4096)
		for {
			n, err := stderr.Read(buf)
			if n > 0 {
				// Pass stderr through with scanning
				chunk := make([]byte, n)
				copy(chunk, buf[:n])
				a.ProcessStdout(chunk)
			}
			if err != nil {
				return
			}
		}
	}()

	return cmd.Wait()
}

// CurrentBundle returns the current scan bundle.
func (a *Agent) CurrentBundle() *scanner.ScanBundle {
	a.bundleMu.RLock()
	defer a.bundleMu.RUnlock()
	return a.bundle
}

// UpdateBundle replaces the scan bundle.
func (a *Agent) UpdateBundle(b *scanner.ScanBundle) {
	a.bundleMu.Lock()
	defer a.bundleMu.Unlock()
	a.bundle = b
}

// GetRetractions returns all retraction verdicts received.
func (a *Agent) GetRetractions() []internal.Verdict {
	a.retractionsMu.Lock()
	defer a.retractionsMu.Unlock()
	result := make([]internal.Verdict, len(a.retractions))
	copy(result, a.retractions)
	return result
}

// GetStats returns agent statistics.
func (a *Agent) GetStats() Stats {
	return Stats{
		EventsTotal:         atomic.LoadInt64(&a.stats.EventsTotal),
		EventsDropped:       atomic.LoadInt64(&a.stats.EventsDropped),
		NetworkEventsDropped: atomic.LoadInt64(&a.stats.NetworkEventsDropped),
	}
}

// IsConnected returns true if connected to the sidecar.
func (a *Agent) IsConnected() bool {
	return a.client.IsConnected()
}

// Close shuts down the agent.
func (a *Agent) Close() error {
	close(a.done)
	a.wg.Wait()
	return a.client.Close()
}

func (a *Agent) emitEvent(evt internal.Event) {
	atomic.AddInt64(&a.stats.EventsTotal, 1)

	if evt.Type == "net_request" {
		// Network events are high priority — block if channel is full
		select {
		case a.eventChan <- evt:
		default:
			// For network events, wait a bit rather than dropping
			select {
			case a.eventChan <- evt:
			case <-time.After(50 * time.Millisecond):
				atomic.AddInt64(&a.stats.EventsDropped, 1)
				atomic.AddInt64(&a.stats.NetworkEventsDropped, 1)
			}
		}
		return
	}

	select {
	case a.eventChan <- evt:
	default:
		atomic.AddInt64(&a.stats.EventsDropped, 1)
	}
}

func (a *Agent) drainEvents() {
	defer a.wg.Done()
	for {
		select {
		case <-a.done:
			return
		case evt := <-a.eventChan:
			_ = a.client.SendAsync(evt)
		}
	}
}
