package transport

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"github.com/kamilrybacki/muselet/internal"
)

// EncodeEvent encodes an event to NDJSON bytes (without trailing newline).
func EncodeEvent(evt internal.Event) ([]byte, error) {
	data, err := json.Marshal(evt)
	if err != nil {
		return nil, err
	}
	return data, nil
}

// DecodeEvent decodes an event from NDJSON bytes.
func DecodeEvent(data []byte) (internal.Event, error) {
	var evt internal.Event
	err := json.Unmarshal(data, &evt)
	return evt, err
}

// EncodeVerdict encodes a verdict to NDJSON bytes.
func EncodeVerdict(v internal.Verdict) ([]byte, error) {
	return json.Marshal(v)
}

// DecodeVerdict decodes a verdict from NDJSON bytes.
func DecodeVerdict(data []byte) (internal.Verdict, error) {
	var v internal.Verdict
	err := json.Unmarshal(data, &v)
	return v, err
}

// EventHandler processes events and returns verdicts.
type EventHandler func(internal.Event) internal.Verdict

// SocketServer is the sidecar-side Unix socket server.
type SocketServer struct {
	listener net.Listener
	handler  EventHandler
	done     chan struct{}
	mu       sync.Mutex
}

// NewSocketServer creates a new socket server at the given path.
func NewSocketServer(sockPath string) (*SocketServer, error) {
	_ = os.Remove(sockPath) // Clean up stale socket
	listener, err := net.Listen("unix", sockPath)
	if err != nil {
		return nil, fmt.Errorf("listen on %s: %w", sockPath, err)
	}
	return &SocketServer{
		listener: listener,
		done:     make(chan struct{}),
	}, nil
}

// OnEvent sets the event handler.
func (ss *SocketServer) OnEvent(handler EventHandler) {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	ss.handler = handler
}

// Serve starts accepting connections.
func (ss *SocketServer) Serve() error {
	for {
		conn, err := ss.listener.Accept()
		if err != nil {
			select {
			case <-ss.done:
				return nil
			default:
				return err
			}
		}
		go ss.handleConn(conn)
	}
}

// Close shuts down the server.
func (ss *SocketServer) Close() error {
	close(ss.done)
	return ss.listener.Close()
}

// Addr returns the listener address.
func (ss *SocketServer) Addr() string {
	return ss.listener.Addr().String()
}

func (ss *SocketServer) handleConn(conn net.Conn) {
	defer conn.Close()
	scanner := bufio.NewScanner(conn)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		evt, err := DecodeEvent(line)
		if err != nil {
			continue
		}

		ss.mu.Lock()
		handler := ss.handler
		ss.mu.Unlock()

		var verdict internal.Verdict
		if handler != nil {
			verdict = handler(evt)
		} else {
			verdict = internal.Verdict{Action: "allow"}
		}

		verdictData, err := EncodeVerdict(verdict)
		if err != nil {
			continue
		}
		conn.Write(append(verdictData, '\n'))
	}
}

// ReconnectConfig configures reconnection behavior.
type ReconnectConfig struct {
	MaxAttempts int
	Backoff     time.Duration
}

// SocketClient is the agent-side Unix socket client.
type SocketClient struct {
	sockPath    string
	conn        net.Conn
	reader      *bufio.Reader
	mu          sync.Mutex
	reconnectCfg ReconnectConfig
}

// ClientOption configures the socket client.
type ClientOption func(*SocketClient)

// WithReconnect sets reconnection parameters.
func WithReconnect(maxAttempts int, backoff time.Duration) ClientOption {
	return func(sc *SocketClient) {
		sc.reconnectCfg = ReconnectConfig{
			MaxAttempts: maxAttempts,
			Backoff:     backoff,
		}
	}
}

// NewSocketClient creates a new socket client.
func NewSocketClient(sockPath string, opts ...ClientOption) (*SocketClient, error) {
	sc := &SocketClient{
		sockPath: sockPath,
		reconnectCfg: ReconnectConfig{
			MaxAttempts: 3,
			Backoff:     100 * time.Millisecond,
		},
	}
	for _, opt := range opts {
		opt(sc)
	}
	if err := sc.connect(); err != nil {
		return nil, err
	}
	return sc, nil
}

func (sc *SocketClient) connect() error {
	conn, err := net.Dial("unix", sc.sockPath)
	if err != nil {
		return err
	}
	sc.conn = conn
	sc.reader = bufio.NewReader(conn)
	return nil
}

// SendSync sends an event and waits for a verdict.
func (sc *SocketClient) SendSync(evt internal.Event) (internal.Verdict, error) {
	sc.mu.Lock()
	defer sc.mu.Unlock()

	data, err := EncodeEvent(evt)
	if err != nil {
		return internal.Verdict{}, err
	}

	// Try send, reconnect if needed
	if _, err := sc.conn.Write(append(data, '\n')); err != nil {
		if reconnErr := sc.reconnect(); reconnErr != nil {
			return internal.Verdict{}, fmt.Errorf("send failed and reconnect failed: %w", reconnErr)
		}
		if _, err := sc.conn.Write(append(data, '\n')); err != nil {
			return internal.Verdict{}, err
		}
	}

	// Read verdict
	line, err := sc.reader.ReadBytes('\n')
	if err != nil {
		return internal.Verdict{}, err
	}
	return DecodeVerdict(line)
}

// SendAsync sends an event without waiting for a verdict.
func (sc *SocketClient) SendAsync(evt internal.Event) error {
	sc.mu.Lock()
	defer sc.mu.Unlock()

	data, err := EncodeEvent(evt)
	if err != nil {
		return err
	}
	_, err = sc.conn.Write(append(data, '\n'))
	return err
}

// Close closes the connection.
func (sc *SocketClient) Close() error {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	if sc.conn != nil {
		return sc.conn.Close()
	}
	return nil
}

// IsConnected returns true if the client has an active connection.
func (sc *SocketClient) IsConnected() bool {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	if sc.conn == nil {
		return false
	}
	// Quick liveness check
	sc.conn.SetReadDeadline(time.Now().Add(1 * time.Millisecond))
	one := make([]byte, 0)
	_, err := sc.conn.Read(one)
	sc.conn.SetReadDeadline(time.Time{})
	if err != nil {
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			return true // timeout is fine, means conn is alive
		}
		return false
	}
	return true
}

func (sc *SocketClient) reconnect() error {
	if sc.conn != nil {
		sc.conn.Close()
	}
	backoff := sc.reconnectCfg.Backoff
	for i := 0; i < sc.reconnectCfg.MaxAttempts; i++ {
		time.Sleep(backoff)
		if err := sc.connect(); err == nil {
			return nil
		}
		backoff *= 2
	}
	return fmt.Errorf("failed to reconnect after %d attempts", sc.reconnectCfg.MaxAttempts)
}
