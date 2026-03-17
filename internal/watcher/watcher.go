package watcher

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/kamilrybacki/muselet/internal"
)

// FSHandler is called when a filesystem event occurs.
type FSHandler func(internal.FSEvent)

// Watcher monitors filesystem changes using polling (portable, no CGO needed).
type Watcher struct {
	root     string
	handler  FSHandler
	excludes []string
	interval time.Duration
	done     chan struct{}
	wg       sync.WaitGroup
	known    map[string]fileInfo
	mu       sync.Mutex
}

type fileInfo struct {
	modTime time.Time
	size    int64
}

// Option configures the watcher.
type Option func(*Watcher)

// WithExcludes sets excluded path patterns.
func WithExcludes(patterns []string) Option {
	return func(w *Watcher) {
		w.excludes = patterns
	}
}

// WithInterval sets the polling interval.
func WithInterval(d time.Duration) Option {
	return func(w *Watcher) {
		w.interval = d
	}
}

// NewWatcher creates a new filesystem watcher.
func NewWatcher(root string, handler FSHandler, opts ...Option) (*Watcher, error) {
	w := &Watcher{
		root:     root,
		handler:  handler,
		interval: 100 * time.Millisecond,
		done:     make(chan struct{}),
		known:    make(map[string]fileInfo),
	}
	for _, opt := range opts {
		opt(w)
	}

	// Initial scan
	if err := w.scan(true); err != nil {
		return nil, fmt.Errorf("initial scan: %w", err)
	}

	// Start polling
	w.wg.Add(1)
	go w.poll()

	return w, nil
}

// Close stops the watcher.
func (w *Watcher) Close() error {
	close(w.done)
	w.wg.Wait()
	return nil
}

func (w *Watcher) poll() {
	defer w.wg.Done()
	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()

	for {
		select {
		case <-w.done:
			return
		case <-ticker.C:
			w.scan(false)
		}
	}
}

func (w *Watcher) scan(initial bool) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	current := make(map[string]fileInfo)

	err := filepath.Walk(w.root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}

		relPath, _ := filepath.Rel(w.root, path)

		// Check excludes
		for _, pattern := range w.excludes {
			if matchGlob(pattern, relPath) {
				if info.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
		}

		if info.IsDir() {
			return nil
		}

		fi := fileInfo{
			modTime: info.ModTime(),
			size:    info.Size(),
		}
		current[path] = fi

		if !initial {
			prev, existed := w.known[path]
			if !existed {
				// New file
				w.handler(internal.FSEvent{
					Op:   internal.FSCreate,
					Path: path,
					Time: time.Now(),
				})
			} else if fi.modTime != prev.modTime || fi.size != prev.size {
				// Modified file
				w.handler(internal.FSEvent{
					Op:   internal.FSWrite,
					Path: path,
					Time: time.Now(),
				})
			}
		}

		return nil
	})

	// Check for deleted files
	if !initial {
		for path := range w.known {
			if _, exists := current[path]; !exists {
				w.handler(internal.FSEvent{
					Op:   internal.FSRemove,
					Path: path,
					Time: time.Now(),
				})
			}
		}
	}

	w.known = current
	return err
}

// matchGlob matches a path against a glob pattern including ** support.
func matchGlob(pattern, path string) bool {
	if matched, _ := filepath.Match(pattern, path); matched {
		return true
	}
	// Handle ** prefix matching
	if strings.HasSuffix(pattern, "/**") {
		prefix := pattern[:len(pattern)-3]
		if strings.HasPrefix(path, prefix+"/") || path == prefix {
			return true
		}
	}
	// Handle patterns like ".git/**" matching ".git"
	if strings.HasSuffix(pattern, "/**") {
		prefix := pattern[:len(pattern)-3]
		if path == prefix {
			return true
		}
	}
	return false
}

// QuarantineFile moves a file to a quarantine location.
func QuarantineFile(path string) error {
	quarantinePath := path + ".muselet-quarantine"
	return os.Rename(path, quarantinePath)
}

// RestoreFile restores a quarantined file.
func RestoreFile(path string) error {
	quarantinePath := path + ".muselet-quarantine"
	return os.Rename(quarantinePath, path)
}
