package watcher

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/kamilrybacki/muselet/internal"
)

func TestWatcherDetectsFileCreation(t *testing.T) {
	dir := t.TempDir()
	events := make(chan internal.FSEvent, 10)
	w, err := NewWatcher(dir, func(evt internal.FSEvent) { events <- evt },
		WithInterval(50*time.Millisecond))
	if err != nil {
		t.Fatalf("new watcher: %v", err)
	}
	defer w.Close()

	// Create a file
	os.WriteFile(filepath.Join(dir, ".env"), []byte("SECRET=foo"), 0644)

	select {
	case evt := <-events:
		if evt.Op != internal.FSCreate {
			t.Errorf("op: want FSCreate, got %v", evt.Op)
		}
		if filepath.Base(evt.Path) != ".env" {
			t.Errorf("path: want .env, got %s", filepath.Base(evt.Path))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for create event")
	}
}

func TestWatcherDetectsFileModification(t *testing.T) {
	dir := t.TempDir()
	filePath := filepath.Join(dir, "config.yaml")
	os.WriteFile(filePath, []byte("old"), 0644)

	// Small delay so initial scan captures the file
	time.Sleep(10 * time.Millisecond)

	events := make(chan internal.FSEvent, 10)
	w, err := NewWatcher(dir, func(evt internal.FSEvent) { events <- evt },
		WithInterval(50*time.Millisecond))
	if err != nil {
		t.Fatalf("new watcher: %v", err)
	}
	defer w.Close()

	// Modify file
	time.Sleep(60 * time.Millisecond)
	os.WriteFile(filePath, []byte("new content with SECRET=bar"), 0644)

	select {
	case evt := <-events:
		if evt.Op != internal.FSWrite {
			t.Errorf("op: want FSWrite, got %v", evt.Op)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for write event")
	}
}

func TestWatcherIgnoresExcludedPaths(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, ".git", "objects"), 0755)

	var mu sync.Mutex
	var events []internal.FSEvent
	w, err := NewWatcher(dir, func(evt internal.FSEvent) {
		mu.Lock()
		events = append(events, evt)
		mu.Unlock()
	}, WithExcludes([]string{".git/**"}), WithInterval(50*time.Millisecond))
	if err != nil {
		t.Fatalf("new watcher: %v", err)
	}
	defer w.Close()

	// Write to .git — should be ignored
	os.WriteFile(filepath.Join(dir, ".git", "objects", "abc"), []byte("data"), 0644)

	// Write to watched path — should fire
	time.Sleep(60 * time.Millisecond)
	os.WriteFile(filepath.Join(dir, "secret.txt"), []byte("data"), 0644)

	time.Sleep(200 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()

	// Should only have events for secret.txt
	for _, evt := range events {
		if filepath.Base(evt.Path) != "secret.txt" {
			t.Errorf("unexpected event for excluded path: %s", evt.Path)
		}
	}
	if len(events) == 0 {
		t.Error("should have at least one event for secret.txt")
	}
}

func TestQuarantineAndRestore(t *testing.T) {
	dir := t.TempDir()
	envPath := filepath.Join(dir, ".env")
	content := "AWS_KEY=AKIAIOSFODNN7EXAMPLE"
	os.WriteFile(envPath, []byte(content), 0644)

	// Quarantine
	err := QuarantineFile(envPath)
	if err != nil {
		t.Fatalf("quarantine: %v", err)
	}

	// Original should not exist
	if _, err := os.Stat(envPath); !os.IsNotExist(err) {
		t.Error("original file should not exist after quarantine")
	}

	// Quarantined version should exist
	if _, err := os.Stat(envPath + ".muselet-quarantine"); err != nil {
		t.Error("quarantined file should exist")
	}

	// Restore
	err = RestoreFile(envPath)
	if err != nil {
		t.Fatalf("restore: %v", err)
	}

	restored, err := os.ReadFile(envPath)
	if err != nil {
		t.Fatalf("read restored: %v", err)
	}
	if string(restored) != content {
		t.Errorf("restored content: want %q, got %q", content, string(restored))
	}
}

func TestWatcherClose(t *testing.T) {
	dir := t.TempDir()
	w, err := NewWatcher(dir, func(evt internal.FSEvent) {},
		WithInterval(50*time.Millisecond))
	if err != nil {
		t.Fatalf("new watcher: %v", err)
	}

	// Should close without blocking
	done := make(chan struct{})
	go func() {
		w.Close()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("watcher.Close() timed out")
	}
}
