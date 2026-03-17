package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/kamilrybacki/muselet/internal/agent"
)

func main() {
	sockPath := flag.String("socket", "/var/run/muselet/muselet.sock", "Path to Unix socket")
	watchDirs := flag.String("watch", "/workspace", "Comma-separated directories to watch")
	excludes := flag.String("exclude", ".git/**", "Comma-separated exclude patterns")
	flag.Parse()

	args := flag.Args()
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "muselet-agent: no command specified")
		fmt.Fprintln(os.Stderr, "usage: muselet-agent [flags] -- command [args...]")
		os.Exit(1)
	}

	// Parse watch dirs
	dirs := strings.Split(*watchDirs, ",")
	excl := strings.Split(*excludes, ",")

	opts := []agent.AgentOption{}
	for _, dir := range dirs {
		dir = strings.TrimSpace(dir)
		if dir != "" {
			opts = append(opts, agent.WithWatchDir(dir))
		}
	}
	_ = excl

	a, err := agent.NewAgent(*sockPath, os.Stdout, opts...)
	if err != nil {
		fmt.Fprintf(os.Stderr, "muselet-agent: failed to start: %v\n", err)
		os.Exit(1)
	}
	defer a.Close()

	// Start filesystem watcher
	if err := a.RunWatcher(); err != nil {
		fmt.Fprintf(os.Stderr, "muselet-agent: watcher error: %v\n", err)
	}

	// Run the child process
	if err := a.RunProcess(args[0], args[1:]...); err != nil {
		fmt.Fprintf(os.Stderr, "muselet-agent: process error: %v\n", err)
		os.Exit(1)
	}
}
