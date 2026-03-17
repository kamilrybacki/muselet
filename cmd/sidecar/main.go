package main

import (
	"crypto/rand"
	"flag"
	"fmt"
	"os"

	"github.com/kamilrybacki/muselet/internal/policy"
	"github.com/kamilrybacki/muselet/internal/sidecar"
)

func main() {
	sockPath := flag.String("socket", "/var/run/muselet/muselet.sock", "Path to Unix socket")
	policyPath := flag.String("policy", "/etc/muselet/policy.yaml", "Path to policy file")
	auditPath := flag.String("audit-log", "/var/log/muselet/audit.jsonl", "Path to audit log")
	flag.Parse()

	// Load policy
	pol := policy.DefaultPolicy()
	if *policyPath != "" {
		if data, err := os.ReadFile(*policyPath); err == nil {
			parsed, err := policy.ParsePolicy(data)
			if err != nil {
				fmt.Fprintf(os.Stderr, "muselet-sidecar: invalid policy: %v\n", err)
				os.Exit(1)
			}
			pol = policy.MergePolicies(pol, parsed)
		}
	}

	// Set up audit log
	auditFile := os.Stdout
	if *auditPath != "" {
		if err := os.MkdirAll(dirOf(*auditPath), 0755); err == nil {
			if f, err := os.OpenFile(*auditPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644); err == nil {
				auditFile = f
				defer f.Close()
			}
		}
	}

	sessionID := generateSessionID()

	s, err := sidecar.NewSidecar(sidecar.Config{
		SocketPath: *sockPath,
		AuditLog:   auditFile,
	}, pol, sessionID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "muselet-sidecar: failed to start: %v\n", err)
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr, "muselet-sidecar: session %s listening on %s\n", sessionID, *sockPath)

	if err := s.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "muselet-sidecar: %v\n", err)
		os.Exit(1)
	}
}

func generateSessionID() string {
	b := make([]byte, 4)
	rand.Read(b)
	return fmt.Sprintf("%x", b)
}

func dirOf(path string) string {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '/' {
			return path[:i]
		}
	}
	return "."
}
