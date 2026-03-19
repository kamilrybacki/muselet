package e2e

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kamilrybacki/muselet/internal/policy"
	"gopkg.in/yaml.v3"
)

// DockerTestEnv manages Docker-based E2E tests.
type DockerTestEnv struct {
	t          *testing.T
	network    string
	sockDir    string
	workDir    string
	containers []string
}

func isDockerAvailable() bool {
	_, err := exec.LookPath("docker")
	return err == nil
}

func randomHex(n int) string {
	return fmt.Sprintf("%x", time.Now().UnixNano())[:n]
}

// NewDockerTestEnv creates a new Docker test environment.
func NewDockerTestEnv(t *testing.T, pol *policy.Policy) *DockerTestEnv {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping Docker E2E test in short mode")
	}
	if !isDockerAvailable() {
		t.Skip("docker not found, skipping E2E test")
	}

	env := &DockerTestEnv{
		t:       t,
		network: fmt.Sprintf("muselet-test-%s", randomHex(8)),
		sockDir: t.TempDir(),
		workDir: t.TempDir(),
	}

	if pol != nil {
		policyBytes, _ := yaml.Marshal(pol)
		os.WriteFile(filepath.Join(env.sockDir, "policy.yaml"), policyBytes, 0644)
	}

	// Create Docker network
	cmd := exec.Command("docker", "network", "create", env.network)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("failed to create docker network: %s %v", out, err)
	}

	t.Cleanup(func() {
		for _, id := range env.containers {
			exec.Command("docker", "rm", "-f", id).Run()
		}
		exec.Command("docker", "network", "rm", env.network).Run()
	})

	return env
}

func (env *DockerTestEnv) runContainer(image string, args ...string) string {
	env.t.Helper()
	allArgs := append([]string{"run", "-d", "--rm", "--network", env.network}, args...)
	allArgs = append(allArgs, image)

	cmd := exec.Command("docker", allArgs...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		env.t.Skipf("docker run: %s %v", out, err)
	}

	id := strings.TrimSpace(string(out))
	env.containers = append(env.containers, id)
	return id
}

func (env *DockerTestEnv) dockerExec(containerID string, args ...string) string {
	env.t.Helper()
	if containerID == "" {
		env.t.Skip("no container to exec into (previous docker run skipped)")
	}
	allArgs := append([]string{"exec", containerID}, args...)
	cmd := exec.Command("docker", allArgs...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		// Don't fatal — some exec failures are expected in tests
		return string(out)
	}
	return string(out)
}

// TestE2EDockerSmokeTest verifies Docker test infrastructure works.
func TestE2EDockerSmokeTest(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping E2E test in short mode")
	}
	if !isDockerAvailable() {
		t.Skip("docker not found")
	}

	env := NewDockerTestEnv(t, nil)
	id := env.runContainer("alpine:3.19", "--entrypoint", "sh", "-c", "echo hello && sleep 5")
	time.Sleep(time.Second)

	out := env.dockerExec(id, "echo", "world")
	if !strings.Contains(out, "world") {
		t.Errorf("expected 'world' in output, got: %s", out)
	}
}

// TestE2EDockerNetworkIsolation verifies container network setup.
func TestE2EDockerNetworkIsolation(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping E2E test in short mode")
	}
	if !isDockerAvailable() {
		t.Skip("docker not found")
	}

	env := NewDockerTestEnv(t, nil)
	id := env.runContainer("alpine:3.19", "--entrypoint", "sleep", "30")
	time.Sleep(time.Second)

	// Container should be on the test network
	out := env.dockerExec(id, "hostname", "-i")
	if strings.TrimSpace(out) == "" {
		t.Error("container should have an IP address on the test network")
	}
}
