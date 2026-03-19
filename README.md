# muselet

Data Loss Prevention for containerized workloads. Muselet intercepts sensitive data — credentials, PII, infrastructure details — before it leaves your containers via stdout, network, filesystem, or patches.

## Architecture

Muselet runs as two cooperating processes:

```
┌─────────────────────────────────────┐
│           Container                 │
│                                     │
│  ┌───────────┐    Unix Socket       │
│  │   Agent   │◄────────────────►┌───┴──────┐
│  │           │   events/verdicts│  Sidecar  │
│  └─────┬─────┘                  │           │
│        │ wraps                  │  policy   │
│   ┌────┴────┐                   │  scanner  │
│   │ Process │                   │  audit    │
│   └─────────┘                   └───┬───────┘
│                                     │
└─────────────────────────────────────┘
                                      │
                              audit.jsonl
```

- **Agent** — runs inside the container, wraps the target process, captures stdout/stderr, monitors filesystem writes, and proxies network requests. Streams events to the sidecar over a Unix socket.
- **Sidecar** — receives events, applies scanning rules and policy, returns verdicts (allow / block / alert / redact), and writes structured audit logs.

## Detection

Muselet ships 13 builtin detection rules across four categories:

| Category | Examples |
|---|---|
| **Credentials** | AWS access keys, GitHub PATs, API keys, private keys, database connection strings, bearer tokens, Slack/Stripe/Google keys |
| **Infrastructure** | Private IPs, AWS ARNs |
| **PII** | Email addresses, SSNs, credit card numbers |
| **Entropy** | High-entropy strings (Shannon entropy >= 4.5, length 20–128) |

The scanner pipeline combines:

- **Aho-Corasick** multi-pattern matching for literal prefixes (`AKIA`, `ghp_`, `sk-live-`, etc.)
- **Bloom filter** for fast safe-domain lookups to reduce false positives
- **Regex rules** for structured pattern matching
- **Context analysis** that adjusts confidence based on file path risk, vector type, and nearby markers (e.g. `test`, `example`, `dummy`)

## Quick Start

### Build

```bash
make build     # outputs bin/muselet-agent and bin/muselet-sidecar
```

### Run with Docker Compose

```bash
docker-compose -f deploy/docker-compose.yaml up
```

### Run directly

```bash
# Start the sidecar
muselet-sidecar \
  -socket /var/run/muselet/muselet.sock \
  -policy /etc/muselet/policy.yaml \
  -audit-log /var/log/muselet/audit.jsonl

# Start the agent, wrapping your process
muselet-agent \
  -socket /var/run/muselet/muselet.sock \
  -watch /workspace \
  -exclude ".git/**" \
  -- python script.py
```

## Usage Examples

### curl — catching leaked tokens in verbose output

```bash
muselet-agent \
  -socket /var/run/muselet/muselet.sock \
  -watch /workspace \
  -- curl -v -H "Authorization: Bearer $API_TOKEN" https://api.example.com/data

# muselet redacts the Bearer token from stderr (-v output)
```

### Python — catching secrets in print/logging output

```bash
muselet-agent \
  -socket /var/run/muselet/muselet.sock \
  -watch /workspace \
  -exclude ".git/**,__pycache__/**,.venv/**" \
  -- python train.py --config config.yaml

# Catches: print(os.environ), logging.debug(f"DSN={dsn}"), tracebacks with boto3 creds
```

### Node.js — catching secrets in console.log

```bash
muselet-agent \
  -socket /var/run/muselet/muselet.sock \
  -watch /workspace \
  -exclude "node_modules/**,.git/**" \
  -- node server.js

# Catches: console.log(process.env), config objects with DB URIs, Stripe keys
```

### git — scanning patches before push

```bash
muselet-agent \
  -socket /var/run/muselet/muselet.sock \
  -watch /workspace \
  -- git push origin main

# Catches: .env files committed by mistake, hardcoded tokens, private keys in diffs
```

### Terraform — catching infrastructure secrets in plan/apply output

```bash
muselet-agent \
  -socket /var/run/muselet/muselet.sock \
  -watch /workspace/infra \
  -exclude ".terraform/**" \
  -- terraform apply -auto-approve

# Catches: DB passwords in outputs, ARNs/account IDs, private IPs, tfstate secrets
```

### Database clients — catching PII and connection strings

```bash
muselet-agent \
  -socket /var/run/muselet/muselet.sock \
  -- psql "postgres://admin:s3cret@10.0.1.5:5432/prod"

# Catches: connection string credentials, SSNs/emails in query results, internal IPs
```

### AWS CLI — catching credential and infrastructure leaks

```bash
muselet-agent \
  -socket /var/run/muselet/muselet.sock \
  -- aws sts get-caller-identity

# Catches: ARNs, account IDs, access key display, signed URLs, private IPs
```

### Docker — catching secrets in build output

```bash
muselet-agent \
  -socket /var/run/muselet/muselet.sock \
  -watch /workspace \
  -- docker build --build-arg API_KEY=$API_KEY -t myapp .

# Catches: build args echoed in RUN steps, env vars in docker inspect/logs
```

## Policy

Policies are YAML files that control what gets scanned and how violations are handled:

```yaml
version: 1

categories:
  credentials:   { enabled: true }
  infrastructure: { enabled: true }
  pii:           { enabled: false }
  proprietary:   { enabled: false }

vectors:
  network:
    enabled: true
    allowed_hosts:
      - "api.anthropic.com"
      - "github.com"
    block_dns_tunneling: true
  filesystem:
    enabled: true
    watch_paths: ["/workspace", "/tmp"]
    excludes: [".git/**", "node_modules/**", "vendor/**"]
  stdout:
    enabled: true
    mode: speculative    # speculative | synchronous | async
    hold_timeout_ms: 5
  patches:
    enabled: true
    scan_before_export: true

interactive:
  timeout_seconds: 30
  on_timeout: block
```

See [`policies/default.yaml`](policies/default.yaml) for the full default configuration.

### Learning Mode

Enable learning mode to audit without blocking — useful for tuning policy before enforcement. The sidecar logs what *would* have been blocked without actually preventing it.

## Vectors

Muselet monitors four attack vectors:

| Vector | How it works |
|---|---|
| **stdout/stderr** | Agent wraps the child process and scans output on the hot path. Supports inline redaction. |
| **Network** | HTTP proxy with host allowlist/blocklist. Optional TLS inspection and DNS tunneling detection. |
| **Filesystem** | Polling-based watcher (no CGO required) monitors configured paths for writes. |
| **Patches** | Scans code diffs before they are exported from the container. |

## Testing

```bash
make test              # all tests
make test-unit         # unit tests (-short -race)
make test-integration  # agent + sidecar integration (60s timeout)
make test-system       # backpressure, latency, false positives (120s timeout)
make test-e2e          # Docker-based end-to-end tests (300s timeout)
make test-bench        # scanner benchmarks
```

CI stages:
- `make ci-fast` — unit tests + benchmarks (< 1 min)
- `make ci-full` — unit + integration + system + benchmarks
- `make ci-nightly` — everything including e2e

## Project Structure

```
cmd/
  agent/             Agent entry point
  sidecar/           Sidecar entry point
internal/
  agent/             Process wrapping, event emission, hot-path scanning
  sidecar/           Verdict engine, policy evaluation
  scanner/           Pattern matching, entropy, Aho-Corasick, bloom filter, context scoring
  policy/            YAML policy parsing and merging
  audit/             NDJSON structured audit logging
  transport/         Unix socket NDJSON protocol
  watcher/           Portable filesystem polling
  proxy/             HTTP proxy with DLP inspection
deploy/
  Dockerfile.agent   Multi-stage Alpine build
  Dockerfile.sidecar Multi-stage Alpine build
  docker-compose.yaml
policies/
  default.yaml       Default policy
test/
  integration/       Agent-sidecar communication tests
  system/            Performance and reliability tests
  e2e/               Full Docker-based tests
```

## Design Decisions

- **Zero CGO** — filesystem watcher uses polling for full portability across platforms
- **Single dependency** — only `gopkg.in/yaml.v3` for policy parsing
- **Streaming hot path** — stdout scanning is synchronous with overlap buffers to catch secrets split across chunks
- **Context-aware scoring** — file path risk, vector type, and nearby markers reduce false positives
- **Async-first** — events flow asynchronously from agent to sidecar with backpressure handling

## License

[MIT](LICENSE)
