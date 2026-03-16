.PHONY: build test test-unit test-integration test-system test-e2e test-bench test-all clean lint

# Build
build:
	go build -o bin/muselet-agent ./cmd/agent
	go build -o bin/muselet-sidecar ./cmd/sidecar

# Test targets
test-unit:
	go test -short -race -count=1 ./internal/...

test-integration:
	go test -race -count=1 -timeout 60s ./test/integration/...

test-system:
	go test -race -count=1 -timeout 120s ./test/system/...

test-e2e:
	go test -count=1 -timeout 300s ./test/e2e/...

test-bench:
	go test -bench=. -benchmem -count=3 ./internal/scanner/...

test: test-unit test-integration test-system

test-all: test test-e2e

# CI pipeline stages
ci-fast: test-unit test-bench
ci-full: test-unit test-integration test-system test-bench
ci-nightly: test-all

# Docker
docker-build:
	docker build -t muselet-agent -f deploy/Dockerfile.agent .
	docker build -t muselet-sidecar -f deploy/Dockerfile.sidecar .

# Lint
lint:
	go vet ./...

# Clean
clean:
	rm -rf bin/
