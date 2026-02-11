.PHONY: build test run clean docker-build docker-run lint security-scan fmt vet ci vulncheck help

# Build variables
BINARY_SERVER = bin/sandbox-server
BINARY_CLI    = bin/sandbox-cli
VERSION      ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_TIME    = $(shell date -u '+%Y-%m-%dT%H:%M:%SZ')
LDFLAGS       = -ldflags "-s -w -X main.version=$(VERSION) -X main.buildTime=$(BUILD_TIME)"

# Go variables
GOFLAGS      = -trimpath
GOTESTFLAGS  = -race -count=1

## build: Build server and CLI binaries
build:
	go build $(GOFLAGS) $(LDFLAGS) -o $(BINARY_SERVER) ./cmd/server
	go build $(GOFLAGS) $(LDFLAGS) -o $(BINARY_CLI) ./cmd/cli

## build-server: Build only the server binary
build-server:
	go build $(GOFLAGS) $(LDFLAGS) -o $(BINARY_SERVER) ./cmd/server

## build-cli: Build only the CLI binary
build-cli:
	go build $(GOFLAGS) $(LDFLAGS) -o $(BINARY_CLI) ./cmd/cli

## run: Build and run the server locally
run: build-server
	./$(BINARY_SERVER)

## test: Run all tests
test:
	go test $(GOTESTFLAGS) ./...

## test-unit: Run unit tests only (no Docker or containerd required)
test-unit:
	go test $(GOTESTFLAGS) -short ./...

## test-e2e: Run end-to-end security tests (requires Docker)
test-e2e:
	go test $(GOTESTFLAGS) -run TestE2E -v -timeout 120s ./tests/

## test-integration: Run integration tests (requires Docker or containerd)
test-integration:
	go test $(GOTESTFLAGS) -run TestEscape -v ./tests/
	go test $(GOTESTFLAGS) -run TestTimeout -v ./tests/

## test-security: Run escape attempt tests
test-security:
	go test $(GOTESTFLAGS) -run TestEscape -v -timeout 120s ./tests/

## test-exploits: Run exploit tests against a running server
test-exploits:
	./scripts/test-exploits.sh http://localhost:8080

## bench: Run benchmarks
bench:
	go test -bench=. -benchmem -run=^$$ ./tests/

## lint: Run golangci-lint
lint:
	golangci-lint run ./...

## fmt: Format code
fmt:
	go fmt ./...
	gofumpt -l -w .

## vet: Run go vet
vet:
	go vet ./...

## security-scan: Run gosec security scanner
security-scan:
	gosec -exclude-generated ./...

## vulncheck: Check for known vulnerabilities in dependencies
vulncheck:
	govulncheck ./...

## docker-build: Build the server Docker image
docker-build:
	docker build -f deployments/docker/Dockerfile.server -t safe-agent-sandbox:$(VERSION) .

## docker-run: Start all services with Docker Compose
docker-run:
	docker-compose -f deployments/docker-compose.yml up

## docker-down: Stop all Docker Compose services
docker-down:
	docker-compose -f deployments/docker-compose.yml down -v

## deps: Download and tidy Go dependencies
deps:
	go mod download
	go mod tidy

## ci: Run the same checks as CI (build, vet, unit tests, e2e, security scan, lint)
ci: build vet test-unit test-e2e security-scan vulncheck lint

## setup: Install development tools (golangci-lint, gosec, govulncheck, gofumpt)
setup:
	go install github.com/securego/gosec/v2/cmd/gosec@latest
	go install golang.org/x/vuln/cmd/govulncheck@latest
	go install mvdan.cc/gofumpt@latest
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest

## migrate: Run database migrations against PostgreSQL
migrate:
	psql "$(DATABASE_URL)" -f internal/storage/migrations/001_initial.sql

## clean: Remove build artifacts and caches
clean:
	rm -rf bin/
	go clean -cache -testcache

## help: Show available targets
help:
	@echo "Usage: make [target]"
	@echo ""
	@sed -n 's/^## //p' $(MAKEFILE_LIST) | column -t -s ':'
