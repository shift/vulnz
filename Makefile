BINARY=vulnz
VERSION?=$(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS=-ldflags "-s -w -X github.com/shift/vulnz/internal/cli.Version=$(VERSION)"

.PHONY: help build test lint clean install vet docker docker-run deps verify test-coverage

help: ## Show this help message
	@echo 'Usage: make [target]'
	@echo ''
	@echo 'Available targets:'
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

build: ## Build the vulnz binary
	@echo "Building vulnz..."
	@go build $(LDFLAGS) -o bin/$(BINARY) ./cmd/vulnz

test: ## Run tests
	@echo "Running tests..."
	@go test -v -race -coverprofile=coverage.txt -covermode=atomic ./...

test-coverage: test ## Run tests and show coverage
	@go tool cover -html=coverage.txt -o coverage.html
	@echo "Coverage report: coverage.html"

vet: ## Run go vet
	@go vet ./...

lint: vet ## Run linters
	@go fmt ./...
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run; \
	else \
		echo "golangci-lint not installed, skipping"; \
	fi

clean: ## Clean build artifacts
	@echo "Cleaning..."
	@rm -rf bin/ dist/ coverage.txt coverage.html data/

install: build ## Install vulnz to /usr/local/bin
	@echo "Installing vulnz..."
	@install -m 755 bin/$(BINARY) /usr/local/bin/

deps: ## Download dependencies
	@echo "Downloading dependencies..."
	@go mod download
	@go mod tidy

verify: ## Verify dependencies
	@echo "Verifying dependencies..."
	@go mod verify

docker: ## Build Docker image
	docker build -t vulnz-go:$(VERSION) .

docker-run: ## Run Docker image with mounted data
	docker run --rm -v $(PWD)/data:/data vulnz-go:$(VERSION) run --all

.DEFAULT_GOAL := help
