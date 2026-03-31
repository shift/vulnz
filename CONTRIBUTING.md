# Contributing to vulnz

Thank you for your interest in contributing to vulnz. This project is a high-performance vulnerability data aggregator focused on EU Cyber Resilience Act (CRA) and NIS2 compliance.

## Quick Start

1. Fork the repository and clone your fork
2. Install dependencies: `make deps`
3. Run tests: `make test`
4. Run linters: `make lint`
5. Create a feature branch and open a PR

## Adding a New Provider

The provider architecture is designed to be easily extensible. Here's how to add a new data source:

### 1. Create the Provider Directory

Create a new directory under `internal/provider/<name>/` with the following files:

```
internal/provider/<name>/
├── provider.go      # Provider implementation
├── manager.go       # Data fetching and parsing logic
├── provider_test.go # Tests
└── *_suite_test.go  # Ginkgo test suite
```

### 2. Implement the Provider Interface

Your provider must implement the `provider.Provider` interface:

```go
type Provider interface {
    Name() string
    Update(ctx context.Context, lastUpdated *time.Time) ([]string, int, error)
}
```

Example structure:

```go
package myprovider

import (
    "context"
    "time"

    "github.com/shift/vulnz/internal/provider"
)

type Provider struct {
    *provider.Base
    config provider.Config
}

func init() {
    provider.Register("myprovider", NewProvider)
}

func NewProvider(config provider.Config) (provider.Provider, error) {
    return &Provider{
        Base:   provider.NewBase(config),
        config: config,
    }, nil
}

func (p *Provider) Name() string {
    return "myprovider"
}

func (p *Provider) Tags() []string {
    return []string{"os", "linux"} // Classify your provider
}

func (p *Provider) Update(ctx context.Context, lastUpdated *time.Time) ([]string, int, error) {
    // 1. Fetch data from upstream API
    // 2. Parse and normalize to vulnerability schema
    // 3. Write results to storage
    return urls, count, nil
}
```

### 3. Register the Provider

Add a blank import in `internal/providers/register.go`:

```go
import (
    _ "github.com/shift/vulnz/internal/provider/myprovider"
)
```

### 4. Follow the Schema

All provider output must conform to the vulnerability schema at:
`docs/schema/vulnerability-1.0.3.json`

The schema is validated at runtime using `santhosh-tekuri/jsonschema/v6`.

### 5. Write Tests

Use Ginkgo/Gomega for BDD-style tests:

```go
func TestMyProvider(t *testing.T) {
    RegisterFailHandler(Fail)
    RunSpecs(t, "MyProvider Suite")
}
```

Test at minimum:
- Successful data fetch and parsing
- Error handling (network failures, invalid responses)
- Schema compliance

### 6. Update Documentation

- Add your provider to the table in `README.md`
- Create a `README.md` in your provider directory explaining the data source

## Code Standards

- **Go 1.25+** required
- Run `make lint` before submitting PRs
- Follow existing code style and conventions
- Use `context.Context` for all I/O operations
- Write meaningful commit messages (conventional commits preferred)

## Architecture Overview

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for a comprehensive overview of the system design.

Key components:
- **Provider Framework** (`internal/provider/`) - Plugin system for data sources
- **Storage Backends** (`internal/storage/`) - Flat-file and SQLite
- **HTTP Client** (`internal/http/`) - Rate limiting, retry, connection pooling
- **Schema Validation** (`internal/schema/`) - JSON Schema enforcement
- **Workspace Management** (`internal/workspace/`) - State, locks, checksums

## Development Workflow

```bash
# Build
make build

# Run tests
make test

# Run linters
make lint

# Clean build artifacts
make clean

# Run a specific provider
./vulnz run kev

# Run all providers
./vulnz run --all --parallel 8
```

## Reporting Issues

- **Security vulnerabilities**: See [`SECURITY.md`](SECURITY.md) for responsible disclosure
- **Bugs**: Open a GitHub issue with steps to reproduce
- **Feature requests**: Open an issue with the `enhancement` label

## License

By contributing to vulnz, you agree that your contributions will be licensed under the AGPL-3.0 license.
