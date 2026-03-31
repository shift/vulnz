# Provider Framework

This directory contains the core provider abstraction for vulnz-go. All vulnerability data providers implement the interfaces defined here.

## Architecture

The provider framework is built on several key components:

### 1. Provider Interface (`provider.go`)

The `Provider` interface defines the contract that all providers must implement:

```go
type Provider interface {
    Name() string
    Update(ctx context.Context, lastUpdated *time.Time) (urls []string, count int, err error)
}
```

Optional interfaces for additional functionality:
- `MetadataProvider`: Expose provider metadata
- `TagsProvider`: Classify providers with tags

### 2. Registry (`registry.go`)

Providers self-register using the registry pattern:

```go
func init() {
    provider.Register("alpine", NewAlpineProvider)
}
```

The registry provides:
- Thread-safe provider registration
- Factory pattern for provider creation
- Discovery of all registered providers

### 3. Base Provider (`base.go`)

Common functionality available to all providers:

```go
type MyProvider struct {
    *provider.Base
    // provider-specific fields
}
```

The base provides:
- Configuration access
- Structured logging
- Workspace management

### 4. Executor (`executor.go`)

Orchestrates parallel provider execution:

```go
executor := provider.NewExecutor(config, logger)
results, err := executor.Run(ctx, []string{"alpine", "debian", "ubuntu"})
```

Features:
- Configurable concurrency limits
- Context-based cancellation
- Result aggregation
- Error handling

## Creating a Provider

See `example_provider.go` for a complete example. Here's the basic structure:

```go
package myprovider

import (
    "context"
    "time"
    "github.com/shift/vulnz/internal/provider"
)

type MyProvider struct {
    *provider.Base
}

func init() {
    provider.Register("myprovider", NewMyProvider)
}

func NewMyProvider(config provider.Config) (provider.Provider, error) {
    return &MyProvider{
        Base: provider.NewBase(config),
    }, nil
}

func (p *MyProvider) Name() string {
    return "myprovider"
}

func (p *MyProvider) Update(ctx context.Context, lastUpdated *time.Time) ([]string, int, error) {
    // 1. Fetch data
    // 2. Parse data
    // 3. Write results
    return urls, count, nil
}
```

## Testing

Each provider should have comprehensive tests:

```go
func TestMyProvider_Update(t *testing.T) {
    logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
    config := provider.Config{
        Name:      "myprovider",
        Workspace: t.TempDir(),
        Logger:    logger,
    }

    p, err := NewMyProvider(config)
    if err != nil {
        t.Fatalf("failed to create provider: %v", err)
    }

    ctx := context.Background()
    urls, count, err := p.Update(ctx, nil)
    
    // Assertions...
}
```

## Directory Structure

```
internal/provider/
├── provider.go          # Core interfaces
├── config.go            # Configuration types
├── base.go              # Base provider implementation
├── registry.go          # Provider registration
├── executor.go          # Execution orchestration
├── registry_test.go     # Registry tests
├── executor_test.go     # Executor tests
├── example_provider.go  # Example implementation
├── echo/                # Echo test provider
│   ├── echo.go
│   └── echo_test.go
└── README.md            # This file
```

## Next Steps

1. **Storage Backend**: Implement storage interfaces for flat-file and SQLite
2. **Workspace Management**: Create workspace directory structure and state management
3. **HTTP Client**: Build HTTP client with rate limiting and retries
4. **Providers**: Implement the 27+ vulnerability data providers
5. **CLI Integration**: Connect providers to the command-line interface

## References

- Architecture: `../../docs/ARCHITECTURE.md`
- Python reference: `../../../vunnel-eu-cra/src/vunnel/provider.py`
- Echo provider: `./echo/echo.go`
- Example: `./example_provider.go`
