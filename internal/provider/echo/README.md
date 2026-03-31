# Echo Provider

The Echo provider is a test provider for the vulnz-go framework that provides mock vulnerability data for validation and testing purposes.

## Overview

Echo is designed as a reference implementation demonstrating how providers should:
- Fetch data from external sources
- Parse and normalize vulnerability data
- Integrate with the storage backend
- Manage workspace state
- Handle errors and context cancellation

## Configuration

```go
config := echo.Config{
    URL:            "https://advisory.echohq.com/data.json",
    RequestTimeout: 125 * time.Second,
    Namespace:      "echo",
}
```

## Data Format

The Echo provider expects JSON data in the following format:

```json
{
  "package_name": {
    "CVE-ID": {
      "severity": "High|Medium|Low|Unknown",
      "fixed_version": "version-string"
    }
  }
}
```

Example:

```json
{
  "libssl": {
    "CVE-2023-0001": {
      "severity": "High",
      "fixed_version": "1.1.1t-r0"
    }
  },
  "curl": {
    "CVE-2023-0002": {
      "severity": "Medium",
      "fixed_version": "8.0.1-r0"
    }
  }
}
```

## Usage

### As a Library

```go
import (
    "context"
    "log/slog"
    
    "github.com/shift/vulnz/internal/provider"
    "github.com/shift/vulnz/internal/provider/echo"
)

// Create provider configuration
config := provider.Config{
    Name:      "echo",
    Workspace: "/data/vulnz",
    Storage: provider.StorageConfig{
        Type: "sqlite",
        Path: "/data/vulnz/echo/results",
    },
    HTTP:   provider.DefaultHTTPConfig(),
    Logger: slog.Default(),
}

// Create provider instance
p, err := echo.NewProvider(config)
if err != nil {
    panic(err)
}

// Run update
ctx := context.Background()
urls, count, err := p.Update(ctx, nil)
if err != nil {
    panic(err)
}

fmt.Printf("Fetched %d vulnerabilities from %v\n", count, urls)
```

### Via CLI

```bash
# Run the echo provider
vulnz run echo

# List all providers (should include echo)
vulnz list
```

## Architecture

### Components

1. **Provider** (`provider.go`)
   - Implements the `provider.Provider` interface
   - Orchestrates the update workflow
   - Manages workspace and storage integration

2. **Parser** (`parser.go`)
   - Fetches data from the Echo API
   - Parses JSON into vulnerability records
   - Normalizes data to the standard format

3. **Config** (`config.go`)
   - Configuration types and defaults
   - URL, timeout, and namespace settings

### Data Flow

```
1. Provider.Update() called
2. Parser.Get() fetches JSON from URL
3. Parser.download() saves to workspace/input/
4. Parser.normalize() transforms to Vulnerability records
5. Provider writes records to storage backend
6. Provider updates workspace state
```

## Testing

The Echo provider includes comprehensive BDD tests using Ginkgo and Gomega:

```bash
# Run all tests
cd internal/provider/echo
go test -v

# Run with Ginkgo
ginkgo -v

# Run with coverage
go test -cover -coverprofile=coverage.out
go tool cover -html=coverage.out
```

### Test Coverage

- **Parser Tests** (`parser_test.go`): Data fetching, parsing, normalization, error handling
- **Provider Tests** (`provider_test.go`): Provider interface, workspace management, storage integration

Target coverage: **75%+**

## Provider Registration

The Echo provider automatically registers itself in the provider registry via `init()`:

```go
func init() {
    provider.Register("echo", NewProvider)
}
```

This enables automatic discovery by the CLI and framework.

## Workspace Structure

```
/data/vulnz/echo/
├── input/
│   └── echo-advisories/
│       └── data.json          # Downloaded raw data
├── results/
│   ├── vulnerability.db        # SQLite backend (if configured)
│   └── *.json                  # Flat-file backend (if configured)
└── metadata.json               # Workspace state
```

## Schema

The Echo provider uses the OS schema version 1.0:

```
https://schema.anchore.io/vulnerability/1.0
```

Vulnerability identifiers follow the pattern:

```
echo:rolling:CVE-YYYY-NNNN
```

## Namespace

All Echo vulnerabilities use the namespace:

```
echo:rolling
```

This indicates:
- Provider: `echo`
- Release: `rolling` (single rolling release for test data)

## Limitations

This is a **test provider** with the following limitations:

1. **Mock Data**: Provides synthetic test data, not real vulnerability information
2. **No Fix Dates**: Does not include availability dates for fixes
3. **Single Release**: Only supports a "rolling" release model
4. **No Incremental Updates**: Re-processes all data on each run

## Development

When using Echo as a reference for implementing new providers:

1. **Study the structure**: Three-file pattern (config, parser, provider)
2. **Follow the interfaces**: Implement `provider.Provider` and optionally `MetadataProvider`, `TagsProvider`
3. **Write BDD tests**: Use Ginkgo for descriptive, readable tests
4. **Use workspace properly**: Separate input/results, track state
5. **Handle errors**: Wrap errors with context, check context cancellation
6. **Log appropriately**: Use structured logging with slog

## See Also

- [Provider Interface](../provider.go)
- [Storage Backend](../../storage/)
- [Workspace Manager](../../workspace/)
- [Vulnerability Types](../../utils/vulnerability/)
