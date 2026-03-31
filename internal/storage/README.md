# Storage Package

This package provides storage backends for vulnerability data in vulnz-go.

## Features

- **Dual Storage Strategy**: Support for both SQLite and flat-file backends
- **Identical Interface**: Both backends implement the same `Backend` interface
- **SQLite Optimizations**:
  - WAL mode for concurrent reads
  - Batch inserts (default: 5000 records per transaction)
  - Atomic writes with temp file strategy
- **Flat-File Features**:
  - Nested directory organization by namespace
  - Pretty-printed JSON for readability
  - Atomic writes using temp file + rename
- **Thread-Safe**: All operations are safe for concurrent use

## Architecture

```
storage/
├── storage.go         # Backend interface and factory
├── sqlite.go          # SQLite implementation
├── flatfile.go        # Flat-file implementation
├── helpers.go         # Utility functions
├── *_test.go          # Comprehensive test suite
└── example_test.go    # Usage examples
```

## Usage

### Creating a Backend

```go
import (
    "context"
    "github.com/shift/vulnz/internal/storage"
)

// SQLite backend
backend, err := storage.New(storage.Config{
    Type:      "sqlite",
    Path:      "data/nvd/results.db",
    BatchSize: 5000,
})
if err != nil {
    log.Fatal(err)
}
defer backend.Close(context.Background())

// Flat-file backend
backend, err := storage.New(storage.Config{
    Type: "flat-file",
    Path: "data/alpine/results",
})
if err != nil {
    log.Fatal(err)
}
defer backend.Close(context.Background())
```

### Writing Records

```go
ctx := context.Background()

envelope := &storage.Envelope{
    Schema:     "https://schema.example.com/vuln/1.0",
    Identifier: "CVE-2023-1234",
    Item: map[string]interface{}{
        "severity":    "HIGH",
        "description": "Buffer overflow vulnerability",
    },
}

err := backend.Write(ctx, envelope)
if err != nil {
    log.Fatal(err)
}
```

### Reading Records

```go
ctx := context.Background()

// Read single record
record, err := backend.Read(ctx, "CVE-2023-1234")
if err != nil {
    log.Fatal(err)
}

// List all IDs
ids, err := backend.List(ctx)
if err != nil {
    log.Fatal(err)
}

// Count records
count, err := backend.Count(ctx)
if err != nil {
    log.Fatal(err)
}
```

## SQLite Backend

### Features

- **WAL Mode**: Write-Ahead Logging for concurrent read access
- **Batch Inserts**: Accumulates records and commits in batches
- **Connection Pool**: Configured for single writer (MaxOpenConns=1)
- **Automatic Flushing**: Batch is auto-flushed when size is reached
- **Graceful Shutdown**: Remaining batch is flushed on Close()

### Schema

```sql
CREATE TABLE vulnerabilities (
    id TEXT PRIMARY KEY,
    record BLOB NOT NULL
);
CREATE INDEX idx_id ON vulnerabilities(id);
```

### Configuration

```go
backend, err := storage.NewSQLiteBackend(
    "data/results.db",  // Database path
    5000,               // Batch size
)
```

### Performance Optimizations

- `PRAGMA journal_mode=WAL` - Concurrent reads during writes
- `PRAGMA synchronous=NORMAL` - Balance performance vs durability
- `PRAGMA cache_size=10000` - Larger cache for better performance
- `PRAGMA temp_store=MEMORY` - Use memory for temp tables
- `PRAGMA wal_autocheckpoint=10000` - Less frequent checkpoints

## Flat-File Backend

### Features

- **Directory Organization**: Files organized by namespace
- **Nested Directories**: Supports identifiers with path separators
- **Pretty-Printed JSON**: Human-readable format with indentation
- **Atomic Writes**: Temp file + rename for safety
- **Duplicate Handling**: Overwrites existing files

### File Structure

```
results/
├── nvd/
│   ├── CVE-2023-1234.json
│   └── CVE-2023-5678.json
├── alpine/
│   ├── alpine_3.18_CVE-2023-1234.json
│   └── alpine_3.19_CVE-2023-5678.json
└── debian/
    └── bookworm/
        └── CVE-2023-1234.json
```

### Namespace Extraction

The flat-file backend automatically extracts namespaces from identifiers:

- `CVE-2023-1234` → `nvd/`
- `GHSA-xxxx-yyyy-zzzz` → `github/`
- `alpine:3.18:CVE-2023-1234` → `alpine/`
- `debian/bookworm/CVE-2023-1234` → `debian/bookworm/`

## Interface

All backends implement the `Backend` interface:

```go
type Backend interface {
    // Write stores a vulnerability record
    Write(ctx context.Context, envelope *Envelope) error
    
    // Read retrieves a vulnerability record by ID
    Read(ctx context.Context, id string) (*Envelope, error)
    
    // List returns all vulnerability IDs
    List(ctx context.Context) ([]string, error)
    
    // Count returns total number of records
    Count(ctx context.Context) (int, error)
    
    // Close finalizes storage (commits, closes files)
    Close(ctx context.Context) error
}
```

## Envelope Structure

```go
type Envelope struct {
    Schema     string      `json:"schema"`      // Schema URL
    Identifier string      `json:"identifier"`  // Unique ID
    Item       interface{} `json:"item"`        // Vulnerability data
}
```

## Testing

Run the test suite:

```bash
go test ./internal/storage/...
```

Run specific tests:

```bash
# Test SQLite backend
go test ./internal/storage -run TestSQLiteBackend

# Test flat-file backend
go test ./internal/storage -run TestFlatFileBackend

# Test helpers
go test ./internal/storage -run TestHelpers
```

Run with race detector:

```bash
go test -race ./internal/storage/...
```

## Examples

See `example_test.go` for comprehensive usage examples:

```bash
go test ./internal/storage -run Example
```

## Error Handling

All methods return descriptive errors with context:

```go
backend, err := storage.New(config)
if err != nil {
    // Handle unsupported backend type
    if _, ok := err.(*storage.UnsupportedBackendError); ok {
        log.Printf("Unsupported backend: %v", err)
    }
}

_, err = backend.Read(ctx, "CVE-9999-9999")
if err != nil {
    // Handle not found error
    log.Printf("Record not found: %v", err)
}
```

## Thread Safety

Both backends are safe for concurrent use:

```go
var wg sync.WaitGroup
for i := 0; i < 10; i++ {
    wg.Add(1)
    go func(id int) {
        defer wg.Done()
        envelope := &storage.Envelope{
            Identifier: fmt.Sprintf("CVE-2023-%04d", id),
            // ...
        }
        backend.Write(ctx, envelope)
    }(i)
}
wg.Wait()
```

## Best Practices

1. **Always close backends**: Use `defer backend.Close(ctx)` to ensure resources are released
2. **Use appropriate batch sizes**: SQLite default of 5000 is good for most cases
3. **Handle errors**: Check all return values for errors
4. **Use context**: Pass context for cancellation and timeouts
5. **Choose the right backend**:
   - SQLite: Better for querying, aggregations, and large datasets
   - Flat-file: Better for inspecting individual records, simpler debugging

## Performance Comparison

| Operation | SQLite | Flat-File |
|-----------|--------|-----------|
| Write (batch) | ⭐⭐⭐⭐⭐ | ⭐⭐⭐ |
| Write (single) | ⭐⭐⭐ | ⭐⭐⭐⭐ |
| Read by ID | ⭐⭐⭐⭐⭐ | ⭐⭐⭐ |
| List all IDs | ⭐⭐⭐⭐⭐ | ⭐⭐ |
| Count | ⭐⭐⭐⭐⭐ | ⭐⭐ |
| Human inspection | ⭐⭐ | ⭐⭐⭐⭐⭐ |
| Storage size | ⭐⭐⭐⭐ | ⭐⭐⭐ |

## Dependencies

- `github.com/mattn/go-sqlite3` - SQLite driver (cgo required)

## License

See LICENSE file in repository root.
