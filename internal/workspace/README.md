# Workspace Management

The `workspace` package provides comprehensive workspace management for vulnerability data providers in vulnz-go. Each provider gets an isolated workspace with input/output directories, state tracking, and file integrity verification.

## Features

- **Isolated Workspaces**: Each provider has its own directory structure
- **State Persistence**: JSON-based metadata tracking with atomic writes
- **File Integrity**: xxHash64 checksums for all result files
- **Thread-Safe Locking**: In-process locks for concurrent access control
- **Flexible Storage**: Support for both SQLite and flat-file backends
- **Clean Separation**: Input and results are kept separate

## Workspace Structure

```
data/                          # Root workspace
└── {provider-name}/           # Per-provider workspace
    ├── metadata.json          # Workspace state
    ├── checksums              # File integrity listing (xxHash64)
    ├── input/                 # Downloaded source data
    │   └── raw-data.json
    └── results/               # Processed vulnerabilities
        ├── results.db         # SQLite (if using sqlite)
        └── {namespace}/       # Flat files (if using flat-file)
            └── {vuln-id}.json
```

## Quick Start

### Basic Usage

```go
import "github.com/shift/vulnz/internal/workspace"

// Create workspace manager
manager := workspace.NewManager("./data")

// Initialize provider workspace
if err := manager.Initialize("alpine"); err != nil {
    log.Fatal(err)
}

// Get paths
inputPath := manager.GetInputPath("alpine")
resultsPath := manager.GetResultsPath("alpine")
```

### State Management

```go
// Create state
state := &workspace.State{
    Provider:            "alpine",
    URLs:                []string{"https://example.com/data.json"},
    Store:               "sqlite",
    Timestamp:           time.Now(),
    Version:             1,
    DistributionVersion: 1,
    Processor:           "vulnz-go@1.0.0",
}

// Save state
if err := manager.UpdateState("alpine", state); err != nil {
    log.Fatal(err)
}

// Read state
state, err := manager.GetState("alpine")
if err != nil {
    log.Fatal(err)
}
```

### Checksum Operations

```go
// Compute checksum for a file
checksum, err := workspace.ComputeChecksum("results/CVE-2023-1234.json")
if err != nil {
    log.Fatal(err)
}

// Verify file integrity
valid, err := workspace.VerifyChecksum("results/CVE-2023-1234.json", expectedChecksum)
if err != nil {
    log.Fatal(err)
}

// Write checksums file
checksums := &workspace.ChecksumFile{
    Files: map[string]string{
        "results/CVE-2023-1234.json": "a1b2c3d4e5f6g7h8",
        "results/CVE-2023-5678.json": "1234567890abcdef",
    },
}
if err := workspace.WriteChecksums("checksums", checksums); err != nil {
    log.Fatal(err)
}

// Read checksums file
checksums, err := workspace.ReadChecksums("checksums")
if err != nil {
    log.Fatal(err)
}
```

### Workspace Locking

```go
// Create locker
locker := workspace.NewLocker()

// Lock workspace for exclusive access
locker.Lock("alpine")
defer locker.Unlock("alpine")

// Perform workspace operations...

// Try non-blocking lock
if locker.TryLock("ubuntu") {
    defer locker.Unlock("ubuntu")
    // Got the lock
} else {
    // Lock is held by another goroutine
}
```

## API Reference

### Manager

The `Manager` type handles workspace directory operations.

#### Methods

- `NewManager(root string) *Manager` - Create a new workspace manager
- `Initialize(providerName string) error` - Create workspace directories
- `GetState(providerName string) (*State, error)` - Read provider state
- `UpdateState(providerName string, state *State) error` - Write provider state (atomic)
- `GetPath(providerName string) string` - Get workspace root path
- `GetInputPath(providerName string) string` - Get input directory path
- `GetResultsPath(providerName string) string` - Get results directory path
- `GetMetadataPath(providerName string) string` - Get metadata file path
- `GetChecksumPath(providerName string) string` - Get checksums file path
- `Clear(providerName string) error` - Remove entire workspace
- `ClearInput(providerName string) error` - Remove only input directory
- `ClearResults(providerName string) error` - Remove only results directory
- `Exists(providerName string) bool` - Check if workspace exists
- `HasState(providerName string) bool` - Check if state exists
- `ListProviders() ([]string, error)` - List all provider workspaces

### State

The `State` type represents workspace metadata.

#### Fields

```go
type State struct {
    Provider            string    // Provider name
    URLs                []string  // URLs fetched
    Store               string    // "sqlite" or "flat-file"
    Timestamp           time.Time // Last run timestamp
    Version             int       // State schema version
    DistributionVersion int       // Data distribution version
    Listing             *File     // Checksums file metadata
    Stale               bool      // Needs update
    Processor           string    // Tool identifier
}
```

### Checksums

#### Functions

- `ComputeChecksum(filePath string) (string, error)` - Compute xxHash64 for file
- `ComputeChecksumReader(r io.Reader) (string, error)` - Compute xxHash64 from reader
- `VerifyChecksum(filePath string, expected string) (bool, error)` - Verify file checksum
- `WriteChecksums(path string, checksums *ChecksumFile) error` - Write checksums file
- `ReadChecksums(path string) (*ChecksumFile, error)` - Read checksums file

#### ChecksumFile Format

The checksums file is a tab-delimited text file:

```
path\tchecksum
results/CVE-2023-1234.json\ta1b2c3d4e5f6g7h8
results/CVE-2023-5678.json\t1234567890abcdef
```

### Locker

The `Locker` type provides in-process workspace locking.

#### Methods

- `NewLocker() *Locker` - Create a new locker
- `Lock(providerName string)` - Acquire exclusive lock (blocking)
- `Unlock(providerName string)` - Release lock
- `TryLock(providerName string) bool` - Try to acquire lock (non-blocking)

## Thread Safety

### Manager

The `Manager` type is thread-safe for operations on **different** providers. Multiple goroutines can safely call methods on different providers concurrently.

For operations on the **same** provider, use the `Locker` to serialize access:

```go
locker := workspace.NewLocker()

// Goroutine 1
go func() {
    locker.Lock("alpine")
    defer locker.Unlock("alpine")
    // Modify alpine workspace
}()

// Goroutine 2
go func() {
    locker.Lock("alpine")
    defer locker.Unlock("alpine")
    // Modify alpine workspace
}()
```

### Atomic Operations

State updates are atomic - they write to a temporary file and then rename:

```go
// This is atomic - either succeeds completely or fails
manager.UpdateState("alpine", state)
```

## Best Practices

### 1. Always Initialize Before Use

```go
if err := manager.Initialize(providerName); err != nil {
    return err
}
```

### 2. Use Locking for Concurrent Access

```go
locker.Lock(providerName)
defer locker.Unlock(providerName)

// Perform workspace operations
```

### 3. Update State After Processing

```go
state := &workspace.State{
    Provider:  providerName,
    Timestamp: time.Now(),
    URLs:      fetchedURLs,
    Store:     "sqlite",
    Version:   1,
}
manager.UpdateState(providerName, state)
```

### 4. Generate Checksums for Results

```go
// After writing all results
checksums := &workspace.ChecksumFile{Files: make(map[string]string)}

err := filepath.Walk(resultsPath, func(path string, info os.FileInfo, err error) error {
    if err != nil || info.IsDir() {
        return err
    }
    checksum, err := workspace.ComputeChecksum(path)
    if err != nil {
        return err
    }
    relPath, _ := filepath.Rel(workspacePath, path)
    checksums.Files[relPath] = checksum
    return nil
})

workspace.WriteChecksums(manager.GetChecksumPath(providerName), checksums)
```

### 5. Verify Checksums on Read

```go
checksums, err := workspace.ReadChecksums(manager.GetChecksumPath(providerName))
if err != nil {
    return err
}

for path, expectedChecksum := range checksums.Files {
    fullPath := filepath.Join(workspacePath, path)
    valid, err := workspace.VerifyChecksum(fullPath, expectedChecksum)
    if err != nil || !valid {
        return fmt.Errorf("checksum verification failed for %s", path)
    }
}
```

## Performance

- **xxHash64**: Extremely fast (10+ GB/s on modern hardware)
- **Atomic Writes**: State updates use temp file + rename (no corruption on crashes)
- **Efficient Locking**: Per-provider mutexes (no global lock contention)
- **Minimal Allocations**: Streaming checksums don't load files into memory

## Testing

Run all tests:

```bash
go test ./internal/workspace/...
```

Run with coverage:

```bash
go test -cover ./internal/workspace/...
```

Run benchmarks:

```bash
go test -bench=. ./internal/workspace/...
```

## Examples

See [example_test.go](./example_test.go) for comprehensive usage examples:

- Basic workspace operations
- Checksum computation and verification
- Concurrent access with locking
- Managing multiple providers
- Selective clearing operations

## Architecture

The workspace package follows these design principles:

1. **Single Responsibility**: Each type has a clear, focused purpose
2. **Fail-Safe**: Operations are atomic and error-handling is comprehensive
3. **No Surprises**: Idempotent operations (safe to call multiple times)
4. **Performance**: Optimized for common operations
5. **Testability**: Full test coverage with unit and integration tests

## Future Enhancements

Potential improvements for future releases:

- Cross-process file locking using OS primitives (flock/LockFileEx)
- Incremental checksum updates (only changed files)
- Compression support for archived workspaces
- Workspace migration utilities for version upgrades
- Parallel checksum computation for large result sets

## License

Copyright © 2024 Anchore, Inc.
