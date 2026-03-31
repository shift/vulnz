# vulnz API Documentation

## Table of Contents

- [Provider Interface](#provider-interface)
- [Storage Interface](#storage-interface)
- [Executor](#executor)
- [Provider Registry](#provider-registry)
- [Configuration](#configuration)
- [Vulnerability Types](#vulnerability-types)
- [HTTP Client](#http-client)
- [Workspace](#workspace)

---

## Provider Interface

`internal/provider/provider.go`

All vulnerability data providers implement the `Provider` interface. Each provider fetches data from a specific source, transforms it to a standard format, and writes results to storage.

```go
type Provider interface {
    // Name returns the unique provider identifier (e.g., "alpine", "ubuntu", "nvd").
    Name() string

    // Update fetches and processes vulnerability data.
    // lastUpdated is nil on the first run, otherwise contains the timestamp
    // of the last successful run. Providers can use this for incremental updates.
    //
    // Returns:
    //   - urls:  List of URLs fetched during the update
    //   - count: Number of vulnerability records processed
    //   - err:   Any error encountered
    Update(ctx context.Context, lastUpdated *time.Time) (urls []string, count int, err error)
}
```

Two optional interfaces extend the base `Provider`:

```go
// MetadataProvider exposes provider metadata.
type MetadataProvider interface {
    Provider
    Metadata() Metadata
}

type Metadata struct {
    Name        string // Provider name
    Description string // Human-readable description
    Version     string // Provider version
    Homepage    string // URL to documentation or source
}

// TagsProvider exposes classification tags (e.g., "os", "language", "cve").
type TagsProvider interface {
    Provider
    Tags() []string
}
```

### Implementing a Provider

```go
package myprovider

import (
    "context"
    "time"

    "github.com/shift/vulnz/internal/provider"
)

type MyProvider struct {
    config provider.Config
}

func NewMyProvider(cfg provider.Config) (provider.Provider, error) {
    return &MyProvider{config: cfg}, nil
}

func (p *MyProvider) Name() string {
    return "myprovider"
}

func (p *MyProvider) Update(ctx context.Context, lastUpdated *time.Time) ([]string, int, error) {
    // Fetch and process vulnerability data
    return []string{"https://example.com/advisories.json"}, 42, nil
}

func init() {
    provider.Register("myprovider", NewMyProvider)
}
```

---

## Storage Interface

`internal/storage/storage.go`

The `Backend` interface defines storage operations. Both SQLite and flat-file implementations provide this interface.

```go
type Backend interface {
    Write(ctx context.Context, envelope *Envelope) error
    Read(ctx context.Context, id string) (*Envelope, error)
    List(ctx context.Context) ([]string, error)
    Count(ctx context.Context) (int, error)
    Close(ctx context.Context) error
}
```

```go
// Envelope wraps vulnerability data with metadata.
type Envelope struct {
    Schema     string      `json:"schema"`     // Schema URL
    Identifier string      `json:"identifier"` // Unique ID (e.g., "CVE-2023-1234")
    Item       interface{} `json:"item"`       // Vulnerability payload
}
```

### Storage Configuration

```go
type Config struct {
    Type      string // "sqlite" or "flat-file"
    Path      string // Directory for flat-file, db file path for sqlite
    BatchSize int    // SQLite batch size (default: 5000)
}
```

### Creating a Backend

```go
func New(config Config) (Backend, error)
```

Returns an `UnsupportedBackendError` if the type is not `"sqlite"` or `"flat-file"`.

```go
// SQLite backend
backend, err := storage.New(storage.Config{
    Type:      "sqlite",
    Path:      "./results.db",
    BatchSize: 5000,
})

// Flat-file backend
backend, err := storage.New(storage.Config{
    Type: "flat-file",
    Path: "./storage/",
})
```

---

## Executor

`internal/provider/executor.go`

The `Executor` orchestrates provider execution with concurrency control.

```go
type Executor struct {
    maxParallel int
    workspace   string
    logger      *slog.Logger
}

type ExecutorConfig struct {
    MaxParallel int    // Maximum providers to run in parallel (default: 1)
    Workspace   string // Root workspace directory
}

type Result struct {
    Provider string        // Provider name
    URLs     []string      // URLs fetched
    Count    int           // Vulnerabilities processed
    Err      error         // Error if provider failed
    Duration time.Duration // Execution time
}
```

### Methods

```go
// NewExecutor creates a new Executor. MaxParallel defaults to 1 if <= 0.
func NewExecutor(config ExecutorConfig, logger *slog.Logger) *Executor

// Run executes the specified providers in parallel with concurrency control.
func (e *Executor) Run(ctx context.Context, providers []string) ([]Result, error)

// RunAll executes all registered providers.
func (e *Executor) RunAll(ctx context.Context) ([]Result, error)
```

### Usage

```go
logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
    Level: slog.LevelInfo,
}))

exec := provider.NewExecutor(provider.ExecutorConfig{
    MaxParallel: 4,
    Workspace:   "./data",
}, logger)

results, err := exec.Run(ctx, []string{"alpine", "ubuntu", "nvd"})
for _, r := range results {
    if r.Err != nil {
        log.Printf("provider %s failed: %v", r.Provider, r.Err)
    } else {
        log.Printf("provider %s: %d vulnerabilities in %s", r.Provider, r.Count, r.Duration)
    }
}
```

---

## Provider Registry

`internal/provider/registry.go`

The registry manages provider registration and discovery using a thread-safe map.

```go
// Factory creates a provider instance from configuration.
type Factory func(config Config) (Provider, error)

// Register registers a provider factory. Panics on duplicate names.
// Should be called from the provider's init() function.
func Register(name string, factory Factory)

// Get retrieves a provider factory by name.
// Returns the factory and true if found, nil and false otherwise.
func Get(name string) (Factory, bool)

// List returns all registered provider names in alphabetical order.
func List() []string

// Count returns the number of registered providers.
func Count() int

// Reset clears all registered providers. Primarily for testing.
func Reset()
```

### Usage

```go
// Check if a provider is registered
if factory, ok := provider.Get("alpine"); ok {
    p, err := factory(config)
    // ...
}

// List all providers
names := provider.List() // ["alpine", "amazon", "debian", ...]

// Count registered providers
n := provider.Count()
```

---

## Configuration

`internal/provider/config.go`

### Provider Config

```go
type Config struct {
    Name      string        // Provider name
    Workspace string        // Root workspace directory for this provider
    Storage   StorageConfig // Storage backend configuration
    HTTP      HTTPConfig    // HTTP client configuration
    Logger    *slog.Logger  // Structured logger instance
}
```

### StorageConfig

```go
type StorageConfig struct {
    Type string // "sqlite" or "flat-file"
    Path string // Path to storage location
}
```

### HTTPConfig

```go
type HTTPConfig struct {
    Timeout      time.Duration // Request timeout
    MaxRetries   int           // Maximum retry attempts
    RateLimitRPS int           // Rate limit in requests per second
    UserAgent    string        // User agent string
}

// DefaultHTTPConfig returns sensible defaults:
//   Timeout:      30s
//   MaxRetries:   5
//   RateLimitRPS: 10
//   UserAgent:    "vulnz/1.0"
func DefaultHTTPConfig() HTTPConfig
```

---

## Vulnerability Types

`internal/utils/vulnerability/types.go`

Core data structures used across all providers. JSON field names are capitalized for backwards compatibility with Python Vunnel output.

### Vulnerability

```go
type Vulnerability struct {
    Name          string         `json:"Name"`          // e.g., "CVE-2021-1234"
    NamespaceName string         `json:"NamespaceName"` // e.g., "rhel:8", "alpine:3.19"
    Description   string         `json:"Description"`
    Severity      string         `json:"Severity"`      // Unknown, Negligible, Low, Medium, High, Critical
    Link          string         `json:"Link"`          // Primary advisory URL
    CVSS          []CVSS         `json:"CVSS"`
    FixedIn       []FixedIn      `json:"FixedIn"`
    Metadata      map[string]any `json:"Metadata"`
}

// ToPayload wraps the vulnerability in a payload map.
func (v Vulnerability) ToPayload() map[string]any
// Returns: {"Vulnerability": {...}}

// VulnerabilityElement returns the default empty vulnerability template.
func VulnerabilityElement() map[string]any
```

### FixedIn

```go
type FixedIn struct {
    Name           string           `json:"Name"`                      // Package name
    NamespaceName  string           `json:"NamespaceName"`             // Provider namespace
    VersionFormat  string           `json:"VersionFormat"`             // "rpm", "deb", "semver", "apk"
    Version        string           `json:"Version"`                   // Fix version ("" = no fix available)
    Module         string           `json:"Module"`                    // Go module path (optional)
    VendorAdvisory *VendorAdvisory  `json:"VendorAdvisory,omitempty"`
    VulnerableRange string          `json:"VulnerableRange,omitempty"` // Affected version range
    Available      *FixAvailability `json:"Available,omitempty"`        // When fix became available
}

func NewFixedIn(name, namespace, versionFormat, version string) FixedIn
```

### CVSS

```go
type CVSS struct {
    Version      string          `json:"version"`       // "2.0", "3.0", "3.1", "4.0"
    VectorString string          `json:"vector_string"`
    BaseMetrics  CVSSBaseMetrics `json:"base_metrics"`
    Status       string          `json:"status"`        // "verified", "unverified"
}

type CVSSBaseMetrics struct {
    BaseScore         float64 `json:"base_score"`          // 0.0-10.0
    ExploitabilityScore float64 `json:"exploitability_score"` // 0.0-10.0
    ImpactScore       float64 `json:"impact_score"`        // 0.0-10.0
    BaseSeverity      string  `json:"base_severity"`       // "LOW", "MEDIUM", "HIGH", "CRITICAL"
}
```

### VendorAdvisory

```go
type VendorAdvisory struct {
    NoAdvisory      bool              `json:"NoAdvisory"`
    AdvisorySummary []AdvisorySummary `json:"AdvisorySummary"`
}

type AdvisorySummary struct {
    ID   string `json:"ID"`   // e.g., "RHSA-2021:1234"
    Link string `json:"Link"`
}

func NewVendorAdvisory(noAdvisory bool, summaries []AdvisorySummary) *VendorAdvisory
```

### FixAvailability

```go
type FixAvailability struct {
    Date string `json:"Date"` // ISO 8601: "YYYY-MM-DD"
    Kind string `json:"Kind"` // "advisory", "backport", "release"
}

func NewFixAvailability(date any, kind string) (*FixAvailability, error)
// Accepts time.Time, ISO 8601 string, RFC3339, RFC3339Nano
```

---

## HTTP Client

`internal/http/`

The HTTP client provides rate limiting, retries with exponential backoff, and per-host connection pooling.

### Client

```go
type Client struct {
    pools       *poolManager
    rateLimiter *RateLimiter
    config      Config
}

func NewClient(config Config) *Client

// Get performs HTTP GET with retry logic and rate limiting.
func (c *Client) Get(ctx context.Context, urlStr string) (*http.Response, error)

// Post performs HTTP POST with retry logic and rate limiting.
func (c *Client) Post(ctx context.Context, urlStr string, contentType string, body io.Reader) (*http.Response, error)

// Download fetches a URL and writes the body to a file.
func (c *Client) Download(ctx context.Context, urlStr string, dest string) error
```

### Config

```go
type Config struct {
    Timeout         time.Duration // Request timeout
    MaxRetries      int           // Maximum retry attempts
    InitialBackoff  time.Duration // Initial backoff for retries
    MaxBackoff      time.Duration // Maximum backoff duration
    RateLimitRPS    int           // Requests per second per host
    MaxConnsPerHost int           // Maximum connections per host
    UserAgent       string        // User-Agent header
}

func DefaultConfig() Config
// Defaults:
//   Timeout:         30s
//   MaxRetries:      5
//   InitialBackoff:  1s
//   MaxBackoff:      60s
//   RateLimitRPS:    10
//   MaxConnsPerHost: 10
//   UserAgent:       "vulnz/1.0"
```

### Rate Limiting

Per-host rate limiting using token bucket algorithm (`golang.org/x/time/rate`).

```go
type RateLimiter struct { ... }

func NewRateLimiter(rps int) *RateLimiter

// Wait blocks until a request can proceed for the given host.
func (rl *RateLimiter) Wait(ctx context.Context, host string) error

// Allow checks if a request can proceed immediately without blocking.
func (rl *RateLimiter) Allow(host string) bool
```

### Retry Behavior

Retry configuration and backoff calculation:

```go
type RetryConfig struct {
    MaxRetries     int
    InitialBackoff time.Duration
    MaxBackoff     time.Duration
    Multiplier     float64 // Default: 2.0
}
```

- **Retryable status codes**: 429 (Too Many Requests), 503 (Service Unavailable), 504 (Gateway Timeout)
- **Retryable errors**: timeout, temporary network errors, connection refused/reset/broken pipe
- **Backoff**: Exponential with +/- 25% jitter, capped at `MaxBackoff`
  - Formula: `initialBackoff * (2.0 ^ attempt)`
- **Retry-After header**: Parsed from integer seconds or RFC1123 date, capped at 5 minutes
- **Non-retryable**: All other 4xx errors (except 429), 5xx errors (except 503/504)

### Connection Pooling

Per-host connection pools with dedicated `http.Transport`:

- Dial timeout: 10s
- Keep-alive: 30s
- Idle connection timeout: 90s
- TLS handshake timeout: 10s
- HTTP/2 enabled via `ForceAttemptHTTP2: true`

### ResponseError

```go
type ResponseError struct {
    StatusCode int
    Status     string
    URL        string
    Body       string // First 1KB of response body
}

func (e *ResponseError) Error() string
```

---

## Workspace

`internal/workspace/`

Each provider gets an isolated workspace directory for managing downloaded data, processed results, and state.

### Directory Structure

```
data/                          # Root workspace
  {provider-name}/             # Per-provider workspace
    metadata.json              # State tracking
    checksums                  # File integrity (xxHash64)
    input/                     # Downloaded source data
    results/                   # Processed vulnerabilities
      results.db               # SQLite backend
      {namespace}/             # Flat-file backend
        {vuln-id}.json
```

### Manager

```go
type Manager struct {
    root string // Root workspace directory
}

func NewManager(root string) *Manager

// Initialize creates input/ and results/ directories. Safe to call multiple times.
func (m *Manager) Initialize(providerName string) error

// GetState reads metadata.json for a provider.
func (m *Manager) GetState(providerName string) (*State, error)

// UpdateState writes metadata.json atomically (write + rename).
func (m *Manager) UpdateState(providerName string, state *State) error

// Path helpers
func (m *Manager) GetPath(providerName string) string          // {root}/{name}
func (m *Manager) GetInputPath(providerName string) string     // {root}/{name}/input
func (m *Manager) GetResultsPath(providerName string) string   // {root}/{name}/results
func (m *Manager) GetMetadataPath(providerName string) string  // {root}/{name}/metadata.json
func (m *Manager) GetChecksumPath(providerName string) string  // {root}/{name}/checksums

// Clear operations
func (m *Manager) Clear(providerName string) error       // Remove entire provider workspace
func (m *Manager) ClearInput(providerName string) error  // Remove input/ only
func (m *Manager) ClearResults(providerName string) error // Remove results/ only

// Inspection
func (m *Manager) Exists(providerName string) bool        // Workspace directory exists
func (m *Manager) HasState(providerName string) bool      // metadata.json exists
func (m *Manager) ListProviders() ([]string, error)        // List provider directories
```

### State

```go
type State struct {
    Provider            string    `json:"provider"`
    URLs                []string  `json:"urls"`
    Store               string    `json:"store"`                // "sqlite" or "flat-file"
    Timestamp           time.Time `json:"timestamp"`
    Version             int       `json:"version"`
    DistributionVersion int       `json:"distribution_version"`
    Listing             *File     `json:"listing,omitempty"`
    Stale               bool      `json:"stale"`
    Processor           string    `json:"processor,omitempty"`
}

type File struct {
    Path         string    `json:"path"`
    Checksum     string    `json:"checksum"`      // xxHash64 hex
    Algorithm    string    `json:"algorithm"`     // "xxh64"
    LastModified time.Time `json:"last_modified"`
}
```

### Checksums

File integrity tracking using xxHash64. Format: tab-delimited `path\tchecksum`.

```go
type ChecksumFile struct {
    Files map[string]string // relative path -> xxHash64 hex
}

func WriteChecksums(path string, checksums *ChecksumFile) error
func ReadChecksums(path string) (*ChecksumFile, error)
func ComputeChecksum(filePath string) (string, error)
func VerifyChecksum(filePath string, expected string) (bool, error)
func ComputeChecksumReader(r io.Reader) (string, error)
```

### Locker

In-process file locking using buffered channels as binary semaphores. Safe to call `Unlock` without a matching `Lock`.

```go
type Locker struct { ... }

func NewLocker() *Locker

// Lock blocks until the lock is acquired.
func (l *Locker) Lock(providerName string)

// Unlock releases the lock. No-op if not held.
func (l *Locker) Unlock(providerName string)

// TryLock attempts to acquire without blocking. Returns true if acquired.
func (l *Locker) TryLock(providerName string) bool
```

### Usage

```go
manager := workspace.NewManager("./data")

// Initialize workspace
manager.Initialize("alpine")

// Update state after processing
state := &workspace.State{
    Provider:  "alpine",
    URLs:      []string{"https://secdb.alpinelinux.org/v3.19/main.json"},
    Store:     "sqlite",
    Timestamp: time.Now(),
    Version:   1,
}
manager.UpdateState("alpine", state)

// Concurrent access
locker := workspace.NewLocker()
locker.Lock("alpine")
defer locker.Unlock("alpine")
```
