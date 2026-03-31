# vulnz-go Architecture

## Overview

vulnz-go is a Go port of Vunnel, a vulnerability data aggregator designed to collect, transform, and store vulnerability information from 27+ data providers. This document details the architectural design decisions, package structure, interfaces, and patterns used to build a concurrent, maintainable, and extensible Go application.

## Design Principles

1. **Interface-First Design**: Define clear contracts between components
2. **Concurrent by Default**: Leverage goroutines for parallel provider execution
3. **Context-Aware**: Use context.Context throughout for cancellation and timeouts
4. **Error Transparency**: Wrap errors with context, distinguish recoverable from fatal
5. **Plugin Architecture**: Providers are self-contained, discoverable plugins
6. **Storage Flexibility**: Support both SQLite and flat-file storage backends

---

## Package Structure

```
vulnz-go/
├── cmd/
│   └── vulnz/              # CLI entry point
│       └── main.go
├── internal/
│   ├── provider/           # Core provider interfaces and registry
│   │   ├── provider.go     # Provider interface
│   │   ├── registry.go     # Provider registration/discovery
│   │   ├── runtime.go      # Runtime configuration
│   │   └── executor.go     # Orchestration logic
│   ├── storage/            # Storage backend interfaces
│   │   ├── storage.go      # Storage interface
│   │   ├── flatfile/       # Flat-file implementation
│   │   │   └── store.go
│   │   └── sqlite/         # SQLite implementation
│   │       └── store.go
│   ├── workspace/          # Workspace management
│   │   ├── workspace.go    # Directory structure, state
│   │   ├── state.go        # State persistence
│   │   └── lock.go         # File locking for concurrency
│   ├── httpclient/         # HTTP client with pooling/rate limiting
│   │   ├── client.go       # Client interface
│   │   ├── pool.go         # Per-host connection pooling
│   │   └── ratelimit.go    # Rate limiting logic
│   ├── result/             # Result writing and envelopes
│   │   ├── envelope.go     # Result envelope structure
│   │   └── writer.go       # Result writer with storage abstraction
│   ├── schema/             # Schema definitions
│   │   └── schema.go       # Schema interface and types
│   ├── config/             # Configuration management
│   │   ├── config.go       # Config structures
│   │   └── loader.go       # YAML/env loading
│   └── util/               # Shared utilities
│       ├── hasher/         # Checksumming
│       ├── archive/        # Archive extraction
│       └── concurrency/    # Worker pool patterns
├── providers/              # Provider implementations (plugins)
│   ├── alpine/
│   │   ├── provider.go     # Provider implementation
│   │   ├── parser.go       # Data parsing logic
│   │   └── config.go       # Provider-specific config
│   ├── debian/
│   ├── nvd/
│   └── ...                 # 27+ providers
└── pkg/                    # Public APIs (if needed for external use)
    └── types/
        └── vulnerability.go
```

### Package Boundaries

- **cmd/**: Entry points only, minimal logic
- **internal/**: Core framework, not importable by external projects
- **providers/**: Self-contained provider plugins, import from internal/
- **pkg/**: Public APIs for external consumers (if library use is required)

### Dependency Flow

```
cmd/vulnz
   ↓
internal/config → internal/provider/executor
   ↓                        ↓
providers/*  →  internal/provider (interface)
                           ↓
                    ┌──────┴──────┐
                    ↓             ↓
            internal/storage  internal/workspace
                    ↓             ↓
            internal/httpclient   internal/result
```

**Key Rules:**
- No circular dependencies
- Providers depend only on `internal/provider` interface
- Storage and workspace are siblings, both used by providers
- `httpclient` is a leaf dependency

---

## Core Interfaces

### 1. Provider Interface

```go
package provider

import (
    "context"
    "time"
)

// Provider defines the contract for all vulnerability data providers
type Provider interface {
    // Name returns the unique identifier for this provider
    Name() string
    
    // Update fetches and processes vulnerability data
    // Returns URLs fetched, count of results, and any error
    Update(ctx context.Context, lastUpdated *time.Time) ([]string, int, error)
    
    // Schema returns the schema definition for this provider's output
    // Returns nil if schema validation is not used
    Schema() Schema
    
    // Tags returns classification tags (e.g., "os", "language")
    Tags() []string
}

// Factory creates provider instances with dependency injection
type Factory interface {
    Create(ws Workspace, store Storage, config ProviderConfig) (Provider, error)
}

// Validator optionally validates provider-specific configuration
type Validator interface {
    Validate() error
}
```

**Provider-Specific Config:**
Each provider defines its own config struct:

```go
// providers/alpine/config.go
package alpine

type Config struct {
    RequestTimeout time.Duration `yaml:"request_timeout"`
    CustomField    string        `yaml:"custom_field"`
}

func (c *Config) Validate() error {
    if c.RequestTimeout < 0 {
        return fmt.Errorf("request_timeout must be positive")
    }
    return nil
}
```

Providers embed a base config and add their own fields:

```go
type AlpineProvider struct {
    config    Config
    workspace Workspace
    storage   Storage
    logger    *slog.Logger
}

func NewAlpineProvider(ws Workspace, store Storage, cfg Config) *AlpineProvider {
    return &AlpineProvider{
        config:    cfg,
        workspace: ws,
        storage:   store,
        logger:    slog.With("provider", "alpine"),
    }
}

func (p *AlpineProvider) Update(ctx context.Context, lastUpdated *time.Time) ([]string, int, error) {
    // Implementation
}
```

---

### 2. Storage Backend Interface

```go
package storage

import (
    "context"
    "io"
)

// Storage defines the contract for persisting vulnerability data
type Storage interface {
    // Prepare initializes storage (e.g., clear old data, create tables)
    Prepare(ctx context.Context) error
    
    // Write stores an envelope with a unique identifier
    Write(ctx context.Context, identifier string, envelope Envelope) error
    
    // Read retrieves an envelope by identifier
    Read(ctx context.Context, identifier string) (Envelope, error)
    
    // List returns all identifiers in storage
    List(ctx context.Context) ([]string, error)
    
    // Close finalizes storage (e.g., flush buffers, move temp files)
    // successful indicates whether the operation completed without errors
    Close(ctx context.Context, successful bool) error
    
    io.Closer // For cleanup
}

// Envelope wraps vulnerability data with metadata
type Envelope struct {
    Schema     string          `json:"schema"`
    Identifier string          `json:"identifier"`
    Item       json.RawMessage `json:"item"`
}

// StoreStrategy selects the storage backend
type StoreStrategy string

const (
    FlatFile StoreStrategy = "flat-file"
    SQLite   StoreStrategy = "sqlite"
)

// Factory creates storage instances
type Factory interface {
    Create(strategy StoreStrategy, workspacePath string, policy ResultPolicy) (Storage, error)
}
```

**Flat-File Implementation:**

```go
// internal/storage/flatfile/store.go
package flatfile

type FlatFileStore struct {
    basePath string
    policy   ResultPolicy
    mu       sync.Mutex
}

func (s *FlatFileStore) Write(ctx context.Context, id string, env Envelope) error {
    // Support nested directories: id can contain "/"
    filepath := filepath.Join(s.basePath, id+".json")
    
    // Create parent dirs if needed
    if err := os.MkdirAll(filepath.Dir(filepath), 0755); err != nil {
        return fmt.Errorf("create directory: %w", err)
    }
    
    data, err := json.Marshal(env)
    if err != nil {
        return fmt.Errorf("marshal envelope: %w", err)
    }
    
    return os.WriteFile(filepath, data, 0644)
}
```

**SQLite Implementation:**

```go
// internal/storage/sqlite/store.go
package sqlite

type SQLiteStore struct {
    db         *sql.DB
    tempPath   string
    finalPath  string
    batchSize  int
    mu         sync.Mutex
    batch      []Envelope
}

func (s *SQLiteStore) Write(ctx context.Context, id string, env Envelope) error {
    s.mu.Lock()
    defer s.mu.Unlock()
    
    s.batch = append(s.batch, env)
    
    // Auto-flush when batch size reached
    if len(s.batch) >= s.batchSize {
        return s.flushLocked(ctx)
    }
    return nil
}

func (s *SQLiteStore) Close(ctx context.Context, successful bool) error {
    s.mu.Lock()
    defer s.mu.Unlock()
    
    // Flush remaining batch
    if err := s.flushLocked(ctx); err != nil {
        return err
    }
    
    if err := s.db.Close(); err != nil {
        return err
    }
    
    // Move temp DB to final location only if successful
    if successful {
        return os.Rename(s.tempPath, s.finalPath)
    }
    return os.Remove(s.tempPath)
}
```

---

### 3. HTTP Client Interface

```go
package httpclient

import (
    "context"
    "net/http"
    "time"
)

// Client provides HTTP operations with rate limiting and retries
type Client interface {
    // Get performs an HTTP GET with retries and rate limiting
    Get(ctx context.Context, url string, opts ...Option) (*http.Response, error)
    
    // Download retrieves large files with streaming
    Download(ctx context.Context, url, destPath string, opts ...Option) error
}

// Option configures request behavior
type Option func(*RequestConfig)

type RequestConfig struct {
    Retries           int
    BackoffBase       time.Duration
    BackoffMax        time.Duration
    Timeout           time.Duration
    UserAgent         string
    StatusHandler     func(*http.Response) error
}

// Functional options pattern
func WithRetries(n int) Option {
    return func(c *RequestConfig) { c.Retries = n }
}

func WithTimeout(d time.Duration) Option {
    return func(c *RequestConfig) { c.Timeout = d }
}

func WithUserAgent(ua string) Option {
    return func(c *RequestConfig) { c.UserAgent = ua }
}
```

**Per-Host Connection Pooling:**

```go
// internal/httpclient/pool.go
package httpclient

import (
    "net/http"
    "sync"
)

// HostPool manages per-host HTTP clients for connection reuse
type HostPool struct {
    mu      sync.RWMutex
    clients map[string]*http.Client
    config  *http.Transport
}

func NewHostPool() *HostPool {
    return &HostPool{
        clients: make(map[string]*http.Client),
        config: &http.Transport{
            MaxIdleConnsPerHost:   10,
            MaxConnsPerHost:       100,
            IdleConnTimeout:       90 * time.Second,
            TLSHandshakeTimeout:   10 * time.Second,
            ExpectContinueTimeout: 1 * time.Second,
        },
    }
}

func (p *HostPool) GetClient(hostname string) *http.Client {
    p.mu.RLock()
    client, exists := p.clients[hostname]
    p.mu.RUnlock()
    
    if exists {
        return client
    }
    
    p.mu.Lock()
    defer p.mu.Unlock()
    
    // Double-check after acquiring write lock
    if client, exists := p.clients[hostname]; exists {
        return client
    }
    
    client = &http.Client{
        Transport: p.config,
        Timeout:   30 * time.Second,
    }
    p.clients[hostname] = client
    return client
}
```

**Rate Limiting:**

```go
// internal/httpclient/ratelimit.go
package httpclient

import (
    "sync"
    "time"
)

// RateLimiter manages per-host rate limiting with Retry-After support
type RateLimiter struct {
    mu             sync.Mutex
    hostStates     map[string]*hostState
}

type hostState struct {
    blockedUntil time.Time
    semaphore    chan struct{} // Serializes requests when rate-limited
}

func NewRateLimiter() *RateLimiter {
    return &RateLimiter{
        hostStates: make(map[string]*hostState),
    }
}

func (rl *RateLimiter) Wait(ctx context.Context, hostname string) error {
    state := rl.getOrCreateState(hostname)
    
    // Acquire semaphore (blocks if rate-limited)
    select {
    case state.semaphore <- struct{}{}:
    case <-ctx.Done():
        return ctx.Err()
    }
    
    // Wait out the rate limit
    state.mu.Lock()
    blockedUntil := state.blockedUntil
    state.mu.Unlock()
    
    if waitTime := time.Until(blockedUntil); waitTime > 0 {
        select {
        case <-time.After(waitTime):
        case <-ctx.Done():
            <-state.semaphore // Release semaphore
            return ctx.Err()
        }
    }
    
    return nil
}

func (rl *RateLimiter) Release(hostname string) {
    state := rl.getState(hostname)
    if state != nil {
        <-state.semaphore
    }
}

func (rl *RateLimiter) RecordRateLimit(hostname string, retryAfter time.Duration) {
    state := rl.getOrCreateState(hostname)
    state.mu.Lock()
    state.blockedUntil = time.Now().Add(retryAfter)
    state.mu.Unlock()
}
```

**Client Implementation:**

```go
// internal/httpclient/client.go
package httpclient

import (
    "context"
    "fmt"
    "net/http"
    "time"
    "log/slog"
)

type httpClient struct {
    pool       *HostPool
    limiter    *RateLimiter
    logger     *slog.Logger
}

func New(logger *slog.Logger) Client {
    return &httpClient{
        pool:    NewHostPool(),
        limiter: NewRateLimiter(),
        logger:  logger,
    }
}

func (c *httpClient) Get(ctx context.Context, url string, opts ...Option) (*http.Response, error) {
    cfg := &RequestConfig{
        Retries:     5,
        BackoffBase: 3 * time.Second,
        BackoffMax:  10 * time.Minute,
        Timeout:     30 * time.Second,
    }
    for _, opt := range opts {
        opt(cfg)
    }
    
    hostname := extractHostname(url)
    client := c.pool.GetClient(hostname)
    
    var lastErr error
    for attempt := 0; attempt <= cfg.Retries; attempt++ {
        // Wait for rate limit
        if err := c.limiter.Wait(ctx, hostname); err != nil {
            return nil, err
        }
        defer c.limiter.Release(hostname)
        
        // Make request
        req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
        if err != nil {
            return nil, fmt.Errorf("create request: %w", err)
        }
        
        if cfg.UserAgent != "" {
            req.Header.Set("User-Agent", cfg.UserAgent)
        }
        
        resp, err := client.Do(req)
        if err != nil {
            lastErr = err
            c.logger.Warn("request failed", "attempt", attempt+1, "error", err)
            c.backoff(ctx, cfg, attempt)
            continue
        }
        
        // Check for rate limiting
        if resp.StatusCode == 429 || (resp.StatusCode == 503 && resp.Header.Get("Retry-After") != "") {
            retryAfter := parseRetryAfter(resp.Header.Get("Retry-After"))
            c.limiter.RecordRateLimit(hostname, retryAfter)
            resp.Body.Close()
            c.logger.Warn("rate limited", "host", hostname, "retry_after", retryAfter)
            continue
        }
        
        // Custom status handler or default validation
        if cfg.StatusHandler != nil {
            if err := cfg.StatusHandler(resp); err != nil {
                resp.Body.Close()
                lastErr = err
                c.backoff(ctx, cfg, attempt)
                continue
            }
        } else if resp.StatusCode >= 400 {
            resp.Body.Close()
            lastErr = fmt.Errorf("HTTP %d: %s", resp.StatusCode, resp.Status)
            c.backoff(ctx, cfg, attempt)
            continue
        }
        
        return resp, nil
    }
    
    return nil, fmt.Errorf("exhausted retries: %w", lastErr)
}

func (c *httpClient) backoff(ctx context.Context, cfg *RequestConfig, attempt int) {
    delay := time.Duration(float64(cfg.BackoffBase) * math.Pow(2, float64(attempt)))
    if delay > cfg.BackoffMax {
        delay = cfg.BackoffMax
    }
    // Add jitter
    delay += time.Duration(rand.Int63n(int64(time.Second)))
    
    select {
    case <-time.After(delay):
    case <-ctx.Done():
    }
}
```

---

### 4. Workspace Manager

```go
package workspace

import (
    "context"
    "encoding/json"
    "os"
    "path/filepath"
    "time"
)

// Workspace manages provider-specific directories and state
type Workspace interface {
    // Path returns the root path for this workspace
    Path() string
    
    // InputPath returns the directory for downloaded raw data
    InputPath() string
    
    // ResultsPath returns the directory for processed results
    ResultsPath() string
    
    // Create initializes the workspace directories
    Create(ctx context.Context) error
    
    // Clear removes all workspace data
    Clear(ctx context.Context) error
    
    // RecordState persists the current run's metadata
    RecordState(ctx context.Context, state State) error
    
    // ReadState loads the previous run's metadata
    ReadState(ctx context.Context) (*State, error)
    
    // Lock acquires an exclusive lock on the workspace
    Lock(ctx context.Context) (func(), error)
}

// State represents provider run metadata
type State struct {
    Provider            string    `json:"provider"`
    Version             int       `json:"version"`
    DistributionVersion int       `json:"distribution_version"`
    Timestamp           time.Time `json:"timestamp"`
    URLs                []string  `json:"urls"`
    Store               string    `json:"store"`
    Stale               bool      `json:"stale"`
    Checksum            *File     `json:"checksum,omitempty"`
}

type File struct {
    Path      string `json:"path"`
    Algorithm string `json:"algorithm"`
    Digest    string `json:"digest"`
}

// Implementation
type workspace struct {
    root   string
    name   string
    logger *slog.Logger
}

func New(root, providerName string, logger *slog.Logger) Workspace {
    return &workspace{
        root:   filepath.Join(root, providerName),
        name:   providerName,
        logger: logger,
    }
}

func (w *workspace) Path() string {
    return w.root
}

func (w *workspace) InputPath() string {
    return filepath.Join(w.root, "input")
}

func (w *workspace) ResultsPath() string {
    return filepath.Join(w.root, "results")
}

func (w *workspace) Create(ctx context.Context) error {
    dirs := []string{w.InputPath(), w.ResultsPath()}
    for _, dir := range dirs {
        if err := os.MkdirAll(dir, 0755); err != nil {
            return fmt.Errorf("create dir %s: %w", dir, err)
        }
    }
    return nil
}

func (w *workspace) RecordState(ctx context.Context, state State) error {
    metadataPath := filepath.Join(w.root, "metadata.json")
    data, err := json.MarshalIndent(state, "", "  ")
    if err != nil {
        return fmt.Errorf("marshal state: %w", err)
    }
    return os.WriteFile(metadataPath, data, 0644)
}

func (w *workspace) ReadState(ctx context.Context) (*State, error) {
    metadataPath := filepath.Join(w.root, "metadata.json")
    data, err := os.ReadFile(metadataPath)
    if err != nil {
        return nil, err
    }
    
    var state State
    if err := json.Unmarshal(data, &state); err != nil {
        return nil, fmt.Errorf("unmarshal state: %w", err)
    }
    return &state, nil
}
```

**File Locking:**

```go
// internal/workspace/lock.go
package workspace

import (
    "context"
    "fmt"
    "os"
    "syscall"
)

func (w *workspace) Lock(ctx context.Context) (func(), error) {
    lockPath := filepath.Join(w.root, ".lock")
    
    // Create lock file
    f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0600)
    if err != nil {
        return nil, fmt.Errorf("create lock file: %w", err)
    }
    
    // Try to acquire exclusive lock (non-blocking)
    if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
        f.Close()
        return nil, fmt.Errorf("workspace locked by another process: %w", err)
    }
    
    // Return unlock function
    unlock := func() {
        syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
        f.Close()
        os.Remove(lockPath)
    }
    
    return unlock, nil
}
```

---

## Concurrency Model

### Provider Execution

```go
// internal/provider/executor.go
package provider

import (
    "context"
    "fmt"
    "sync"
    "log/slog"
)

// Executor orchestrates parallel provider execution
type Executor struct {
    registry *Registry
    config   ExecutorConfig
    logger   *slog.Logger
}

type ExecutorConfig struct {
    MaxConcurrent int           // Max providers running in parallel
    Timeout       time.Duration // Per-provider timeout
}

type Result struct {
    Provider  string
    URLs      []string
    Count     int
    Err       error
    Duration  time.Duration
}

func (e *Executor) Run(ctx context.Context, providerNames []string) ([]Result, error) {
    // Create semaphore to limit concurrency
    sem := make(chan struct{}, e.config.MaxConcurrent)
    
    var wg sync.WaitGroup
    results := make(chan Result, len(providerNames))
    
    // Launch goroutines for each provider
    for _, name := range providerNames {
        wg.Add(1)
        
        go func(providerName string) {
            defer wg.Done()
            
            // Acquire semaphore slot
            select {
            case sem <- struct{}{}:
                defer func() { <-sem }()
            case <-ctx.Done():
                results <- Result{Provider: providerName, Err: ctx.Err()}
                return
            }
            
            // Execute provider with timeout
            provCtx, cancel := context.WithTimeout(ctx, e.config.Timeout)
            defer cancel()
            
            result := e.runProvider(provCtx, providerName)
            results <- result
            
        }(name)
    }
    
    // Wait for all providers to complete
    go func() {
        wg.Wait()
        close(results)
    }()
    
    // Collect results
    var allResults []Result
    for result := range results {
        allResults = append(allResults, result)
        
        if result.Err != nil {
            e.logger.Error("provider failed",
                "provider", result.Provider,
                "error", result.Err,
            )
        } else {
            e.logger.Info("provider completed",
                "provider", result.Provider,
                "count", result.Count,
                "duration", result.Duration,
            )
        }
    }
    
    return allResults, nil
}

func (e *Executor) runProvider(ctx context.Context, name string) Result {
    start := time.Now()
    result := Result{Provider: name}
    
    // Get provider factory
    factory, err := e.registry.Get(name)
    if err != nil {
        result.Err = fmt.Errorf("get provider: %w", err)
        return result
    }
    
    // Create workspace and storage
    ws := workspace.New(e.config.WorkspaceRoot, name, e.logger)
    store, err := storage.NewSQLite(ws.ResultsPath())
    if err != nil {
        result.Err = fmt.Errorf("create storage: %w", err)
        return result
    }
    defer store.Close(ctx, result.Err == nil)
    
    // Create provider instance
    provider, err := factory.Create(ws, store, e.config.ProviderConfigs[name])
    if err != nil {
        result.Err = fmt.Errorf("create provider: %w", err)
        return result
    }
    
    // Acquire workspace lock
    unlock, err := ws.Lock(ctx)
    if err != nil {
        result.Err = fmt.Errorf("lock workspace: %w", err)
        return result
    }
    defer unlock()
    
    // Run provider
    urls, count, err := provider.Update(ctx, nil)
    result.URLs = urls
    result.Count = count
    result.Err = err
    result.Duration = time.Since(start)
    
    return result
}
```

### Context Propagation

```
CLI Context (with signal handling)
    ↓
Executor Context (with global timeout)
    ↓
Provider Context (with per-provider timeout)
    ↓
HTTP Request Context (with request timeout)
```

**Example:**

```go
// cmd/vulnz/main.go
func main() {
    // Create root context with signal handling
    ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
    defer stop()
    
    // Load configuration
    cfg, err := config.Load(".vulnz.yaml")
    if err != nil {
        log.Fatal(err)
    }
    
    // Create executor
    executor := provider.NewExecutor(cfg.Executor)
    
    // Run providers
    results, err := executor.Run(ctx, cfg.Providers)
    if err != nil {
        log.Fatal(err)
    }
    
    // Report results
    for _, r := range results {
        if r.Err != nil {
            log.Printf("[%s] FAILED: %v", r.Provider, r.Err)
        } else {
            log.Printf("[%s] SUCCESS: %d results in %v", r.Provider, r.Count, r.Duration)
        }
    }
}
```

### Error Aggregation

```go
// Collect errors from multiple providers
type MultiError struct {
    Errors []ProviderError
}

type ProviderError struct {
    Provider string
    Err      error
}

func (m *MultiError) Error() string {
    if len(m.Errors) == 0 {
        return "no errors"
    }
    
    var msgs []string
    for _, pe := range m.Errors {
        msgs = append(msgs, fmt.Sprintf("%s: %v", pe.Provider, pe.Err))
    }
    return strings.Join(msgs, "; ")
}

func (m *MultiError) Add(provider string, err error) {
    if err != nil {
        m.Errors = append(m.Errors, ProviderError{Provider: provider, Err: err})
    }
}

func (m *MultiError) Err() error {
    if len(m.Errors) == 0 {
        return nil
    }
    return m
}
```

### Resource Cleanup

Use `defer` statements with error checking:

```go
func (e *Executor) runProvider(ctx context.Context, name string) (result Result) {
    // Track success for cleanup decisions
    var success bool
    defer func() {
        // Example: close storage with success flag
        if store != nil {
            store.Close(ctx, success)
        }
    }()
    
    // ... provider logic ...
    
    // Mark as successful before return
    success = true
    return result
}
```

---

## Data Flow

### Overview

```
1. Fetch Raw Data
   Provider → HTTP Client → Download to workspace/input/
                                ↓
2. Parse/Transform
   Provider reads input → Transforms to schema → Creates envelopes
                                ↓
3. Write Results
   Provider → Result Writer → Storage Backend → workspace/results/
                                ↓
4. Generate Checksums
   Storage → Hasher → Checksum file
                                ↓
5. Update State
   Provider → Workspace → metadata.json
```

### Detailed Flow

```go
func (p *AlpineProvider) Update(ctx context.Context, lastUpdated *time.Time) ([]string, int, error) {
    // 1. Fetch raw data
    urls, err := p.fetchData(ctx)
    if err != nil {
        return nil, 0, fmt.Errorf("fetch data: %w", err)
    }
    
    // 2. Parse data from input directory
    vulnerabilities, err := p.parseData(ctx)
    if err != nil {
        return nil, 0, fmt.Errorf("parse data: %w", err)
    }
    
    // 3. Write results through storage backend
    writer := result.NewWriter(p.storage, p.logger)
    count := 0
    
    for namespace, vulns := range vulnerabilities {
        for id, vuln := range vulns {
            envelope := result.Envelope{
                Schema:     p.Schema().URL(),
                Identifier: filepath.Join(namespace, id),
                Item:       vuln,
            }
            
            if err := writer.Write(ctx, envelope); err != nil {
                return urls, count, fmt.Errorf("write result: %w", err)
            }
            count++
        }
    }
    
    // 4. Finalize storage (generates checksums, moves temp files)
    if err := writer.Close(ctx); err != nil {
        return urls, count, fmt.Errorf("close writer: %w", err)
    }
    
    return urls, count, nil
}
```

---

## Configuration Strategy

### YAML Structure

```yaml
# .vulnz.yaml
log:
  level: INFO
  slim: false
  show_timestamp: true
  show_level: true

root: ./data  # Base directory for all workspaces

executor:
  max_concurrent: 4
  timeout: 30m

providers:
  common:
    user_agent: "vulnz-go/1.0"
    import_results:
      enabled: false
      host: ""
      path: "providers/{provider_name}/listing.json"
  
  alpine:
    runtime:
      result_store: sqlite
      existing_results: delete-before-write
    request_timeout: 125s
  
  debian:
    runtime:
      result_store: flat-file
      existing_results: keep
    custom_field: "value"
  
  nvd:
    runtime:
      result_store: sqlite
    api_key: "${NVD_API_KEY}"  # Supports env var substitution
    request_timeout: 60s
```

### Configuration Structure

```go
// internal/config/config.go
package config

type Config struct {
    Log      LogConfig      `yaml:"log"`
    Root     string         `yaml:"root"`
    Executor ExecutorConfig `yaml:"executor"`
    Providers ProvidersConfig `yaml:"providers"`
}

type LogConfig struct {
    Level         string `yaml:"level"`
    Slim          bool   `yaml:"slim"`
    ShowTimestamp bool   `yaml:"show_timestamp"`
    ShowLevel     bool   `yaml:"show_level"`
}

type ExecutorConfig struct {
    MaxConcurrent int           `yaml:"max_concurrent"`
    Timeout       time.Duration `yaml:"timeout"`
}

type ProvidersConfig struct {
    Common   CommonProviderConfig       `yaml:"common"`
    Providers map[string]ProviderConfig `yaml:",inline"`  // Dynamic provider configs
}

type CommonProviderConfig struct {
    UserAgent     string              `yaml:"user_agent"`
    ImportResults ImportResultsConfig `yaml:"import_results"`
}

type ProviderConfig struct {
    Runtime RuntimeConfig     `yaml:"runtime"`
    Custom  map[string]any    `yaml:",inline"`  // Provider-specific fields
}

type RuntimeConfig struct {
    ResultStore      string `yaml:"result_store"`       // "flat-file" or "sqlite"
    ExistingResults  string `yaml:"existing_results"`   // "keep", "delete", "delete-before-write"
    ExistingInput    string `yaml:"existing_input"`     // "keep", "delete"
}
```

### Environment Variable Overrides

Environment variables override YAML config using this pattern:
- `VULNZ_LOG_LEVEL` → `log.level`
- `VULNZ_ROOT` → `root`
- `VULNZ_EXECUTOR_MAX_CONCURRENT` → `executor.max_concurrent`
- `VULNZ_PROVIDERS_NVD_API_KEY` → `providers.nvd.api_key`

```go
// internal/config/loader.go
package config

import (
    "os"
    "strings"
    "gopkg.in/yaml.v3"
)

func Load(path string) (*Config, error) {
    // 1. Load YAML file
    data, err := os.ReadFile(path)
    if err != nil && !os.IsNotExist(err) {
        return nil, err
    }
    
    cfg := &Config{}
    if len(data) > 0 {
        if err := yaml.Unmarshal(data, cfg); err != nil {
            return nil, fmt.Errorf("parse yaml: %w", err)
        }
    }
    
    // 2. Apply defaults
    cfg.applyDefaults()
    
    // 3. Override with environment variables
    applyEnvOverrides(cfg, "VULNZ")
    
    // 4. Validate
    if err := cfg.Validate(); err != nil {
        return nil, fmt.Errorf("validate config: %w", err)
    }
    
    return cfg, nil
}

func applyEnvOverrides(cfg *Config, prefix string) {
    // Use reflection to walk struct and apply env vars
    // Example: VULNZ_LOG_LEVEL overrides cfg.Log.Level
    for _, env := range os.Environ() {
        if !strings.HasPrefix(env, prefix+"_") {
            continue
        }
        
        parts := strings.SplitN(env, "=", 2)
        if len(parts) != 2 {
            continue
        }
        
        key := strings.TrimPrefix(parts[0], prefix+"_")
        value := parts[1]
        
        // Map key to config field path
        // E.g., "LOG_LEVEL" → cfg.Log.Level
        setConfigValue(cfg, key, value)
    }
}
```

### CLI Flag Overrides

```go
// cmd/vulnz/main.go
func main() {
    var (
        configPath  = flag.String("config", ".vulnz.yaml", "path to config file")
        logLevel    = flag.String("log-level", "", "log level (overrides config)")
        maxConcurrent = flag.Int("max-concurrent", 0, "max concurrent providers (overrides config)")
        providers   = flag.String("providers", "", "comma-separated list of providers to run")
    )
    flag.Parse()
    
    // Load config
    cfg, err := config.Load(*configPath)
    if err != nil {
        log.Fatal(err)
    }
    
    // Apply CLI flag overrides
    if *logLevel != "" {
        cfg.Log.Level = *logLevel
    }
    if *maxConcurrent > 0 {
        cfg.Executor.MaxConcurrent = *maxConcurrent
    }
    
    // Parse provider list
    var providerNames []string
    if *providers != "" {
        providerNames = strings.Split(*providers, ",")
    } else {
        providerNames = cfg.Providers.EnabledProviders()
    }
    
    // Run...
}
```

---

## Error Handling

### Error Types

```go
// internal/provider/errors.go
package provider

import (
    "errors"
    "fmt"
)

// Sentinel errors
var (
    ErrProviderNotFound    = errors.New("provider not found")
    ErrInvalidConfig       = errors.New("invalid configuration")
    ErrWorkspaceLocked     = errors.New("workspace locked")
    ErrNetworkTimeout      = errors.New("network timeout")
    ErrRateLimited         = errors.New("rate limited")
)

// ProviderError wraps errors with provider context
type ProviderError struct {
    Provider string
    Op       string  // Operation that failed (e.g., "fetch", "parse", "write")
    Err      error
}

func (e *ProviderError) Error() string {
    return fmt.Sprintf("%s/%s: %v", e.Provider, e.Op, e.Err)
}

func (e *ProviderError) Unwrap() error {
    return e.Err
}

// Helper constructors
func Errorf(provider, op, format string, args ...interface{}) error {
    return &ProviderError{
        Provider: provider,
        Op:       op,
        Err:      fmt.Errorf(format, args...),
    }
}

func WrapError(provider, op string, err error) error {
    if err == nil {
        return nil
    }
    return &ProviderError{
        Provider: provider,
        Op:       op,
        Err:      err,
    }
}
```

### Recoverable vs Fatal Errors

```go
// Recoverable: Retry with backoff
func isRecoverable(err error) bool {
    // Network errors are recoverable
    if errors.Is(err, ErrNetworkTimeout) {
        return true
    }
    
    // Rate limiting is recoverable
    if errors.Is(err, ErrRateLimited) {
        return true
    }
    
    // Context cancellation is not recoverable
    if errors.Is(err, context.Canceled) {
        return false
    }
    
    // Context deadline is not recoverable (timeout already exhausted)
    if errors.Is(err, context.DeadlineExceeded) {
        return false
    }
    
    // Default: not recoverable
    return false
}

// Retry logic with exponential backoff
func (e *Executor) runProviderWithRetry(ctx context.Context, name string, maxRetries int) Result {
    var result Result
    
    for attempt := 0; attempt <= maxRetries; attempt++ {
        result = e.runProvider(ctx, name)
        
        if result.Err == nil {
            return result
        }
        
        if !isRecoverable(result.Err) {
            e.logger.Error("non-recoverable error", "provider", name, "error", result.Err)
            return result
        }
        
        if attempt < maxRetries {
            backoff := time.Duration(1<<uint(attempt)) * time.Second
            e.logger.Warn("retrying after error",
                "provider", name,
                "attempt", attempt+1,
                "backoff", backoff,
                "error", result.Err,
            )
            
            select {
            case <-time.After(backoff):
            case <-ctx.Done():
                result.Err = ctx.Err()
                return result
            }
        }
    }
    
    return result
}
```

### Error Propagation

```go
// Wrap errors at each layer with context
func (p *AlpineProvider) Update(ctx context.Context, lastUpdated *time.Time) ([]string, int, error) {
    urls, err := p.fetchData(ctx)
    if err != nil {
        return nil, 0, WrapError(p.Name(), "fetch", err)
    }
    
    vulns, err := p.parseData(ctx)
    if err != nil {
        return urls, 0, WrapError(p.Name(), "parse", err)
    }
    
    count, err := p.writeResults(ctx, vulns)
    if err != nil {
        return urls, count, WrapError(p.Name(), "write", err)
    }
    
    return urls, count, nil
}

// Caller can inspect error chain
func handleError(err error) {
    var provErr *ProviderError
    if errors.As(err, &provErr) {
        log.Printf("Provider %s failed during %s: %v", provErr.Provider, provErr.Op, provErr.Err)
    }
    
    if errors.Is(err, ErrRateLimited) {
        log.Println("Rate limited, consider reducing concurrency")
    }
}
```

---

## Provider Plugin System

### Registration

```go
// internal/provider/registry.go
package provider

import (
    "fmt"
    "sync"
)

type Registry struct {
    mu        sync.RWMutex
    factories map[string]Factory
}

func NewRegistry() *Registry {
    return &Registry{
        factories: make(map[string]Factory),
    }
}

func (r *Registry) Register(name string, factory Factory) {
    r.mu.Lock()
    defer r.mu.Unlock()
    r.factories[name] = factory
}

func (r *Registry) Get(name string) (Factory, error) {
    r.mu.RLock()
    defer r.mu.RUnlock()
    
    factory, ok := r.factories[name]
    if !ok {
        return nil, fmt.Errorf("%w: %s", ErrProviderNotFound, name)
    }
    return factory, nil
}

func (r *Registry) List() []string {
    r.mu.RLock()
    defer r.mu.RUnlock()
    
    names := make([]string, 0, len(r.factories))
    for name := range r.factories {
        names = append(names, name)
    }
    return names
}

// Global registry
var defaultRegistry = NewRegistry()

func Register(name string, factory Factory) {
    defaultRegistry.Register(name, factory)
}

func GetProvider(name string) (Factory, error) {
    return defaultRegistry.Get(name)
}
```

### Provider Auto-Registration

Each provider registers itself in an `init()` function:

```go
// providers/alpine/provider.go
package alpine

import (
    "github.com/yourusername/vulnz-go/internal/provider"
)

func init() {
    provider.Register("alpine", &factory{})
}

type factory struct{}

func (f *factory) Create(ws provider.Workspace, store provider.Storage, cfg provider.ProviderConfig) (provider.Provider, error) {
    // Extract alpine-specific config
    alpineCfg, err := parseConfig(cfg)
    if err != nil {
        return nil, err
    }
    
    return &AlpineProvider{
        workspace: ws,
        storage:   store,
        config:    alpineCfg,
    }, nil
}

func parseConfig(cfg provider.ProviderConfig) (Config, error) {
    // Convert map[string]any to Alpine-specific config struct
    // Using mapstructure or manual extraction
}
```

### Dynamic Loading

All providers are imported in one place to trigger `init()`:

```go
// internal/provider/all.go
package provider

import (
    _ "github.com/yourusername/vulnz-go/providers/alpine"
    _ "github.com/yourusername/vulnz-go/providers/debian"
    _ "github.com/yourusername/vulnz-go/providers/nvd"
    // ... all 27+ providers
)
```

---

## Example: Complete Provider Implementation

```go
// providers/alpine/provider.go
package alpine

import (
    "context"
    "encoding/json"
    "fmt"
    "io"
    "path/filepath"
    "time"
    
    "github.com/yourusername/vulnz-go/internal/httpclient"
    "github.com/yourusername/vulnz-go/internal/provider"
    "github.com/yourusername/vulnz-go/internal/result"
    "github.com/yourusername/vulnz-go/internal/schema"
)

const (
    alpineURL = "https://secdb.alpinelinux.org/"
)

type Config struct {
    RequestTimeout time.Duration `yaml:"request_timeout"`
}

type AlpineProvider struct {
    workspace provider.Workspace
    storage   provider.Storage
    config    Config
    http      httpclient.Client
    logger    *slog.Logger
}

func init() {
    provider.Register("alpine", &factory{})
}

type factory struct{}

func (f *factory) Create(ws provider.Workspace, store provider.Storage, cfg provider.ProviderConfig) (provider.Provider, error) {
    var alpineCfg Config
    // Parse config.Custom map into Config struct
    // (use mapstructure or similar)
    
    return &AlpineProvider{
        workspace: ws,
        storage:   store,
        config:    alpineCfg,
        http:      httpclient.New(slog.With("provider", "alpine")),
        logger:    slog.With("provider", "alpine"),
    }, nil
}

func (p *AlpineProvider) Name() string {
    return "alpine"
}

func (p *AlpineProvider) Schema() provider.Schema {
    return schema.OSSchema{Version: "1.0.0"}
}

func (p *AlpineProvider) Tags() []string {
    return []string{"os", "vulnerability"}
}

func (p *AlpineProvider) Update(ctx context.Context, lastUpdated *time.Time) ([]string, int, error) {
    // 1. Fetch data
    urls := []string{alpineURL + "alpine/v3.19/main.json"}
    
    for _, url := range urls {
        destPath := filepath.Join(p.workspace.InputPath(), filepath.Base(url))
        if err := p.http.Download(ctx, url, destPath); err != nil {
            return urls, 0, fmt.Errorf("download %s: %w", url, err)
        }
    }
    
    // 2. Parse data
    vulnerabilities, err := p.parse(ctx)
    if err != nil {
        return urls, 0, fmt.Errorf("parse: %w", err)
    }
    
    // 3. Write results
    count := 0
    for namespace, vulns := range vulnerabilities {
        for id, vuln := range vulns {
            envelope := result.Envelope{
                Schema:     p.Schema().URL(),
                Identifier: filepath.Join(namespace, id),
                Item:       vuln,
            }
            
            if err := p.storage.Write(ctx, envelope.Identifier, envelope); err != nil {
                return urls, count, fmt.Errorf("write %s: %w", envelope.Identifier, err)
            }
            count++
        }
    }
    
    return urls, count, nil
}

func (p *AlpineProvider) parse(ctx context.Context) (map[string]map[string]Vulnerability, error) {
    // Read files from input directory and parse
    files, err := filepath.Glob(filepath.Join(p.workspace.InputPath(), "*.json"))
    if err != nil {
        return nil, err
    }
    
    results := make(map[string]map[string]Vulnerability)
    
    for _, file := range files {
        data, err := os.ReadFile(file)
        if err != nil {
            return nil, fmt.Errorf("read %s: %w", file, err)
        }
        
        var secdb SecurityDB
        if err := json.Unmarshal(data, &secdb); err != nil {
            return nil, fmt.Errorf("parse %s: %w", file, err)
        }
        
        // Transform to standard schema
        namespace := secdb.DistroVersion
        results[namespace] = make(map[string]Vulnerability)
        
        for _, pkg := range secdb.Packages {
            for _, vuln := range pkg.Vulnerabilities {
                results[namespace][vuln.ID] = transformVulnerability(pkg, vuln)
            }
        }
    }
    
    return results, nil
}

type SecurityDB struct {
    DistroVersion string    `json:"distroversion"`
    Packages      []Package `json:"packages"`
}

type Package struct {
    Name            string          `json:"pkg"`
    Vulnerabilities []VulnReference `json:"secfixes"`
}

type VulnReference struct {
    ID          string `json:"id"`
    FixedVersion string `json:"fixed"`
}

type Vulnerability struct {
    ID           string   `json:"id"`
    Package      string   `json:"package"`
    FixedVersion string   `json:"fixed_version"`
    Namespace    string   `json:"namespace"`
}

func transformVulnerability(pkg Package, vuln VulnReference) Vulnerability {
    return Vulnerability{
        ID:           vuln.ID,
        Package:      pkg.Name,
        FixedVersion: vuln.FixedVersion,
    }
}
```

---

## Key Architectural Decisions Summary

### 1. **Interface-First Design**
- All core components (Provider, Storage, Workspace, HTTPClient) are interfaces
- Enables testing with mocks and swapping implementations
- Clear contracts between layers

### 2. **Dependency Injection**
- Providers receive workspace and storage via factory pattern
- No global state (except provider registry)
- Easier testing and composition

### 3. **Context Propagation**
- Every operation accepts `context.Context` as first parameter
- Enables graceful cancellation and timeout handling
- Follows Go best practices

### 4. **Concurrency Control**
- Semaphore limits max concurrent providers
- Per-host rate limiting prevents thundering herd
- Workspace locking prevents concurrent writes to same provider

### 5. **Error Handling**
- Custom error types with wrapping (`ProviderError`)
- Distinguish recoverable vs fatal errors
- Aggregate errors from parallel operations (`MultiError`)

### 6. **Plugin Architecture**
- Providers self-register via `init()` functions
- Registry enables dynamic discovery
- No compile-time coupling between core and providers

### 7. **Storage Abstraction**
- Single `Storage` interface for flat-file and SQLite
- Writer handles batching and finalization
- Atomic writes via temp files

### 8. **Configuration Hierarchy**
- YAML base config → env vars → CLI flags
- Provider-specific configs with common defaults
- Type-safe config structs

### 9. **HTTP Client Design**
- Per-host connection pooling via `http.Transport`
- Exponential backoff with jitter
- Retry-After header support for rate limiting

### 10. **Workspace Isolation**
- Each provider has isolated directory tree
- File locking prevents concurrent access
- State persisted as JSON metadata

---

## Testing Strategy

### Unit Tests

```go
// providers/alpine/provider_test.go
package alpine

import (
    "context"
    "testing"
    
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/mock"
)

// Mock storage
type mockStorage struct {
    mock.Mock
}

func (m *mockStorage) Write(ctx context.Context, id string, env result.Envelope) error {
    args := m.Called(ctx, id, env)
    return args.Error(0)
}

func TestAlpineProvider_Update(t *testing.T) {
    // Setup
    mockStore := &mockStorage{}
    mockWs := &mockWorkspace{}
    
    provider := &AlpineProvider{
        workspace: mockWs,
        storage:   mockStore,
    }
    
    // Expectations
    mockStore.On("Write", mock.Anything, mock.Anything, mock.Anything).Return(nil)
    
    // Execute
    urls, count, err := provider.Update(context.Background(), nil)
    
    // Assert
    assert.NoError(t, err)
    assert.Greater(t, count, 0)
    assert.NotEmpty(t, urls)
    mockStore.AssertExpectations(t)
}
```

### Integration Tests

```go
// internal/provider/executor_integration_test.go
package provider

import (
    "context"
    "testing"
    "time"
)

func TestExecutor_RunProviders(t *testing.T) {
    // Create real workspace in temp dir
    tmpDir := t.TempDir()
    
    // Create real SQLite storage
    store, err := storage.NewSQLite(tmpDir)
    require.NoError(t, err)
    
    // Run executor with real providers
    executor := NewExecutor(ExecutorConfig{
        MaxConcurrent: 2,
        Timeout:       5 * time.Minute,
        WorkspaceRoot: tmpDir,
    })
    
    results, err := executor.Run(context.Background(), []string{"alpine", "debian"})
    require.NoError(t, err)
    
    // Verify results
    for _, result := range results {
        assert.NoError(t, result.Err, "provider %s failed", result.Provider)
        assert.Greater(t, result.Count, 0, "provider %s returned no results", result.Provider)
    }
}
```

---

## Performance Considerations

### 1. **HTTP Connection Pooling**
- Reuse TCP connections per host
- Reduce TLS handshake overhead
- Configure `MaxIdleConnsPerHost` and `MaxConnsPerHost`

### 2. **SQLite Optimizations**
- WAL mode for concurrent reads during writes
- Batch inserts (5000 records per transaction)
- `PRAGMA synchronous=NORMAL` for performance vs durability balance

### 3. **Goroutine Limits**
- Semaphore prevents unbounded goroutines
- Configurable via `max_concurrent` setting
- Default: 4 (conservative for I/O-bound workload)

### 4. **Memory Management**
- Stream large HTTP responses to disk
- Don't load entire result set into memory
- Use `json.Decoder` for streaming JSON parsing

### 5. **Disk I/O**
- Write to temp files, then atomic rename
- Batch checksum calculations
- Consider SSD for workspace directory

---

## Future Enhancements

### 1. **Distributed Execution**
- Message queue for provider jobs
- Worker pool across multiple machines
- Shared storage (S3, GCS)

### 2. **Incremental Updates**
- Track last-updated timestamp per provider
- Only fetch changed data
- Delta updates to storage

### 3. **Metrics and Monitoring**
- Prometheus metrics (provider duration, error rates)
- OpenTelemetry tracing
- Health check endpoint

### 4. **Caching Layer**
- Redis for intermediate data
- Reduce redundant downloads
- Cache parsed schemas

### 5. **Plugin Discovery**
- Load providers from external `.so` files
- Hot-reload providers without restart
- Third-party provider packages

---

## References

- Python Vunnel: `/home/shift/Documents/d-stack-desktop/vunnel-eu-cra`
- Go Concurrency Patterns: https://go.dev/blog/pipelines
- Go Error Handling: https://go.dev/blog/error-handling-and-go
- SQLite Performance: https://www.sqlite.org/pragma.html#pragma_optimize

---

## Appendix: ASCII Architecture Diagram

```
┌──────────────────────────────────────────────────────────────┐
│                         CLI Layer                            │
│  cmd/vulnz/main.go                                           │
│  - Parse flags                                               │
│  - Load config                                               │
│  - Setup logging                                             │
└────────────────────┬─────────────────────────────────────────┘
                     │
                     ▼
┌──────────────────────────────────────────────────────────────┐
│                    Executor Layer                            │
│  internal/provider/executor.go                               │
│  - Orchestrate providers                                     │
│  - Manage concurrency                                        │
│  - Aggregate results                                         │
└───┬──────────────────────────────────────────────────────┬───┘
    │                                                      │
    │ spawn goroutines                                     │ uses
    │                                                      │
    ▼                                                      ▼
┌──────────────────────────────────┐      ┌──────────────────────────┐
│      Provider Layer               │      │    Storage Layer         │
│  internal/provider/provider.go    │      │  internal/storage/       │
│  - Provider interface             │      │  - Storage interface     │
│  - Registry                       │      │  - FlatFile impl         │
│  - Factory pattern                │──────▶  - SQLite impl           │
└───┬──────────────────────────────┘      └──────────────────────────┘
    │                                                      ▲
    │ implements                                           │ writes to
    │                                                      │
    ▼                                                      │
┌──────────────────────────────────┐      ┌──────────────┴───────────┐
│   Provider Implementations        │      │    Result Layer          │
│  providers/alpine/                │      │  internal/result/        │
│  providers/debian/                │──────▶  - Envelope             │
│  providers/nvd/                   │      │  - Writer                │
│  ... (27+ providers)              │      └──────────────────────────┘
└───┬──────────────────────────────┘
    │ uses
    │
    ▼
┌──────────────────────────────────┐      ┌──────────────────────────┐
│    Workspace Layer                │      │    HTTP Client Layer     │
│  internal/workspace/              │      │  internal/httpclient/    │
│  - Directory management           │      │  - Connection pooling    │
│  - State persistence              │      │  - Rate limiting         │
│  - File locking                   │      │  - Retry logic           │
└───────────────────────────────────┘      └──────────────────────────┘
```

---

**Document Version:** 1.0  
**Last Updated:** 2026-03-30  
**Author:** 03-the-architect
