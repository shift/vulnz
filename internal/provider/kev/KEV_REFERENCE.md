# KEV Provider Reference Implementation

**Purpose:** This is a reference implementation for simple JSON-based vulnerability providers in vulnz-go. Use this as a template when implementing similar providers.

## Overview

The KEV (Known Exploited Vulnerabilities) provider fetches CISA's KEV catalog and integrates it with the vulnz-go framework. It demonstrates:

1. Provider registration
2. HTTP data fetching
3. JSON parsing and transformation
4. Storage backend integration
5. EU CRA compliance metadata injection
6. Comprehensive BDD testing

**Lines of Code:** ~330 LOC (provider + manager + tests)  
**Test Coverage Target:** 75%+  
**Complexity:** Simple (single JSON endpoint, no authentication)

---

## File Structure

```
internal/provider/kev/
├── provider.go           # Provider implementation (106 LOC)
├── manager.go            # Data fetching and parsing (154 LOC)
├── kev_suite_test.go     # Ginkgo test suite setup (14 LOC)
├── provider_test.go      # Provider integration tests (175 LOC)
└── manager_test.go       # Manager unit tests with mocks (285 LOC)
```

---

## Implementation Pattern

### 1. Provider Structure (`provider.go`)

**Key Components:**
- `Provider` struct embeds `*provider.Base` for common functionality
- Stores `provider.Config` for workspace, storage, HTTP, logger access
- Delegates data fetching to `Manager` for separation of concerns
- Implements `provider.Provider` interface (Name, Update methods)
- Optionally implements `provider.TagsProvider` interface

**Example:**
```go
type Provider struct {
    *provider.Base           // Embedded base provides Logger(), Config()
    config  provider.Config  // Store config for storage/workspace access
    manager *Manager         // Delegate HTTP/parsing to manager
}
```

**Registration Pattern:**
```go
func init() {
    provider.Register("kev", NewProvider)  // Auto-registers on import
}
```

**Update Method Pattern:**
```go
func (p *Provider) Update(ctx context.Context, lastUpdated *time.Time) ([]string, int, error) {
    // 1. Log start
    p.Logger().InfoContext(ctx, "starting KEV provider update")
    
    // 2. Fetch data via manager
    records, err := p.manager.Get(ctx)
    if err != nil {
        return nil, 0, fmt.Errorf("fetch KEV data: %w", err)
    }
    
    // 3. Initialize storage backend
    storageBackend, err := storage.New(storage.Config{
        Type: p.config.Storage.Type,
        Path: p.config.Storage.Path,
    })
    if err != nil {
        return nil, 0, fmt.Errorf("initialize storage: %w", err)
    }
    defer storageBackend.Close(ctx)
    
    // 4. Write records to storage
    for cveID, record := range records {
        envelope := &storage.Envelope{
            Schema:     "https://raw.githubusercontent.com/anchore/vunnel/main/schema/vulnerability/os/schema-1.0.0.json",
            Identifier: fmt.Sprintf("kev:%s", cveID),
            Item:       record,
        }
        
        if err := storageBackend.Write(ctx, envelope); err != nil {
            p.Logger().WarnContext(ctx, "failed to write record", "cve", cveID, "error", err)
            continue
        }
    }
    
    // 5. Return URLs, count, error
    return p.manager.URLs(), len(records), nil
}
```

---

### 2. Manager Structure (`manager.go`)

**Responsibilities:**
- HTTP fetching with context support
- JSON parsing and validation
- Data transformation (e.g., EU CRA metadata injection)
- Saving raw data to workspace

**Key Methods:**
- `Get(ctx)` - Main entry point, returns map[string]map[string]interface{}
- `download(ctx)` - Fetches JSON, saves to workspace, returns parsed map
- `parse(catalog)` - Transforms raw data, injects metadata
- `URLs()` - Returns list of URLs this manager fetches from

**Example Pattern:**
```go
type Manager struct {
    url    string
    config provider.Config
    client *http.Client
}

func (m *Manager) Get(ctx context.Context) (map[string]map[string]interface{}, error) {
    // 1. Download raw data
    catalog, err := m.download(ctx)
    if err != nil {
        return nil, fmt.Errorf("download KEV catalog: %w", err)
    }
    
    // 2. Parse and enhance
    records, err := m.parse(catalog)
    if err != nil {
        return nil, fmt.Errorf("parse KEV catalog: %w", err)
    }
    
    return records, nil
}

func (m *Manager) download(ctx context.Context) (map[string]interface{}, error) {
    // 1. Create input directory
    inputDir := filepath.Join(m.config.Workspace, "input")
    os.MkdirAll(inputDir, 0755)
    
    // 2. Fetch with context
    req, _ := http.NewRequestWithContext(ctx, http.MethodGet, m.url, nil)
    req.Header.Set("User-Agent", m.config.HTTP.UserAgent)
    resp, err := m.client.Do(req)
    // ... error handling ...
    
    // 3. Save to workspace
    body, _ := io.ReadAll(resp.Body)
    os.WriteFile(filepath.Join(inputDir, "kev.json"), body, 0644)
    
    // 4. Parse and return
    var catalog map[string]interface{}
    json.Unmarshal(body, &catalog)
    return catalog, nil
}
```

---

### 3. Testing Pattern

**Test Suite Setup (`kev_suite_test.go`):**
```go
package kev_test

import (
    "testing"
    . "github.com/onsi/ginkgo/v2"
    . "github.com/onsi/gomega"
)

func TestKEV(t *testing.T) {
    RegisterFailHandler(Fail)
    RunSpecs(t, "KEV Provider Suite")
}
```

**Provider Tests (`provider_test.go`):**
- Test provider registration
- Test interface implementations (TagsProvider)
- Test storage backend integration
- Test error handling
- Use real provider, skip network tests with `Skip()`

**Manager Tests (`manager_test.go`):**
- Use `httptest.NewServer()` for mocking
- Test successful data fetching
- Test error conditions (HTTP errors, malformed JSON)
- Test context cancellation
- Test data transformation (EU CRA metadata injection)

**Mock Server Pattern:**
```go
testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(testData)
}))
defer testServer.Close()

manager := kev.NewManager(testServer.URL, config)
```

---

## Phase 1 Framework APIs Used

### Provider Interface
```go
type Provider interface {
    Name() string
    Update(ctx context.Context, lastUpdated *time.Time) ([]string, int, error)
}
```

### Provider Config
```go
type Config struct {
    Name      string        // Provider name
    Workspace string        // Root workspace directory
    Storage   StorageConfig // Storage backend configuration
    HTTP      HTTPConfig    // HTTP client configuration
    Logger    *slog.Logger  // Structured logger
}
```

### Provider Base
```go
type Base struct { /* ... */ }

func NewBase(config Config) *Base
func (b *Base) Logger() *slog.Logger
func (b *Base) Name() string
```

### Provider Registry
```go
func Register(name string, factory Factory)  // Call from init()
func Get(name string) (Factory, bool)
func List() []string
```

### Storage Backend
```go
type Backend interface {
    Write(ctx context.Context, envelope *Envelope) error
    Read(ctx context.Context, id string) (*Envelope, error)
    Close(ctx context.Context) error
}

type Envelope struct {
    Schema     string      // Schema URL
    Identifier string      // Unique ID (e.g., "kev:CVE-2023-1234")
    Item       interface{} // Vulnerability payload
}

func New(config Config) (Backend, error)
```

---

## Key Design Decisions

### 1. Separation of Concerns
- **Provider** handles framework integration (registration, storage, logging)
- **Manager** handles domain logic (HTTP, parsing, transformation)
- Tests separated by concern (provider tests vs manager tests)

### 2. Storage Integration
- Storage backend is initialized in `Update()`, not in `NewProvider()`
- This allows different storage types per run (testing flexibility)
- Always defer `Close()` with error handling

### 3. Error Handling
- Wrap errors with context using `fmt.Errorf("context: %w", err)`
- Log warnings for individual record failures, don't fail entire update
- Respect context cancellation throughout

### 4. EU CRA Compliance
- KEV provider injects `exploited_in_wild: true` flag
- Adds structured metadata for policy engines
- Namespace pattern: `cisa:kev`

### 5. Testing Strategy
- Unit tests use mock HTTP servers (`httptest`)
- Integration tests skip network with `Skip()` annotation
- Target: 75%+ coverage, all critical paths tested

---

## Workspace Layout

```
<workspace>/
├── input/
│   └── kev.json          # Raw downloaded data
└── results/
    └── <storage-type>/   # Storage backend writes here
        └── vulnerabilities/
            ├── kev:CVE-2023-1234.json
            ├── kev:CVE-2023-5678.json
            └── ...
```

---

## Checklist for New Providers

When implementing a new provider using this pattern:

- [ ] Create provider.go with Provider struct
- [ ] Embed `*provider.Base` in Provider
- [ ] Implement `init()` with `provider.Register()`
- [ ] Implement `Name()` method
- [ ] Implement `Update()` method with storage integration
- [ ] Optionally implement `TagsProvider` interface
- [ ] Create manager.go for HTTP/parsing logic
- [ ] Implement `Get()` method in manager
- [ ] Save raw data to workspace/input
- [ ] Create test suite setup file
- [ ] Write provider tests (registration, interfaces)
- [ ] Write manager tests with mock HTTP server
- [ ] Test context cancellation
- [ ] Test error conditions
- [ ] Verify 75%+ test coverage

---

## Common Patterns

### Context Handling
```go
req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
// ... always check ctx.Err() in loops
```

### Logging
```go
p.Logger().InfoContext(ctx, "message", "key", value)
p.Logger().WarnContext(ctx, "warning", "error", err)
p.Logger().ErrorContext(ctx, "error", "error", err)
```

### Storage Envelope Pattern
```go
envelope := &storage.Envelope{
    Schema:     "https://raw.githubusercontent.com/anchore/vunnel/main/schema/vulnerability/os/schema-1.0.0.json",
    Identifier: fmt.Sprintf("namespace:%s", id),
    Item:       record,
}
```

---

## Next Steps

After completing KEV provider:

1. Run tests: `go test ./internal/provider/kev/... -v`
2. Check coverage: `go test ./internal/provider/kev/... -coverprofile=coverage.out`
3. Verify provider registration: `go run ./cmd/vulnz list`
4. Test end-to-end: `go run ./cmd/vulnz run kev`
5. Use as template for delegating other providers to subagents

---

## Delegation Notes

When delegating provider implementation to `71-the-gopher` subagent:

1. Provide this reference document
2. Specify data source URL and format
3. Provide example JSON response
4. Specify any special transformations needed
5. Request tests with mock HTTP server
6. Require 75%+ coverage
7. Ask agent to verify compilation (but note sqlite3 build times)

**Success Criteria:**
- Provider compiles without errors
- Registers in provider registry
- All tests pass
- Coverage ≥ 75%
- Follows KEV pattern exactly
