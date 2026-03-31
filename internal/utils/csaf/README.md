# CSAF Parser for vulnz-go

## Overview

The CSAF (Common Security Advisory Framework) parser provides a Go interface for parsing and extracting data from CSAF 2.0 security advisories. It wraps the `gocsaf/csaf/v3` library with convenient helpers for common operations.

## Package Structure

```
internal/utils/csaf/
├── parser.go          # Core CSAF parsing functionality
├── extractor.go       # Data extraction helpers
├── types.go           # Simplified types
├── testdata/          # Test fixtures
│   ├── rhsa-2023-0001.json    # Red Hat advisory
│   ├── suse-su-2023-0100.json # SUSE advisory
│   ├── minimal.json   # Minimal valid CSAF
│   ├── invalid.json   # Invalid document
│   └── malformed.json # Malformed JSON
└── *_test.go          # BDD tests
```

## Usage

### Basic Parsing

```go
package main

import (
    "context"
    "fmt"
    "log"

    "github.com/shift/vulnz/internal/utils/csaf"
)

func main() {
    ctx := context.Background()
    parser := csaf.NewParser()

    // Parse CSAF file
    if err := parser.ParseFile(ctx, "rhsa-2023-0001.json"); err != nil {
        log.Fatalf("Parse error: %v", err)
    }

    // Validate document
    if err := parser.Validate(); err != nil {
        log.Printf("Validation failed: %v", err)
    }

    // Get parsed document
    doc := parser.GetDocument()
    fmt.Printf("Parsed advisory: %s\n", *doc.Document.Title)
}
```

### Extracting CVEs

```go
// Extract all CVE IDs from an advisory
cves := csaf.ExtractCVEs(doc)
fmt.Printf("Found %d CVEs: %v\n", len(cves), cves)
// Output: Found 2 CVEs: [CVE-2023-1234 CVE-2023-5678]
```

### Extracting Products

```go
// Extract all product names from the product tree
products := csaf.ExtractProducts(doc)
for _, product := range products {
    fmt.Printf("Product: %s\n", product)
}
// Output: Product: openssl-1.1.1k-7.el8_6
```

### Extracting Remediations

```go
// Extract remediation information
remediations := csaf.ExtractRemediations(doc)
for _, rem := range remediations {
    fmt.Printf("Type: %s\n", rem.Category)
    fmt.Printf("Details: %s\n", rem.Details)
    fmt.Printf("URL: %s\n", rem.URL)
    fmt.Printf("Affects: %v\n", rem.ProductIDs)
}
```

### Extracting CVSS Scores

```go
// Extract CVSS scores
scores := csaf.ExtractScores(doc)
for _, score := range scores {
    fmt.Printf("CVE: %s\n", score.CVE)
    fmt.Printf("Version: %s\n", score.Version)
    fmt.Printf("Base Score: %.1f (%s)\n", score.BaseScore, score.Severity)
    fmt.Printf("Vector: %s\n", score.Vector)
    fmt.Printf("Products: %v\n", score.ProductIDs)
}
```

### Simplified Advisory View

```go
// Get a simplified view of the advisory
simplified := csaf.Simplify(doc)

fmt.Printf("ID: %s\n", simplified.ID)
fmt.Printf("Title: %s\n", simplified.Title)
fmt.Printf("Publisher: %s\n", simplified.Publisher)
fmt.Printf("Status: %s\n", simplified.Status)
fmt.Printf("Severity: %s\n", simplified.Severity)
fmt.Printf("CVEs: %v\n", simplified.CVEs)
fmt.Printf("Products: %v\n", simplified.Products)
fmt.Printf("Released: %s\n", simplified.InitialRelease)
```

### Parsing from Bytes

```go
// Parse CSAF from byte slice (e.g., HTTP response)
data := []byte(`{"document": {...}}`)
if err := parser.ParseBytes(ctx, data); err != nil {
    log.Fatalf("Parse error: %v", err)
}
```

### Context Handling

```go
// Use context for cancellation and timeouts
ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
defer cancel()

if err := parser.ParseFile(ctx, "large-advisory.json"); err != nil {
    if err == context.DeadlineExceeded {
        log.Println("Parsing timed out")
    }
}
```

## Complete Example

```go
package main

import (
    "context"
    "fmt"
    "log"

    "github.com/shift/vulnz/internal/utils/csaf"
)

func main() {
    ctx := context.Background()
    parser := csaf.NewParser()

    // Parse CSAF advisory
    if err := parser.ParseFile(ctx, "rhsa-2023-0001.json"); err != nil {
        log.Fatalf("Failed to parse: %v", err)
    }

    // Validate
    if err := parser.Validate(); err != nil {
        log.Printf("Validation warning: %v", err)
    }

    // Get document
    doc := parser.GetDocument()

    // Extract information
    cves := csaf.ExtractCVEs(doc)
    products := csaf.ExtractProducts(doc)
    remediations := csaf.ExtractRemediations(doc)
    scores := csaf.ExtractScores(doc)

    // Get simplified view
    simplified := csaf.Simplify(doc)

    // Display summary
    fmt.Printf("=== CSAF Advisory Summary ===\n")
    fmt.Printf("ID: %s\n", simplified.ID)
    fmt.Printf("Title: %s\n", simplified.Title)
    fmt.Printf("Publisher: %s\n", simplified.Publisher)
    fmt.Printf("Severity: %s\n", simplified.Severity)
    fmt.Printf("Status: %s\n\n", simplified.Status)

    fmt.Printf("Vulnerabilities: %d CVEs\n", len(cves))
    for _, cve := range cves {
        fmt.Printf("  - %s\n", cve)
    }

    fmt.Printf("\nAffected Products: %d\n", len(products))
    for _, product := range products {
        fmt.Printf("  - %s\n", product)
    }

    fmt.Printf("\nRemediations: %d\n", len(remediations))
    for _, rem := range remediations {
        fmt.Printf("  [%s] %s\n", rem.Category, rem.Details)
        if rem.URL != "" {
            fmt.Printf("    URL: %s\n", rem.URL)
        }
    }

    fmt.Printf("\nCVSS Scores:\n")
    for _, score := range scores {
        fmt.Printf("  %s: %.1f (%s) - %s\n",
            score.CVE, score.BaseScore, score.Severity, score.Version)
    }
}
```

## Integration Points

This parser is designed to be used by vulnerability data providers:

### Red Hat Enterprise Linux (RHEL)
```go
// RHEL publishes CSAF advisories
parser := csaf.NewParser()
err := parser.ParseFile(ctx, "rhsa-2023-0001.json")
```

### SUSE Linux
```go
// SUSE security updates in CSAF format
parser := csaf.NewParser()
err := parser.ParseFile(ctx, "suse-su-2023-0100.json")
```

### BSI CERT-Bund (German)
```go
// German BSI CSAF advisories
parser := csaf.NewParser()
err := parser.ParseFile(ctx, "bsi-advisory.json")
```

### CERT-FR (French)
```go
// French CERT CSAF advisories
parser := csaf.NewParser()
err := parser.ParseFile(ctx, "certfr-advisory.json")
```

## API Reference

### Parser

#### `NewParser() *Parser`
Creates a new CSAF parser instance.

#### `ParseFile(ctx context.Context, path string) error`
Parses a CSAF JSON file from the given path.

#### `ParseBytes(ctx context.Context, data []byte) error`
Parses CSAF JSON from a byte slice.

#### `GetDocument() *csaf.Advisory`
Returns the parsed CSAF advisory. Returns nil if no document has been parsed.

#### `Validate() error`
Validates the CSAF document against the schema.

### Extractor Functions

#### `ExtractCVEs(doc *csaf.Advisory) []string`
Extracts all unique CVE IDs from the advisory.

#### `ExtractProducts(doc *csaf.Advisory) []string`
Extracts all unique product names from the product tree.

#### `ExtractRemediations(doc *csaf.Advisory) []Remediation`
Extracts all remediation details from the advisory.

#### `ExtractScores(doc *csaf.Advisory) []Score`
Extracts all CVSS scores from the advisory.

### Types

#### `Remediation`
```go
type Remediation struct {
    Category   string   // workaround, mitigation, vendor_fix
    Details    string
    ProductIDs []string
    URL        string
}
```

#### `Score`
```go
type Score struct {
    CVE        string
    Version    string   // CVSS v2, v3.0, v3.1
    BaseScore  float64
    Vector     string
    Severity   string   // Low, Medium, High, Critical
    ProductIDs []string
}
```

#### `SimplifiedAdvisory`
```go
type SimplifiedAdvisory struct {
    ID             string
    Title          string
    Summary        string
    Publisher      string
    InitialRelease string
    CurrentRelease string
    CVEs           []string
    Products       []string
    Severity       string
    Status         string   // draft, interim, final
}
```

#### `Simplify(doc *csaf.Advisory) *SimplifiedAdvisory`
Converts a CSAF Advisory to a simplified format with commonly accessed fields.

## Testing

The package includes comprehensive BDD tests using Ginkgo/Gomega:

```bash
# Run all CSAF tests
go test ./internal/utils/csaf/...

# Run with verbose output
go test -v ./internal/utils/csaf/...

# Run with coverage
go test -cover ./internal/utils/csaf/...
```

### Test Coverage

- **Parser Tests**: 25 test cases covering file/bytes parsing, validation, error handling
- **Extractor Tests**: 25 test cases covering CVE, product, remediation, and score extraction
- **Types Tests**: 13 test cases covering simplified advisory conversion

Total: **63 BDD test cases** ensuring comprehensive coverage.

## Dependencies

- `github.com/gocsaf/csaf/v3` v3.5.1 - Core CSAF library
- `github.com/onsi/ginkgo/v2` - BDD testing framework
- `github.com/onsi/gomega` - Matcher library for tests

## Error Handling

The parser provides detailed error messages:

```go
// File not found
err := parser.ParseFile(ctx, "missing.json")
// Error: file does not exist: missing.json

// Malformed JSON
err := parser.ParseBytes(ctx, []byte("invalid"))
// Error: failed to parse CSAF JSON: ...

// Validation failure
err := parser.Validate()
// Error: validation failed: ...

// Context cancelled
ctx, cancel := context.WithCancel(context.Background())
cancel()
err := parser.ParseFile(ctx, "file.json")
// Error: context canceled
```

## Performance Considerations

- **Streaming**: The parser loads entire documents into memory. For large files, consider streaming approaches.
- **Validation**: Validation happens during parse by default. Skip validation for trusted sources if needed.
- **Context**: Always use context with timeouts for production code to prevent indefinite hangs.

## Best Practices

1. **Always use context**: Pass context to ParseFile/ParseBytes for cancellation support
2. **Validate after parse**: Call Validate() to ensure document integrity
3. **Handle errors**: Check all return values and handle errors appropriately
4. **Use extractors**: Prefer extractor functions over direct field access
5. **Simplify when possible**: Use Simplify() for common use cases

## License

This package is part of vulnz-go and follows the same license.
