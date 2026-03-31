# OVAL XML Parser for vulnz-go

## Overview

This package provides a comprehensive Go wrapper around the `quay/goval-parser` library for parsing OVAL (Open Vulnerability and Assessment Language) XML files. OVAL is an industry-standard XML-based language used to describe vulnerability definitions, security advisories, and system configuration checks.

## Features

- ✅ Parse OVAL XML files from filesystem or byte slices
- ✅ Query definitions by ID with efficient lookup
- ✅ Filter definitions by severity (Critical, Important, Moderate, Low)
- ✅ Filter definitions by OS family (unix, linux, windows, macos)
- ✅ Extract CVE IDs from vulnerability definitions
- ✅ Extract affected package names from criteria
- ✅ Simplified types for common operations
- ✅ Context support for cancellable operations
- ✅ Comprehensive BDD test suite (89 tests, 93.1% coverage)
- ✅ GoDoc documentation

## Installation

The package uses `github.com/quay/goval-parser@v0.8.8` as its underlying parser:

```bash
go get github.com/quay/goval-parser@v0.8.8
```

## Architecture

The OVAL parser consists of three main components:

### 1. Parser (`parser.go`)

The core parser wrapping `goval-parser` functionality:

- `NewParser()` - Create a new parser instance
- `ParseFile(ctx, path)` - Parse OVAL XML from file
- `ParseBytes(ctx, data)` - Parse OVAL XML from bytes
- `GetDefinition(id)` - Retrieve definition by ID
- `GetDefinitions()` - Get all parsed definitions
- `FilterBySeverity(severity)` - Filter by severity level
- `FilterByFamily(family)` - Filter by OS family

### 2. Types (`types.go`)

Simplified type definitions for easier consumption:

- `SimplifiedDefinition` - Key fields extracted from OVAL definitions
- `Reference` - External references (CVEs, advisories)
- `Criteria` - Logical conditions for vulnerability detection
- `Criterion` - Individual test conditions
- `Simplify(def)` - Convert goval Definition to simplified format
- `ToMap()` - Convert to map for JSON/YAML export
- `HasCVE(cveID)` - Check if definition references a CVE
- `GetCVEs()` - Get all CVE IDs from definition

### 3. Helpers (`helpers.go`)

Utility functions for extracting metadata:

- `ExtractCVEs(def)` - Extract CVE IDs from definition
- `ExtractPackages(def)` - Extract affected package names
- `GetSeverity(def)` - Get severity level
- `GetFamily(def)` - Get OS family
- `GetPlatforms(def)` - Get affected platforms
- `GetAdvisoryID(def)` - Get primary advisory ID (RHSA, USN, etc.)

## Usage Examples

### Basic Parsing

```go
package main

import (
    "context"
    "fmt"
    "log"
    
    "github.com/shift/vulnz/internal/utils/oval"
)

func main() {
    parser := oval.NewParser()
    ctx := context.Background()
    
    // Parse OVAL file
    if err := parser.ParseFile(ctx, "rhel-8.oval.xml"); err != nil {
        log.Fatal(err)
    }
    
    // Get all definitions
    defs := parser.GetDefinitions()
    fmt.Printf("Parsed %d OVAL definitions\n", len(defs))
}
```

### Filtering by Severity

```go
// Get critical vulnerabilities
critical := parser.FilterBySeverity("Critical")
fmt.Printf("Found %d critical vulnerabilities\n", len(critical))

// Severity values: Critical, Important, Moderate, Low
important := parser.FilterBySeverity("Important")
```

### Filtering by OS Family

```go
// Get Unix/Linux definitions
unix := parser.FilterByFamily("unix")

// Family values: unix, linux, windows, macos
```

### Extracting CVEs and Packages

```go
def, ok := parser.GetDefinition("oval:com.redhat.rhsa:def:20230001")
if ok {
    // Extract CVEs
    cves := oval.ExtractCVEs(def)
    fmt.Printf("CVEs: %v\n", cves)
    
    // Extract affected packages
    packages := oval.ExtractPackages(def)
    fmt.Printf("Packages: %v\n", packages)
    
    // Get metadata
    severity := oval.GetSeverity(def)
    advisory := oval.GetAdvisoryID(def)
    
    fmt.Printf("Advisory: %s (Severity: %s)\n", advisory, severity)
}
```

### Simplified Types

```go
def, _ := parser.GetDefinition("oval:com.redhat.rhsa:def:20230001")

// Convert to simplified format
simplified := oval.Simplify(def)

fmt.Printf("ID: %s\n", simplified.ID)
fmt.Printf("Title: %s\n", simplified.Title)
fmt.Printf("Severity: %s\n", simplified.Severity)
fmt.Printf("CVEs: %v\n", simplified.GetCVEs())

// Check for specific CVE
if simplified.HasCVE("CVE-2023-1234") {
    fmt.Println("This definition addresses CVE-2023-1234")
}

// Export to JSON
data := simplified.ToMap()
json.NewEncoder(os.Stdout).Encode(data)
```

### Multi-file Parsing

```go
parser := oval.NewParser()

// Parse multiple OVAL files
files := []string{
    "rhel-8.oval.xml",
    "ubuntu-22.04.oval.xml",
    "debian-11.oval.xml",
}

for _, file := range files {
    if err := parser.ParseFile(ctx, file); err != nil {
        log.Printf("Failed to parse %s: %v", file, err)
        continue
    }
}

// All definitions accumulated
allDefs := parser.GetDefinitions()
```

### Real-world Security Report

```go
parser := oval.NewParser()
ctx := context.Background()

if err := parser.ParseFile(ctx, "rhel-8.oval.xml"); err != nil {
    log.Fatal(err)
}

// Get all critical vulnerabilities
critical := parser.FilterBySeverity("Critical")

for _, def := range critical {
    // Extract details
    cves := oval.ExtractCVEs(def)
    packages := oval.ExtractPackages(def)
    advisory := oval.GetAdvisoryID(def)
    
    // Print security report
    fmt.Printf("\n🚨 Critical Vulnerability\n")
    fmt.Printf("Advisory: %s\n", advisory)
    fmt.Printf("CVEs: %v\n", cves)
    fmt.Printf("Affected Packages: %v\n", packages)
    fmt.Printf("Description: %s\n", def.Description)
}
```

## OVAL Background

OVAL defines several key components:

- **Definitions**: Vulnerability metadata and descriptions
- **Tests**: Checks to perform on systems
- **Objects**: Items to examine (packages, files, etc.)
- **States**: Expected values for objects
- **Variables**: Reusable values
- **Criteria**: Logical conditions combining tests

This parser focuses on definitions and criteria, which are the most commonly used components for vulnerability management.

## Supported OVAL Sources

The parser is designed to work with OVAL data from:

- **Red Hat Enterprise Linux (RHEL)** - RHSA advisories
- **Oracle Linux** - Similar to RHEL
- **Ubuntu** - USN advisories
- **Debian** - DSA/DLA advisories
- **SUSE Linux Enterprise (SLES)** - SUSE advisories
- **Amazon Linux** - ALAS advisories

## Testing

The package includes a comprehensive BDD test suite using Ginkgo/Gomega:

```bash
go test ./internal/utils/oval/... -v
```

### Test Coverage

- **89 test cases** covering all functionality
- **93.1% code coverage**
- Test fixtures for RHEL, Ubuntu, and Debian OVAL
- Edge case handling and error scenarios

### Test Structure

- `oval_suite_test.go` - Test suite setup
- `parser_bdd_test.go` - Parser functionality tests (30+ tests)
- `types_bdd_test.go` - Simplified types tests (20+ tests)
- `helpers_bdd_test.go` - Helper functions tests (35+ tests)

## Performance Characteristics

- **Memory Efficient**: Definitions stored by ID in a map for O(1) lookup
- **Parsing**: Handles large OVAL files (100MB+) efficiently using streaming XML parsing
- **Filtering**: In-memory filtering with O(n) complexity
- **Thread Safety**: Create separate parser instances per goroutine

## Error Handling

The parser provides clear error messages:

```go
// File not found
err: failed to open file: open rhel.xml: no such file or directory

// Malformed XML
err: failed to parse OVAL XML: XML syntax error

// Context cancellation
err: context error: context canceled

// Empty input
err: empty input data
```

## Integration Points

This OVAL parser will be used by:

- **RHEL Provider** - Red Hat Enterprise Linux vulnerability data
- **Oracle Linux Provider** - Oracle Linux advisories
- **SLES Provider** - SUSE Linux Enterprise
- **Amazon Linux Provider** - Amazon Linux Security Advisories
- **Debian Provider** - Debian Security Advisories (some)

## API Stability

This package follows semantic versioning. The API is considered stable with:

- Public functions documented with GoDoc
- Comprehensive test coverage
- Backward-compatible changes only

## License

This package is part of vulnz-go and follows the repository's license.

## References

- [OVAL Official Site](https://oval.mitre.org/)
- [OVAL Language Specification](https://oval.mitre.org/language/)
- [quay/goval-parser](https://github.com/quay/goval-parser)
- [vunnel Python OVAL parser](../../../vunnel-eu-cra/src/vunnel/utils/oval_v2.py) (reference implementation)

## Contributing

When contributing to the OVAL parser:

1. Add BDD tests for new functionality
2. Maintain code coverage above 90%
3. Update documentation with examples
4. Follow Go best practices and conventions
5. Test with real OVAL files from multiple sources
