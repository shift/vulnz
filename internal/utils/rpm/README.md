# RPM Version Comparison for vulnz-go

This package implements RPM version comparison following RPM's version ordering algorithm. It is critical for vulnerability matching in RHEL, Fedora, CentOS, SUSE, Oracle Linux, and other RPM-based distributions.

## Overview

RPM versions consist of three parts: `[epoch:]version[-release]`

- **Epoch** (optional): Integer, highest epoch wins (e.g., `2:` > `1:`)
- **Version**: Main version string (e.g., `1.2.3`)
- **Release**: Distribution-specific release (e.g., `4.el8`)

## Usage

### Basic Usage

```go
package main

import (
    "fmt"
    "github.com/shift/vulnz/internal/utils/rpm"
)

func main() {
    // Parse versions
    v1, _ := rpm.Parse("2:1.1.1k-7.el8_6")
    v2, _ := rpm.Parse("2:1.1.1k-8.el8_7")

    // Compare
    if v1.Less(v2) {
        fmt.Printf("%s is older than %s\n", v1, v2)
    }

    // Check equality
    if v1.Equal(v2) {
        fmt.Println("Versions are equal")
    }

    // Full comparison (-1, 0, 1)
    result := v1.Compare(v2)
    fmt.Printf("Comparison result: %d\n", result)
}
```

### Vulnerability Checking

```go
func isVulnerable(installed, fixed *rpm.Version) bool {
    // If installed version is less than fixed version, it's vulnerable
    return installed.Less(fixed)
}

func checkVulnerability() {
    installed, _ := rpm.Parse("2:1.1.1k-7.el8_6")
    fixed, _ := rpm.Parse("2:1.1.1k-8.el8_6")

    if isVulnerable(installed, fixed) {
        fmt.Println("System is vulnerable! Please upgrade.")
    } else {
        fmt.Println("System is patched.")
    }
}
```

### Constructor Functions

```go
// Parse from string (returns error)
v, err := rpm.Parse("2:1.2.3-4.el8")
if err != nil {
    log.Fatal(err)
}

// MustParse (panics on error, useful for tests)
v := rpm.MustParse("2:1.2.3-4.el8")

// Create from components
v, err := rpm.New(2, "1.2.3", "4.el8")

// MustNew (panics on error)
v := rpm.MustNew(2, "1.2.3", "4.el8")
```

### Validation

```go
// Validate version string
if err := rpm.Validate("2:1.2.3-4.el8"); err != nil {
    log.Fatal("Invalid version:", err)
}

// Validate epoch
if !rpm.IsValidEpoch(2) {
    log.Fatal("Invalid epoch")
}

// Validate version string
if !rpm.IsValidVersion("1.2.3") {
    log.Fatal("Invalid version")
}
```

## Comparison Rules

### 1. Epoch Comparison

Epoch always takes precedence. Higher epoch wins regardless of version/release.

```go
v1 := rpm.MustParse("2:1.0-1")
v2 := rpm.MustParse("1:9999-999")
v1.Greater(v2) // true (epoch 2 > epoch 1)
```

### 2. Numeric Comparison

Numeric segments are compared as integers, not strings.

```go
v1 := rpm.MustParse("1.10")
v2 := rpm.MustParse("1.9")
v1.Greater(v2) // true (10 > 9, not "10" < "9")
```

### 3. Alpha Comparison

Alphabetic segments are compared lexicographically.

```go
v1 := rpm.MustParse("1.a")
v2 := rpm.MustParse("1.b")
v1.Less(v2) // true ("a" < "b")
```

### 4. Numeric vs Alpha

Numeric segments always win over alpha segments.

```go
v1 := rpm.MustParse("1.0.1")
v2 := rpm.MustParse("1.0.a")
v1.Greater(v2) // true (numeric > alpha)
```

### 5. Tilde for Pre-releases

Tilde (~) sorts before everything, used for pre-release versions.

```go
v1 := rpm.MustParse("1.0~rc1")
v2 := rpm.MustParse("1.0")
v1.Less(v2) // true (tilde makes it pre-release)
```

### 6. Trailing Zeros

Trailing zeros are ignored in numeric comparisons.

```go
v1 := rpm.MustParse("1.0.0")
v2 := rpm.MustParse("1.0")
v1.Equal(v2) // true (trailing zeros ignored)
```

## Real-World Examples

### RHEL Package Versions

```go
// OpenSSL vulnerability check
installed := rpm.MustParse("2:1.1.1k-7.el8_6")
fixed := rpm.MustParse("2:1.1.1k-8.el8_6")
installed.Less(fixed) // true - vulnerable

// Kernel version comparison
kernel1 := rpm.MustParse("4.18.0-372.el8")
kernel2 := rpm.MustParse("4.18.0-373.el8")
kernel1.Less(kernel2) // true

// glibc across RHEL versions
rhel7 := rpm.MustParse("2.17-326.el7")
rhel8 := rpm.MustParse("2.28-164.el8")
rhel7.Less(rhel8) // true
```

### Fedora Package Versions

```go
// Across Fedora releases
fc38 := rpm.MustParse("1.0-1.fc38")
fc39 := rpm.MustParse("1.0-1.fc39")
fc38.Less(fc39) // true
```

### SUSE Package Versions

```go
// SLES with service packs
sles15sp1 := rpm.MustParse("1.0-1.sles15sp1")
sles15sp2 := rpm.MustParse("1.0-1.sles15sp2")
sles15sp1.Less(sles15sp2) // true
```

## Integration with Providers

This package is designed to be used by vulnerability data providers:

- **RHEL Provider**: Red Hat Enterprise Linux vulnerability data
- **Fedora Provider**: Fedora security advisories
- **CentOS Provider**: CentOS vulnerability tracking
- **Oracle Linux Provider**: Oracle Linux security data
- **SUSE Provider**: SUSE Linux Enterprise security updates
- **Amazon Linux Provider**: Amazon Linux (RPM-based)

### Example Provider Integration

```go
type RHELProvider struct {
    // ... provider fields
}

func (p *RHELProvider) isPackageVulnerable(
    installed string,
    vuln *Vulnerability,
) (bool, error) {
    installedVer, err := rpm.Parse(installed)
    if err != nil {
        return false, fmt.Errorf("invalid installed version: %w", err)
    }

    fixedVer, err := rpm.Parse(vuln.FixedVersion)
    if err != nil {
        return false, fmt.Errorf("invalid fixed version: %w", err)
    }

    // Vulnerable if installed < fixed
    return installedVer.Less(fixedVer), nil
}
```

## Performance

- **Time Complexity**: O(n) where n is the number of segments
- **Space Complexity**: O(1) for comparison (no allocations)
- **Typical Performance**: < 1μs per comparison

## Testing

The package includes comprehensive BDD tests:

- **166 test cases** covering:
  - Parsing (valid/invalid formats)
  - String representation
  - Comparison logic
  - Edge cases (tilde, zeros, etc.)
  - Real-world package versions
  - Distribution-specific formats

Run tests:

```bash
go test ./internal/utils/rpm/...
```

Run with coverage:

```bash
go test -cover ./internal/utils/rpm/...
```

## References

- [RPM Version Comparison Algorithm](https://github.com/rpm-software-management/rpm/blob/master/lib/rpmvercmp.c)
- [Fedora Packaging Guidelines](https://docs.fedoraproject.org/en-US/packaging-guidelines/Versioning/)
- [RHEL Package Naming](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/8/html/packaging_and_distributing_software/assembly_packaging-software_packaging-and-distributing-software)

## License

See LICENSE file in the repository root.
